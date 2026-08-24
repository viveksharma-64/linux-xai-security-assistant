#!/usr/bin/env python3
"""Supervised bounded ingestion for live JSONL telemetry sources."""

import argparse
import json
import os
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Callable, Iterable, Iterator, Optional, Union

from assistant.service import AssistantService
from baseline.behavior_analyzer import BehaviorAnalyzer
from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from pipeline.event_stream import CanonicalNormalizer, Event
from policy.engine import PolicyEngine
from storage.sqlite_store import SQLiteEventStore


RawInput = Union[str, bytes, dict]
_SENTINEL = object()


@dataclass
class CollectorHealth:
    status: str = "unknown"
    detail: str = ""
    error: Optional[str] = None
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    last_event_timestamp: Optional[float] = None
    processed_count: int = 0
    malformed_count: int = 0
    dropped_event_count: int = 0
    duplicate_count: int = 0
    throughput: float = 0.0
    updated_at: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)


class SubprocessJSONLSource:
    """Read stdout from a collector subprocess and surface non-zero exits."""

    def __init__(self, command: list[str]):
        if not command:
            raise ValueError("collector command is required")
        self.command = list(command)
        self.process: Optional[subprocess.Popen[str]] = None
        self._stderr_lines = deque(maxlen=20)
        self._stderr_thread: Optional[threading.Thread] = None
        self._closed = threading.Event()

    def __iter__(self) -> Iterator[str]:
        self._closed.clear()
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()
        assert self.process.stdout is not None
        for line in self.process.stdout:
            yield line
        return_code = self.process.wait()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=1)
        if return_code != 0 and not self._closed.is_set():
            detail = " ".join(self._stderr_lines).strip()
            raise RuntimeError(f"collector exited with status {return_code}: {detail}")

    def _read_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        for line in self.process.stderr:
            line = line.strip()
            if line:
                self._stderr_lines.append(line)

    def close(self) -> None:
        self._closed.set()
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class DatabaseAnalysisPipeline:
    """Run existing analysis stages without learning from monitoring data."""

    def __init__(self, store: SQLiteEventStore, policy_path: Optional[str] = None, ml_scorer: Optional[Any] = None):
        self.store = store
        self.analyzer = BehaviorAnalyzer(store)
        self.detector = DetectionEngine(store, ml_scorer=ml_scorer)
        self.explainer = FindingExplainer(store)
        self.assistant = AssistantService(None, store=store)
        policy_file = policy_path or str(Path(__file__).parents[1] / "policy" / "default_policy.yaml")
        self.policy = PolicyEngine.from_yaml(store, policy_file)

    def process(self, events: list[Event]) -> None:
        if not events:
            return
        monitoring = self.analyzer.monitor(events)
        if not monitoring["risks"]:
            return
        detection = self.detector.detect(monitoring["risks"], events)
        findings = detection["findings"]
        explanations = self.explainer.explain_all(findings)
        responses = self.assistant.generate_all(explanations)
        response_by_finding = {
            response["finding_id"]: response for response in responses
        }
        self.policy.evaluate_all(findings, response_by_finding)


class LiveIngestionService:
    """Supervise source -> bounded queue -> normalization -> SQLite ingestion."""

    def __init__(
        self,
        source: Iterable[RawInput],
        store: SQLiteEventStore,
        queue_size: int = 1024,
        normalizer: Optional[CanonicalNormalizer] = None,
        analysis_pipeline: Optional[Callable[[list[Event]], None]] = None,
        health_interval_seconds: float = 1.0,
    ):
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        if health_interval_seconds <= 0:
            raise ValueError("health_interval_seconds must be positive")
        self.source = source
        self.store = store
        self.queue: Queue[object] = Queue(maxsize=queue_size)
        self.normalizer = normalizer or CanonicalNormalizer()
        self.analysis_pipeline = analysis_pipeline
        self.health_interval_seconds = health_interval_seconds
        self._stop = threading.Event()
        self._producer_done = threading.Event()
        self._health_lock = threading.Lock()
        self._producer: Optional[threading.Thread] = None
        self._consumer: Optional[threading.Thread] = None
        self._health = CollectorHealth()
        self._last_health_write = 0.0

    def start(self) -> None:
        if self._producer and self._producer.is_alive():
            raise RuntimeError("ingestion service is already running")
        now = time.time()
        with self._health_lock:
            self._health = CollectorHealth(status="running", started_at=now, updated_at=now)
        self._persist_health()
        self._stop.clear()
        self._producer_done.clear()
        self._producer = threading.Thread(target=self._produce, name="telemetry-producer", daemon=True)
        self._consumer = threading.Thread(target=self._consume, name="telemetry-consumer", daemon=True)
        self._producer.start()
        self._consumer.start()

    def run(self) -> CollectorHealth:
        self.start()
        assert self._producer is not None
        assert self._consumer is not None
        self._producer.join()
        self._consumer.join()
        return self.health()

    def stop(self) -> None:
        with self._health_lock:
            if self._health.status in {"stopped", "failed", "unknown"}:
                return
            self._health.status = "stopping"
            self._health.detail = "shutdown requested"
        self._stop.set()
        close = getattr(self.source, "close", None)
        if callable(close):
            close()
        self._persist_health(force=True)

    def health(self) -> CollectorHealth:
        with self._health_lock:
            return CollectorHealth(**self._health.to_dict())

    def _set_error(self, error: Exception) -> None:
        with self._health_lock:
            self._health.status = "failed"
            self._health.error = f"{type(error).__name__}: {error}"
            self._health.detail = "collector or ingestion failure"

    def _produce(self) -> None:
        try:
            for raw in self.source:
                if self._stop.is_set():
                    break
                try:
                    item = self._decode(raw)
                except (TypeError, ValueError, json.JSONDecodeError):
                    with self._health_lock:
                        self._health.malformed_count += 1
                    continue
                try:
                    self.queue.put_nowait(item)
                except Full:
                    with self._health_lock:
                        self._health.dropped_event_count += 1
        except Exception as error:
            self._set_error(error)
        finally:
            self._producer_done.set()
            while True:
                try:
                    self.queue.put(_SENTINEL, timeout=0.1)
                    break
                except Full:
                    if self._consumer is None or not self._consumer.is_alive():
                        break

    def _consume(self) -> None:
        batch: list[Event] = []
        try:
            while True:
                try:
                    item = self.queue.get(timeout=0.1)
                except Empty:
                    if self._producer_done.is_set():
                        break
                    self._persist_health()
                    continue
                if item is _SENTINEL:
                    break
                event = self.normalizer.normalize(item)
                if event is None:
                    with self._health_lock:
                        self._health.malformed_count += 1
                    continue
                inserted = self.store.write(event)
                with self._health_lock:
                    self._health.processed_count += 1
                    self._health.last_event_timestamp = event.timestamp
                    if not inserted:
                        self._health.duplicate_count += 1
                batch.append(event)
                if len(batch) >= 50:
                    self._process_batch(batch)
                    batch = []
                self._persist_health()
            self._process_batch(batch)
        except Exception as error:
            self._set_error(error)
        finally:
            with self._health_lock:
                if self._health.status != "failed":
                    self._health.status = "stopped"
                    self._health.detail = "collector stopped cleanly"
                self._health.stopped_at = time.time()
            self._persist_health(force=True)

    def _process_batch(self, batch: list[Event]) -> None:
        if self.analysis_pipeline is None or not batch:
            return
        try:
            self.analysis_pipeline(batch)
        except Exception as error:
            self._set_error(error)

    def _decode(self, raw: RawInput) -> dict:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if isinstance(raw, str):
            value = json.loads(raw)
        else:
            value = raw
        if not isinstance(value, dict):
            raise ValueError("telemetry record must be a JSON object")
        return value

    def _persist_health(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_health_write < self.health_interval_seconds:
            return
        with self._health_lock:
            elapsed = max(now - self._health.started_at, 0.001) if self._health.started_at else 0.001
            self._health.throughput = self._health.processed_count / elapsed
            self._health.updated_at = now
            snapshot = self._health.to_dict()
        self.store.write_collector_health(snapshot)
        self._last_health_write = now


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest a supervised JSONL telemetry collector into SQLite.")
    parser.add_argument("--db", default=os.getenv("SECURITY_DB_PATH", "phase2_events.db"))
    parser.add_argument("--queue-size", type=int, default=1024)
    parser.add_argument("--no-analysis", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="collector command after --")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise SystemExit("provide a collector command after --")
    store = SQLiteEventStore(args.db)
    source = SubprocessJSONLSource(command)
    analysis = None if args.no_analysis else DatabaseAnalysisPipeline(store).process
    service = LiveIngestionService(source, store, queue_size=args.queue_size, analysis_pipeline=analysis)

    def request_stop(signum, frame):
        service.stop()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    health = service.run()
    print(json.dumps(health.to_dict(), sort_keys=True))
    return 0 if health.status == "stopped" else 1


if __name__ == "__main__":
    raise SystemExit(main())
