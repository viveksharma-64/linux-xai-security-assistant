#!/usr/bin/env python3
"""
Supervised bounded ingestion for live JSONL telemetry sources.

Event loss and backpressure
---------------------------
The producer used to call `put_nowait` and, on a full queue, increment a counter
and move on. Telemetry was therefore discarded at the first instant of pressure
even when the consumer was about to drain -- and the only trace was a number
that said how many events were gone, not when, or whether loss was still
happening. For a detection system that is the worst possible failure mode: the
evidence for a finding disappears silently and the gap is indistinguishable from
a quiet host.

The producer now waits for the consumer for a bounded budget before giving up,
so a transient burst costs latency rather than evidence. When the budget does
expire the drop is explicit: counted, timestamped at both ends so an analyst can
tell ongoing loss from stale loss, and logged to stderr. Queue depth, capacity,
and a high-water mark are reported too -- depth sampled at health-write time
cannot show a queue that filled and drained in between.

The budget is bounded rather than unlimited on purpose. Blocking forever would
turn a slow consumer into a stalled collector and could wedge shutdown, and an
unbounded in-memory queue just moves the loss to the OOM killer.

Deliberately not done here: spilling overflow to a side file. Under saturation
the disk is usually what is already slow, so a second write path from the
producer competes with the writes that are causing the pressure, and it adds a
rotation/replay/corruption surface next to the database that holds the audit
record. Backpressure plus honest accounting is the smaller and more truthful
mechanism.

Kernel-side loss
----------------
The accounting above only sees events that reached this process. A BCC perf ring
buffer that overruns destroys samples before userspace hears about them, so a
collector that is polling too slowly leaves a hole no queue counter can detect.
The collectors now report those overruns as `telemetry_loss` records on their
stdout (see `telemetry/bcc/perf_loss.py`), and the producer intercepts them into
a counter of their own. Kept separate from `dropped_event_count` on purpose: a
ring overrun means the collector could not keep up with the kernel, a queue drop
means this consumer could not keep up with the collector, and the two call for
different remedies.
"""

import argparse
import json
import logging
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
from observability import configure_logging
from pipeline.event_stream import CanonicalNormalizer, Event
from pipeline.quarantine import BatchQuarantine
from policy.engine import PolicyEngine
from storage.sqlite_store import SQLiteEventStore


LOGGER = logging.getLogger(__name__)

RawInput = Union[str, bytes, dict]
_SENTINEL = object()

# The wire name of a collector's kernel-loss report. Duplicated from
# `telemetry.bcc.perf_loss.LOSS_EVENT_TYPE` rather than imported: the collectors
# are run as bare scripts under sudo and cannot import this package, and this
# supervisor must not import a module that pulls in bcc. `tests/test_perf_loss.py`
# asserts the two constants stay equal.
LOSS_EVENT_TYPE = "telemetry_loss"


def _is_order_of_magnitude(count: int) -> bool:
    """True for 1, 10, 100, ... -- the drop counts worth a log line."""
    while count > 1 and count % 10 == 0:
        count //= 10
    return count == 1


def _decimal_magnitude(count: int) -> int:
    """Digit count, with 0 for zero, so the first loss always reads as a change."""
    return len(str(count)) if count > 0 else 0


def _crossed_order_of_magnitude(before: int, after: int) -> bool:
    """
    True when a running total gained a decimal digit.

    `_is_order_of_magnitude` answers the same question for a counter that
    increments by one. Kernel loss does not: it arrives already batched, and a
    first report of 250 lost samples lands on no power of ten at all, so an
    exact-match test would log nothing about the largest gap in the record. This
    asks whether the total crossed a magnitude instead, which reports every
    escalation once and leaves no burst silent.
    """
    return _decimal_magnitude(after) > _decimal_magnitude(before)


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
    # Backpressure and event-loss accounting. `backpressure_wait_count` counts
    # every event that had to wait for queue space, whether or not it was
    # eventually queued, so dropped_event_count <= backpressure_wait_count
    # always holds and the ratio shows how often waiting actually rescued an
    # event. The drop timestamps are wall clock, to be read against updated_at.
    queue_depth: int = 0
    queue_capacity: int = 0
    queue_high_water_mark: int = 0
    backpressure_wait_seconds: float = 0.0
    backpressure_wait_count: int = 0
    first_drop_timestamp: Optional[float] = None
    last_drop_timestamp: Optional[float] = None
    # Kernel-side loss, reported by the collector rather than observed here. Held
    # apart from dropped_event_count because the two have different causes and
    # different fixes: a perf ring overrun means the collector could not drain
    # the kernel fast enough, while a dropped event means this consumer could not
    # keep up with the collector. Summing them would hide which one is happening.
    kernel_lost_event_count: int = 0
    first_kernel_loss_timestamp: Optional[float] = None
    last_kernel_loss_timestamp: Optional[float] = None
    # Batches the database refused, set aside for replay. Counted separately from
    # every other loss figure because it is the only one that is recoverable: the
    # events still exist on disk, and the operator's action is a replay rather
    # than an investigation into a gap.
    quarantined_batch_count: int = 0
    quarantined_event_count: int = 0

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
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("collector subprocess is already running")
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
        try:
            for line in self.process.stdout:
                yield line
            return_code = self.process.wait()
            if self._stderr_thread is not None:
                self._stderr_thread.join(timeout=1)
            if return_code != 0 and not self._closed.is_set():
                detail = " ".join(self._stderr_lines).strip()
                raise RuntimeError(f"collector exited with status {return_code}: {detail}")
        finally:
            # Reaped here rather than in close(): this runs on the thread that owns
            # the stdout read, so it cannot close the pipe out from under a blocked
            # reader. Runs on every exit path, including generator abandonment.
            self._reap()

    def _reap(self) -> None:
        """Stop the child if it outlived its reader, then close its pipes. Idempotent."""
        process = self.process
        if process is None:
            return
        # Stop the child before touching the pipes. stderr stays open until the
        # collector exits, and closing a stream that _read_stderr is blocked on
        # waits for that thread's in-flight read to finish.
        self._terminate()
        stderr_thread = self._stderr_thread
        if stderr_thread is not None and stderr_thread is not threading.current_thread():
            stderr_thread.join(timeout=1)
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

    def _terminate(self) -> None:
        """Terminate the collector, escalating to SIGKILL. No-op if already exited."""
        process = self.process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def _read_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        try:
            for line in self.process.stderr:
                line = line.strip()
                if line:
                    self._stderr_lines.append(line)
        except (OSError, ValueError):
            # _reap() closed stderr while this thread was blocked on a read.
            return

    def close(self) -> None:
        self._closed.set()
        # Terminating the child closes its end of stdout, which ends the reader's
        # loop and lets __iter__'s finally block reap the pipes. The pipes are
        # deliberately not closed here: a reader may be blocked on them, and
        # closing underneath it would surface a requested shutdown as a failure.
        self._terminate()


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
        backpressure_timeout_seconds: float = 2.0,
        ingest_batch_size: int = 50,
        quarantine: Optional[BatchQuarantine] = None,
        source_name: Optional[str] = None,
    ):
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        if health_interval_seconds <= 0:
            raise ValueError("health_interval_seconds must be positive")
        if backpressure_timeout_seconds < 0:
            raise ValueError("backpressure_timeout_seconds must not be negative")
        if ingest_batch_size <= 0:
            raise ValueError("ingest_batch_size must be positive")
        self.source = source
        self.store = store
        self.queue: Queue[object] = Queue(maxsize=queue_size)
        self.normalizer = normalizer or CanonicalNormalizer()
        self.analysis_pipeline = analysis_pipeline
        self.health_interval_seconds = health_interval_seconds
        # How long the producer will wait for queue space before accepting the
        # loss. 0 restores the old drop-immediately behaviour for callers that
        # would rather shed load than add latency.
        self.backpressure_timeout_seconds = backpressure_timeout_seconds
        # Events per write transaction, and per analysis pass. One knob for both
        # because they were the same number before batching existed, and splitting
        # them would let an operator tune the write path into a state where
        # analysis windows silently changed size.
        self.ingest_batch_size = ingest_batch_size
        self.analysis_batch_size = ingest_batch_size
        self.quarantine = quarantine
        self.source_name = source_name
        self._stop = threading.Event()
        self._producer_done = threading.Event()
        self._health_lock = threading.Lock()
        self._producer: Optional[threading.Thread] = None
        self._consumer: Optional[threading.Thread] = None
        self._health = CollectorHealth(queue_capacity=queue_size)
        self._queue_depth = 0
        self._queue_high_water_mark = 0
        self._last_health_write = 0.0
        # Sticky, unlike `_stop`, which `start()` may clear.
        self._stop_requested = False

    def start(self) -> None:
        if self._producer and self._producer.is_alive():
            raise RuntimeError("ingestion service is already running")
        now = time.time()
        with self._health_lock:
            self._health = CollectorHealth(
                status="running",
                started_at=now,
                updated_at=now,
                queue_capacity=self.queue.maxsize,
            )
        self._persist_health()
        # Deliberately not an unconditional clear. A stop that arrived before the
        # threads existed has to survive `start()`: clearing it would resurrect a
        # collector the operator (or systemd) already asked to shut down, and the
        # producer would run on with nothing left to stop it. A caller that starts a
        # service which has already run once is asking for a restart, so that case
        # does clear -- the distinction is whether a lifecycle ever began.
        if self._producer is None and self._stop_requested:
            LOGGER.info("ingestion_start_skipped reason=stop_requested_before_start")
        else:
            self._stop_requested = False
            self._stop.clear()
        self._producer_done.clear()
        self._queue_depth = 0
        self._queue_high_water_mark = 0
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
        # The event and the source close happen unconditionally, before the health
        # bookkeeping. Guarding them behind the status check meant a stop that
        # arrived before `start()` -- status still "unknown" -- was dropped whole:
        # the flag was never set, the source was never closed, and the collector
        # then ran until the process was killed. Health status is the only part that
        # is conditional, so a terminal status is not overwritten by "stopping".
        self._stop_requested = True
        self._stop.set()
        with self._health_lock:
            if self._health.status not in {"stopped", "failed", "unknown"}:
                self._health.status = "stopping"
                self._health.detail = "shutdown requested"
        close = getattr(self.source, "close", None)
        if callable(close):
            close()
        self._persist_health(force=True)

    def health(self) -> CollectorHealth:
        with self._health_lock:
            snapshot = CollectorHealth(**self._health.to_dict())
        # Folded in outside the lock: see _observe_queue_depth for why these two
        # are producer-owned rather than lock-protected.
        snapshot.queue_depth = self._queue_depth
        snapshot.queue_high_water_mark = self._queue_high_water_mark
        return snapshot

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
                # Intercepted before the queue rather than in the consumer. A
                # loss report arrives precisely when things are congested, and
                # routing it through the queue would make the record describing
                # the loss the next thing to be dropped -- or to be counted as
                # malformed downstream, since it is not a canonical event type.
                if item.get("event_type") == LOSS_EVENT_TYPE:
                    self._record_kernel_loss(item)
                    continue
                self._enqueue(item)
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

    def _enqueue(self, item: dict) -> None:
        """
        Hand an event to the consumer, waiting for space before losing it.

        The fast path is unchanged: an unsaturated queue accepts immediately and
        costs nothing extra. Only when the queue is full does the producer wait,
        and only up to `backpressure_timeout_seconds`, so a slow consumer cannot
        stall the collector or wedge shutdown. Waiting is polled rather than one
        long blocking put so a stop request is honoured promptly.
        """
        try:
            self.queue.put_nowait(item)
        except Full:
            pass
        else:
            self._observe_queue_depth()
            return

        waited = 0.0
        deadline = time.monotonic() + self.backpressure_timeout_seconds
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self.queue.put(item, timeout=min(remaining, 0.05))
            except Full:
                continue
            waited = self.backpressure_timeout_seconds - max(deadline - time.monotonic(), 0.0)
            with self._health_lock:
                self._health.backpressure_wait_count += 1
                self._health.backpressure_wait_seconds += waited
            self._observe_queue_depth()
            return

        waited = self.backpressure_timeout_seconds - max(deadline - time.monotonic(), 0.0)
        self._record_drop(waited)

    def _observe_queue_depth(self) -> None:
        """
        Sample queue occupancy.

        These two counters are written only by the producer thread and read only
        under `_health_lock` when a snapshot is taken, so they are deliberately
        kept off the health lock: this runs once per event, and taking a second
        lock on the ingest hot path to maintain a metric would make the
        saturation it measures marginally more likely.
        """
        depth = self.queue.qsize()
        self._queue_depth = depth
        if depth > self._queue_high_water_mark:
            self._queue_high_water_mark = depth

    def _record_drop(self, waited_seconds: float) -> None:
        """
        Account for an event that could not be queued, and say so out loud.

        Logged on the first loss and then once per order of magnitude. Sustained
        saturation would otherwise emit a line per lost event, competing for the
        CPU that is already behind and burying the first occurrence -- the one
        that says when loss began. Exact counts are always in the health record;
        the log exists to mark the transitions.
        """
        now = time.time()
        with self._health_lock:
            self._health.backpressure_wait_count += 1
            self._health.backpressure_wait_seconds += waited_seconds
            self._health.dropped_event_count += 1
            dropped = self._health.dropped_event_count
            if self._health.first_drop_timestamp is None:
                self._health.first_drop_timestamp = now
            self._health.last_drop_timestamp = now
        if _is_order_of_magnitude(dropped):
            LOGGER.warning(
                "telemetry event dropped: dropped_event_count=%d queue_capacity=%d "
                "waited_seconds=%.3f reason=queue_full",
                dropped,
                self.queue.maxsize,
                waited_seconds,
            )

    def _record_kernel_loss(self, record: dict) -> None:
        """
        Account for samples the kernel discarded before this process saw them.

        The count is the collector's, not ours: a perf ring overrun happens
        inside the kernel, so the only honest source for how many events were
        destroyed is the `lost_cb` that observed it. A record whose count cannot
        be read is therefore counted as malformed rather than assigned a guessed
        magnitude -- we know loss occurred, we do not know how much, and inventing
        a number here would put a fabricated figure in the evidence trail.

        Logged on the first loss and then whenever the total crosses an order of
        magnitude, matching `_record_drop`'s cadence. `reason=` differs from the
        queue-drop line on purpose: an overrun means this collector could not
        drain the kernel fast enough, which is fixed with a larger `page_cnt` or a
        cheaper handler, not with a bigger ingestion queue.
        """
        try:
            lost = int(record["lost_events"])
        except (KeyError, TypeError, ValueError):
            with self._health_lock:
                self._health.malformed_count += 1
            return
        if lost <= 0:
            with self._health_lock:
                self._health.malformed_count += 1
            return

        now = time.time()
        with self._health_lock:
            previous = self._health.kernel_lost_event_count
            self._health.kernel_lost_event_count = previous + lost
            total = self._health.kernel_lost_event_count
            if self._health.first_kernel_loss_timestamp is None:
                self._health.first_kernel_loss_timestamp = now
            self._health.last_kernel_loss_timestamp = now
        if _crossed_order_of_magnitude(previous, total):
            try:
                reported_total: object = int(record["total_lost_events"])
            except (KeyError, TypeError, ValueError):
                reported_total = "unknown"
            # %r on the collector-supplied buffer name, and the collector's own
            # total narrowed to an int, so no field of the record can inject a
            # newline and forge a second log line.
            LOGGER.warning(
                "telemetry events lost in kernel: kernel_lost_event_count=%d "
                "lost_events=%d buffer=%r collector_reported_total=%s "
                "reason=perf_buffer_overrun",
                total,
                lost,
                str(record.get("buffer", "unknown"))[:64],
                reported_total,
            )

    def _consume(self) -> None:
        pending: list[Event] = []
        batch: list[Event] = []
        try:
            while True:
                try:
                    item = self.queue.get(timeout=0.1)
                except Empty:
                    if self._producer_done.is_set():
                        break
                    # Idle: flush what is held rather than waiting for the batch to
                    # fill. Otherwise a quiet host's last few events would sit in
                    # memory indefinitely -- unqueryable, and lost on a crash --
                    # which is the opposite of what batching is for. The durability
                    # bound is therefore this poll interval, not the batch size.
                    pending = self._flush(pending, batch)
                    batch = self._maybe_analyse(batch)
                    self._persist_health()
                    continue
                if item is _SENTINEL:
                    break
                event = self.normalizer.normalize(item)
                if event is None:
                    with self._health_lock:
                        self._health.malformed_count += 1
                    continue
                pending.append(event)
                if len(pending) >= self.ingest_batch_size:
                    pending = self._flush(pending, batch)
                    batch = self._maybe_analyse(batch)
                self._persist_health()
            self._flush(pending, batch)
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

    def _flush(self, pending: list[Event], batch: list[Event]) -> list[Event]:
        """
        Persist a batch of events in one transaction, then queue them for analysis.

        One transaction per batch instead of one per event is the whole point: a
        durable single-event write costs a WAL append plus an fsync-class barrier
        each, and at collector rates that barrier -- not normalization, not
        indexing -- was the ingest ceiling. Batching amortises it across the batch
        while keeping the same durability guarantee for everything in it.

        Events reach `batch` (the analysis queue) only after they are committed, so
        a finding can never cite an event that is not in the database.

        Returns the new pending list so the caller cannot accidentally keep using
        a list whose contents were already written.
        """
        if not pending:
            return pending
        try:
            result = self.store.write_events(pending)
        except Exception as error:
            # A batch that the database refuses is not the consumer's to lose: the
            # quarantine writes it aside so it can be replayed after the cause is
            # fixed. Without a handler here one malformed-for-SQLite batch would
            # kill the consumer thread and stop ingestion entirely.
            self._quarantine_batch(pending, error)
            return []

        now_events = len(pending)
        with self._health_lock:
            self._health.processed_count += result.inserted + result.duplicates
            self._health.duplicate_count += result.duplicates
            self._health.malformed_count += result.rejected_count
            self._health.last_event_timestamp = pending[-1].timestamp
        if result.rejected:
            for _, reason in result.rejected[:1]:
                LOGGER.warning(
                    "telemetry events rejected before write: rejected=%d of %d reason=%s",
                    result.rejected_count,
                    now_events,
                    reason,
                )
        batch.extend(pending)
        return []

    def _maybe_analyse(self, batch: list[Event]) -> list[Event]:
        if len(batch) < self.analysis_batch_size:
            return batch
        self._process_batch(batch)
        return []

    def _quarantine_batch(self, events: list[Event], error: Exception) -> None:
        """
        Hand a rejected batch to the quarantine, and record that it happened.

        Reported at error level even when the quarantine accepts it: a quarantined
        batch is evidence that is in the database's place but not in the database,
        and an operator who never hears about it will not replay it.
        """
        detail = f"{type(error).__name__}: {error}"
        stored = False
        if self.quarantine is not None:
            try:
                stored = self.quarantine.store(events, detail, source=self.source_name)
            except Exception as quarantine_error:  # pragma: no cover - defensive
                LOGGER.error(
                    "quarantine_write_failed events=%d write_error=%s quarantine_error=%s",
                    len(events),
                    detail,
                    f"{type(quarantine_error).__name__}: {quarantine_error}",
                )
        with self._health_lock:
            self._health.quarantined_batch_count += 1
            self._health.quarantined_event_count += len(events)
            self._health.error = detail
            self._health.detail = "batch quarantined after a failed write"
        LOGGER.error(
            "telemetry batch quarantined: events=%d persisted=%s error=%s",
            len(events),
            stored,
            detail,
        )

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
        snapshot["queue_depth"] = self._queue_depth
        snapshot["queue_high_water_mark"] = self._queue_high_water_mark
        self.store.write_collector_health(snapshot)
        self._last_health_write = now


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest a supervised JSONL telemetry collector into SQLite.")
    parser.add_argument("--db", default=os.getenv("SECURITY_DB_PATH", "phase2_events.db"))
    parser.add_argument("--queue-size", type=int, default=1024)
    parser.add_argument(
        "--backpressure-timeout",
        type=float,
        default=2.0,
        help="seconds the producer waits for queue space before recording a dropped event (0 sheds load immediately)",
    )
    parser.add_argument("--no-analysis", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="collector command after --")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    configure_logging()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise SystemExit("provide a collector command after --")
    store = SQLiteEventStore(args.db)
    source = SubprocessJSONLSource(command)
    analysis = None if args.no_analysis else DatabaseAnalysisPipeline(store).process
    service = LiveIngestionService(
        source,
        store,
        queue_size=args.queue_size,
        analysis_pipeline=analysis,
        backpressure_timeout_seconds=args.backpressure_timeout,
    )

    def request_stop(signum, frame):
        service.stop()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    health = service.run()
    print(json.dumps(health.to_dict(), sort_keys=True))
    return 0 if health.status == "stopped" else 1


if __name__ == "__main__":
    raise SystemExit(main())
