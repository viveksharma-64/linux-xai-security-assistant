"""
The unattended ingestion service: supervised collectors, retention, alerting.

Why a separate entry point from `pipeline.live_ingestion.main`
-------------------------------------------------------------
`live_ingestion.main` runs one collector in the foreground and prints its health
on exit. That is the right shape for a developer testing a probe and the wrong
shape for a host that must keep collecting for a week: it has no retention, no
per-source degradation, and it exits when its single collector dies.

This module is the long-running form. It owns three periodic responsibilities that
have nothing to do with each other except that they must all happen without a
human present:

  supervision  restart collectors under backoff, degrade the ones that crash-loop
  retention    bound the database by age and by size, vacuum on a slow schedule
  alerting     evaluate the loss/death/staleness/disk rules and log what fires

Why one process and not three timers
------------------------------------
Retention and alerting could be systemd timers, and retention *is* also available
as one (`python3 -m storage.retention`) for operators who prefer that. Running them
in-process as well means a host with no timers configured still bounds its disk and
still says out loud when it has stopped collecting. The retention lock in
`RetentionManager` makes the overlap safe.

Shutdown
--------
SIGTERM and SIGINT ask every supervisor to stop and then wait, bounded. The bound
matters: systemd escalates to SIGKILL after `TimeoutStopSec`, and a service killed
mid-transaction is exactly the scenario WAL recovery has to clean up on the next
start. Stopping deliberately inside the window keeps that off the normal path.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from observability import alerts as alerting
from observability import configure_logging, metrics
from observability.config import ConfigError, Settings, load_settings
from pipeline.event_stream import Event
from pipeline.live_ingestion import DatabaseAnalysisPipeline, SubprocessJSONLSource
from pipeline.supervisor import CollectorSupervisor, SupervisedSource
from storage.retention import RetentionManager
from storage.sqlite_store import SQLiteEventStore

LOGGER = logging.getLogger(__name__)

# How often the maintenance thread wakes. Independent of the retention and alert
# intervals, which are checked against the clock inside the loop: a short tick with
# cheap predicates keeps shutdown responsive without running policy every second.
TICK_SECONDS = 1.0
DEFAULT_ALERT_INTERVAL_SECONDS = 30.0


def parse_source_spec(spec: str) -> SupervisedSource:
    """
    Turn a `name=command args...` spec into a supervised source.

    Named rather than positional because every operator-facing record of a
    collector -- the state row, the metric label, the degradation alert -- is keyed
    by that name. Deriving it from the command line would make the record change
    when a flag changes.
    """
    name, separator, command = spec.partition("=")
    name = name.strip()
    if not separator or not name or not command.strip():
        raise ValueError(f"source spec must be NAME=COMMAND, got {spec!r}")
    argv = command.split()
    return SupervisedSource(name=name, factory=lambda: SubprocessJSONLSource(argv))


class IngestionService:
    """
    Owns the store, the supervisors, and the maintenance loop for one host.

    Split from `main()` so the whole unattended lifecycle is testable: a test can
    construct this with fake sources and a fast clock, run it, kill a collector,
    and assert on what was persisted -- which is what the Phase B exit criterion
    actually asks to be demonstrated.
    """

    def __init__(
        self,
        store: SQLiteEventStore,
        sources: Sequence[SupervisedSource],
        config: Settings,
        service_factory: Optional[Callable[[SupervisedSource], Any]] = None,
        analysis_pipeline: Optional[Callable[[List[Event]], None]] = None,
        alert_interval_seconds: float = DEFAULT_ALERT_INTERVAL_SECONDS,
    ):
        self.store = store
        self.settings = config
        self.supervisor = CollectorSupervisor(
            store,
            list(sources),
            config=config,
            service_factory=service_factory,
            analysis_pipeline=analysis_pipeline,
        )
        self.retention = RetentionManager(store, config)
        self.alert_interval_seconds = alert_interval_seconds
        self._stop = threading.Event()
        self._maintenance: Optional[threading.Thread] = None
        self._last_alert_check = 0.0
        self._alert_state: List[alerting.Alert] = []

    # ------------------------------------------------------------------ control

    def start(self) -> None:
        self._stop.clear()
        self.supervisor.start()
        self._maintenance = threading.Thread(
            target=self._maintenance_loop, name="maintenance", daemon=True
        )
        self._maintenance.start()
        LOGGER.info(
            "service_start sources=%s db=%s retention_days=%.1f",
            ",".join(sorted(state for state in self.supervisor.states())),
            self.store.db_path,
            self.settings.retention_max_age_days,
        )

    def stop(self) -> None:
        self._stop.set()
        self.supervisor.stop()

    def join(self, timeout: Optional[float] = None) -> None:
        self.supervisor.join(timeout)
        if self._maintenance is not None:
            self._maintenance.join(timeout)

    def run(self) -> Dict[str, Any]:
        """
        Run until every source has stopped or been degraded, or until asked to stop.

        Returns the final state so the caller -- systemd's journal, or a test --
        gets one machine-readable record of how the run ended.
        """
        self.start()
        try:
            while not self._stop.is_set():
                if not any(
                    state.status in {"starting", "running", "backoff"}
                    for state in self.supervisor.states().values()
                ):
                    # Nothing left that will ever produce another event. Exiting
                    # lets systemd's Restart= policy decide, rather than holding a
                    # process open that is no longer collecting anything.
                    LOGGER.error("service_no_active_sources detail=%r", "every collector has stopped or degraded")
                    break
                time.sleep(TICK_SECONDS)
        finally:
            self.stop()
            self.join(timeout=10.0)
        return self.report()

    def report(self) -> Dict[str, Any]:
        states = {name: state.to_dict() for name, state in self.supervisor.states().items()}
        return {
            "sources": states,
            "alerts": [alert.to_dict() for alert in self._alert_state],
            "healthy": self.supervisor.healthy(),
        }

    # -------------------------------------------------------------- maintenance

    def _maintenance_loop(self) -> None:
        while not self._stop.wait(TICK_SECONDS):
            try:
                self.retention.maybe_run()
            except Exception as error:
                # Retention failing must not stop ingestion: a database that cannot
                # be pruned still collects, and the size cap alert will fire if the
                # failure persists.
                LOGGER.error("retention_failed error=%s", f"{type(error).__name__}: {error}")
            try:
                self._maybe_alert()
            except Exception as error:  # pragma: no cover - defensive
                LOGGER.error("alert_evaluation_failed error=%s", f"{type(error).__name__}: {error}")

    def _maybe_alert(self) -> None:
        now = time.monotonic()
        if self._last_alert_check and now - self._last_alert_check < self.alert_interval_seconds:
            return
        self._last_alert_check = now
        snapshot = metrics.collect_snapshot(self.store, self.settings)
        firing = alerting.evaluate(snapshot, self.settings)
        # Only transitions are logged. Re-logging every firing alert on every
        # interval would bury the moment a condition started -- which is the one
        # timestamp an operator needs -- under thousands of identical lines.
        previous = {alert.name for alert in self._alert_state}
        current = {alert.name for alert in firing}
        alerting.log_alerts([alert for alert in firing if alert.name not in previous])
        for name in sorted(previous - current):
            LOGGER.info("alert_cleared alert=%s", name)
        self._alert_state = firing


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run supervised telemetry ingestion with retention and alerting.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="NAME=COMMAND",
        help="a collector to supervise, e.g. process_exec=python3 telemetry/bcc/process_exec_probe.py "
        "(repeatable)",
    )
    parser.add_argument("--db", default=None, help="database path (defaults to the configured db_path)")
    parser.add_argument(
        "--no-analysis",
        action="store_true",
        help="ingest and persist only; skip feature extraction, detection, and explanation",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    configure_logging()
    try:
        config = load_settings()
    except ConfigError as error:
        raise SystemExit(f"invalid configuration: {error}") from error
    if args.db:
        config = config.replace(db_path=args.db)
    if not args.source:
        raise SystemExit("provide at least one --source NAME=COMMAND")
    try:
        sources = [parse_source_spec(spec) for spec in args.source]
    except ValueError as error:
        raise SystemExit(str(error)) from error

    store = SQLiteEventStore(
        config.db_path, file_mode=config.db_file_mode, enforce_file_mode=config.db_enforce_mode
    )
    analysis = None if args.no_analysis else DatabaseAnalysisPipeline(store).process
    service = IngestionService(store, sources, config, analysis_pipeline=analysis)

    def request_stop(signum, _frame):
        LOGGER.info("service_signal signal=%s", signal.Signals(signum).name)
        service.stop()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    try:
        report = service.run()
    finally:
        store.close()
    print(json.dumps(report, sort_keys=True, default=str))
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
