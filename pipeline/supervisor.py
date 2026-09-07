"""
Collector supervision: restart with backoff, crash-loop detection, per-source
degradation.

Why supervision belongs here and not in systemd
-----------------------------------------------
`Restart=always` restarts the *process*. This process ingests from one or more
collectors, and a collector dying is not the same event as the service dying:
letting systemd handle it means one failed BPF probe tears down ingestion for
every other source, drops whatever is in the queue, and reopens the database. The
blast radius of a single collector failure should be that collector.

So the process stays up and the collector is restarted inside it. systemd remains
the supervisor of last resort for the process itself; the two are complementary,
not redundant.

Backoff, and why it resets on runtime rather than on success
-----------------------------------------------------------
A collector that fails immediately -- a missing kernel symbol, a revoked
capability -- will fail identically on the next attempt, and retrying it in a
tight loop burns CPU on a host that may already be degraded, while filling the
log with the same line. Delay therefore doubles per consecutive failure up to a
ceiling.

The ladder resets when a collector has *run* for `restart_healthy_runtime_seconds`
rather than when it exits cleanly. Exit is the wrong signal: a collector that runs
for six hours and is then killed exits non-zero, and treating that as a
continuation of a failure streak would put an unrelated restart at the top of the
backoff ladder. Sustained runtime is the only evidence available that a start
actually worked.

Crash-loop detection and degradation
------------------------------------
Retrying forever is not resilience when the cause is permanent -- it is an
infinite loop that reports "restarting" to anyone who looks and never says the
word "broken". After `crash_loop_threshold` failures inside
`crash_loop_window_seconds` the source is marked `degraded` and retries stop, the
state is written to the database, and an error is logged. The remaining sources
keep running: partial telemetry that is honestly labelled partial is worth more
than a supervisor that hides which half it lost.

Degradation is deliberately terminal until an operator intervenes. A source that
silently resurrects itself after being declared broken would make the record
unreadable -- "degraded at 04:00" would no longer mean the data has a hole.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from observability.config import Settings, settings as load_process_settings
from pipeline.event_stream import Event
from pipeline.live_ingestion import CollectorHealth, LiveIngestionService, RawInput
from pipeline.quarantine import BatchQuarantine
from storage.sqlite_store import SQLiteEventStore

LOGGER = logging.getLogger(__name__)

# Supervision states, in the order an operator cares about them.
STATUS_STARTING = "starting"
STATUS_RUNNING = "running"
STATUS_BACKOFF = "backoff"
STATUS_DEGRADED = "degraded"
STATUS_STOPPED = "stopped"


@dataclass
class SupervisedSource:
    """
    One collector, described by how to build it rather than by an instance.

    A factory rather than an iterable because restarting means starting over: a
    `SubprocessJSONLSource` whose child has exited cannot be re-iterated, and a
    generator that raised is finished. Handing the supervisor the recipe is what
    makes a restart a real restart instead of a second read of a dead pipe.
    """

    name: str
    factory: Callable[[], Iterable[RawInput]]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("supervised source requires a name")
        if not callable(self.factory):
            raise TypeError("supervised source factory must be callable")


@dataclass
class SourceState:
    """The supervision state of one source, as persisted and as reported."""

    name: str
    status: str = STATUS_STARTING
    detail: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    last_event_timestamp: Optional[float] = None
    processed_count: int = 0
    restart_count: int = 0
    consecutive_failures: int = 0
    last_failure_at: Optional[float] = None
    next_restart_at: Optional[float] = None
    backoff_seconds: float = 0.0
    crash_looping: bool = False
    quarantined_batch_count: int = 0
    quarantined_event_count: int = 0
    updated_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        state = {key: value for key, value in self.__dict__.items() if key != "name"}
        state["crash_looping"] = bool(self.crash_looping)
        return state


class RestartPolicy:
    """
    The backoff ladder and the crash-loop window for one source.

    Separated from the supervisor so the decision -- "how long do we wait, and is
    this a loop?" -- is testable without threads, subprocesses, or a clock that
    actually passes.
    """

    def __init__(self, config: Settings, clock: Callable[[], float] = time.monotonic):
        self.initial = config.restart_initial_backoff_seconds
        self.maximum = config.restart_max_backoff_seconds
        self.healthy_runtime = config.restart_healthy_runtime_seconds
        self.threshold = config.crash_loop_threshold
        self.window = config.crash_loop_window_seconds
        self.clock = clock
        self.consecutive_failures = 0
        self._failures: deque[float] = deque()

    def record_start(self) -> None:
        pass

    def record_failure(self, runtime_seconds: float) -> float:
        """
        Register one failure and return how long to wait before retrying.

        `runtime_seconds` is how long the collector ran before it died, which is
        what decides whether this is a new problem or the continuation of one.
        """
        now = self.clock()
        if runtime_seconds >= self.healthy_runtime:
            # It ran long enough to have worked. Whatever killed it is a new event,
            # so the ladder starts from the bottom and the window is cleared: a
            # failure hours ago is not evidence about this one.
            self.consecutive_failures = 0
            self._failures.clear()
        self.consecutive_failures += 1
        self._failures.append(now)
        self._trim(now)
        exponent = max(self.consecutive_failures - 1, 0)
        # Capped exponent so a long-lived process cannot overflow the shift; the
        # min() below would clamp the value anyway, but 2**10000 is expensive to
        # compute before it is discarded.
        delay = self.initial * (2 ** min(exponent, 32))
        return min(delay, self.maximum)

    def is_crash_looping(self) -> bool:
        self._trim(self.clock())
        return len(self._failures) >= self.threshold

    def failures_in_window(self) -> int:
        self._trim(self.clock())
        return len(self._failures)

    def _trim(self, now: float) -> None:
        cutoff = now - self.window
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()


class SourceSupervisor:
    """
    Runs one source, restarting it under policy, until stopped or degraded.

    Owns a thread; `start()`/`stop()`/`join()` mirror `threading.Thread` so the
    multi-source supervisor is a thin loop over these.
    """

    def __init__(
        self,
        source: SupervisedSource,
        store: SQLiteEventStore,
        config: Settings,
        service_factory: Optional[Callable[[SupervisedSource], LiveIngestionService]] = None,
        quarantine: Optional[BatchQuarantine] = None,
        analysis_pipeline: Optional[Callable[[List[Event]], None]] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        self.source = source
        self.store = store
        self.settings = config
        self.quarantine = quarantine
        # Held on the supervisor rather than on a service instance because every
        # restart builds a new service: analysis must survive the collector dying,
        # or a source would silently stop producing findings after its first crash.
        self.analysis_pipeline = analysis_pipeline
        self.clock = clock
        self.wall_clock = wall_clock
        self.policy = RestartPolicy(config, clock=clock)
        self.state = SourceState(name=source.name)
        self._service_factory = service_factory or self._default_service_factory
        self._service: Optional[LiveIngestionService] = None
        self._service_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()

    # ------------------------------------------------------------------ control

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError(f"source {self.source.name!r} is already supervised")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run, name=f"supervisor-{self.source.name}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """
        Ask the source to stop and stop restarting it.

        The stop flag is set *before* the running service is told to stop, so a
        service that exits promptly cannot be seen as a failure and restarted in
        the window between the two calls.
        """
        self._stop.set()
        with self._service_lock:
            service = self._service
        if service is not None:
            service.stop()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def snapshot(self) -> SourceState:
        with self._state_lock:
            return SourceState(**self.state.__dict__)

    # --------------------------------------------------------------------- loop

    def run(self) -> SourceState:
        while not self._stop.is_set():
            started_wall = self.wall_clock()
            started = self.clock()
            self._update(
                status=STATUS_RUNNING,
                started_at=started_wall,
                detail="collector running",
                next_restart_at=None,
                backoff_seconds=0.0,
                error=None,
            )
            health, failure = self._run_once()
            runtime = self.clock() - started
            self._absorb_health(health)

            if self._stop.is_set():
                self._update(status=STATUS_STOPPED, detail="shutdown requested", stopped_at=self.wall_clock())
                break
            if failure is None:
                # A source that ends without error has nothing left to read -- a
                # finite file, or a collector that exited 0. Restarting it would
                # either re-ingest the same records or spin on an empty pipe, so
                # this is a terminal success, not something to retry.
                self._update(
                    status=STATUS_STOPPED,
                    detail="collector finished without error",
                    stopped_at=self.wall_clock(),
                )
                break

            delay = self.policy.record_failure(runtime)
            looping = self.policy.is_crash_looping()
            with self._state_lock:
                self.state.restart_count += 1
            if looping:
                self._degrade(failure)
                break
            self._update(
                status=STATUS_BACKOFF,
                error=failure,
                detail=f"restarting after failure (runtime {runtime:.1f}s)",
                consecutive_failures=self.policy.consecutive_failures,
                last_failure_at=self.wall_clock(),
                backoff_seconds=delay,
                next_restart_at=self.wall_clock() + delay,
                stopped_at=self.wall_clock(),
            )
            LOGGER.warning(
                "collector_restart source=%s runtime_seconds=%.1f consecutive_failures=%d "
                "backoff_seconds=%.1f error=%s",
                self.source.name,
                runtime,
                self.policy.consecutive_failures,
                delay,
                failure,
            )
            # Interruptible: a shutdown during a 60-second backoff must not wait
            # out the backoff.
            if self._stop.wait(delay):
                self._update(status=STATUS_STOPPED, detail="shutdown requested during backoff")
                break
        return self.snapshot()

    def _run_once(self) -> tuple[Optional[CollectorHealth], Optional[str]]:
        """
        One collector lifetime. Returns (health, failure description or None).

        Every failure mode is folded into the second element rather than raised:
        building the source, running it, and the service reporting `failed` are all
        "this attempt did not work", and the caller's decision is the same for each.
        """
        try:
            service = self._service_factory(self.source)
        except Exception as error:
            # A factory that cannot even construct the source counts as a failure
            # attempt, otherwise a bad command line would spin with no backoff.
            return None, f"{type(error).__name__}: {error}"
        with self._service_lock:
            self._service = service
        if self._stop.is_set():
            # A stop that arrived while the factory was still building the service
            # found `self._service` empty and had nothing to stop. Re-checking after
            # registration closes that window; without it a shutdown landing in the
            # gap is silently dropped and the collector runs until systemd SIGKILLs
            # the process mid-transaction.
            service.stop()
        try:
            health = service.run()
        except Exception as error:
            return None, f"{type(error).__name__}: {error}"
        finally:
            with self._service_lock:
                self._service = None
        if health.status == "failed":
            return health, health.error or "collector failed without a reported error"
        return health, None

    def _default_service_factory(self, source: SupervisedSource) -> LiveIngestionService:
        return LiveIngestionService(
            source.factory(),
            self.store,
            queue_size=self.settings.queue_size,
            health_interval_seconds=self.settings.health_interval_seconds,
            backpressure_timeout_seconds=self.settings.backpressure_timeout_seconds,
            ingest_batch_size=self.settings.ingest_batch_size,
            quarantine=self.quarantine,
            analysis_pipeline=self.analysis_pipeline,
            source_name=source.name,
        )

    # -------------------------------------------------------------------- state

    def _absorb_health(self, health: Optional[CollectorHealth]) -> None:
        if health is None:
            return
        with self._state_lock:
            # Cumulative across restarts: the operator's question is how much this
            # source has delivered, not how much the current attempt delivered.
            self.state.processed_count += health.processed_count
            self.state.quarantined_batch_count += health.quarantined_batch_count
            self.state.quarantined_event_count += health.quarantined_event_count
            if health.last_event_timestamp is not None:
                self.state.last_event_timestamp = health.last_event_timestamp

    def _degrade(self, failure: str) -> None:
        self._update(
            status=STATUS_DEGRADED,
            error=failure,
            detail=(
                f"crash loop: {self.policy.failures_in_window()} failures in "
                f"{self.settings.crash_loop_window_seconds:g}s; restarts stopped"
            ),
            crash_looping=True,
            consecutive_failures=self.policy.consecutive_failures,
            last_failure_at=self.wall_clock(),
            next_restart_at=None,
            backoff_seconds=0.0,
            stopped_at=self.wall_clock(),
        )
        LOGGER.error(
            "collector_degraded source=%s failures_in_window=%d window_seconds=%.0f error=%s",
            self.source.name,
            self.policy.failures_in_window(),
            self.settings.crash_loop_window_seconds,
            failure,
        )

    def _update(self, **changes: Any) -> None:
        with self._state_lock:
            for key, value in changes.items():
                setattr(self.state, key, value)
            self.state.updated_at = self.wall_clock()
            snapshot = self.state.to_dict()
        try:
            self.store.write_source_state(self.source.name, snapshot)
        except Exception as error:
            # Supervision must not depend on the database it is supervising writes
            # into. Losing a state row costs visibility; raising here would stop
            # the restart that the row was describing.
            LOGGER.warning(
                "source_state_write_failed source=%s error=%s",
                self.source.name,
                f"{type(error).__name__}: {error}",
            )


class CollectorSupervisor:
    """
    Supervises several collectors independently.

    The only shared state is the store, so one source's failures, backoff, and
    degradation are invisible to the others -- which is the whole point of
    per-source supervision.
    """

    def __init__(
        self,
        store: SQLiteEventStore,
        sources: List[SupervisedSource],
        config: Optional[Settings] = None,
        service_factory: Optional[Callable[[SupervisedSource], LiveIngestionService]] = None,
        analysis_pipeline: Optional[Callable[[List[Event]], None]] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        if not sources:
            raise ValueError("at least one source is required")
        names = [source.name for source in sources]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            # Two sources sharing a name would overwrite each other's state row,
            # so the operator would see one collector where two are running.
            raise ValueError(f"duplicate source names: {', '.join(duplicates)}")
        self.store = store
        self.settings = config or load_process_settings()
        self.quarantine = (
            BatchQuarantine(self.settings.quarantine_dir, self.settings.quarantine_max_batches)
            if self.settings.quarantine_dir
            else None
        )
        self.supervisors = [
            SourceSupervisor(
                source,
                store,
                self.settings,
                service_factory=service_factory,
                quarantine=self.quarantine,
                analysis_pipeline=analysis_pipeline,
                clock=clock,
                wall_clock=wall_clock,
            )
            for source in sources
        ]

    def start(self) -> None:
        for supervisor in self.supervisors:
            supervisor.start()

    def stop(self) -> None:
        for supervisor in self.supervisors:
            supervisor.stop()

    def join(self, timeout: Optional[float] = None) -> None:
        for supervisor in self.supervisors:
            supervisor.join(timeout)

    def run(self) -> Dict[str, SourceState]:
        self.start()
        self.join()
        return self.states()

    def states(self) -> Dict[str, SourceState]:
        return {supervisor.source.name: supervisor.snapshot() for supervisor in self.supervisors}

    def healthy(self) -> bool:
        """
        True when no source has been given up on.

        Degradation is the only state that means telemetry is missing and will stay
        missing; backoff is a source that is expected back. Used by the readiness
        probe, which should fail on the former and not on the latter.
        """
        return all(state.status != STATUS_DEGRADED for state in self.states().values())
