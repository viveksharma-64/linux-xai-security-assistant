"""
Tests for collector supervision.

The property under test is the one the Phase B exit criterion names: a collector
can be killed repeatedly and ingestion continues without a human. That splits into
four claims -- restarts happen, backoff grows, a permanent failure is eventually
declared broken instead of retried forever, and one source's failure does not
affect another's.

Timing is kept out of the assertions by injecting a fake clock. A test that waits
for a real 1s, 2s, 4s ladder is a slow test that fails on a loaded CI runner; a test
that asserts on the *computed* delay is fast and exact.
"""

from __future__ import annotations

import threading
import time

import pytest

from observability.config import Settings
from pipeline.supervisor import (
    STATUS_DEGRADED,
    STATUS_STOPPED,
    CollectorSupervisor,
    RestartPolicy,
    SourceSupervisor,
    SupervisedSource,
)
from storage.sqlite_store import SQLiteEventStore


@pytest.fixture
def store(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "supervision.db"))
    yield store
    store.close()


def fast_settings(**overrides) -> Settings:
    base = Settings(
        restart_initial_backoff_seconds=0.001,
        restart_max_backoff_seconds=0.004,
        restart_healthy_runtime_seconds=0.05,
        crash_loop_threshold=3,
        crash_loop_window_seconds=60.0,
    )
    return base.replace(**overrides) if overrides else base


class FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ------------------------------------------------------------------- policy

def test_backoff_doubles_and_is_capped():
    clock = FakeClock()
    policy = RestartPolicy(
        Settings(
            restart_initial_backoff_seconds=1.0,
            restart_max_backoff_seconds=8.0,
            restart_healthy_runtime_seconds=60.0,
        ),
        clock=clock,
    )
    delays = [policy.record_failure(runtime_seconds=0.0) for _ in range(6)]
    assert delays == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]


def test_backoff_resets_after_a_healthy_runtime_not_after_a_clean_exit():
    # A collector that ran for six hours and was then killed exits non-zero. If the
    # ladder keyed on exit status, that unrelated restart would inherit the top of
    # a months-old failure streak and wait a minute before coming back.
    clock = FakeClock()
    policy = RestartPolicy(
        Settings(
            restart_initial_backoff_seconds=1.0,
            restart_max_backoff_seconds=64.0,
            restart_healthy_runtime_seconds=60.0,
        ),
        clock=clock,
    )
    for _ in range(4):
        policy.record_failure(runtime_seconds=0.0)
    assert policy.consecutive_failures == 4

    delay = policy.record_failure(runtime_seconds=3600.0)
    assert delay == 1.0
    assert policy.consecutive_failures == 1


def test_crash_loop_only_counts_failures_inside_the_window():
    clock = FakeClock()
    policy = RestartPolicy(
        Settings(crash_loop_threshold=3, crash_loop_window_seconds=10.0), clock=clock
    )
    policy.record_failure(runtime_seconds=0.0)
    policy.record_failure(runtime_seconds=0.0)
    clock.advance(11.0)
    policy.record_failure(runtime_seconds=0.0)
    # The first two aged out: three failures spread over a day is not a crash loop.
    assert policy.failures_in_window() == 1
    assert not policy.is_crash_looping()

    policy.record_failure(runtime_seconds=0.0)
    policy.record_failure(runtime_seconds=0.0)
    assert policy.is_crash_looping()


# --------------------------------------------------------------- supervision

def test_a_failing_source_is_restarted_until_it_is_declared_degraded(store):
    attempts = []

    def factory():
        attempts.append(time.time())
        raise RuntimeError("probe cannot attach")

    supervisor = SourceSupervisor(
        SupervisedSource(name="flaky", factory=factory), store, fast_settings()
    )
    state = supervisor.run()

    assert state.status == STATUS_DEGRADED
    assert state.crash_looping is True
    assert len(attempts) == 3  # crash_loop_threshold
    assert "probe cannot attach" in (state.error or "")
    # Degradation is the moment the record acquires a hole, so it must be legible
    # in the persisted state and not only in the log.
    persisted = {row["name"]: row for row in store.read_source_states()}
    assert persisted["flaky"]["status"] == STATUS_DEGRADED


def test_a_source_that_finishes_cleanly_is_not_restarted(store):
    calls = []

    def factory():
        calls.append(1)
        return iter([])

    supervisor = SourceSupervisor(
        SupervisedSource(name="finite", factory=factory), store, fast_settings()
    )
    state = supervisor.run()

    # A finite source that ends without error has nothing left to read. Restarting
    # would either re-ingest the same records or spin on an empty pipe.
    assert state.status == STATUS_STOPPED
    assert len(calls) == 1


def test_a_recovering_source_keeps_running_and_counts_its_restarts(store):
    started = threading.Event()
    attempts = {"n": 0}

    def factory():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("transient")
        started.set()
        # Block so the second attempt looks like a collector that is alive; the
        # test stops it explicitly rather than letting it end.
        return iter(lambda: time.sleep(0.01) or "", None)

    supervisor = SourceSupervisor(
        SupervisedSource(name="recovering", factory=factory), store, fast_settings()
    )
    supervisor.start()
    assert started.wait(timeout=5.0)
    supervisor.stop()
    supervisor.join(timeout=5.0)

    state = supervisor.snapshot()
    assert state.restart_count == 1
    assert state.status == STATUS_STOPPED
    assert state.crash_looping is False


def test_one_source_failing_does_not_stop_the_others(store):
    healthy_started = threading.Event()

    def failing():
        raise RuntimeError("permanently broken")

    def healthy():
        healthy_started.set()
        return iter(lambda: time.sleep(0.01) or "", None)

    supervisor = CollectorSupervisor(
        store,
        [
            SupervisedSource(name="broken", factory=failing),
            SupervisedSource(name="working", factory=healthy),
        ],
        config=fast_settings(),
    )
    supervisor.start()
    assert healthy_started.wait(timeout=5.0)

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if supervisor.states()["broken"].status == STATUS_DEGRADED:
            break
        time.sleep(0.01)

    states = supervisor.states()
    assert states["broken"].status == STATUS_DEGRADED
    # Partial telemetry that is honestly labelled partial beats a supervisor that
    # tears everything down because one probe could not attach.
    assert states["working"].status == "running"
    assert supervisor.healthy() is False

    supervisor.stop()
    supervisor.join(timeout=5.0)


def test_duplicate_source_names_are_refused(store):
    with pytest.raises(ValueError, match="duplicate"):
        CollectorSupervisor(
            store,
            [
                SupervisedSource(name="dup", factory=lambda: iter([])),
                SupervisedSource(name="dup", factory=lambda: iter([])),
            ],
            config=fast_settings(),
        )


def test_supervision_survives_a_database_that_cannot_be_written(store, monkeypatch):
    # Supervision must not depend on the database it supervises writes into: losing
    # a state row costs visibility, but raising here would stop the restart the row
    # was describing.
    def explode(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "write_source_state", explode)
    supervisor = SourceSupervisor(
        SupervisedSource(name="unwritable", factory=lambda: iter([])), store, fast_settings()
    )
    state = supervisor.run()
    assert state.status == STATUS_STOPPED
