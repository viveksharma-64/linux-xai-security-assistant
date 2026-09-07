"""
Tests for the unattended ingestion service.

This is the process the Phase B exit criterion is about: it must keep collecting
across collector deaths, bound its own disk, and say out loud when it has stopped
working -- all without a human. The tests drive the whole lifecycle with real
supervision and a fast clock: finite sources that complete, a source that crash-
loops into degradation, and the mix where one dies and another keeps delivering.

Sources here are plain callables returning event dicts or a blocking iterator,
which is what a `SupervisedSource.factory` is; that keeps the tests off real
subprocesses while exercising the real supervisor, retention manager, and alert
evaluation the service wires together.
"""

from __future__ import annotations

import logging
import threading
import time

import pytest

from observability.config import Settings
from pipeline.service import IngestionService, parse_source_spec
from pipeline.supervisor import SupervisedSource
from storage.sqlite_store import SQLiteEventStore


@pytest.fixture
def store(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "service.db"))
    yield store
    store.close()


def fast_config(**overrides) -> Settings:
    base = Settings(
        restart_initial_backoff_seconds=0.001,
        restart_max_backoff_seconds=0.004,
        restart_healthy_runtime_seconds=0.05,
        crash_loop_threshold=2,
        crash_loop_window_seconds=60.0,
        retention_max_age_days=0.0,
    )
    return base.replace(**overrides) if overrides else base


def _event(pid: int, comm: str = "bash", timestamp: float = 1000.0):
    return {
        "event_type": "process_exec",
        "timestamp": timestamp + pid,
        "pid": pid,
        "uid": 1000,
        "gid": 1000,
        "comm": comm,
        "filename": "/usr/bin/" + comm,
        "source": "test_source",
        "version": "1.0",
    }


def _blocking_source():
    # Looks like a collector that is alive and producing nothing right now; the
    # test stops it rather than letting it end.
    return iter(lambda: time.sleep(0.01) or "", None)


# --------------------------------------------------------------- spec parsing

def test_parse_source_spec_reads_name_and_command():
    source = parse_source_spec("process_exec=python3 probe.py --flag")
    assert source.name == "process_exec"
    # The factory is deferred so a restart builds a fresh subprocess each time.
    assert callable(source.factory)


def test_parse_source_spec_rejects_a_spec_without_a_name_or_command():
    for bad in ("=python3 probe.py", "process_exec=", "no-equals-sign"):
        with pytest.raises(ValueError, match="NAME=COMMAND"):
            parse_source_spec(bad)


# ------------------------------------------------------------------ lifecycle

def test_a_finite_source_is_ingested_and_the_run_ends_healthy(store):
    source = SupervisedSource(
        name="batch", factory=lambda: [_event(pid) for pid in range(5)]
    )
    report = IngestionService(store, [source], fast_config()).run()

    assert store.count_events() == 5
    # A source that ended without error is a terminal success, not a degradation,
    # so the service reports healthy even though nothing is running any more.
    assert report["healthy"] is True
    assert report["sources"]["batch"]["status"] == "stopped"


def test_a_crash_looping_source_is_degraded_and_the_run_reports_unhealthy(store):
    def broken():
        raise RuntimeError("probe cannot attach")

    report = IngestionService(
        store, [SupervisedSource(name="doomed", factory=broken)], fast_config()
    ).run()

    # The run must end on its own: with no source left that could produce another
    # event, holding the process open collects nothing and hides the failure from
    # systemd's Restart= policy.
    assert report["healthy"] is False
    assert report["sources"]["doomed"]["status"] == "degraded"
    persisted = {row["name"]: row for row in store.read_source_states()}
    assert persisted["doomed"]["status"] == "degraded"


def test_one_source_degrading_does_not_lose_the_other_source_events(store):
    def broken():
        raise RuntimeError("permanently broken")

    good = SupervisedSource(name="good", factory=lambda: [_event(pid) for pid in range(3)])
    bad = SupervisedSource(name="bad", factory=broken)

    report = IngestionService(store, [good, bad], fast_config()).run()

    # Partial telemetry honestly labelled partial beats tearing everything down
    # because one probe could not attach.
    assert store.count_events() == 3
    assert report["sources"]["good"]["status"] == "stopped"
    assert report["sources"]["bad"]["status"] == "degraded"
    assert report["healthy"] is False


def test_an_explicit_stop_shuts_a_live_service_down(store):
    started = threading.Event()

    def alive():
        started.set()
        return _blocking_source()

    service = IngestionService(
        store, [SupervisedSource(name="live", factory=alive)], fast_config()
    )
    service.start()
    assert started.wait(timeout=5.0)
    service.stop()
    service.join(timeout=5.0)

    assert service.report()["sources"]["live"]["status"] == "stopped"


# ------------------------------------------------------------------ alerting

def test_only_alert_transitions_are_logged(store, monkeypatch, caplog):
    from pipeline import service as service_module

    # A source is required at construction but never started here: _maybe_alert is
    # driven directly with a patched snapshot/evaluate.
    idle = SupervisedSource(name="idle", factory=list)
    service = IngestionService(store, [idle], fast_config(), alert_interval_seconds=0.0)

    stale = service_module.alerting.Alert(
        name="telemetry_stale", severity="critical", summary="no events for 400s"
    )
    monkeypatch.setattr(service_module.metrics, "collect_snapshot", lambda *a, **k: object())

    sequence = [[stale], [stale], []]
    monkeypatch.setattr(service_module.alerting, "evaluate", lambda *a, **k: sequence.pop(0))

    with caplog.at_level(logging.INFO):
        service._maybe_alert()  # fires: logged once
        service._maybe_alert()  # still firing: not re-logged
        service._maybe_alert()  # cleared: a clear line

    fired = [r for r in caplog.records if "alert=telemetry_stale" in r.getMessage() and "cleared" not in r.getMessage()]
    cleared = [r for r in caplog.records if "alert_cleared alert=telemetry_stale" in r.getMessage()]
    # The one timestamp an operator needs is when the condition started; re-logging
    # every interval would bury it under identical lines.
    assert len(fired) == 1
    assert len(cleared) == 1


def test_retention_failure_does_not_stop_the_service(store, monkeypatch):
    # A database that cannot be pruned still collects; the size-cap alert covers a
    # sustained failure. Retention raising must not take ingestion down with it.
    started = threading.Event()

    def alive():
        started.set()
        return _blocking_source()

    service = IngestionService(
        store,
        [SupervisedSource(name="live", factory=alive)],
        fast_config(retention_interval_seconds=0.001),
        alert_interval_seconds=1000.0,
    )
    monkeypatch.setattr(
        service.retention, "maybe_run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full"))
    )
    service.start()
    assert started.wait(timeout=5.0)
    # Give the maintenance loop a tick to hit the raising retention call.
    time.sleep(1.2)
    assert service.supervisor.states()["live"].status == "running"
    service.stop()
    service.join(timeout=5.0)
