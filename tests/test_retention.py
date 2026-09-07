"""
Tests for the data lifecycle policy.

The properties worth defending here are the ones an operator relies on when the
service runs unattended: bounded growth, a coverage floor they can read back, and
an audit trail of what was destroyed. Byte-cap behaviour is tested against a real
file rather than an in-memory database, because file size is the thing under test
and `:memory:` has none.
"""

from __future__ import annotations

import time

import pytest

from observability.config import Settings
from pipeline.event_stream import Event, EventType
from storage.retention import RetentionManager
from storage.sqlite_store import SQLiteEventStore


DAY = 86400.0


def _event(timestamp: float, pid: int = 1000) -> Event:
    return Event(
        event_type=EventType.PROCESS_EXEC,
        timestamp=timestamp,
        pid=pid,
        ppid=1,
        uid=0,
        comm="bash",
        executable="/bin/bash",
        payload={"cwd": "/root", "argv": f"job {pid}"},
    )


@pytest.fixture()
def store(tmp_path):
    handle = SQLiteEventStore(str(tmp_path / "events.db"))
    try:
        yield handle
    finally:
        handle.close()


def _settings(**overrides) -> Settings:
    # Every policy off by default so each test enables exactly the one it asserts
    # on; otherwise a vacuum triggered by an unrelated default would be
    # indistinguishable from the behaviour under test.
    base = Settings(
        retention_max_age_days=0.0,
        retention_max_db_bytes=0,
        retention_vacuum_interval_seconds=0.0,
    )
    return base.replace(**overrides)


class TestAgeRetention:
    def test_deletes_events_older_than_the_window(self, store):
        now = 1_000_000.0
        for age_days in (40, 35, 10, 1):
            store.write(_event(now - age_days * DAY, pid=1000 + age_days))
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)

        actions = manager.run_once()

        assert [a["action"] for a in actions] == ["prune_age"]
        assert actions[0]["events_deleted"] == 2
        remaining = [event.timestamp for event in store.read_all()]
        assert remaining == [now - 10 * DAY, now - 1 * DAY]

    def test_reports_the_coverage_floor_that_remains(self, store):
        now = 1_000_000.0
        store.write(_event(now - 40 * DAY, pid=1))
        store.write(_event(now - 5 * DAY, pid=2))
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)

        action = manager.run_once()[0]

        # The floor is what an analyst needs in order to distinguish "aged out"
        # from "never collected".
        assert action["oldest_retained_timestamp"] == now - 5 * DAY
        assert action["cutoff_timestamp"] == now - 30 * DAY

    def test_no_action_recorded_when_nothing_is_stale(self, store):
        now = 1_000_000.0
        store.write(_event(now - 2 * DAY))
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)

        assert manager.run_once() == []
        assert store.count_events() == 1

    def test_zero_days_means_keep_indefinitely(self, store):
        now = 1_000_000.0
        store.write(_event(now - 9999 * DAY))
        manager = RetentionManager(store, _settings(retention_max_age_days=0.0), clock=lambda: now)

        # A missing or zeroed window must never read as "delete everything", which
        # is what `now - 0` as a cutoff would mean.
        assert manager.run_once() == []
        assert store.count_events() == 1

    def test_prunes_dependent_analytics_rows(self, store):
        now = 1_000_000.0
        finding_id = store.write_detection_finding(
            {
                "window_start": now - 40 * DAY,
                "window_end": now - 40 * DAY + 60,
                "entity_type": "process",
                "entity_key": "bash:1000",
                "severity": "medium",
                "risk_score": 0.5,
                "behavior_score": 0.5,
                "rule_score": 0.5,
                "context_score": 0.5,
                "evidence": {},
                "explanation": "aged finding",
                "mode": "observe",
            }
        )
        store.write_explanation({"finding_id": finding_id, "explanation_type": "why", "content": "old"})
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)

        action = manager.run_once()[0]

        assert action["rows_deleted"] >= 2
        assert store.read_detection_findings() == []


class TestSizeCap:
    def test_deletes_oldest_events_until_under_the_cap(self, store):
        now = 1_000_000.0
        for index in range(400):
            store.write(_event(now - (400 - index), pid=index))
        over_cap = store.database_bytes() - 1
        manager = RetentionManager(
            store, _settings(retention_max_db_bytes=over_cap), clock=lambda: now
        )

        actions = manager.run_once()

        assert [a["action"] for a in actions] == ["size_cap", "vacuum"]
        assert store.database_bytes() <= over_cap
        assert actions[0]["events_deleted"] > 0
        assert store.count_events() < 400

    def test_deletes_from_the_oldest_end(self, store):
        now = 1_000_000.0
        for index in range(400):
            store.write(_event(now - (400 - index), pid=index))
        manager = RetentionManager(
            store, _settings(retention_max_db_bytes=store.database_bytes() - 1), clock=lambda: now
        )

        manager.run_once()

        remaining = [event.timestamp for event in store.read_all()]
        # Newest telemetry is the most operationally useful, so the cap must trim
        # history rather than the present.
        assert remaining == sorted(remaining)
        assert remaining[-1] == now - 1

    def test_zero_cap_disables_the_policy(self, store):
        store.write(_event(1_000_000.0))
        manager = RetentionManager(store, _settings(retention_max_db_bytes=0))

        assert manager.run_once() == []
        assert store.count_events() == 1

    def test_records_an_unsatisfiable_cap_instead_of_looping(self, store):
        # A cap smaller than an empty schema can never be met. The pass must
        # report that and return, not spin deleting rows that cannot help.
        manager = RetentionManager(store, _settings(retention_max_db_bytes=1))

        actions = manager.run_once()

        assert [a["action"] for a in actions] == ["size_cap", "vacuum"]
        assert actions[0]["events_deleted"] == 0
        assert "no events could be reclaimed" in actions[0]["detail"]


class TestVacuum:
    def test_first_pass_arms_the_schedule_without_vacuuming(self, store):
        manager = RetentionManager(store, _settings(retention_vacuum_interval_seconds=3600.0))

        # Vacuuming on every start would make a crash-looping service hammer the
        # disk it is already failing on.
        assert manager.run_once() == []

    def test_vacuums_once_the_interval_elapses(self, store):
        store.write(_event(1_000_000.0))
        manager = RetentionManager(store, _settings(retention_vacuum_interval_seconds=3600.0))
        manager.run_once()
        manager._last_vacuum = time.monotonic() - 7200.0

        actions = manager.run_once()

        assert [a["action"] for a in actions] == ["vacuum"]
        assert actions[0]["db_bytes_after"] is not None
        assert store.count_events() == 1

    def test_zero_interval_disables_scheduled_vacuum(self, store):
        manager = RetentionManager(store, _settings(retention_vacuum_interval_seconds=0.0))
        manager._last_vacuum = time.monotonic() - 10_000.0

        assert manager.run_once() == []


class TestMaintenanceLog:
    def test_every_action_is_persisted(self, store):
        now = 1_000_000.0
        store.write(_event(now - 40 * DAY))
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)

        manager.run_once()

        records = store.read_maintenance_records()
        assert len(records) == 1
        assert records[0]["action"] == "prune_age"
        assert records[0]["events_deleted"] == 1
        assert records[0]["created_at"] == now

    def test_a_log_write_failure_does_not_lose_the_action(self, store, monkeypatch):
        now = 1_000_000.0
        store.write(_event(now - 40 * DAY))
        manager = RetentionManager(store, _settings(retention_max_age_days=30.0), clock=lambda: now)
        monkeypatch.setattr(
            store, "write_maintenance_record", lambda record: (_ for _ in ()).throw(RuntimeError("disk full"))
        )

        actions = manager.run_once()

        # The deletion already happened; reporting must degrade, not raise.
        assert actions[0]["events_deleted"] == 1
        assert "id" not in actions[0]
        assert store.count_events() == 0


class TestScheduling:
    def test_maybe_run_honours_the_interval(self, store):
        now = 1_000_000.0
        store.write(_event(now - 40 * DAY))
        manager = RetentionManager(
            store,
            _settings(retention_max_age_days=30.0, retention_interval_seconds=3600.0),
            clock=lambda: now,
        )

        first = manager.maybe_run()
        store.write(_event(now - 41 * DAY))
        second = manager.maybe_run()

        assert [a["action"] for a in first] == ["prune_age"]
        assert second == []
        # Skipped, not silently applied: the stale event is still there.
        assert store.count_events() == 1

    def test_force_bypasses_the_interval(self, store):
        now = 1_000_000.0
        store.write(_event(now - 40 * DAY))
        manager = RetentionManager(
            store,
            _settings(retention_max_age_days=30.0, retention_interval_seconds=3600.0),
            clock=lambda: now,
        )
        manager.maybe_run()
        store.write(_event(now - 41 * DAY, pid=2))

        assert [a["action"] for a in manager.maybe_run(force=True)] == ["prune_age"]
        assert store.count_events() == 0
