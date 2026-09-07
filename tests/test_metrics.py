"""
Tests for the metrics snapshot, Prometheus exposition, and the health probes.

Two properties matter beyond "the numbers come out". First, the snapshot is read
from the database rather than from process memory, because the API and the
collector are different processes -- a fake store here stands in for that shared
record. Second, liveness and readiness answer different questions and must not
collapse into each other: liveness stays true through a collector outage, and
readiness goes false when a served answer would be wrong.
"""

from __future__ import annotations

from observability.config import Settings
from observability.metrics import (
    MetricsSnapshot,
    collect_snapshot,
    liveness,
    readiness,
    render_prometheus,
)


class FakeStore:
    """A store standing in for the persisted operational picture."""

    def __init__(self, **overrides):
        self.db_path = overrides.get("db_path", "/var/lib/x/events.db")
        self._data = {
            "count_events": 10,
            "latest_event_timestamp": 1000.0,
            "oldest_event_timestamp": 100.0,
            "read_detection_findings": [
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "low"},
            ],
            "database_bytes": 4096,
            "file_permissions": {"/var/lib/x/events.db": 0o600},
            "read_collector_health": {
                "processed_count": 500,
                "dropped_event_count": 0,
                "queue_depth": 2,
                "queue_capacity": 100,
                "updated_at": 990.0,
                "throughput": 12.5,
            },
            "read_source_states": [{"name": "exec", "status": "running", "restart_count": 0}],
        }
        self._data.update(overrides)

    def __getattr__(self, name):
        if name in self._data:
            value = self._data[name]
            return lambda *a, **k: value
        raise AttributeError(name)


def snapshot_from(**overrides) -> MetricsSnapshot:
    return collect_snapshot(FakeStore(**overrides), config=Settings())


def test_snapshot_reads_every_figure_from_the_store():
    snap = snapshot_from()
    assert snap.event_count == 10
    assert snap.finding_count == 3
    assert snap.severity_counts == {"high": 2, "low": 1}
    assert snap.collector["processed_count"] == 500


def test_a_database_error_is_captured_not_raised():
    class Broken(FakeStore):
        def count_events(self):
            raise RuntimeError("database is locked")

    # The endpoints built on this must be able to *report* an unreadable database;
    # an exception here would turn the only channel that could say so into a 500.
    snap = collect_snapshot(Broken(), config=Settings())
    assert "database is locked" in (snap.database_error or "")


def test_data_age_is_the_gap_between_collection_and_the_newest_event():
    snap = snapshot_from()
    snap.collected_at = 1300.0
    assert snap.data_age_seconds == 300.0


def test_a_world_readable_database_shows_up_as_an_insecure_file():
    snap = snapshot_from(file_permissions={"/var/lib/x/events.db": 0o644})
    assert snap.insecure_files == ["/var/lib/x/events.db"]


def test_prometheus_output_names_counters_with_total_and_gauges_without():
    text = render_prometheus(snapshot_from())
    assert "linux_xai_events_processed_total 500" in text
    assert "linux_xai_events_stored 10" in text
    # Per-source series carry the source as a label, not baked into the name.
    assert 'linux_xai_source_up{source="exec"} 1' in text
    # up == 1 only when the database read succeeded.
    assert "linux_xai_up 1" in text


def test_prometheus_renders_a_missing_value_as_nan_not_zero():
    # A missing figure averaged in as a zero would understate event age and hide a
    # stalled collector, so the format's own "no value" is used.
    snap = snapshot_from(latest_event_timestamp=None)
    text = render_prometheus(snap)
    assert "linux_xai_event_age_seconds NaN" in text


def test_liveness_stays_true_through_a_collector_outage():
    # Restarting the API cannot revive a dead probe; killing the one component that
    # can still report the outage would only deepen it.
    snap = snapshot_from(read_source_states=[{"name": "exec", "status": "degraded"}])
    alive, detail = liveness(snap)
    assert alive is True
    assert detail["status"] == "alive"


def test_readiness_fails_on_an_unreadable_database():
    class Broken(FakeStore):
        def count_events(self):
            raise RuntimeError("no such table")

    ready, detail = readiness(collect_snapshot(Broken(), config=Settings()), config=Settings())
    assert ready is False
    assert any("database unavailable" in reason for reason in detail["reasons"])


def test_readiness_fails_when_the_database_is_world_readable():
    # Serving from an evidence store other local accounts can read would endorse a
    # broken confidentiality control, so readiness refuses rather than answers.
    snap = snapshot_from(file_permissions={"/var/lib/x/events.db": 0o644})
    ready, detail = readiness(snap, config=Settings())
    assert ready is False
    assert any("group or other" in reason for reason in detail["reasons"])


def test_readiness_fails_on_stale_telemetry():
    snap = snapshot_from()
    snap.collected_at = snap.latest_event_timestamp + 10_000
    ready, detail = readiness(snap, config=Settings(stale_after_seconds=300.0))
    assert ready is False
    assert any("old" in reason for reason in detail["reasons"])


def test_readiness_fails_before_any_telemetry_has_been_ingested():
    # A fresh instance with an empty database looks healthy on every counter but
    # cannot answer a question about the host yet.
    snap = snapshot_from(latest_event_timestamp=None, count_events=0)
    ready, detail = readiness(snap, config=Settings())
    assert ready is False
    assert any("no telemetry" in reason for reason in detail["reasons"])


def test_readiness_is_true_on_a_healthy_recent_instance():
    snap = snapshot_from()
    snap.collected_at = snap.latest_event_timestamp + 10
    ready, detail = readiness(snap, config=Settings(stale_after_seconds=300.0))
    assert ready is True
    assert detail["reasons"] == []
