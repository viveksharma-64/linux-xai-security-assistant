"""
Tests for the alert rules.

The rules are pure -- snapshot in, alerts out -- which is the whole point: the
four failures Phase B promises to surface (event loss, collector death, stale
data, disk pressure) include states that are hard to produce on a real host, like
a full disk or a crash-looped probe. Constructing the snapshot lets every one of
them be asserted directly. The tests also pin the severity split, because paging
policy is written against that field.
"""

from __future__ import annotations

from observability.alerts import (
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    evaluate,
    log_alerts,
)
from observability.config import Settings
from observability.metrics import DiskUsage, MetricsSnapshot


def config(**overrides) -> Settings:
    return Settings(**overrides)


def fired(alerts):
    return {alert.name: alert for alert in alerts}


def test_a_healthy_snapshot_fires_nothing():
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0, "queue_capacity": 100, "queue_depth": 1},
        disk=DiskUsage(total_bytes=1000, free_bytes=900, used_bytes=100),
    )
    assert evaluate(snap, config(stale_after_seconds=300.0, alert_min_free_disk_bytes=100)) == []


def test_dropped_events_are_critical_because_the_record_has_gaps():
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0, "dropped_event_count": 7},
    )
    alert = fired(evaluate(snap, config()))["events_dropped"]
    assert alert.severity == SEVERITY_CRITICAL
    # Self-justifying: the measured value and the threshold it crossed travel with
    # the alert so an operator need not query anything to see why it fired.
    assert alert.value == 7.0
    assert alert.threshold == 0.0


def test_kernel_ring_loss_is_reported_separately_from_backpressure_drops():
    # They have different causes and different fixes: one is the queue, the other
    # is the perf buffer sizing, so they cannot share an alert.
    snap = MetricsSnapshot(collected_at=1000.0, collector={"kernel_lost_event_count": 3})
    names = fired(evaluate(snap, config()))
    assert "kernel_events_lost" in names
    assert names["kernel_events_lost"].severity == SEVERITY_CRITICAL


def test_quarantined_events_warn_rather_than_page():
    # The events are not lost -- they are on disk awaiting replay -- so this is a
    # trajectory to fix, not evidence already gone.
    snap = MetricsSnapshot(collected_at=1000.0, collector={"quarantined_event_count": 12})
    alert = fired(evaluate(snap, config()))["events_quarantined"]
    assert alert.severity == SEVERITY_WARNING


def test_a_degraded_source_pages_and_names_the_source():
    snap = MetricsSnapshot(
        collected_at=1000.0,
        sources=[
            {"name": "exec", "status": "running"},
            {"name": "net", "status": "degraded"},
        ],
    )
    alert = fired(evaluate(snap, config()))["collector_degraded"]
    assert alert.severity == SEVERITY_CRITICAL
    assert alert.labels == {"source": "net"}


def test_silent_collector_health_is_treated_as_a_wedged_process():
    snap = MetricsSnapshot(collected_at=1000.0, collector={"updated_at": 800.0})
    alert = fired(evaluate(snap, config(alert_collector_silence_seconds=120.0)))[
        "collector_health_stale"
    ]
    assert alert.severity == SEVERITY_CRITICAL
    assert alert.value == 200.0


def test_stale_telemetry_fires_when_nothing_arrives_inside_the_window():
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=600.0,
        collector={"updated_at": 999.0},
    )
    alert = fired(evaluate(snap, config(stale_after_seconds=300.0)))["telemetry_stale"]
    assert alert.severity == SEVERITY_CRITICAL
    assert alert.value == 400.0


def test_an_absolute_disk_floor_pages_and_a_relative_one_only_warns():
    critical = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0},
        disk=DiskUsage(total_bytes=1_000_000, free_bytes=1_000, used_bytes=999_000),
    )
    alert = fired(evaluate(critical, config(alert_min_free_disk_bytes=10_000)))["disk_space_low"]
    assert alert.severity == SEVERITY_CRITICAL

    warning = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0},
        disk=DiskUsage(total_bytes=1_000_000, free_bytes=20_000, used_bytes=980_000),
    )
    names = fired(
        evaluate(
            warning,
            config(alert_min_free_disk_bytes=10_000, alert_min_free_disk_ratio=0.05),
        )
    )
    assert "disk_space_low" not in names
    assert names["disk_space_low_ratio"].severity == SEVERITY_WARNING


def test_disk_pressure_is_silent_when_free_space_cannot_be_measured():
    # A zero total means disk_usage failed; alerting on it would page on every
    # host where the filesystem could not be stat'd rather than on real pressure.
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0},
        disk=DiskUsage(),
    )
    names = fired(evaluate(snap, config()))
    assert "disk_space_low" not in names
    assert "disk_space_low_ratio" not in names


def test_a_deep_queue_alone_is_only_a_warning():
    # A full queue is backpressure working as designed; it is worth saying because
    # sustained fill precedes drops, but it is not itself a fault.
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=999.0,
        collector={"updated_at": 999.0, "queue_capacity": 100, "queue_depth": 95},
    )
    alert = fired(evaluate(snap, config(alert_max_queue_fill_ratio=0.8)))[
        "ingest_queue_saturated"
    ]
    assert alert.severity == SEVERITY_WARNING


def test_critical_alerts_sort_ahead_of_warnings():
    snap = MetricsSnapshot(
        collected_at=1000.0,
        latest_event_timestamp=600.0,
        collector={"updated_at": 999.0, "quarantined_event_count": 1},
    )
    alerts = evaluate(snap, config(stale_after_seconds=300.0))
    severities = [alert.severity for alert in alerts]
    # A responder scanning top-down must hit everything page-worthy first.
    assert severities == sorted(
        severities, key=lambda s: 0 if s == SEVERITY_CRITICAL else 1
    )
    assert severities[0] == SEVERITY_CRITICAL


def test_log_alerts_uses_error_for_critical_and_warning_for_warning(caplog):
    import logging

    alerts = evaluate(
        MetricsSnapshot(
            collected_at=1000.0,
            latest_event_timestamp=600.0,
            collector={"updated_at": 999.0, "quarantined_event_count": 1},
        ),
        config(stale_after_seconds=300.0),
    )
    with caplog.at_level(logging.WARNING):
        log_alerts(alerts)
    # Severity has to reach the log level so a journald paging rule keyed on level
    # matches, not only a rule that parses the message text.
    levels = {record.levelno for record in caplog.records}
    assert logging.ERROR in levels
    assert logging.WARNING in levels
