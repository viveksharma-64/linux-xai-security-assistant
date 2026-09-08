"""
Tests for the system-failure scorer (detection/system_failure.py).

The scorer is DETECTION ONLY: every assertion here is about what is *observed*
and *persisted*, never about any response. The tests pin the load-bearing
behaviours that make the findings trustworthy: hysteresis over wall-clock
windows (not ingestion batches), a dead band so a value hovering at a threshold
does not flap, missing telemetry read as "unknown" rather than healthy, and
one finding per entity per window.
"""

from __future__ import annotations

import pytest

from detection.system_failure import (
    FAILURE_DETECTOR_VERSION,
    SystemFailureScorer,
    WINDOW_SECONDS,
    _breach_high,
    _breach_low,
)
from observability.config import ConfigError, Settings, _validate
from pipeline.event_stream import Event, EventType
from storage.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------

def _settings(**overrides) -> Settings:
    """A Settings with predictable failure thresholds, tunable per test."""
    base = dict(
        failure_memory_high_pct=90.0,
        failure_memory_medium_pct=80.0,
        failure_memory_min_available_mb=128,
        failure_cpu_high_pct=95.0,
        failure_disk_full_pct=99.0,
        failure_consecutive_windows=2,
        failure_clear_windows=2,
        failure_clear_ratio=0.9,
        failure_crash_loop_threshold=3,
        failure_crash_loop_window_seconds=600.0,
    )
    base.update(overrides)
    return Settings().replace(**base)


@pytest.fixture
def store(tmp_path):
    return SQLiteEventStore(str(tmp_path / "failures.db"))


def _scorer(store, **overrides) -> SystemFailureScorer:
    return SystemFailureScorer(store, settings=_settings(**overrides))


def _health(ts, host="h1", **payload):
    # Only the keys a test passes are set; anything absent is genuinely missing
    # telemetry, which the scorer must read as "unknown".
    return Event(
        event_type=EventType.SYSTEM_HEALTH,
        timestamp=float(ts),
        payload=dict(payload),
        host_id=host,
    )


def _service(ts, unit, action=None, result=None, host="h1"):
    return Event(
        event_type=EventType.SERVICE_STATE,
        timestamp=float(ts),
        payload={"unit": unit, "action": action, "result": result},
        host_id=host,
    )


def _win(index):
    """(start, end) of the index-th epoch-aligned window."""
    start = index * WINDOW_SECONDS
    return start, start + WINDOW_SECONDS


# ---------------------------------------------------------------------------
# Empty / unknown telemetry
# ---------------------------------------------------------------------------

def test_empty_window_yields_no_finding(store):
    scorer = _scorer(store)
    start, end = _win(0)
    assert scorer.score([], start, end) == []


def test_missing_telemetry_is_unknown_not_a_failure(store):
    # A health event whose fields are all None must never produce a finding, and
    # must never count as a "clear" either -- it is simply unknown.
    scorer = _scorer(store, failure_consecutive_windows=1)
    for i in range(3):
        start, end = _win(i)
        found = scorer.score(
            [_health(start + 1, disk_percent=None, mem_percent=None,
                     mem_available_mb=None, cpu_percent=None)],
            start, end,
        )
        assert found == []
    assert store.read_detection_findings() == []


def test_partial_telemetry_scores_only_present_dimensions(store):
    # disk present and breaching, cpu absent: exactly one finding, for disk.
    scorer = _scorer(store, failure_consecutive_windows=1)
    start, end = _win(0)
    found = scorer.score([_health(start + 1, disk_percent=99.9)], start, end)
    conditions = [f["evidence"][0]["condition"] for f in found]
    assert conditions == ["disk_full"]


# ---------------------------------------------------------------------------
# Hysteresis: breach requires N consecutive windows
# ---------------------------------------------------------------------------

def test_breach_requires_consecutive_windows_before_emitting(store):
    scorer = _scorer(store, failure_consecutive_windows=2)
    s0, e0 = _win(0)
    # First breaching window: nothing yet.
    assert scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0) == []
    s1, e1 = _win(1)
    # Second consecutive breaching window: disk_full fires.
    found = scorer.score([_health(s1 + 1, disk_percent=99.9)], s1, e1)
    assert [f["evidence"][0]["condition"] for f in found] == ["disk_full"]
    assert found[0]["severity"] == "HIGH"
    assert found[0]["risk_score"] == 0.85


def test_non_consecutive_breach_resets_the_counter(store):
    scorer = _scorer(store, failure_consecutive_windows=2)
    s0, e0 = _win(0)
    scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0)      # breach 1
    s1, e1 = _win(1)
    scorer.score([_health(s1 + 1, disk_percent=10.0)], s1, e1)      # healthy -> reset
    s2, e2 = _win(2)
    # This is only the first breach again; must not fire.
    assert scorer.score([_health(s2 + 1, disk_percent=99.9)], s2, e2) == []


# ---------------------------------------------------------------------------
# Window idempotency: many batches in one window advance the counter once
# ---------------------------------------------------------------------------

def test_multiple_batches_in_one_window_do_not_over_count(store):
    # Two score() calls for the SAME window must not satisfy a 2-window breach.
    scorer = _scorer(store, failure_consecutive_windows=2)
    s0, e0 = _win(0)
    scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0)
    assert scorer.score([_health(s0 + 2, disk_percent=99.9)], s0, e0) == []
    assert store.read_detection_findings() == []


def test_stale_window_is_ignored(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s1, e1 = _win(1)
    scorer.score([_health(s1 + 1, disk_percent=99.9)], s1, e1)   # active now
    # A late batch for an earlier window must not advance/clear the counter.
    s0, e0 = _win(0)
    scorer.score([_health(s0 + 1, disk_percent=10.0)], s0, e0)
    # Still active: re-scoring window 1 conditions re-emits (deduped) rather than
    # having been cleared by the stale window.
    found = scorer.score([_health(s1 + 2, disk_percent=99.9)], s1, e1)
    assert [f["evidence"][0]["condition"] for f in found] == ["disk_full"]


def test_reemitted_finding_in_same_window_dedups_to_one_row(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    first = scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0)
    again = scorer.score([_health(s0 + 2, disk_percent=99.5)], s0, e0)
    assert [f["id"] for f in first] == [f["id"] for f in again]
    assert len(store.read_detection_findings()) == 1


# ---------------------------------------------------------------------------
# Dead band: clearing needs to cross a distinct lower threshold
# ---------------------------------------------------------------------------

def test_dead_band_holds_active_between_clear_and_breach(store):
    scorer = _scorer(store, failure_consecutive_windows=2, failure_clear_windows=2,
                     failure_disk_full_pct=99.0, failure_clear_ratio=0.9)
    s0, e0 = _win(0)
    s1, e1 = _win(1)
    scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0)
    scorer.score([_health(s1 + 1, disk_percent=99.9)], s1, e1)   # active
    # 89.5 is under the breach threshold (99) but above the clear threshold
    # (99 * 0.9 = 89.1): the condition must stay active.
    s2, e2 = _win(2)
    found = scorer.score([_health(s2 + 1, disk_percent=89.5)], s2, e2)
    assert [f["evidence"][0]["condition"] for f in found] == ["disk_full"]


def test_condition_clears_after_clear_windows_below_lower_threshold(store):
    scorer = _scorer(store, failure_consecutive_windows=2, failure_clear_windows=2,
                     failure_disk_full_pct=99.0, failure_clear_ratio=0.9)
    for i in (0, 1):
        s, e = _win(i)
        scorer.score([_health(s + 1, disk_percent=99.9)], s, e)  # active by window 1
    # Two windows below the clear threshold (89.1) -> clears; final window emits nothing.
    s2, e2 = _win(2)
    assert scorer.score([_health(s2 + 1, disk_percent=50.0)], s2, e2)  # still active (clear count 1)
    s3, e3 = _win(3)
    assert scorer.score([_health(s3 + 1, disk_percent=50.0)], s3, e3) == []


def test_breach_helpers_directionality():
    # Upper-bound (breach when high): clear threshold sits below breach threshold.
    assert _breach_high(False, 99.0, 99.0, 0.9) is True
    assert _breach_high(False, 89.5, 99.0, 0.9) is False
    assert _breach_high(True, 89.5, 99.0, 0.9) is True    # dead band holds
    assert _breach_high(True, 89.0, 99.0, 0.9) is False   # below clear -> releases
    # Lower-bound (breach when low): clear threshold sits above breach threshold.
    assert _breach_low(False, 128.0, 128.0, 0.9) is True
    assert _breach_low(False, 140.0, 128.0, 0.9) is False
    assert _breach_low(True, 140.0, 128.0, 0.9) is True   # 140 <= 128/0.9 (=142.2)
    assert _breach_low(True, 150.0, 128.0, 0.9) is False  # recovered past clear


# ---------------------------------------------------------------------------
# Memory: high band -> MEDIUM, medium band -> LOW, mutually exclusive
# ---------------------------------------------------------------------------

def test_memory_high_band_emits_medium_severity(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    found = scorer.score([_health(s0 + 1, mem_percent=95.0)], s0, e0)
    assert [(f["evidence"][0]["condition"], f["severity"], f["risk_score"]) for f in found] == [
        ("memory_pressure_high", "MEDIUM", 0.65)
    ]


def test_memory_medium_band_emits_low_severity(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    found = scorer.score([_health(s0 + 1, mem_percent=85.0)], s0, e0)
    assert [(f["evidence"][0]["condition"], f["severity"], f["risk_score"]) for f in found] == [
        ("memory_pressure_medium", "LOW", 0.40)
    ]


def test_memory_high_and_medium_are_mutually_exclusive(store):
    # A value above the high threshold emits only the high finding, not both.
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    found = scorer.score([_health(s0 + 1, mem_percent=99.0)], s0, e0)
    conditions = sorted(f["evidence"][0]["condition"] for f in found)
    assert conditions == ["memory_pressure_high"]


def test_medium_counter_keeps_history_while_high_is_quiet(store):
    # Sustained mem in the medium band across two windows must emit the medium
    # finding even though the high counter never advanced -- both counters are
    # observed every window.
    scorer = _scorer(store, failure_consecutive_windows=2)
    s0, e0 = _win(0)
    s1, e1 = _win(1)
    assert scorer.score([_health(s0 + 1, mem_percent=85.0)], s0, e0) == []
    found = scorer.score([_health(s1 + 1, mem_percent=85.0)], s1, e1)
    assert [f["evidence"][0]["condition"] for f in found] == ["memory_pressure_medium"]


def test_low_available_memory_emits_medium(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    found = scorer.score([_health(s0 + 1, mem_available_mb=64)], s0, e0)
    assert [(f["evidence"][0]["condition"], f["severity"]) for f in found] == [
        ("memory_available_low", "MEDIUM")
    ]


def test_cpu_pressure_emits_only_when_field_present(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    # cpu absent -> no cpu finding
    assert scorer.score([_health(s0 + 1, mem_percent=10.0)], s0, e0) == []
    s1, e1 = _win(1)
    found = scorer.score([_health(s1 + 1, cpu_percent=99.0)], s1, e1)
    assert [f["evidence"][0]["condition"] for f in found] == ["cpu_pressure_high"]


# ---------------------------------------------------------------------------
# Representative sample: last sample in the window drives the decision
# ---------------------------------------------------------------------------

def test_latest_sample_in_window_is_representative(store):
    # An early spike that has recovered by the end of the window is not a
    # sustained failure; the most recent sample governs.
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    found = scorer.score(
        [_health(s0 + 1, disk_percent=99.9), _health(s0 + 200, disk_percent=20.0)],
        s0, e0,
    )
    assert found == []


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

def test_service_failure_emits_high_finding(store):
    scorer = _scorer(store)
    s0, e0 = _win(0)
    found = scorer.score([_service(s0 + 1, "nginx.service", action="failed")], s0, e0)
    assert len(found) == 1
    f = found[0]
    assert f["entity_type"] == "systemd_unit"
    assert f["entity_key"] == "nginx.service"
    assert f["evidence"][0]["condition"] == "service_unit_failed"
    assert f["severity"] == "HIGH"


def test_service_result_failure_counts_as_failure(store):
    scorer = _scorer(store)
    s0, e0 = _win(0)
    found = scorer.score([_service(s0 + 1, "db.service", result="failure")], s0, e0)
    assert [f["evidence"][0]["condition"] for f in found] == ["service_unit_failed"]


def test_service_without_unit_name_is_skipped(store):
    scorer = _scorer(store)
    s0, e0 = _win(0)
    assert scorer.score([_service(s0 + 1, None, action="failed")], s0, e0) == []


def test_multiple_failures_of_one_unit_in_window_collapse_to_one_finding(store):
    scorer = _scorer(store)
    s0, e0 = _win(0)
    found = scorer.score(
        [
            _service(s0 + 1, "web.service", action="failed"),
            _service(s0 + 2, "web.service", action="failed"),
        ],
        s0, e0,
    )
    assert len(found) == 1
    assert found[0]["evidence"][0]["threshold_context"]["failures_in_this_window"] == 2


def test_crash_loop_across_windows_is_labelled(store):
    # Three failures within the crash-loop lookback (600s) escalate the label,
    # and the lookback intentionally spans window boundaries.
    scorer = _scorer(store, failure_crash_loop_threshold=3,
                     failure_crash_loop_window_seconds=600.0)
    s0, e0 = _win(0)
    s1, e1 = _win(1)
    scorer.score([_service(s0 + 1, "api.service", action="failed")], s0, e0)
    found = scorer.score(
        [
            _service(s1 + 1, "api.service", action="failed"),
            _service(s1 + 2, "api.service", action="failed"),
        ],
        s1, e1,
    )
    assert [f["evidence"][0]["condition"] for f in found] == ["service_crash_loop"]
    assert found[0]["evidence"][0]["threshold_context"]["failure_count_in_crash_loop_window"] == 3


def test_two_units_failing_in_one_window_are_two_findings(store):
    scorer = _scorer(store)
    s0, e0 = _win(0)
    found = scorer.score(
        [
            _service(s0 + 1, "a.service", action="failed"),
            _service(s0 + 2, "b.service", action="failed"),
        ],
        s0, e0,
    )
    assert sorted(f["entity_key"] for f in found) == ["a.service", "b.service"]


# ---------------------------------------------------------------------------
# Persisted-finding shape
# ---------------------------------------------------------------------------

def test_persisted_finding_shape_is_detection_only(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    scorer.score([_health(s0 + 1, disk_percent=99.9)], s0, e0)
    rows = store.read_detection_findings()
    assert len(rows) == 1
    row = rows[0]
    assert row["mode"] == "system_failure"
    assert row["detector_version"] == FAILURE_DETECTOR_VERSION
    # Behaviour/rule/context scores are zero: the failure magnitude lives in risk_score.
    assert row["behavior_score"] == 0.0
    assert row["rule_score"] == 0.0
    assert row["context_score"] == 0.0
    assert row["evidence"][0]["signal"] == "system_failure"


def test_other_event_types_are_ignored(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    s0, e0 = _win(0)
    other = Event(event_type=EventType.PROCESS_EXEC, timestamp=s0 + 1, payload={"comm": "bash"})
    assert scorer.score([other], s0, e0) == []


# ---------------------------------------------------------------------------
# score_batch windowing
# ---------------------------------------------------------------------------

def test_score_batch_buckets_events_into_epoch_windows(store):
    scorer = _scorer(store, failure_consecutive_windows=1)
    # Two events in different epoch-aligned windows; each fires independently.
    batch = [
        _health(WINDOW_SECONDS * 0 + 10, disk_percent=99.9),
        _health(WINDOW_SECONDS * 1 + 10, disk_percent=99.9),
    ]
    found = scorer.score_batch(batch)
    starts = sorted(f["window_start"] for f in found)
    assert starts == [0.0, WINDOW_SECONDS]


def test_score_batch_orders_windows_ascending_for_hysteresis(store):
    # Even when events arrive out of order in the batch, two consecutive
    # breaching windows must satisfy a 2-window breach.
    scorer = _scorer(store, failure_consecutive_windows=2)
    batch = [
        _health(WINDOW_SECONDS * 1 + 10, disk_percent=99.9),  # later window first
        _health(WINDOW_SECONDS * 0 + 10, disk_percent=99.9),
    ]
    found = scorer.score_batch(batch)
    assert [f["evidence"][0]["condition"] for f in found] == ["disk_full"]
    assert found[0]["window_start"] == WINDOW_SECONDS  # fired on the second window


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def test_config_rejects_medium_at_or_above_high():
    with pytest.raises(ConfigError):
        _validate(Settings().replace(failure_memory_medium_pct=90.0,
                                     failure_memory_high_pct=90.0))


def test_config_rejects_percentage_above_100():
    with pytest.raises(ConfigError):
        _validate(Settings().replace(failure_disk_full_pct=150.0))


@pytest.mark.parametrize("ratio", [0.0, -0.1, 1.5])
def test_config_rejects_out_of_range_clear_ratio(ratio):
    with pytest.raises(ConfigError):
        _validate(Settings().replace(failure_clear_ratio=ratio))


def test_config_accepts_ratio_of_one():
    # 1.0 means no dead band -- valid, just no hysteresis margin.
    assert _validate(Settings().replace(failure_clear_ratio=1.0)).failure_clear_ratio == 1.0


@pytest.mark.parametrize("field", [
    "failure_consecutive_windows",
    "failure_clear_windows",
    "failure_crash_loop_threshold",
])
def test_config_rejects_non_positive_window_counts(field):
    with pytest.raises(ConfigError):
        _validate(Settings().replace(**{field: 0}))


# ---------------------------------------------------------------------------
# Pipeline integration: failure findings persist without a behaviour risk
# ---------------------------------------------------------------------------

def test_pipeline_persists_failures_for_health_only_batch(store):
    # The pipeline early-returns when the behaviour analyzer reports no risks.
    # A batch of pure health telemetry produces no behaviour risk, so this
    # asserts the failure scorer runs BEFORE that gate: two consecutive
    # breaching windows (default breach = 2) must leave a persisted finding,
    # and it must be a detection-only availability finding.
    from pipeline.live_ingestion import DatabaseAnalysisPipeline

    pipeline = DatabaseAnalysisPipeline(store)
    pipeline.process([
        _health(WINDOW_SECONDS * 0 + 10, disk_percent=99.9),
        _health(WINDOW_SECONDS * 1 + 10, disk_percent=99.9),
    ])

    rows = store.read_detection_findings()
    assert [r["mode"] for r in rows] == ["system_failure"]
    assert rows[0]["evidence"][0]["condition"] == "disk_full"


def test_pipeline_ignores_non_telemetry_batch(store):
    # A batch with neither health nor service events must not fabricate a
    # failure finding.
    from pipeline.live_ingestion import DatabaseAnalysisPipeline

    pipeline = DatabaseAnalysisPipeline(store)
    pipeline.process([
        Event(event_type=EventType.PROCESS_EXEC, timestamp=1000 + i,
              payload={"comm": "bash"}, pid=i)
        for i in range(3)
    ])
    assert [r for r in store.read_detection_findings() if r["mode"] == "system_failure"] == []
