"""
Finding correlation and suppression tests (Deliverable 4).

Correlation groups findings about one entity across a contiguous run of windows
and is deterministic for a given detect() batch. Suppression is an operator
disposition, never a silent drop: a suppressed finding is still scored, returned,
persisted, and hash-chained, and suppression changes only the two disposition
fields -- so the explainer's score reconciliation still holds. These tests pin
both, plus the fail-closed validation of suppression specs.
"""

import pytest

from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


def _event(timestamp, comm="bash", uid=1000, pid=1):
    return Event.from_raw_json(
        {"event_type": "process_exec", "timestamp": timestamp, "comm": comm, "uid": uid, "pid": pid}
    )


def _risk(window_start, window_end, entity_key="nc", entity_type="command", score=0.7, unique_uids=1):
    return {
        "id": None,
        "window_start": window_start,
        "window_end": window_end,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "anomaly_score": score,
        "contributing_features": {
            "execution_frequency": 1,
            "unique_uids": unique_uids,
            "burst_activity": {"peak_execs_per_second": 0},
        },
        "explanation": "simulated deviation",
        "mode": "monitoring",
    }


# ------------------------------------------------------------- correlation


def test_correlation_groups_contiguous_windows_and_splits_on_gap(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    engine = DetectionEngine(store)
    risks = [
        _risk(1000.0, 1300.0),
        _risk(1300.0, 1600.0),  # adjacent to the previous window -> same run
        _risk(2000.0, 2300.0),  # gap before this window -> new run
    ]
    findings = engine.detect(risks=risks, events=[], persist=False)["findings"]
    cids = [f["correlation_id"] for f in findings]
    assert all(cids), "every finding is correlated"
    assert cids[0] == cids[1], "contiguous windows for one entity share a correlation id"
    assert cids[2] != cids[0], "a window gap starts a new correlation group"


def test_correlation_distinguishes_entities(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    engine = DetectionEngine(store)
    risks = [
        _risk(1000.0, 1300.0, entity_key="nc"),
        _risk(1000.0, 1300.0, entity_key="curl"),
    ]
    findings = engine.detect(risks=risks, events=[], persist=False)["findings"]
    by_key = {f["entity_key"]: f["correlation_id"] for f in findings}
    assert by_key["nc"] != by_key["curl"]


def test_correlation_is_deterministic_for_identical_input(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    engine = DetectionEngine(store)
    risks = [_risk(1000.0, 1300.0), _risk(1300.0, 1600.0)]
    first = engine.detect(risks=risks, events=[], persist=False)["findings"]
    second = engine.detect(risks=list(reversed(risks)), events=[], persist=False)["findings"]
    assert [f["correlation_id"] for f in first] == [f["correlation_id"] for f in second]


# ------------------------------------------------------------- suppression


def test_suppression_is_disposition_only_and_changes_no_score(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    risk = _risk(1000.0, 1300.0, entity_key="nc", score=0.7)

    unsuppressed = DetectionEngine(store).detect(risks=[risk], events=[], persist=False)["findings"][0]
    engine = DetectionEngine(store, suppressions=[{"entity_key": "nc", "reason": "known scanner host"}])
    suppressed = engine.detect(risks=[risk], events=[], persist=False)["findings"][0]

    assert suppressed["suppressed"] is True
    assert suppressed["suppression_reason"] == "known scanner host"
    # Disposition only: identity and every score/severity/evidence are untouched.
    for key in (
        "risk_score", "behavior_score", "rule_score", "context_score",
        "severity", "evidence", "provenance_hash", "correlation_id",
    ):
        assert suppressed[key] == unsuppressed[key], key


def test_suppressed_finding_is_persisted_and_chained_not_dropped(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    engine = DetectionEngine(store, suppressions=[{"entity_key": "nc", "reason": "maintenance window"}])
    engine.detect(risks=[_risk(1000.0, 1300.0, entity_key="nc")], events=[])

    stored = store.read_detection_findings()
    assert len(stored) == 1, "suppression is never a silent drop"
    assert stored[0]["suppressed"] is True
    assert stored[0]["suppression_reason"] == "maintenance window"
    assert store.verify_findings_chain()["ok"] is True


def test_suppression_can_target_a_matched_rule(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    events = [_event(1000, comm="nc", uid=1000)]
    risk = _risk(1000.0, 1300.0, entity_key="nc", score=0.8)  # trips suspicious_utility_activity

    on = DetectionEngine(
        store, suppressions=[{"matched_rule": "suspicious_utility_activity", "reason": "benign admin transfer"}]
    )
    assert on.detect(risks=[risk], events=events, persist=False)["findings"][0]["suppressed"] is True

    # A spec keyed on a rule that did not match leaves the finding untouched.
    off = DetectionEngine(store, suppressions=[{"matched_rule": "multi_uid_activity", "reason": "n/a"}])
    assert off.detect(risks=[risk], events=events, persist=False)["findings"][0]["suppressed"] is False


def test_no_suppressions_by_default(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    finding = DetectionEngine(store).detect(risks=[_risk(1000.0, 1300.0)], events=[], persist=False)["findings"][0]
    assert finding["suppressed"] is False
    assert finding["suppression_reason"] is None
    assert finding["correlation_id"]  # correlation is still assigned


def test_suppressed_finding_still_reconciles_in_explainer(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    engine = DetectionEngine(store, suppressions=[{"entity_key": "nc", "reason": "known benign"}])
    finding = engine.detect(
        risks=[_risk(1000.0, 1300.0, entity_key="nc", score=0.7)], events=[_event(1000, comm="nc")]
    )["findings"][0]
    assert finding["suppressed"] is True
    # The explainer recomputes the fused score and rule fusion and raises on any
    # mismatch; suppression must not perturb either.
    explanation = FindingExplainer(store).explain_finding(finding, persist=False)
    assert explanation


def test_malformed_suppression_specs_fail_closed(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    with pytest.raises(ValueError):
        DetectionEngine(store, suppressions=[{"entity_key": "nc"}])  # no reason
    with pytest.raises(ValueError):
        DetectionEngine(store, suppressions=[{"reason": "matches everything"}])  # no criterion
