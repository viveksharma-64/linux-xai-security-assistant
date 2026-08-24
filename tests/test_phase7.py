from pathlib import Path

import pytest

from policy.engine import PolicyConfigurationError, PolicyDecision, PolicyEngine
from storage.sqlite_store import SQLiteEventStore


ROOT = Path(__file__).parents[1]
DEFAULT_POLICY = ROOT / "policy" / "default_policy.yaml"


def _finding(score, severity, finding_id=1, with_evidence=True):
    evidence = [
        {
            "signal": "behavior_anomaly",
            "score": score,
            "features": {"execution_frequency": 1},
            "source": "behavior_risk",
        },
        {
            "signal": "rule_fusion",
            "score": 0.0,
            "rules": [
                {
                    "rule_id": "suspicious_utility_activity",
                    "matched": False,
                    "score": 0.65,
                    "evidence": {},
                    "explanation": "no anomalous dual-use utility activity matched",
                }
            ],
        },
        {
            "signal": "process_context",
            "score": 0.0,
            "event_count": 1,
            "privileged_event_count": 0,
        },
    ]
    return {
        "id": finding_id,
        "risk_score": score,
        "severity": severity,
        "entity_type": "command",
        "entity_key": "bash",
        "evidence": evidence if with_evidence else [],
    }


def test_default_policy_covers_low_medium_high_critical(tmp_path):
    engine = PolicyEngine.from_yaml(SQLiteEventStore(str(tmp_path / "policy.db")), str(DEFAULT_POLICY))
    decisions = [
        engine.evaluate(_finding(0.10, "LOW"), persist=False),
        engine.evaluate(_finding(0.40, "MEDIUM", finding_id=2), persist=False),
        engine.evaluate(_finding(0.65, "HIGH", finding_id=3), persist=False),
        engine.evaluate(_finding(0.90, "CRITICAL", finding_id=4), persist=False),
    ]
    assert [item["decision"] for item in decisions] == [
        PolicyDecision.LOG.value,
        PolicyDecision.LOG.value,
        PolicyDecision.DRY_RUN.value,
        PolicyDecision.DRY_RUN.value,
    ]
    assert decisions[2]["required_approval"] is True
    assert decisions[3]["required_approval"] is True


def test_dry_run_never_executes_and_action_requires_approval(tmp_path):
    engine = PolicyEngine.from_yaml(SQLiteEventStore(str(tmp_path / "policy.db")), str(DEFAULT_POLICY), dry_run=True)
    decision = engine.evaluate(_finding(0.9, "CRITICAL"), persist=False)
    assert decision["decision"] == PolicyDecision.DRY_RUN.value
    assert decision["dry_run"] is True
    assert decision["required_approval"] is True
    assert "No action is executed" in decision["reason"]


def test_ai_recommendation_conflicting_with_policy_is_rejected(tmp_path):
    engine = PolicyEngine.from_yaml(SQLiteEventStore(str(tmp_path / "policy.db")), str(DEFAULT_POLICY))
    decision = engine.evaluate(
        _finding(0.9, "CRITICAL"),
        assistant_response={"recommended_action": "Kill PID 1234 immediately."},
        persist=False,
    )
    assert decision["decision"] == PolicyDecision.DRY_RUN.value
    assert decision["required_approval"] is True
    assert decision["advisory_rejection"]
    assert "rejected" in decision["reason"]


def test_malformed_policy_fails_closed_at_load(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\npolicies:\n  - policy_id: bad\n    match: {}\n    decision: UNKNOWN\n", encoding="utf-8")
    with pytest.raises(PolicyConfigurationError):
        PolicyEngine.from_yaml(SQLiteEventStore(str(tmp_path / "policy.db")), str(path))


def test_unknown_policy_match_key_fails_closed(tmp_path):
    document = {
        "version": 1,
        "policies": [{
            "policy_id": "bad",
            "priority": 1,
            "match": {"unknown_field": True},
            "decision": "LOG",
            "required_approval": False,
            "proposed_action": "Record the finding.",
        }],
    }
    with pytest.raises(PolicyConfigurationError):
        PolicyEngine.from_document(SQLiteEventStore(str(tmp_path / "policy.db")), document)


def test_missing_finding_evidence_fails_closed_to_review(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "policy.db"))
    engine = PolicyEngine.from_yaml(store, str(DEFAULT_POLICY))
    decision = engine.evaluate(_finding(0.1, "LOW", with_evidence=False), persist=False)
    assert decision["decision"] == PolicyDecision.REVIEW_REQUIRED.value
    assert decision["required_approval"] is True
    assert decision["policy_id"] == "policy.fail_closed"


def test_unavailable_telemetry_does_not_allow_safety(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "policy.db"))
    document = {
        "version": 1,
        "policies": [{
            "policy_id": "allow_only_complete",
            "priority": 100,
            "match": {"severity": ["LOW"], "telemetry_complete": True},
            "decision": "ALLOW",
            "required_approval": False,
            "proposed_action": "No response action.",
        }],
    }
    engine = PolicyEngine.from_document(store, document)
    decision = engine.evaluate(_finding(0.1, "LOW"), persist=False)
    assert decision["decision"] == PolicyDecision.REVIEW_REQUIRED.value
    assert decision["required_approval"] is True


def test_policy_decisions_are_deterministic_except_timestamp(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "policy.db"))
    engine = PolicyEngine.from_yaml(store, str(DEFAULT_POLICY))
    first = engine.evaluate(_finding(0.65, "HIGH"), persist=False)
    second = engine.evaluate(_finding(0.65, "HIGH"), persist=False)
    first.pop("timestamp")
    second.pop("timestamp")
    assert first == second


def test_policy_decisions_persist_and_reload(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "policy.db"))
    engine = PolicyEngine.from_yaml(store, str(DEFAULT_POLICY))
    decision = engine.evaluate(_finding(0.65, "HIGH"))
    stored = store.read_policy_decisions()
    assert len(stored) == 1
    assert stored[0]["finding_id"] == decision["finding_id"]
    assert stored[0]["decision"] == decision["decision"]
    assert stored[0]["required_approval"] is True
    assert stored[0]["dry_run"] is True


def test_unknown_or_malformed_runtime_input_fails_closed(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "policy.db"))
    engine = PolicyEngine.from_yaml(store, str(DEFAULT_POLICY))
    decision = engine.evaluate({"id": 99, "risk_score": "bad"}, persist=False)
    assert decision["decision"] == PolicyDecision.REVIEW_REQUIRED.value
    assert decision["required_approval"] is True
