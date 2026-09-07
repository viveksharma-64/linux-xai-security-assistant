from detection.detector import DetectionEngine
from detection.rules import load_rules
from baseline.behavior_analyzer import BehaviorAnalyzer
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


def _rule(rule_id):
    for rule in load_rules():
        if rule.rule_id == rule_id:
            return rule
    raise AssertionError(f"rule {rule_id} is not bound by the default catalog")


def _event(timestamp, comm="bash", uid=1000, pid=1):
    return Event.from_raw_json(
        {
            "event_type": "process_exec",
            "timestamp": timestamp,
            "comm": comm,
            "uid": uid,
            "pid": pid,
        }
    )


def _risk(score=0.85, entity_type="command", entity_key="nc"):
    return {
        "id": 7,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "anomaly_score": score,
        "contributing_features": {
            "execution_frequency": 12,
            "unique_commands": 4,
            "unique_uids": 3,
            "command_frequency": {"nc": 2, "bash": 8},
            "uid_activity": {"0": 1, "1000": 10, "1001": 1},
            "burst_activity": {"active_seconds": 3, "peak_execs_per_second": 6},
            "entity_event_count": 2,
            "event_max_score": score,
        },
        "explanation": "simulated behavior deviation",
        "mode": "monitoring",
    }


def test_rules_are_independently_testable():
    context = {
        "behavior_score": 0.8,
        "features": _risk()["contributing_features"],
        "events": [_event(1000, comm="nc", uid=1000)],
    }
    utility = _rule("suspicious_utility_activity").evaluate(context)
    burst = _rule("execution_burst").evaluate(context)
    assert utility.matched is True
    assert utility.score == 0.65
    assert burst.matched is True
    assert burst.score == 0.60


def test_normal_behavior_without_behavior_risk_produces_no_findings(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    engine = DetectionEngine(store)
    result = engine.detect(risks=[], events=[_event(1000, "bash")])
    assert result == {"status": "detected", "mode": "detection", "findings": []}
    assert store.read_detection_findings() == []


def test_detection_fuses_behavior_rules_and_context(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    engine = DetectionEngine(store)
    events = [
        _event(1000 + index, comm="nc" if index < 2 else "bash", uid=0 if index == 0 else 1000, pid=index)
        for index in range(12)
    ]
    risk = _risk()

    first = engine.detect(risks=[risk], events=events, persist=False)
    second = engine.detect(risks=[risk], events=list(reversed(events)), persist=False)
    assert first == second

    finding = first["findings"][0]
    expected_rule_score = 1.0 - (
        (1.0 - 0.80) * (1.0 - 0.65) * (1.0 - 0.60) * (1.0 - 0.40)
    )
    expected_score = round(0.50 * 0.85 + 0.35 * expected_rule_score + 0.15 * 1.0, 4)
    assert finding["risk_score"] == expected_score
    assert finding["severity"] == "CRITICAL"
    assert finding["behavior_score"] == 0.85
    assert finding["rule_score"] == round(expected_rule_score, 4)
    assert finding["context_score"] == 1.0
    assert [item["signal"] for item in finding["evidence"]] == [
        "behavior_anomaly",
        "rule_fusion",
        "process_context",
    ]
    assert all(0.0 <= finding[key] <= 1.0 for key in (
        "risk_score", "behavior_score", "rule_score", "context_score"
    ))


def test_findings_are_persisted_with_structured_evidence(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    engine = DetectionEngine(store)
    engine.detect(risks=[_risk(score=0.7)], events=[_event(1000, "nc")])

    stored = store.read_detection_findings()
    assert len(stored) == 1
    assert stored[0]["source_risk_id"] == 7
    assert stored[0]["severity"] in {"HIGH", "CRITICAL", "MEDIUM"}
    assert stored[0]["evidence"][0]["source"] == "behavior_risk"
    assert stored[0]["evidence"][1]["signal"] == "rule_fusion"
    assert "behavior=" in stored[0]["explanation"]
    assert "rules=" in stored[0]["explanation"]
    assert "context=" in stored[0]["explanation"]
    assert stored[0]["provenance_hash"]
    assert stored[0]["detector_version"] == "detector.v1"


def test_detection_persistence_is_idempotent_for_identical_evidence(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    engine = DetectionEngine(store)
    first = engine.detect(risks=[_risk(score=0.7)], events=[_event(1000, "nc")])
    second = engine.detect(risks=[_risk(score=0.7)], events=[_event(1000, "nc")])
    assert first["findings"][0]["provenance_hash"] == second["findings"][0]["provenance_hash"]
    assert first["findings"][0]["id"] == second["findings"][0]["id"]
    assert len(store.read_detection_findings()) == 1


def test_behavior_risk_to_finding_sqlite_integration(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    analyzer = BehaviorAnalyzer(store, minimum_normal_execs=4)
    normal = [_event(1000 + index, comm="bash", pid=index) for index in range(4)]
    analyzer.learn_normal(normal, verified_normal=True)
    for event in normal:
        store.write(event)

    suspicious = _event(1100, comm="nc", uid=1000, pid=99)
    store.write(suspicious)
    analyzer.monitor([suspicious])

    result = DetectionEngine(store).detect()
    assert result["findings"]
    assert result["findings"][0]["entity_type"] in {"command", "uid"}
    assert store.read_detection_findings()


def test_severity_thresholds_are_explicit(tmp_path):
    engine = DetectionEngine(SQLiteEventStore(str(tmp_path / "events.db")))
    assert engine._severity(0.10) == "LOW"
    assert engine._severity(0.35) == "MEDIUM"
    assert engine._severity(0.60) == "HIGH"
    assert engine._severity(0.80) == "CRITICAL"
