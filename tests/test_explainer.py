from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from baseline.behavior_analyzer import BehaviorAnalyzer
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


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


def _finding(tmp_path, multi_rule=True):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    engine = DetectionEngine(store)
    features = {
        "execution_frequency": 12 if multi_rule else 1,
        "unique_commands": 4 if multi_rule else 1,
        "unique_uids": 3 if multi_rule else 1,
        "command_frequency": {"nc": 2, "bash": 8},
        "uid_activity": {"0": 1, "1000": 10, "1001": 1},
        "burst_activity": {"active_seconds": 3, "peak_execs_per_second": 6 if multi_rule else 1},
        "entity_event_count": 2,
        "event_max_score": 0.85,
    }
    risk = {
        "id": 11 if multi_rule else 12,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": "command",
        "entity_key": "nc",
        "anomaly_score": 0.85 if multi_rule else 0.55,
        "contributing_features": features,
        "explanation": "test-only simulated behavior risk",
        "mode": "monitoring",
    }
    events = [_event(1000, "nc", uid=1000)] if not multi_rule else [
        _event(1000, "nc", uid=0),
        *[_event(1001 + index, "bash", uid=1000, pid=index + 1) for index in range(11)],
    ]
    finding = engine.detect([risk], events, persist=True)["findings"][0]
    return store, finding


def test_no_detection_produces_no_explanation(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    assert FindingExplainer(store).explain_all() == []
    assert store.read_explanations() == []


def test_insufficient_baseline_produces_no_detection_or_explanation(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    analyzer = BehaviorAnalyzer(store, minimum_normal_execs=500)
    learning = analyzer.learn_normal([_event(1000, "bash")], verified_normal=True)
    assert learning["status"] == "insufficient_normal_data"
    assert analyzer.monitor([_event(1100, "nc")])["status"] == "baseline_not_ready"
    assert DetectionEngine(store).detect()["findings"] == []
    assert FindingExplainer(store).explain_all() == []


def test_single_rule_explanation_is_traceable_and_persisted(tmp_path):
    store, finding = _finding(tmp_path, multi_rule=False)
    explanation = FindingExplainer(store).explain_finding(finding)

    assert explanation["finding_id"] == finding["id"]
    assert explanation["risk_score"] == finding["risk_score"]
    assert explanation["calculation"]["stored_risk_score"] == finding["risk_score"]
    assert explanation["calculation"]["matched_rule_scores"] == [0.65]
    assert any(item["label"] == "FACT" for item in explanation["contributing_factors"])
    assert any(item["label"] == "INTERPRETATION" for item in explanation["contributing_factors"])
    assert len(store.read_explanations()) == 1


def test_multi_rule_high_critical_explanation_reconstructs_fusion(tmp_path):
    store, finding = _finding(tmp_path, multi_rule=True)
    explanation = FindingExplainer(store).explain_all()[0]

    assert finding["severity"] == "CRITICAL"
    assert explanation["calculation"]["reconstructed_rule_score"] == finding["rule_score"]
    assert explanation["calculation"]["calculated_risk_score"] == finding["risk_score"]
    assert len(explanation["calculation"]["matched_rule_scores"]) >= 3
    assert explanation["evidence"] == finding["evidence"]
    assert explanation["limitations"] == []


def test_explanation_rejects_incomplete_evidence(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    explainer = FindingExplainer(store)
    finding = {
        "id": 1,
        "window_start": 1,
        "window_end": 2,
        "entity_type": "command",
        "entity_key": "bash",
        "risk_score": 0.2,
        "severity": "LOW",
        "behavior_score": 0.2,
        "rule_score": 0.0,
        "context_score": 0.0,
        "evidence": [],
        "mode": "detection",
    }
    try:
        explainer.explain_finding(finding, persist=False)
    except ValueError as error:
        assert "missing signals" in str(error)
    else:
        raise AssertionError("incomplete evidence was explained")


def test_explanation_reload_is_deterministic(tmp_path):
    store, finding = _finding(tmp_path, multi_rule=True)
    first = FindingExplainer(store).explain_finding(finding)
    second = FindingExplainer(store).explain_all()[0]
    assert first == second
