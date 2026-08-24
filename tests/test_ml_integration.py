from pathlib import Path

import pytest

from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from ml.evaluation import MIN_NORMAL_HOLDOUT_WINDOWS, evaluate_threshold, normal_fpr_acceptance
from ml.feature_schema import FEATURE_NAMES, extract_features, feature_vector, schema_hash
from ml.scoring import MLScorer, MLScoringError
from ml.training import SKLEARN_AVAILABLE, MLTrainingError, add_verified_normal_window, create_verified_normal_dataset, train_isolation_forest
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


def _event(timestamp, event_type="process_exec", **values):
    raw = {"event_type": event_type, "timestamp": timestamp, "pid": 10, "uid": 1000, "comm": "python3", **values}
    return Event.from_raw_json(raw)


def _normal_windows():
    return [
        [_event(100.0, executable="/usr/bin/python3"), _event(102.0, "tcp_connect", dest_ip="127.0.0.1", dest_port=18080)],
        [_event(200.0, executable="/usr/bin/python3"), _event(203.0, "ipc_event", action="pipe_created", kind="anonymous_pipe", success=True, read_fd=3, write_fd=4)],
        [_event(300.0, "auth_session", action="session_opened", result="success", service="sudo", account="root")],
    ]


def _training_windows():
    base = _normal_windows()
    windows = []
    for index in range(10):
        source = base[index % len(base)]
        windows.append([
            Event.from_raw_json({
                **event.to_dict(),
                "event_type": event.event_type.value,
                "timestamp": event.timestamp + index * 10.0,
                "pid": (event.pid or 0) + index,
            })
            for event in source
        ])
    return windows


def _trained(tmp_path):
    if not SKLEARN_AVAILABLE:
        pytest.skip("scikit-learn is not installed in the active Python environment")
    store = SQLiteEventStore(str(tmp_path / "ml.db"))
    verification = {"verified_normal": True, "operator": "test", "method": "controlled normal workload"}
    dataset_id = create_verified_normal_dataset(store, "test-normal", verification)
    for index, events in enumerate(_training_windows()):
        add_verified_normal_window(store, dataset_id, events, [index * 10 + offset for offset in range(len(events))], verification)
    metadata = train_isolation_forest(store, dataset_id, str(tmp_path / "models"))
    return store, dataset_id, metadata


def test_named_feature_schema_is_deterministic_and_complete():
    events = _normal_windows()[0]
    assert extract_features(events) == extract_features(list(reversed(events)))
    assert list(extract_features(events)) == list(FEATURE_NAMES)
    assert feature_vector(events) == [extract_features(events)[name] for name in FEATURE_NAMES]
    assert schema_hash() == schema_hash()
    empty = extract_features([])
    assert set(empty) == set(FEATURE_NAMES) and all(value == 0.0 for value in empty.values())


def test_training_boundary_rejects_unverified_or_mixed_windows(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "ml.db"))
    with pytest.raises(MLTrainingError, match="verified_normal"):
        create_verified_normal_dataset(store, "bad", {"verified_normal": False})
    dataset_id = create_verified_normal_dataset(store, "good", {"verified_normal": True, "operator": "test"})
    with pytest.raises(MLTrainingError, match="verified_normal"):
        add_verified_normal_window(store, dataset_id, _normal_windows()[0], [1, 2], {"verified_normal": False})
    expected = "at least 10" if SKLEARN_AVAILABLE else "scikit-learn"
    with pytest.raises(MLTrainingError, match=expected):
        train_isolation_forest(store, dataset_id, str(tmp_path / "models"))


def test_training_persists_immutable_provenance_and_checksum(tmp_path):
    store, dataset_id, metadata = _trained(tmp_path)
    windows = store.read_ml_training_windows(dataset_id)
    persisted = store.read_ml_model(metadata["id"])
    assert len(windows) == 10 and all(window["verified_normal"] for window in windows)
    assert all(window["immutable_hash"] for window in windows)
    assert persisted["active"] is False
    assert persisted["schema_hash"] == schema_hash()
    assert Path(persisted["artifact_path"]).exists()


def test_schema_checked_scoring_is_deterministic_and_detects_corruption(tmp_path):
    store, _, metadata = _trained(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    first = scorer.score(_normal_windows()[0])
    second = scorer.score(list(reversed(_normal_windows()[0])))
    assert first == second
    assert first["schema_hash"] == schema_hash() and first["contributing_feature_deviations"]
    assert first["feature_diagnostics"] and first["calibration"]["status"]
    Path(metadata["artifact_path"]).write_bytes(b"corrupt")
    with pytest.raises(MLScoringError, match="checksum"):
        MLScorer(store, metadata["id"])


def test_evaluation_reports_normal_fpr_and_only_labeled_metrics_when_available(tmp_path):
    store, _, metadata = _trained(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    unlabeled = evaluate_threshold(scorer, _normal_windows())
    assert unlabeled["labels_available"] is False and "precision" not in unlabeled
    assert unlabeled["acceptance"]["activation_eligible"] is False
    assert len(unlabeled["normal_window_scores"]) == len(_normal_windows())
    labeled = evaluate_threshold(scorer, _normal_windows(), [(_normal_windows()[0], 0), ([_event(500, comm="nc"), _event(501, "service_state", action="failed", unit="x.service")], 1)])
    assert labeled["labels_available"] is True and set(labeled["confusion_matrix"]) == {"tp", "fp", "tn", "fn"}


def test_fpr_acceptance_keeps_small_or_over_threshold_evaluations_inactive():
    insufficient = normal_fpr_acceptance(0, MIN_NORMAL_HOLDOUT_WINDOWS - 1)
    rejected = normal_fpr_acceptance(1, MIN_NORMAL_HOLDOUT_WINDOWS)
    assert insufficient["activation_eligible"] is False
    assert rejected["activation_eligible"] is False


def test_detection_and_explanation_include_ml_as_additive_evidence(tmp_path):
    store, _, metadata = _trained(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    risk = {"id": 7, "window_start": 100.0, "window_end": 110.0, "entity_type": "command", "entity_key": "python3", "anomaly_score": 0.7,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "deterministic behavior risk", "mode": "monitoring"}
    events = _normal_windows()[0]
    finding = DetectionEngine(store, ml_scorer=scorer).detect([risk], events)["findings"][0]
    assert finding["evidence"][-1]["signal"] == "ml_anomaly"
    explanation = FindingExplainer(store).explain_finding(finding)
    assert explanation["calculation"]["inputs"]["ml_score"] is not None
    assert any(item["factor"] == "ml_anomaly_evidence" for item in explanation["contributing_factors"])


def test_detection_without_ml_preserves_existing_fusion_behavior(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "fallback.db"))
    risk = {"id": 1, "window_start": 1.0, "window_end": 3.0, "entity_type": "command", "entity_key": "nc", "anomaly_score": 0.5,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "risk", "mode": "monitoring"}
    finding = DetectionEngine(store).detect([risk], [_event(1.5, comm="nc")], persist=False)["findings"][0]
    assert [item["signal"] for item in finding["evidence"]] == ["behavior_anomaly", "rule_fusion", "process_context"]


def test_ml_failure_falls_back_to_deterministic_detection(tmp_path):
    class BrokenScorer:
        def score(self, events):
            raise RuntimeError("artifact unavailable")

    store = SQLiteEventStore(str(tmp_path / "fallback.db"))
    risk = {"id": 1, "window_start": 1.0, "window_end": 3.0, "entity_type": "command", "entity_key": "nc", "anomaly_score": 0.5,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "risk", "mode": "monitoring"}
    finding = DetectionEngine(store, ml_scorer=BrokenScorer()).detect([risk], [_event(1.5, comm="nc")], persist=False)["findings"][0]
    assert "ml_anomaly" not in [item["signal"] for item in finding["evidence"]]
    assert finding["fusion_formula"] == "min(1, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)"
