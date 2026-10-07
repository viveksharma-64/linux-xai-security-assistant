import math
from inspect import signature
from pathlib import Path

import pytest

from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from ml.artifact import TRAINING_DECISION_PERCENTILE_LEVELS, load_artifact
from ml.evaluation import (
    MAX_NORMAL_FPR,
    MIN_NORMAL_HOLDOUT_WINDOWS,
    calibrate_threshold,
    evaluate_threshold,
    evaluate_threshold_from_windows,
    normal_fpr_acceptance,
)
from ml.feature_schema import FEATURE_NAMES, extract_features, feature_vector, schema_hash
from ml.lifecycle import (
    record_activation,
    record_activation_gate,
    record_evaluated,
    record_trained,
)
from ml.scoring import MLScorer, MLScoringError
from ml.training import (
    SKLEARN_AVAILABLE,
    UNCALIBRATED_THRESHOLD_PROVENANCE,
    MLTrainingError,
    add_verified_normal_window,
    create_verified_normal_dataset,
    rethreshold_model,
    train_isolation_forest,
)
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


# Counts that clear the activation gate, supplied by the fixture below.
_GATE_COUNTS = {"false_positive_count": 0, "normal_window_count": MIN_NORMAL_HOLDOUT_WINDOWS}


def _activated(tmp_path):
    """
    A trained model walked through the lifecycle to `active`, which scoring requires.

    A sibling of `_trained` rather than a change to it, because trained and active
    are different states and several tests need the first: evaluation scores an
    inactive model by design, and
    `test_training_persists_immutable_provenance_and_checksum` asserts that
    training alone leaves the flag false.

    The counts handed to the gate are **supplied, not measured.** This fixture
    trains on ten windows and the gate's floor is sixty independent verified-normal
    *holdout* windows, so nothing in this file could clear the gate on its own
    measurements -- these numbers exist to reach the state the scorer requires, and
    are not evidence that this model would qualify on a host. The `evaluated` row
    carries the same supplied numbers so the recorded history is at least
    self-consistent.
    """
    store, dataset_id, metadata = _trained(tmp_path)
    record_trained(store, metadata)
    record_evaluated(store, metadata["id"], {
        "normal_window_count": MIN_NORMAL_HOLDOUT_WINDOWS,
        "normal_false_positive_count": 0,
        "normal_false_positive_rate": 0.0,
        "labels_available": False,
        "confusion_matrix": None,
    })
    record_activation_gate(store, metadata["id"], **_GATE_COUNTS)
    record_activation(store, metadata["id"], **_GATE_COUNTS)
    return store, dataset_id, metadata


def _risk():
    return {"id": 7, "window_start": 100.0, "window_end": 110.0, "entity_type": "command", "entity_key": "python3", "anomaly_score": 0.7,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "deterministic behavior risk", "mode": "monitoring"}


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


def test_training_cannot_activate(tmp_path):
    """
    Training has no activation parameter, and the row it writes is inactive.

    `train_isolation_forest` used to take `activate: bool = False`, which was the
    one route to `active = 1` that consulted no gate. It was deleted rather than
    gated because no honest caller could satisfy a gated version: the gate
    measures a false-positive rate on *held-out* windows, and that measurement
    cannot exist at the moment training returns -- the model whose errors would be
    counted is the value being constructed.

    The signature check runs before the fixture on purpose. It needs no
    scikit-learn, so in an environment without it this still fails rather than
    skipping if the parameter is ever reintroduced.
    """
    assert "activate" not in signature(train_isolation_forest).parameters
    store, _, metadata = _trained(tmp_path)
    assert metadata["active"] is False
    assert store.read_ml_model(metadata["id"])["active"] is False
    # Nothing is active, and the log is empty: training is not a lifecycle event
    # on its own -- `record_trained` is a separate, explicit call.
    assert [model for model in store.read_ml_models() if model["active"]] == []
    assert store.read_ml_lifecycle(metadata["id"]) == []
    # And the gate-facing fields say so, so a reader of the row does not have to
    # infer "unevaluated" from the absence of something.
    assert metadata["evaluation"]["status"] == "not_evaluated"
    assert metadata["evaluation"]["activation_eligible"] is False


def test_schema_checked_scoring_is_deterministic_and_detects_corruption(tmp_path):
    store, _, metadata = _activated(tmp_path)
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
    # The documented exception to the activation gate, and the reason it has one:
    # evaluating a model is how it becomes eligible, so evaluation necessarily
    # scores a model that is not yet active. A gate that refused this would be
    # unsatisfiable. Nothing on the detection path passes `allow_inactive`.
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
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
    store, _, metadata = _activated(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    risk = {"id": 7, "window_start": 100.0, "window_end": 110.0, "entity_type": "command", "entity_key": "python3", "anomaly_score": 0.7,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "deterministic behavior risk", "mode": "monitoring"}
    events = _normal_windows()[0]
    finding = DetectionEngine(store, ml_scorer=scorer).detect([risk], events)["findings"][0]
    assert finding["evidence"][-1]["signal"] == "ml_anomaly"
    explanation = FindingExplainer(store).explain_finding(finding)
    assert explanation["calculation"]["inputs"]["ml_score"] is not None
    assert any(item["factor"] == "ml_anomaly_evidence" for item in explanation["contributing_factors"])


def test_ml_attribution_opt_in_flows_to_finding_and_explanation(tmp_path):
    # With attribution enabled the same payload the detector passes through verbatim
    # now carries the model-faithful decomposition, and the explainer's existing
    # FACT factor surfaces it -- no new signal, no detector change.
    store, _, metadata = _activated(tmp_path)
    scorer = MLScorer(store, metadata["id"], attribute=True)
    risk = {"id": 7, "window_start": 100.0, "window_end": 110.0, "entity_type": "command", "entity_key": "python3", "anomaly_score": 0.7,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "deterministic behavior risk", "mode": "monitoring"}
    events = _normal_windows()[0]
    finding = DetectionEngine(store, ml_scorer=scorer).detect([risk], events)["findings"][0]
    ml_evidence = finding["evidence"][-1]
    assert ml_evidence["signal"] == "ml_anomaly"
    attribution = ml_evidence["model"]["attribution"]
    assert attribution["method"] == "path-length-split-attribution.v1" and attribution["reconciles"] is True
    explanation = FindingExplainer(store).explain_finding(finding)
    factor = next(item for item in explanation["contributing_factors"] if item["factor"] == "ml_anomaly_evidence")
    assert factor["label"] == "FACT"
    assert factor["evidence"]["attribution"]["method"] == "path-length-split-attribution.v1"
    assert "isolation-path length" in factor["statement"]


def test_default_scorer_omits_attribution_from_payload_and_factor(tmp_path):
    # Regression guard on the default path: a scorer built without attribute=True
    # adds no attribution key to the score payload, so the finding and the
    # explanation factor are byte-for-byte what they were before this track.
    store, _, metadata = _activated(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    assert "attribution" not in scorer.score(_normal_windows()[0])
    risk = {"id": 7, "window_start": 100.0, "window_end": 110.0, "entity_type": "command", "entity_key": "python3", "anomaly_score": 0.7,
            "contributing_features": {"execution_frequency": 1, "unique_commands": 1, "unique_uids": 1, "burst_activity": {"peak_execs_per_second": 1}}, "explanation": "deterministic behavior risk", "mode": "monitoring"}
    finding = DetectionEngine(store, ml_scorer=scorer).detect([risk], _normal_windows()[0])["findings"][0]
    assert "attribution" not in finding["evidence"][-1]["model"]
    explanation = FindingExplainer(store).explain_finding(finding)
    factor = next(item for item in explanation["contributing_factors"] if item["factor"] == "ml_anomaly_evidence")
    assert "attribution" not in factor["evidence"]
    assert factor["statement"].endswith("statistical, not causal explanations.")


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


# --- activation gates scoring ---


def test_scorer_refuses_an_inactive_model(tmp_path):
    # The gate is only a gate if something is shut by it. A trained-but-not-yet-
    # activated model has no scoring path at all -- not one whose output a caller is
    # trusted to discard.
    store, _, metadata = _trained(tmp_path)
    assert store.read_ml_model(metadata["id"])["active"] is False
    with pytest.raises(MLScoringError, match="not active"):
        MLScorer(store, metadata["id"])
    # The named exception still works, so evaluation remains possible.
    assert MLScorer(store, metadata["id"], allow_inactive=True).score(_normal_windows()[0])["available"] is True
    # Refused before any filesystem I/O: with the artifact gone, a check ordered
    # after `load_artifact` would report a missing or unverifiable artifact
    # instead. The activation refusal does not depend on the artifact being
    # readable, which is what makes it a cheap, unconditional first gate.
    Path(metadata["artifact_path"]).unlink()
    with pytest.raises(MLScoringError, match="not active"):
        MLScorer(store, metadata["id"])


def test_inactive_model_does_not_influence_the_fused_score(tmp_path):
    # The detector's own check, exercised through the one construction that can
    # reach it: `allow_inactive=True` yields a scorer whose payload reports
    # `model_active: False`. An inactive model must then read exactly as a missing
    # one -- not merely "close", but the same finding, including the provenance
    # hash that is the finding's identity.
    store, _, metadata = _trained(tmp_path)
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
    events = _normal_windows()[0]
    with_inactive = DetectionEngine(store, ml_scorer=scorer).detect([_risk()], events, persist=False)["findings"][0]
    without_ml = DetectionEngine(store).detect([_risk()], events, persist=False)["findings"][0]
    assert [item["signal"] for item in with_inactive["evidence"]] == ["behavior_anomaly", "rule_fusion", "process_context"]
    assert with_inactive["fusion_formula"] == "min(1, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)"
    assert with_inactive["risk_score"] == without_ml["risk_score"]
    assert with_inactive["provenance_hash"] == without_ml["provenance_hash"]


def test_explanation_reconstructs_the_score_without_ml(tmp_path):
    # Detector and explainer have to drop ML on the same condition or the
    # explainer's reconciliation raises. Pinned here because the two branch on
    # different things: the detector on `model_active`, the explainer on whether an
    # `ml_anomaly` evidence row is present.
    store, _, metadata = _trained(tmp_path)
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
    finding = DetectionEngine(store, ml_scorer=scorer).detect([_risk()], _normal_windows()[0])["findings"][0]
    explanation = FindingExplainer(store).explain_finding(finding)
    assert explanation["calculation"]["inputs"]["ml_score"] is None
    assert explanation["calculation"]["formula"] == "min(1, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)"
    assert not any(item["factor"] == "ml_anomaly_evidence" for item in explanation["contributing_factors"])


def test_deactivation_takes_effect_for_scorers_constructed_after_it(tmp_path):
    # A documented boundary, asserted rather than implied: `MLScorer.metadata` is a
    # construction-time snapshot, so deactivating a model does not reach into a
    # scorer that already exists. Enforcement is at construction. An operator
    # standing a model down stops it being loaded again; it does not interrupt a
    # detection run already holding it.
    store, _, metadata = _activated(tmp_path)
    scorer = MLScorer(store, metadata["id"])
    assert store.deactivate_ml_model(metadata["id"]) is True
    assert store.read_ml_model(metadata["id"])["active"] is False
    assert scorer.score(_normal_windows()[0])["model_active"] is True  # the snapshot, not the row
    with pytest.raises(MLScoringError, match="not active"):
        MLScorer(store, metadata["id"])


# --- calibration: contamination, the training distribution, and provenance ---


def test_contamination_default_is_below_the_gate_budget():
    """
    The trainer no longer aims the model at exactly the ceiling it has to clear.

    `contamination` is not a side knob: `IsolationForest.decision_function` is
    centred on the fitted contamination quantile and the trainer thresholds at 0.0,
    so a forest fitted at `contamination=c` declares it will flag about `c` of
    windows drawn from its own training distribution. The gate's budget is the same
    kind of number, which is the problem -- the old default of 0.05 was the gate's
    own ceiling, so the expected outcome of a training run was a refusal.

    Asserted here as arithmetic rather than as a literal, so the relationship is
    what is pinned and not the current value of either constant.
    """
    default = signature(train_isolation_forest).parameters["contamination"].default
    assert 0.0 < default < MAX_NORMAL_FPR
    # At the gate's minimum sample the Wilson bound permits zero failures: 0/60
    # bounds to 4.31% and 1/60 to 7.13%, so "clearing the gate" means 60
    # independent draws all landing on the quiet side, with probability (1-c)**60.
    assert normal_fpr_acceptance(0, MIN_NORMAL_HOLDOUT_WINDOWS)["activation_eligible"] is True
    assert normal_fpr_acceptance(1, MIN_NORMAL_HOLDOUT_WINDOWS)["activation_eligible"] is False
    at_the_ceiling = (1.0 - MAX_NORMAL_FPR) ** MIN_NORMAL_HOLDOUT_WINDOWS
    at_the_default = (1.0 - default) ** MIN_NORMAL_HOLDOUT_WINDOWS
    assert at_the_ceiling < 0.05  # ~4.6%: the old default was a refusal by design
    assert at_the_default > 0.5  # ~55%: a genuinely quiet model now has a chance
    # The gate itself has not moved -- only what the trainer aims at.
    assert MAX_NORMAL_FPR == 0.05 and MIN_NORMAL_HOLDOUT_WINDOWS == 60


def test_artifact_records_training_decision_percentiles(tmp_path):
    """
    The training score distribution is recorded, not just its two extremes.

    `decision_min`/`decision_max` alone could not show where the threshold sits
    inside the training scores, which is exactly why the coupling between
    `contamination` and the threshold was invisible to a reader of the artifact.
    """
    store, _, metadata = _trained(tmp_path)
    descriptor = load_artifact(metadata["artifact_path"], metadata["artifact_checksum"])["descriptor"]
    percentiles = descriptor["training_decision_percentiles"]
    # Set equality, not sequence equality: `_canonical_json` serialises with
    # sort_keys=True, so the on-disk order is alphabetical (p1, p25, p5, ...). The
    # level order is reconstructed below rather than assumed.
    assert set(percentiles) == {f"p{level}" for level in TRAINING_DECISION_PERCENTILE_LEVELS}
    ordered = [percentiles[f"p{level}"] for level in TRAINING_DECISION_PERCENTILE_LEVELS]
    assert all(math.isfinite(value) for value in ordered)
    assert ordered == sorted(ordered)
    assert descriptor["decision_min"] <= ordered[0] and ordered[-1] <= descriptor["decision_max"]

    # And the thing it was added to make legible: the threshold is not an
    # independent boundary, it *is* the contamination quantile of the training
    # scores. sklearn sets `offset_` to that percentile and subtracts it, so the
    # matching percentile of the recorded distribution lands on the threshold.
    contamination = metadata["hyperparameters"]["contamination"]
    level = f"p{contamination * 100:g}"
    assert level in percentiles, f"{level} is not a recorded level; the coupling check needs one that is"
    assert descriptor["threshold"] == 0.0
    assert abs(percentiles[level] - descriptor["threshold"]) < 1e-12
    assert percentiles["p1"] <= descriptor["threshold"] <= percentiles["p50"]

    # Diagnostic only. The loader treats it as optional on read precisely so
    # artifacts written before it existed still verify, and the scorer never reads
    # it -- a model's decisions must not depend on a descriptive field.
    scored = MLScorer(store, metadata["id"], allow_inactive=True).score(_normal_windows()[0])
    assert "training_decision_percentiles" not in scored


# A richer corpus than `_training_windows`, for the one thing that needs it.
# `_training_windows` varies only a uniform timestamp offset and a uniform pid
# delta, and no feature reads absolute time or an absolute pid -- so its ten
# windows collapse to three distinct feature vectors, and quantile calibration
# against the resulting score distribution is degenerate (measured: seven distinct
# scores across twenty windows, eleven of them tied at the minimum, so every
# budget overruns and the selection rule always falls through to flagging
# nothing). What does move the vector is *within-window* structure: the spacing
# between adjacent events, and the number of distinct executables, destination
# IPs, ports and pids inside a single window. This varies those.


def _varied_windows(count, offset=0):
    windows = []
    for raw in range(count):
        index = raw + offset
        events = [_event(100.0, executable=f"/usr/bin/tool{index % 3}")]
        for step in range(index % 5 + 1):
            events.append(_event(101.0 + step * (1.0 + index % 7 * 0.5), "tcp_connect",
                                 dest_ip=f"10.0.0.{step % 3}", dest_port=9000 + step % 4, pid=11 + step))
        if index % 2:
            events.append(_event(99.0 + index % 3, "ipc_event", action="pipe_created", kind="anonymous_pipe",
                                 success=True, read_fd=3, write_fd=4, pid=30 + index % 4))
        windows.append(events)
    return windows


_CALIBRATION_TRAINING_WINDOWS = 40
_CALIBRATION_HOLDOUT_WINDOWS = 20


def _calibration_corpus(tmp_path):
    """
    A model trained on varied windows, plus a disjoint holdout to calibrate on.

    The holdout is a second `role: holdout` dataset drawn from the same generator
    at a disjoint offset, so it is genuinely unseen by the forest. Twenty windows,
    not the gate's sixty: this exercises the calibration arithmetic, and a holdout
    that cleared the gate's floor is not something a unit test can fabricate --
    see the note on supplied counts in `_activated`.
    """
    if not SKLEARN_AVAILABLE:
        pytest.skip("scikit-learn is not installed in the active Python environment")
    store = SQLiteEventStore(str(tmp_path / "calibration.db"))
    verification = {"verified_normal": True, "operator": "test", "method": "controlled normal workload"}
    training_id = create_verified_normal_dataset(store, "calibration-training", verification)
    for index, events in enumerate(_varied_windows(_CALIBRATION_TRAINING_WINDOWS)):
        add_verified_normal_window(store, training_id, events, [index * 10 + offset for offset in range(len(events))], verification)
    metadata = train_isolation_forest(store, training_id, str(tmp_path / "models"))
    holdout_id = create_verified_normal_dataset(store, "calibration-holdout", verification, {"role": "holdout"})
    for index, events in enumerate(_varied_windows(_CALIBRATION_HOLDOUT_WINDOWS, offset=_CALIBRATION_TRAINING_WINDOWS)):
        add_verified_normal_window(store, holdout_id, events, [100_000 + index * 10 + offset for offset in range(len(events))], verification)
    return store, metadata, store.read_ml_training_windows(holdout_id)


def test_calibrated_threshold_hits_the_target_fpr_on_its_own_holdout(tmp_path):
    """
    The calibrated threshold realises the target rate exactly, and is maximal.

    `is_anomaly` is `raw_score <= threshold`, so the flagged set grows with the
    threshold; the rule takes the largest observed score whose flagged count still
    fits `floor(target_fpr * n)`. Choosing an observed score rather than
    interpolating is what makes the realised rate a count over n, so it cannot
    round past the target.
    """
    store, metadata, holdout = _calibration_corpus(tmp_path)
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
    target = 0.1
    calibration = calibrate_threshold(scorer, holdout, target_fpr=target)
    scores = sorted(
        float(item["raw_score"])
        for item in evaluate_threshold_from_windows(scorer, holdout)["normal_window_scores"]
    )
    budget = math.floor(target * len(scores))

    # Guard on the fixture, not on the code: with a heavily tied distribution every
    # budget overruns, the rule falls through to flagging nothing, and the
    # assertions below would hold vacuously. Measured here: 19 distinct of 20.
    assert len(set(scores)) >= len(scores) - 1 and budget >= 1
    assert calibration["normal_window_count"] == len(holdout) == len(scores)
    assert calibration["normal_window_ids"] == [window["id"] for window in holdout]
    assert calibration["false_positive_count"] == budget
    assert calibration["quantile"] == budget / len(scores) == target
    assert calibration["in_sample"] is True

    # Maximal: the next observed score up would overrun the budget. Unconditional
    # -- with n > budget there is always a score above the chosen threshold, since
    # either it is not the maximum or the fallback put it below the minimum.
    higher = [value for value in scores if value > calibration["threshold"]]
    assert higher
    assert sum(1 for value in scores if value <= min(higher)) > budget

    # Re-measured through a model that actually carries the threshold, which is the
    # only way to know the number survives the artifact round trip. Exact, not
    # approximate: JSON float repr round-trips, and the derived forest's arrays are
    # the parent's arrays read back off the verified artifact.
    derived = rethreshold_model(store, metadata["id"], str(tmp_path / "models"), calibration=calibration)
    remeasured = evaluate_threshold_from_windows(MLScorer(store, derived["id"], allow_inactive=True), holdout)
    assert remeasured["normal_false_positive_count"] == calibration["false_positive_count"]
    assert remeasured["normal_false_positive_rate"] == calibration["quantile"]

    # Which is the trap, stated as an assertion: measured on the set it was fitted
    # to, the derived model sits inside the budget *by construction*. That is
    # arithmetic restating the target, not evidence, and it is why calibrating
    # records no `evaluated` row and no gate verdict.
    assert remeasured["normal_false_positive_rate"] <= target
    assert store.read_ml_lifecycle(derived["id"]) == []


def test_calibration_writes_a_new_artifact_and_leaves_the_original_intact(tmp_path):
    """
    Rethresholding mints a second model; it never edits the first.

    Artifacts are checksum-pinned in both directions -- the row pins the
    descriptor, the descriptor pins the arrays -- so "move the threshold" cannot
    mean rewriting a file in place without breaking the chain that makes a loaded
    model trustworthy.
    """
    store, metadata, holdout = _calibration_corpus(tmp_path)
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
    calibration = calibrate_threshold(scorer, holdout, target_fpr=0.1)
    before = Path(metadata["artifact_path"]).read_bytes()
    derived = rethreshold_model(store, metadata["id"], str(tmp_path / "models"), calibration=calibration)

    assert derived["id"] != metadata["id"] and derived["artifact_path"] != metadata["artifact_path"]
    # Inactive, like every row this module writes: recalibrating is not evaluating,
    # and `activate_ml_model` remains the only door to `active = 1`.
    assert derived["active"] is False and store.read_ml_model(derived["id"])["active"] is False
    assert [model for model in store.read_ml_models() if model["active"]] == []

    # The parent is untouched, bytes and all, and still verifies against the
    # checksum recorded in its row.
    assert Path(metadata["artifact_path"]).read_bytes() == before
    parent_row = store.read_ml_model(metadata["id"])
    parent = load_artifact(metadata["artifact_path"], parent_row["artifact_checksum"])
    assert parent["descriptor"]["threshold"] == 0.0
    assert parent["descriptor"]["threshold_provenance"] == UNCALIBRATED_THRESHOLD_PROVENANCE
    assert parent["descriptor"]["calibration"]["status"] == "requires_independent_verified_normal_holdouts"

    # The child verifies on its own recorded checksum, carries the new threshold,
    # and shares the parent's forest and training distribution -- same scores,
    # because neither the fitted forest nor the training data moved.
    child_row = store.read_ml_model(derived["id"])
    child = load_artifact(derived["artifact_path"], child_row["artifact_checksum"])
    assert child["descriptor"]["threshold"] == calibration["threshold"] != 0.0
    assert child["descriptor"]["forest"] == parent["descriptor"]["forest"]
    assert child["descriptor"]["trees"] == parent["descriptor"]["trees"]
    assert child["descriptor"]["decision_min"] == parent["descriptor"]["decision_min"]
    assert child["descriptor"]["decision_max"] == parent["descriptor"]["decision_max"]
    assert child["descriptor"]["training_decision_percentiles"] == parent["descriptor"]["training_decision_percentiles"]
    assert child_row["training_window_ids"] == parent_row["training_window_ids"]
    assert child_row["schema_hash"] == parent_row["schema_hash"] == schema_hash()
    # Not `arrays_checksum`: `np.savez` embeds zip member timestamps, so two writes
    # of identical arrays do not produce identical bytes. The arrays are compared
    # through the descriptor's shape commitment and the scores below instead.
    assert derived["artifact_checksum"] != parent_row["artifact_checksum"]

    # Same forest, different boundary: the raw score of a window is unchanged and
    # only the verdict can differ.
    features = holdout[0]["features"]
    parent_score = MLScorer(store, metadata["id"], allow_inactive=True).score_features(features)
    child_score = MLScorer(store, derived["id"], allow_inactive=True).score_features(features)
    assert child_score["raw_score"] == parent_score["raw_score"]
    assert child_score["threshold"] == calibration["threshold"]
    assert child_score["is_anomaly"] == (child_score["raw_score"] <= calibration["threshold"])


def test_threshold_provenance_names_the_calibration_source(tmp_path):
    """
    A threshold is only trustworthy if the artifact says where it came from.

    A trained model claims nothing -- its boundary is wherever `contamination` put
    it. A calibrated one names the method, the sample size, the target, the
    realised quantile, and the in-sample caveat, so a later reader can tell it from
    an arbitrary number without consulting anything else.
    """
    store, metadata, holdout = _calibration_corpus(tmp_path)
    trained = load_artifact(metadata["artifact_path"], metadata["artifact_checksum"])["descriptor"]
    assert trained["threshold_provenance"] == UNCALIBRATED_THRESHOLD_PROVENANCE
    assert "not independently calibrated" in trained["threshold_provenance"]

    scorer = MLScorer(store, metadata["id"], allow_inactive=True)
    calibration = calibrate_threshold(scorer, holdout, target_fpr=0.1)
    derived = rethreshold_model(store, metadata["id"], str(tmp_path / "models"), calibration=calibration)
    descriptor = load_artifact(derived["artifact_path"], derived["artifact_checksum"])["descriptor"]
    provenance = descriptor["threshold_provenance"]
    assert provenance == calibration["threshold_provenance"]
    assert provenance.startswith("holdout_quantile(")
    assert f"n={calibration['normal_window_count']}" in provenance
    assert f"target_fpr={calibration['target_fpr']!r}" in provenance
    assert f"quantile={calibration['quantile']!r}" in provenance
    # The caveat travels with the number. Without it, the one-line summary of this
    # model reads exactly like an independently calibrated one.
    assert "in_sample" in provenance and "not independent evidence" in provenance

    # The calibration block makes the circularity checkable rather than merely
    # stated: it records which windows produced the threshold, so a reader can
    # compare them against the windows a gate run measured.
    block = descriptor["calibration"]
    assert block["method"] == "holdout_quantile" and block["in_sample"] is True
    assert block["derived_from"] == metadata["id"]
    assert block["normal_window_ids"] == [window["id"] for window in holdout]
    assert block["target_fpr"] == calibration["target_fpr"] and block["quantile"] == calibration["quantile"]
    assert store.read_ml_model(derived["id"])["evaluation"]["calibration_status"] == "holdout_quantile"
    assert store.read_ml_model(derived["id"])["evaluation"]["calibration_in_sample"] is True

    # And it reaches the score payload, which is where an operator or an API
    # consumer actually reads it -- not only the file on disk.
    assert scorer.score_features(holdout[0]["features"])["threshold_provenance"] == UNCALIBRATED_THRESHOLD_PROVENANCE
    child = MLScorer(store, derived["id"], allow_inactive=True)
    assert child.score_features(holdout[0]["features"])["threshold_provenance"] == provenance
