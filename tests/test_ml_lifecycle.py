"""
Tests for the model lifecycle log: what it records, what it refuses, and what it cannot reach.

The log's value rests on three properties, and each one gets tests here:

* **It records; it does not decide.** No sequence of appends activates anything.
  There is no store method that flips `ml_models.active` on an existing model, and
  a `drift_assessed` or `retraining_required` row may not carry an eligibility
  claim -- so drift cannot log its way to an activation. Asserted at the store
  boundary rather than only through `ml/lifecycle.py`, because the invariant has to
  hold for any writer.
* **The gate is the only door.** `activation_eligible` comes from a fresh
  `normal_fpr_acceptance` call on raw counts, never from a caller-supplied verdict.
  The gate's own constants and outputs are pinned as literals here: this track adds
  drift and a lifecycle log, and a test that fails when the 5% ceiling or the
  60-window floor moves is the mechanism that keeps "the gate is untouched" a
  checkable claim rather than an assurance.
* **The history is tamper-evident.** `ml_model_lifecycle` is hash-chained, and each
  `drift_assessed` row commits to a `content_hash` of the unchained assessment
  written with it, which `verify_ml_lifecycle_chain` recomputes. Editing a
  lifecycle row, editing or deleting an assessment, and editing only the
  per-feature detail are all exercised -- the last one because it is the tamper a
  verifier reading decoded rows would miss.

No scikit-learn needed: the gate takes counts, and the lifecycle takes metadata.
"""

import sqlite3

import pytest

from ml.evaluation import MAX_NORMAL_FPR, MIN_NORMAL_HOLDOUT_WINDOWS, normal_fpr_acceptance
from ml.feature_schema import SCHEMA_VERSION, schema_hash
from ml.lifecycle import (
    DRIFT_STATES,
    LIFECYCLE_PATH,
    current_state,
    eligible_model_ids,
    lifecycle_report,
    record_activation,
    record_activation_gate,
    record_drift_assessment,
    record_drifted,
    record_evaluated,
    record_retired,
    record_trained,
)
from storage.sqlite_store import SQLiteEventStore

# Counts that clear the gate: 60 holdout windows is the floor, and zero false
# positives puts the Wilson upper bound (4.31%) under the 5% ceiling. One false
# positive out of 60 does not -- the observed rate is 1.67% but the upper bound is
# 7.13%, which is the whole point of bounding rather than reading the point estimate.
PASSING_COUNTS = {"false_positive_count": 0, "normal_window_count": 60}
FAILING_COUNTS = {"false_positive_count": 1, "normal_window_count": 60}


def _store(tmp_path):
    return SQLiteEventStore(str(tmp_path / "lifecycle.db"))


def _metadata(model_id="model-1"):
    return {
        "id": model_id,
        "artifact_checksum": "a" * 64,
        "artifact_format": "iforest-native.v1",
        "schema_hash": schema_hash(),
        "schema_version": SCHEMA_VERSION,
        "training_window_ids": [1, 2, 3],
        "hyperparameters": {"n_estimators": 100, "random_state": 42},
    }


def _report(normal_windows=60, false_positives=0):
    return {
        "normal_window_count": normal_windows,
        "normal_false_positive_count": false_positives,
        "normal_false_positive_rate": false_positives / normal_windows,
        "labels_available": False,
        "confusion_matrix": None,
    }


def _assessment(status="drift_detected", model_id="model-1", **overrides):
    features = [
        {"feature": "event_count", "drifted": status == "drift_detected", "statistic": 1.0, "p_value": 1e-11},
        {"feature": "unique_pids", "drifted": False, "statistic": 0.1, "p_value": 0.9},
    ]
    assessment = {
        "model_id": model_id,
        "comparison_dataset_id": "verified-normal-week-2",
        "status": status,
        "method": "two_sample_ks_holm_bonferroni.v1",
        "alpha": 0.01,
        "reference_window_count": 12,
        "comparison_window_count": 40,
        "drifted_feature_count": 1 if status == "drift_detected" else 0,
        "out_of_range_rate": 0.029411764705882353,
        "features": features,
        "reasons": [],
        "created_at": 3000.0,
    }
    assessment.update(overrides)
    return assessment


# --- the gate ------------------------------------------------------------------

def test_activation_gate_criteria_are_unchanged():
    """
    The gate's constants and verdicts, pinned as literals.

    This track adds drift assessment and a lifecycle log. Neither may become a
    route around activation, so the criteria are asserted here as values rather
    than recomputed from the module -- a change to either constant fails this test
    instead of silently widening what qualifies.
    """
    assert MAX_NORMAL_FPR == 0.05
    assert MIN_NORMAL_HOLDOUT_WINDOWS == 60
    assert normal_fpr_acceptance(0, 60) == {
        "activation_eligible": True,
        "max_normal_fpr": 0.05,
        "minimum_normal_holdout_windows": 60,
        "normal_fpr_upper_95": 0.04314681732000257,
        "reasons": [],
    }
    # 59 windows: the observed rate is perfect and the bound would pass, and it is
    # still refused. The window floor is a floor, not a tiebreak.
    assert normal_fpr_acceptance(0, 59) == {
        "activation_eligible": False,
        "max_normal_fpr": 0.05,
        "minimum_normal_holdout_windows": 60,
        "normal_fpr_upper_95": 0.0438460546015603,
        "reasons": ["requires at least 60 independent verified-normal holdout windows"],
    }
    # 1 in 60 = 1.67% observed, which passes the point estimate and fails the
    # one-sided bound. The bound is what the gate decides on.
    assert normal_fpr_acceptance(1, 60) == {
        "activation_eligible": False,
        "max_normal_fpr": 0.05,
        "minimum_normal_holdout_windows": 60,
        "normal_fpr_upper_95": 0.07131489631575917,
        "reasons": ["one-sided 95% FPR upper bound must be at most 5.00%"],
    }
    # No observations at all: no bound is reported, and every criterion refuses.
    # A gate that returned "eligible" on an empty measurement would be the worst
    # available failure, so it is pinned rather than left to the window floor.
    assert normal_fpr_acceptance(0, 0) == {
        "activation_eligible": False,
        "max_normal_fpr": 0.05,
        "minimum_normal_holdout_windows": 60,
        "normal_fpr_upper_95": None,
        "reasons": [
            "requires at least 60 independent verified-normal holdout windows",
            "observed normal FPR must be at most 5.00%",
            "one-sided 95% FPR upper bound must be at most 5.00%",
        ],
    }


def test_gate_row_records_the_verdict_it_was_given_by_the_gate(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    row = record_activation_gate(store, "model-1", **PASSING_COUNTS)
    assert row["to_state"] == "eligible"
    assert row["activation_eligible"] is True
    assert row["reason"] == "activation gate satisfied"
    # The numbers behind the verdict travel with it, so the claim is auditable.
    assert row["evidence"]["acceptance"] == normal_fpr_acceptance(0, 60)
    assert row["evidence"]["false_positive_count"] == 0
    assert row["evidence"]["normal_window_count"] == 60


def test_an_ineligible_verdict_is_recorded_rather_than_raised(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report(false_positives=1))
    row = record_activation_gate(store, "model-1", **FAILING_COUNTS)
    assert row["to_state"] == "ineligible"
    assert row["activation_eligible"] is False
    assert "one-sided 95% FPR upper bound must be at most 5.00%" in row["reason"]
    # "measured and did not qualify" is the record that stops a quiet re-proposal.
    assert row["evidence"]["acceptance"]["activation_eligible"] is False
    assert eligible_model_ids(store) == []


def test_recording_an_activation_the_gate_refuses_raises(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    with pytest.raises(ValueError, match="activation gate not satisfied"):
        record_activation(store, "model-1", **FAILING_COUNTS)
    # And nothing was appended: a refused claim is not a fact worth recording.
    assert [row["to_state"] for row in store.read_ml_lifecycle()] == ["trained"]


def test_activation_row_carries_a_freshly_recomputed_verdict(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_activation_gate(store, "model-1", **PASSING_COUNTS)
    row = record_activation(store, "model-1", **PASSING_COUNTS)
    assert row["to_state"] == "active"
    assert row["activation_eligible"] is True
    assert row["evidence"]["acceptance"] == normal_fpr_acceptance(0, 60)
    # Recording is all it did: the model row's own flag is untouched, and there is
    # no store method that could have changed it.
    assert not hasattr(store, "activate_ml_model")
    assert not hasattr(store, "set_ml_model_active")


# --- what the log cannot reach -------------------------------------------------

def test_the_store_refuses_an_eligibility_claim_without_the_gate_verdict(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="must carry the activation gate verdict"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="trust me", activation_eligible=True
        )
    # A non-dict stand-in for the verdict is refused the same way.
    with pytest.raises(ValueError, match="must carry the activation gate verdict"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="trust me",
            evidence={"acceptance": True}, activation_eligible=True,
        )


def test_the_store_refuses_an_active_row_without_a_gate_verdict(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="an active ML lifecycle row requires the activation gate verdict"):
        store.write_ml_lifecycle_transition("model-1", "active", reason="activated by hand")


@pytest.mark.parametrize("state", DRIFT_STATES)
def test_drift_reachable_states_may_not_assert_eligibility(tmp_path, state):
    """
    The one-way property, enforced at the writer.

    A drift assessment can append exactly these two states. Neither may carry an
    eligibility verdict, and `active` requires one -- so there is no append a drift
    check can make, in any order, that ends in an activation.
    """
    store = _store(tmp_path)
    with pytest.raises(ValueError, match=f"{state} may not assert activation eligibility"):
        store.write_ml_lifecycle_transition(
            "model-1", state, reason="drift found",
            evidence={"acceptance": normal_fpr_acceptance(0, 60)}, activation_eligible=True,
        )
    assert "active" not in DRIFT_STATES
    assert "eligible" not in DRIFT_STATES


def test_unknown_states_and_empty_reasons_are_refused(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="unknown ML lifecycle state: 'promoted'"):
        store.write_ml_lifecycle_transition("model-1", "promoted", reason="why not")
    with pytest.raises(ValueError, match="unknown ML lifecycle state: 'promoted'"):
        store.write_ml_lifecycle_transition(
            "model-1", "retired", reason="ok", from_state="promoted"
        )
    with pytest.raises(ValueError, match="ML lifecycle transitions require a reason"):
        store.write_ml_lifecycle_transition("model-1", "retired", reason="")


# --- drift assessments in the log ----------------------------------------------

def test_recording_drift_appends_the_assessment_and_a_consequence_row(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    written = record_drift_assessment(store, _assessment(), actor="operator@host")
    assert [row["to_state"] for row in written["lifecycle"]] == ["drift_assessed", "retraining_required"]
    assessed, required = written["lifecycle"]
    assert assessed["activation_eligible"] is False
    assert required["activation_eligible"] is False
    assert assessed["evidence"]["drift_assessment_id"] == written["assessment"]["id"]
    assert assessed["evidence"]["status"] == "drift_detected"
    assert required["evidence"]["drifted_features"] == ["event_count"]
    # The consequence row states its own bounds: drift does not authorize reusing
    # the model's training data, and a retrained model starts inactive.
    assert len(required["evidence"]["limitations"]) == 2
    assert any("activation gate" in text for text in required["evidence"]["limitations"])
    assert store.verify_ml_lifecycle_chain()["ok"] is True


def test_a_clean_assessment_appends_no_consequence_row(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    written = record_drift_assessment(store, _assessment(status="no_drift_detected"))
    assert [row["to_state"] for row in written["lifecycle"]] == ["drift_assessed"]
    assert written["assessment"]["drifted_feature_count"] == 0


def test_a_refused_assessment_is_recorded_as_such(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    written = record_drift_assessment(
        store,
        _assessment(status="insufficient_data", out_of_range_rate=None,
                    reasons=["fewer than 30 comparison windows"], drifted_feature_count=0),
    )
    assert [row["to_state"] for row in written["lifecycle"]] == ["drift_assessed"]
    assert written["assessment"]["out_of_range_rate"] is None
    assert written["assessment"]["reasons"] == ["fewer than 30 comparison windows"]


def test_drift_assessments_require_their_core_fields(tmp_path):
    store = _store(tmp_path)
    incomplete = _assessment()
    del incomplete["alpha"]
    del incomplete["method"]
    with pytest.raises(ValueError, match="missing fields: method, alpha"):
        store.write_ml_drift_assessment(incomplete)
    with pytest.raises(ValueError, match="unknown ML drift status: 'probably_fine'"):
        store.write_ml_drift_assessment(_assessment(status="probably_fine"))
    assert store.read_ml_drift_assessments() == []
    assert store.read_ml_lifecycle() == []


def test_drift_assessed_rows_do_not_shadow_the_model_state(tmp_path):
    """A routine drift check must not read as a state change on the dashboard."""
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_activation_gate(store, "model-1", **PASSING_COUNTS)
    record_drift_assessment(store, _assessment(status="no_drift_detected"))
    assert current_state(store, "model-1")["to_state"] == "eligible"
    # `retraining_required` is a conclusion about the model, so it does surface.
    record_drift_assessment(store, _assessment())
    assert current_state(store, "model-1")["to_state"] == "retraining_required"


# --- history and tamper-evidence ------------------------------------------------

def test_lifecycle_report_is_the_history_plus_its_verification(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_activation_gate(store, "model-1", **PASSING_COUNTS)
    record_drift_assessment(store, _assessment())
    record_drifted(store, "model-1", reason="host workload changed", actor="operator@host")
    record_retired(store, "model-1", reason="superseded by model-2")
    report = lifecycle_report(store, "model-1")
    assert [row["to_state"] for row in report["transitions"]] == [
        "trained", "evaluated", "eligible", "drift_assessed", "retraining_required", "drifted", "retired",
    ]
    assert report["state"] == "retired"
    assert report["activation_eligible"] is False
    assert report["transition_count"] == 7
    assert len(report["drift_assessments"]) == 1
    assert report["chain"]["ok"] is True
    assert report["chain"]["checked"] == 7
    # Every state the report can show is one the module declares.
    assert set(row["to_state"] for row in report["transitions"]) <= set(LIFECYCLE_PATH) | set(DRIFT_STATES)


def test_no_history_reports_no_state(tmp_path):
    store = _store(tmp_path)
    assert current_state(store, "model-1") is None
    report = lifecycle_report(store, "model-1")
    assert report["state"] is None
    assert report["activation_eligible"] is False
    assert report["transitions"] == []
    # The honest answer on a default install, and the expected one.
    assert eligible_model_ids(store) == []


def test_editing_a_lifecycle_row_breaks_the_chain(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_activation_gate(store, "model-1", **FAILING_COUNTS)
    assert store.verify_ml_lifecycle_chain()["ok"] is True
    connection = sqlite3.connect(store.db_path)
    try:
        # The tamper an unfaithful record would want: turn a refusal into a pass.
        connection.execute(
            "UPDATE ml_model_lifecycle SET to_state = 'eligible', activation_eligible = 1 "
            "WHERE to_state = 'ineligible'"
        )
        connection.commit()
    finally:
        connection.close()
    verification = store.verify_ml_lifecycle_chain()
    assert verification["ok"] is False
    assert verification["break_seq"] == 2
    assert verification["reason"] == "hash mismatch at seq 2 (row mutated, reordered, or removed)"


def test_editing_a_drift_assessment_fails_verification(tmp_path):
    """
    The binding that gives an unchained table tamper-evidence.

    `ml_drift_assessments` carries no chain of its own; the `drift_assessed` row
    written in the same transaction stores a `content_hash` of its core columns,
    and `verify_ml_lifecycle_chain` recomputes it. Both halves matter: the edit
    leaves every lifecycle hash valid, since it happens outside the chained
    columns, so the recomputation is the entire detection.
    """
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_drift_assessment(store, _assessment())
    assert store.verify_ml_lifecycle_chain()["ok"] is True
    connection = sqlite3.connect(store.db_path)
    try:
        # The tamper that matters: rewrite a "drift found" assessment as clean.
        connection.execute(
            "UPDATE ml_drift_assessments SET status = 'no_drift_detected', drifted_feature_count = 0"
        )
        connection.commit()
    finally:
        connection.close()
    verification = store.verify_ml_lifecycle_chain()
    assert verification["ok"] is False
    assert verification["reason"] == "drift assessment 1 does not match the hash chained at seq 1"
    # The chained row still says what was measured, which is what makes the
    # disagreement legible rather than just a failed hash.
    assessed = next(row for row in store.read_ml_lifecycle() if row["to_state"] == "drift_assessed")
    assert assessed["evidence"]["status"] == "drift_detected"
    assert store.read_ml_drift_assessments()[0]["status"] == "no_drift_detected"


def test_editing_the_per_feature_detail_fails_verification(tmp_path):
    """
    The hash covers the stored JSON text, not the decoded lists.

    Which is the reason verification reads raw rows: recomputing from
    `read_ml_drift_assessments` would hash `features` where the writer hashed
    `features_json`, and a rewritten feature table -- the edit that changes which
    feature drifted while leaving the summary counts alone -- would pass.
    """
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_drift_assessment(store, _assessment())
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("UPDATE ml_drift_assessments SET features_json = '[]'")
        connection.commit()
    finally:
        connection.close()
    assert store.verify_ml_lifecycle_chain()["ok"] is False


def test_deleting_a_drift_assessment_fails_verification(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_drift_assessment(store, _assessment())
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("DELETE FROM ml_drift_assessments")
        connection.commit()
    finally:
        connection.close()
    verification = store.verify_ml_lifecycle_chain()
    assert verification["ok"] is False
    assert verification["reason"] == "drift assessment 1 is missing (chained row 1)"


def test_a_broken_link_is_reported_ahead_of_its_bindings(tmp_path):
    """
    Once the sequence is untrustworthy, so is the set of commitments read from it,
    so the chain break is the finding -- not a binding derived from tampered rows.
    """
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_drift_assessment(store, _assessment())
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("UPDATE ml_model_lifecycle SET reason = 'nothing happened' WHERE chain_seq = 1")
        connection.execute("UPDATE ml_drift_assessments SET status = 'no_drift_detected'")
        connection.commit()
    finally:
        connection.close()
    verification = store.verify_ml_lifecycle_chain()
    assert verification["ok"] is False
    assert verification["reason"] == "hash mismatch at seq 1 (row mutated, reordered, or removed)"


def test_deleting_a_lifecycle_row_breaks_the_chain(tmp_path):
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_retired(store, "model-1", reason="superseded")
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("DELETE FROM ml_model_lifecycle WHERE to_state = 'evaluated'")
        connection.commit()
    finally:
        connection.close()
    verification = store.verify_ml_lifecycle_chain()
    assert verification["ok"] is False
    # Detected by the sequence gap rather than a hash mismatch: a deletion leaves
    # the surviving rows individually valid, which is why contiguity is checked too.
    assert verification["break_seq"] == 2
    assert verification["reason"] == "non-contiguous chain_seq at position 1: found 2"


def test_the_actor_is_recorded_as_a_claim_and_chained(tmp_path):
    """
    `actor` is self-reported -- the store cannot authenticate a local operator --
    but it is inside the chained columns, so it cannot be revised afterwards.
    """
    store = _store(tmp_path)
    row = record_trained(store, _metadata(), actor="operator@host")
    assert row["actor"] == "operator@host"
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("UPDATE ml_model_lifecycle SET actor = 'someone else'")
        connection.commit()
    finally:
        connection.close()
    assert store.verify_ml_lifecycle_chain()["ok"] is False
