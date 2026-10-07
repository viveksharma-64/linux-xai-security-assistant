"""
Tests for the model lifecycle log: what it records, what it refuses, and what it cannot reach.

The log's value rests on three properties, and each one gets tests here:

* **One door to `active`, with the gate across it.** `activate_ml_model` is the
  only writer of `ml_models.active = 1`, and it refuses unless the gate grants
  eligibility over raw counts *and* the model's own latest recorded state is
  already `eligible` -- so a retired model cannot be re-activated by re-asserting
  its old numbers. No sequence of plain appends activates anything: a
  `drift_assessed` or `retraining_required` row may not carry an eligibility claim
  at all, so drift cannot log its way to an activation. The one-directional
  exception is tested too -- appending `retired` or `drifted` *does* stand a model
  down, because a retirement that left a model scoring is the worse failure.
  Asserted at the store boundary rather than only through `ml/lifecycle.py`,
  because the invariant has to hold for any writer.

  This reverses an earlier rule that no store method could set `active` at all.
  That rule was absence-as-guarantee, and it made the gate unreachable: `active`
  could then only be set at INSERT, before any evaluation could have happened.
  What is asserted now is enforcement, not absence -- so `set_ml_model_active`,
  an *unguarded* setter, must still not exist. The INSERT route is asserted shut
  from the other side as well, so that enforcement is one door and not two:
  `train_isolation_forest` has no `activate` parameter, and `write_ml_model`
  refuses an active row outright -- including one carrying otherwise-valid gate
  evidence, because at INSERT the model cannot have the recorded `eligible` state
  that `activate_ml_model` requires.
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

import json
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


def _model_fields(model_id="model-1", **overrides):
    """
    The minimum `write_ml_model` accepts, with overrides for the refusal tests.

    Only the required columns -- nothing built here is ever scored, so
    `artifact_path` does not have to exist.
    """
    return {
        "id": model_id,
        "version": "1",
        "algorithm": "isolation_forest",
        "hyperparameters": {"n_estimators": 100, "random_state": 42},
        "artifact_path": f"/nonexistent/{model_id}.npz",
        "artifact_checksum": "a" * 64,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema_hash(),
        "training_window_ids": [1, 2, 3],
        "runtime": {},
        "evaluation": {},
        "active": False,
        "created_at": 1000.0,
    } | overrides


def _model_row(store, model_id="model-1"):
    """
    Put a model on the `ml_models` table, which activating one now requires.

    `activate_ml_model` refuses a model that has no row: appending an `active` row
    for a model that was never written is exactly the unfounded claim the rest of
    this layer refuses. There is no `active=` parameter here because there is no
    longer one on `write_ml_model` worth exercising -- an active row is refused,
    which `test_write_ml_model_refuses_an_active_row_without_gate_evidence`
    asserts directly.
    """
    store.write_ml_model(_model_fields(model_id))
    return model_id


def _gated(store, model_id="model-1"):
    """Walk a model to `eligible`: the state activation is allowed to follow."""
    _model_row(store, model_id)
    record_trained(store, _metadata(model_id))
    record_evaluated(store, model_id, _report())
    record_activation_gate(store, model_id, **PASSING_COUNTS)
    return model_id


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
    _model_row(store)
    record_trained(store, _metadata())
    with pytest.raises(ValueError, match="activation gate not satisfied"):
        record_activation(store, "model-1", **FAILING_COUNTS)
    # And nothing was appended: a refused claim is not a fact worth recording.
    assert [row["to_state"] for row in store.read_ml_lifecycle()] == ["trained"]
    assert store.read_ml_model("model-1")["active"] is False


def test_activation_row_carries_a_freshly_recomputed_verdict(tmp_path):
    store = _store(tmp_path)
    _gated(store)
    row = record_activation(store, "model-1", **PASSING_COUNTS)
    assert row["to_state"] == "active"
    assert row["activation_eligible"] is True
    assert row["evidence"]["acceptance"] == normal_fpr_acceptance(0, 60)
    # The flag and the row saying why are one transaction, so a model is never
    # active without its justification and never carries the row without the flag.
    assert store.read_ml_model("model-1")["active"] is True
    assert store.verify_ml_lifecycle_chain()["ok"] is True
    # Enforcement, not absence: there *is* a door, and it is the gated one. An
    # unguarded setter still must not exist -- that is the part that never changed.
    assert hasattr(store, "activate_ml_model")
    assert not hasattr(store, "set_ml_model_active")


# --- the one door to `active` ---------------------------------------------------

def test_activation_refuses_a_model_that_was_never_written(tmp_path):
    """
    An activation claim about a model with no row is not worth recording.

    The gate passes here -- the counts are the passing ones -- so this isolates the
    second condition: eligibility is about a model, and a model the store has never
    heard of cannot be the subject of one.
    """
    store = _store(tmp_path)
    record_trained(store, _metadata())
    record_evaluated(store, "model-1", _report())
    record_activation_gate(store, "model-1", **PASSING_COUNTS)
    with pytest.raises(ValueError, match="no such ML model: 'model-1'"):
        record_activation(store, "model-1", **PASSING_COUNTS)
    assert [row["to_state"] for row in store.read_ml_lifecycle()] == [
        "trained", "evaluated", "eligible",
    ]


@pytest.mark.parametrize("reached", ["trained", "evaluated", "ineligible"])
def test_activation_requires_a_recorded_eligible_state(tmp_path, reached):
    """
    The log is a precondition of acting, not a commentary on it.

    Passing counts are not enough on their own: the model's own history has to
    record that it was measured and passed. Without this, the gate's verdict could
    be asserted for a model whose log never shows the measurement -- which would
    make the whole lifecycle table decorative.
    """
    store = _store(tmp_path)
    _model_row(store)
    record_trained(store, _metadata())
    if reached != "trained":
        record_evaluated(store, "model-1", _report())
    if reached == "ineligible":
        record_activation_gate(store, "model-1", **FAILING_COUNTS)
    with pytest.raises(ValueError, match=f"latest lifecycle state must be 'eligible', not '{reached}'"):
        record_activation(store, "model-1", **PASSING_COUNTS)
    assert store.read_ml_model("model-1")["active"] is False
    assert "active" not in [row["to_state"] for row in store.read_ml_lifecycle()]


def test_a_retired_model_cannot_be_reactivated_by_reasserting_its_counts(tmp_path):
    """
    The counts that once passed do not stay spendable.

    This is what the recorded-state condition buys that re-running the gate alone
    does not: the numbers are still true, the gate still grants eligibility over
    them, and activation is still refused -- because the model's latest recorded
    state says it is out of service. A returning model goes through the gate again.
    """
    store = _store(tmp_path)
    _gated(store)
    record_activation(store, "model-1", **PASSING_COUNTS)
    record_retired(store, "model-1", reason="superseded by model-2")
    assert normal_fpr_acceptance(0, 60)["activation_eligible"] is True
    with pytest.raises(ValueError, match="latest lifecycle state must be 'eligible', not 'retired'"):
        record_activation(store, "model-1", **PASSING_COUNTS)
    assert store.read_ml_model("model-1")["active"] is False


def test_a_routine_drift_check_does_not_block_activation(tmp_path):
    """
    `drift_assessed` is an observation about a model, not a stage it entered.

    Same rule `current_state` applies, re-expressed as SQL inside the activation
    transaction. A clean drift check appending only `drift_assessed` must not strand
    an eligible model -- otherwise looking at a model would change what may be done
    with it.
    """
    store = _store(tmp_path)
    _gated(store)
    record_drift_assessment(store, _assessment(status="no_drift_detected"))
    row = record_activation(store, "model-1", **PASSING_COUNTS)
    assert row["to_state"] == "active"
    assert row["from_state"] == "eligible"
    assert store.read_ml_model("model-1")["active"] is True
    # A drift check that *concluded* something does surface, and does block.
    record_drift_assessment(store, _assessment())
    assert current_state(store, "model-1")["to_state"] == "retraining_required"


def test_activating_one_model_stands_the_previous_one_down(tmp_path):
    """At most one model is active, and the handover is a single transaction."""
    store = _store(tmp_path)
    _gated(store, "model-1")
    record_activation(store, "model-1", **PASSING_COUNTS)
    _gated(store, "model-2")
    record_activation(store, "model-2", **PASSING_COUNTS)
    assert store.read_ml_model("model-1")["active"] is False
    assert store.read_ml_model("model-2")["active"] is True
    assert [model["id"] for model in store.read_ml_models() if model["active"]] == ["model-2"]
    # The stand-down is a flag change, not a lifecycle claim: model-1's history
    # still ends at `active`, because nothing has been recorded about it since.
    assert current_state(store, "model-1")["to_state"] == "active"
    assert store.verify_ml_lifecycle_chain()["ok"] is True


@pytest.mark.parametrize("evaluation", [
    # No evidence at all: the shape every existing caller writes.
    {},
    # A verdict that reads `False` -- claiming active while the gate said no.
    {"acceptance": normal_fpr_acceptance(1, 60), "false_positive_count": 1,
     "normal_window_count": 60, "activation_eligible": False},
    # Counts that do not reproduce the verdict sitting beside them: an eligible
    # acceptance dict pasted next to the numbers that would have failed.
    {"acceptance": normal_fpr_acceptance(0, 60), "false_positive_count": 1,
     "normal_window_count": 60, "activation_eligible": True},
    # Fully valid, internally consistent, gate-granted evidence. Refused anyway,
    # and this is the case that makes the rule a refusal rather than a gate.
    {"acceptance": normal_fpr_acceptance(0, 60), "false_positive_count": 0,
     "normal_window_count": 60, "activation_eligible": True},
], ids=["no-evidence", "verdict-says-no", "counts-contradict-verdict", "valid-evidence"])
def test_write_ml_model_refuses_an_active_row_without_gate_evidence(tmp_path, evaluation):
    """
    An INSERT cannot activate, on any evidence -- including evidence that is good.

    The fourth case is the point of the test. Gating this door on the gate verdict
    would have left two doors to `active = 1` with different locks: a new row has
    no lifecycle history, so it can never satisfy `activate_ml_model`'s third
    condition that the model's latest recorded state already be `eligible`. A
    gated INSERT would therefore mint an active model with an empty history --
    precisely the state the lifecycle log exists to make impossible. So the answer
    here is no, and the evidence is not consulted.
    """
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="refusing to insert an active ML model"):
        store.write_ml_model(_model_fields(active=True, evaluation=evaluation))
    # And the refusal is before the write: no half-made row, active or otherwise.
    assert store.read_ml_model("model-1") is None
    assert store.read_ml_models() == []


def test_activation_is_atomic(tmp_path, monkeypatch):
    """
    The flag and its justifying row land together or not at all.

    Failure is injected between the two: the `UPDATE`s have run, the lifecycle
    append has not. Both halves must roll back -- including the stand-down of the
    model that was already active, which is the half that would otherwise leave
    the system with *no* active model and no record of why.
    """
    store = _store(tmp_path)
    _gated(store, "model-1")
    record_activation(store, "model-1", **PASSING_COUNTS)
    _gated(store, "model-2")

    def _fail(*args, **kwargs):
        raise RuntimeError("injected failure after the flag, before the row")

    monkeypatch.setattr(store, "_insert_ml_lifecycle", _fail)
    with pytest.raises(RuntimeError, match="injected failure"):
        record_activation(store, "model-2", **PASSING_COUNTS)

    assert store.read_ml_model("model-2")["active"] is False
    assert store.read_ml_model("model-1")["active"] is True
    assert current_state(store, "model-2")["to_state"] == "eligible"
    assert store.verify_ml_lifecycle_chain()["ok"] is True
    # The lock was released, not left held by the failed attempt: a later
    # activation still works.
    monkeypatch.undo()
    assert record_activation(store, "model-2", **PASSING_COUNTS)["to_state"] == "active"
    assert store.read_ml_model("model-1")["active"] is False


# --- standing a model down ------------------------------------------------------

@pytest.mark.parametrize("record", [record_retired, record_drifted])
def test_logging_a_model_out_of_service_stands_it_down(tmp_path, record):
    """
    The one-directional exception: these two appends do have an effect.

    No append can make a model active, but an append saying a model is out of
    service clears `ml_models.active` in the same transaction as the row. Atomic
    on purpose -- there is no way to log a retirement and leave the model scoring,
    and no caller that can forget to.
    """
    store = _store(tmp_path)
    _gated(store)
    record_activation(store, "model-1", **PASSING_COUNTS)
    assert store.read_ml_model("model-1")["active"] is True
    record(store, "model-1", reason="host workload changed", actor="operator@host")
    assert store.read_ml_model("model-1")["active"] is False
    assert store.verify_ml_lifecycle_chain()["ok"] is True


def test_deactivation_is_idempotent_and_cannot_activate(tmp_path):
    """
    The deliberate asymmetry: activation is gated, deactivation is not.

    Standing a model down can only ever remove ML influence from a fused score, so
    the safe failure mode is for it to be easy -- an operator who suspects a model
    should not have to satisfy a precondition to silence it. Hence ungated,
    idempotent, and silent about ids it has never seen, so it is safe to call
    against an uncertain state. The return value is the only thing that
    distinguishes the cases.
    """
    store = _store(tmp_path)
    _gated(store)
    record_activation(store, "model-1", **PASSING_COUNTS)
    assert store.deactivate_ml_model("model-1") is True
    assert store.read_ml_model("model-1")["active"] is False
    # Again, and against a model that does not exist: no raise, no change.
    assert store.deactivate_ml_model("model-1") is False
    assert store.deactivate_ml_model("model-does-not-exist") is False
    assert store.read_ml_model("model-1")["active"] is False
    # And it appends nothing -- the flag is the whole effect.
    assert [row["to_state"] for row in store.read_ml_lifecycle()] == [
        "trained", "evaluated", "eligible", "active",
    ]
    # Re-activating after a bare deactivation is refused: the latest recorded state
    # is `active`, not `eligible`. Silencing a model is cheap; un-silencing it is
    # not, and goes back through the gate.
    with pytest.raises(ValueError, match="latest lifecycle state must be 'eligible', not 'active'"):
        record_activation(store, "model-1", **PASSING_COUNTS)



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


def test_the_store_refuses_a_verdict_that_itself_says_ineligible(tmp_path):
    """
    A row may not claim an eligibility its own attached verdict refused.

    This is the shape-versus-content gap. A check that asked only for *a dict*
    under `acceptance` accepts an empty one, and accepts the real gate output for
    counts that failed -- so `activation_eligible=True` on the row could sit beside
    a verdict reading `activation_eligible: False`, and the log would record a
    gated activation the gate had refused. Attaching the verdict is only worth
    anything if a reader can check the claim against it, so the writer is not
    allowed to contradict it.
    """
    store = _store(tmp_path)
    # Genuine gate output for counts that fail -- not a fabrication, which is what
    # makes it the sharp case: the evidence is real, the claim about it is not.
    refused = normal_fpr_acceptance(1, 60)
    assert refused["activation_eligible"] is False
    with pytest.raises(ValueError, match="may not carry a verdict that refused it"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="the gate said no; recording a yes",
            evidence={"acceptance": refused, **FAILING_COUNTS},
            activation_eligible=True,
        )
    # The empty dict is the other thing a shape check waved through.
    with pytest.raises(ValueError, match="may not carry a verdict that refused it"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="the shape of a verdict, with no verdict in it",
            evidence={"acceptance": {}, **PASSING_COUNTS},
            activation_eligible=True,
        )
    # `is True`, not truthiness: the gate returns a bool, so a stand-in that merely
    # evaluates true is a different claim and is refused as one.
    with pytest.raises(ValueError, match="may not carry a verdict that refused it"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="truthy is not True",
            evidence={"acceptance": {"activation_eligible": 1}, **PASSING_COUNTS},
            activation_eligible=True,
        )
    assert store.read_ml_lifecycle() == []


def test_the_store_recomputes_the_gate_over_the_recorded_counts(tmp_path):
    """
    The verdict is checked against its own numbers rather than taken on trust.

    Requiring the verdict to *say* eligible is still only a statement; it becomes
    evidence when the writer can re-derive it. `write_ml_lifecycle_transition` re-runs
    `normal_fpr_acceptance` over the counts recorded beside the verdict and requires
    an exact match, which is what makes the docstring's promise -- that an
    eligibility claim always carries the numbers behind it -- a fact rather than a
    convention a writer may ignore.

    Deliberately not a second gate: whatever `normal_fpr_acceptance` returns for
    those counts is what passes here. A reimplemented Wilson bound living in the
    storage layer would drift from the one the ML layer gates on, and a check that
    disagrees with the gate it enforces is worse than none.
    """
    store = _store(tmp_path)

    # A passing model's verdict attached to a failing model's counts. Both halves
    # are real gate output; the pairing is the lie, and only a writer that re-runs
    # the gate over the recorded counts can see it.
    with pytest.raises(ValueError, match="does not match the recorded counts"):
        store.write_ml_lifecycle_transition(
            "model-1", "active", reason="borrowed a verdict from a model that passed",
            evidence={"acceptance": normal_fpr_acceptance(0, 60), **FAILING_COUNTS},
            activation_eligible=True,
        )

    # Thresholds are part of the verdict, so equality is required rather than a
    # check of the eligibility flag alone: a passing verdict carrying a widened
    # ceiling would read, to anyone auditing the row later, as having been gated on
    # 5% when it was not gated at all.
    with pytest.raises(ValueError, match="does not match the recorded counts"):
        store.write_ml_lifecycle_transition(
            "model-1", "active", reason="same numbers, a ceiling moved under them",
            evidence={
                "acceptance": normal_fpr_acceptance(0, 60) | {"max_normal_fpr": 0.95},
                **PASSING_COUNTS,
            },
            activation_eligible=True,
        )

    # And the counts have to be present at all: a recompute needs inputs, so a
    # verdict arriving without them is refused rather than let through unchecked --
    # otherwise omitting the numbers would be the way around the check.
    with pytest.raises(ValueError, match="must record the false_positive_count and"):
        store.write_ml_lifecycle_transition(
            "model-1", "eligible", reason="a verdict with its numbers left off",
            evidence={"acceptance": normal_fpr_acceptance(0, 60)},
            activation_eligible=True,
        )
    assert store.read_ml_lifecycle() == []

    # The honest row is unaffected, which is the other half of the claim: this
    # rejects forgeries, not eligibility. `ml/lifecycle.py` already records the
    # counts beside the verdict, so nothing in the real write path had to change.
    row = store.write_ml_lifecycle_transition(
        "model-1", "eligible", reason="activation gate satisfied",
        evidence={"acceptance": normal_fpr_acceptance(0, 60), **PASSING_COUNTS},
        activation_eligible=True, from_state="evaluated",
    )
    assert row["activation_eligible"] is True
    assert row["evidence"]["acceptance"] == normal_fpr_acceptance(0, 60)


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


# --- Training-window hash verification ----------------------------------------
# `ml_training_windows.immutable_hash` has been recorded since migration 7 and,
# until now, recomputed nowhere -- which made it a stored string rather than
# tamper-evidence. `verify_ml_training_windows` closes that, and these tests pin
# the part that is easy to get wrong: the digest covers *normalised* values, so
# the recompute from REAL/INTEGER columns has to agree with the write from Python
# floats and bools. The round-trip test is the one that catches a drift between
# the two; the mutation tests are what the verification is for.


def _dataset(store, dataset_id="verified-normal-1", verification=None):
    store.create_ml_dataset({
        "id": dataset_id,
        "name": "normal-corpus",
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema_hash(),
        "environment": {"host": "test-host"},
        "verification": verification or {"verified_normal": True, "operator": "test"},
        "created_at": 1000.0,
    })
    return dataset_id


def _training_window(store, dataset_id, start=1000, **overrides):
    """
    One window, with `start` deliberately an *int* by default.

    `window_start`/`window_end` are REAL columns, so an int here is read back as a
    float. That asymmetry is the digest's main hazard and the default exercises it
    on every test below rather than only in the one that names it.
    """
    return store.write_ml_training_window({
        "dataset_id": dataset_id,
        "window_start": start,
        "window_end": start + 300,
        "event_ids": [start, start + 1],
        # Mixed int/float/zero values on purpose: feature extraction emits counts
        # as ints and rates as floats, and `json.dumps(1)` vs `json.dumps(1.0)`
        # differ, so the containers have to survive a loads/dumps round-trip.
        "features": {"process_count": 7, "privileged_ratio": 0.25, "idle": 0.0},
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema_hash(),
        "collector_context": {"sources": ["audit", "proc"], "nested": {"b": 2, "a": 1}},
        "verified_normal": True,
        "verification": {"verified_normal": True, "operator": "test"},
        "created_at": float(start),
    } | overrides)


def _raw_update(store, statement, parameters=()):
    """Tamper behind the store's back, the way these tests' threat model assumes."""
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute(statement, parameters)
        connection.commit()
    finally:
        connection.close()


def test_training_window_hash_verifies_on_round_trip(tmp_path):
    """
    An untouched window verifies -- the property everything below depends on.

    This fails for any digest that hashes the caller's values instead of the
    stored ones: `window_start=1000` hashes as `1000` but reads back `1000.0`, and
    `verified_normal=True` hashes as `true` but reads back `1`. A verifier that
    disagreed with the writer here would report every honest row as tampered,
    which is worse than no verification at all because it would be ignored.
    """
    store = _store(tmp_path)
    dataset = _dataset(store)
    ids = [_training_window(store, dataset, start=start) for start in (1000, 2000, 3000)]
    assert len(set(ids)) == 3

    verdict = store.verify_ml_training_windows()
    assert verdict == {"ok": True, "checked": 3, "mismatched_ids": []}

    # A float-valued start must verify identically -- the normalisation has to be
    # idempotent, not merely consistent in the int case.
    _training_window(store, dataset, start=4000.0)
    assert store.verify_ml_training_windows() == {"ok": True, "checked": 4, "mismatched_ids": []}

    # Nothing to verify is `ok`, not a failure: a default install has no corpus,
    # and an empty table is not a tampered one.
    assert store.verify_ml_training_windows("no-such-dataset") == {"ok": True, "checked": 0, "mismatched_ids": []}


def test_mutated_features_are_detected(tmp_path):
    """
    Editing the feature values a model was fitted on is caught.

    This is the tamper that matters most: features are the only part of a window
    that reaches a model, so silently rewriting them changes what "normal" means
    without touching the model, the gate, or the lifecycle chain. The row stays
    individually well-formed -- it is only the recomputed digest that disagrees.
    """
    store = _store(tmp_path)
    dataset = _dataset(store)
    kept = _training_window(store, dataset, start=1000)
    edited = _training_window(store, dataset, start=2000)

    _raw_update(
        store,
        "UPDATE ml_training_windows SET features_json = ? WHERE id = ?",
        (json.dumps({"process_count": 7, "privileged_ratio": 0.95, "idle": 0.0}, sort_keys=True), edited),
    )
    verdict = store.verify_ml_training_windows()
    assert verdict["ok"] is False
    # Attributable to the row, not just to the table: unlike a hash chain, each
    # digest stands alone, so the verdict names which windows to distrust.
    assert verdict["mismatched_ids"] == [edited]
    assert verdict["checked"] == 2
    assert kept not in verdict["mismatched_ids"]

    # Content that no longer parses is a mismatch, not an exception out of the
    # verifier -- the worst row must not take the verdict on the rest with it.
    _raw_update(store, "UPDATE ml_training_windows SET features_json = 'not json' WHERE id = ?", (kept,))
    assert store.verify_ml_training_windows()["mismatched_ids"] == [kept, edited]


def test_mutated_verified_normal_is_detected(tmp_path):
    """
    Flipping the attestation column is caught -- the bool-versus-int path.

    The writer is handed Python `True` and the column stores `1`, so the digest
    must normalise both sides to the same thing. The tempting shortcut is to hash
    a hardcoded `True`, since the writer refuses anything else; that would make
    exactly this UPDATE invisible. `bool()` on both sides is what keeps the
    attestation covered.
    """
    store = _store(tmp_path)
    dataset = _dataset(store)
    window = _training_window(store, dataset)
    assert store.verify_ml_training_windows()["ok"] is True

    _raw_update(store, "UPDATE ml_training_windows SET verified_normal = 0 WHERE id = ?", (window,))
    assert store.verify_ml_training_windows()["mismatched_ids"] == [window]
    # The decoded read still presents a perfectly plausible record; the digest is
    # the only thing that knows the attestation was withdrawn after the fact.
    assert store.read_ml_training_windows(dataset)[0]["verified_normal"] is False


def test_the_timestamp_and_attestation_columns_are_all_covered(tmp_path):
    """
    Every field the digest claims to cover, mutated one at a time.

    Written as a sweep rather than one test per column because the risk is a field
    quietly dropped from the material dict, and a sweep fails the moment one is.
    `created_at` is deliberately absent: it is excluded from the digest by design
    (a write timestamp is not part of the window's content), and the final
    assertion pins that exclusion so it stays a decision rather than an oversight.
    """
    store = _store(tmp_path)
    dataset = _dataset(store)
    covered = {
        "window_start": "1.5",
        "window_end": "9.5",
        "event_ids_json": "'[99]'",
        "schema_version": "'0.0.1-not-real'",
        "schema_hash": "'" + "f" * 64 + "'",
        "collector_context_json": "'{\"sources\":[]}'",
        "verification_json": "'{\"verified_normal\":true,\"operator\":\"someone else\"}'",
    }
    for column, value in covered.items():
        window = _training_window(store, _dataset(store, f"dataset-{column}"))
        _raw_update(store, f"UPDATE ml_training_windows SET {column} = {value} WHERE id = ?", (window,))
        assert store.verify_ml_training_windows(f"dataset-{column}")["mismatched_ids"] == [window], column

    # `dataset_id` is covered too, but moving a window between datasets needs a
    # real target row, so it is exercised separately rather than in the sweep.
    elsewhere = _dataset(store, "dataset-elsewhere")
    moved = _training_window(store, dataset)
    _raw_update(store, "UPDATE ml_training_windows SET dataset_id = ? WHERE id = ?", (elsewhere, moved))
    assert store.verify_ml_training_windows(elsewhere)["mismatched_ids"] == [moved]

    # And `created_at` is not: it still verifies after being rewritten.
    untouched = _training_window(store, _dataset(store, "dataset-created-at"))
    _raw_update(store, "UPDATE ml_training_windows SET created_at = 0.0 WHERE id = ?", (untouched,))
    assert store.verify_ml_training_windows("dataset-created-at")["ok"] is True


def test_verify_scopes_to_one_dataset_when_asked(tmp_path):
    """
    The scoped form checks one dataset and ignores the rest of the table.

    Not an optimisation detail: the unscoped form is a full scan, and the callers
    that run on a request path pass a dataset id precisely so a growing corpus
    elsewhere cannot make a single model's verification slow. A scoped call must
    therefore report `checked` for its own dataset only -- and must still refuse
    to launder a break in the dataset it was asked about.
    """
    store = _store(tmp_path)
    clean = _dataset(store, "dataset-clean")
    dirty = _dataset(store, "dataset-dirty")
    _training_window(store, clean, start=1000)
    _training_window(store, clean, start=2000)
    broken = _training_window(store, dirty, start=3000)
    _raw_update(store, "UPDATE ml_training_windows SET window_end = 0.0 WHERE id = ?", (broken,))

    assert store.verify_ml_training_windows("dataset-clean") == {"ok": True, "checked": 2, "mismatched_ids": []}
    assert store.verify_ml_training_windows("dataset-dirty") == {"ok": False, "checked": 1, "mismatched_ids": [broken]}
    # The unscoped form sees both, and is false because one of them is.
    everything = store.verify_ml_training_windows()
    assert everything == {"ok": False, "checked": 3, "mismatched_ids": [broken]}
