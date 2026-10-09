"""
The model lifecycle log: how a model got from trained to trusted, and on what evidence.

Why this module exists
----------------------
Two questions need an answer that survives an audit months later: *was this model
ever allowed to influence a finding*, and *what measurement justified that*.
Neither is answerable from `ml_models` alone -- that table holds the current state,
and a current state cannot testify about how it was reached. So every transition is
appended to `ml_model_lifecycle`, which is hash-chained, so the history cannot be
rewritten to make a decision look better-founded than it was.

The log records; the gate decides
---------------------------------
The lifecycle log is one-way, with one deliberate exception in each direction.
Writing a row does not change a threshold and does not make a scorer load. No
append can make a model active: `record_activation` does not flip the flag
itself, it calls `storage/sqlite_store.py:activate_ml_model`, which is the only
writer of `active = 1` and which refuses unless the gate grants eligibility *and*
the model's latest recorded state is already `eligible`. In the other direction,
appending `retired` or `drifted` *does* stand a model down, in the same
transaction as the row -- because the failure mode of a retirement that leaves a
model scoring is strictly worse than the failure mode of one that does not.

So the log is still not a control surface for activation: it cannot grant
eligibility, and the gate's verdict is not something a caller can supply. What
changed from the earlier design is where the guarantee lives. It used to be
absence -- no store method existed to activate an existing model -- and absence
made the gate unreachable, since `active` could then only be set at INSERT,
before any evaluation could have happened. The guarantee is now enforcement: one
door, with the gate across it. The INSERT route is closed from the other side to
keep it one door and not two: `train_isolation_forest` no longer takes an
`activate` flag, and `write_ml_model` refuses an active row outright rather than
gating it, because a model has no lifecycle history at the moment its row is
inserted and so could never meet the `eligible`-latest-state precondition that
`activate_ml_model` imposes.

The gate is the only door
-------------------------
`activation_eligible` is set from exactly one thing: a fresh call to
`ml/evaluation.py:normal_fpr_acceptance` made *here*, from the raw
false-positive and holdout-window counts. This module never accepts a
pre-computed acceptance dict from a caller, because that would let a caller
assert eligibility the gate never granted -- the whole point of the gate is that
its verdict cannot be supplied by the party who wants a particular answer. The
gate's thresholds (5% maximum false-positive rate, 60-window minimum, Wilson
upper bound) are not read, copied, or re-derived here; the verdict is taken
verbatim, including its `reasons`.

`storage/sqlite_store.py:write_ml_lifecycle_transition` independently refuses an
`active` row without a gate verdict, refuses any eligibility claim on a
drift-reachable state, and -- for any row claiming eligibility -- re-runs the gate
over the counts recorded beside the verdict and refuses unless it reproduces that
verdict exactly. That duplication is intentional: the invariant holds even for a
writer that bypasses this module, including one that hands the store a verdict it
assembled itself.

Drift's reach is bounded
------------------------
A drift assessment can append exactly two states, `drift_assessed` and
`retraining_required`. It cannot record `eligible`, cannot record `active`, and
cannot retire a model. Drift raises the question; a human answers it by training
a new model and putting it through the same gate.
"""

import time
from collections.abc import Mapping, Sequence
from typing import Any

from ml.evaluation import normal_fpr_acceptance
from storage.sqlite_store import SQLiteEventStore

# The ordered path a model can take. `drift_assessed` and `retraining_required`
# sit outside it: they are observations about a model, not stages of one, and can
# be appended at any point after training.
LIFECYCLE_PATH = ("trained", "evaluated", "eligible", "ineligible", "active", "drifted", "retired")

# The only states a drift assessment may append. Mirrored by
# `_ML_DRIFT_LIFECYCLE_STATES` in the store, which enforces it independently.
DRIFT_STATES = ("drift_assessed", "retraining_required")


def record_trained(
    store: SQLiteEventStore,
    metadata: Mapping[str, Any],
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Open a model's history with what it was trained on and what artifact it produced.

    `metadata` is `ml/training.py:train_isolation_forest`'s return value. The
    recorded evidence is deliberately identifying rather than descriptive: the
    artifact checksum and the training window ids are what let a later reader
    confirm that the model being discussed is the one that was measured.
    """
    return store.write_ml_lifecycle_transition(
        metadata["id"],
        "trained",
        reason="model trained on verified-normal windows",
        evidence={
            "artifact_checksum": metadata["artifact_checksum"],
            "artifact_format": metadata.get("artifact_format"),
            "schema_hash": metadata["schema_hash"],
            "training_window_count": len(metadata["training_window_ids"]),
            "training_window_ids": list(metadata["training_window_ids"]),
            "hyperparameters": dict(metadata["hyperparameters"]),
        },
        actor=actor,
    )


def record_evaluated(
    store: SQLiteEventStore,
    model_id: str,
    report: Mapping[str, Any],
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Record that a model was evaluated, without recording a verdict.

    `report` is `ml/evaluation.py:evaluate_threshold`'s output. Its own
    `acceptance` block is not copied into `activation_eligible` here: evaluation
    and the gate decision are separate rows precisely so that the log shows the
    measurement existing before the decision that cites it.
    """
    return store.write_ml_lifecycle_transition(
        model_id,
        "evaluated",
        reason="threshold evaluated against holdout windows",
        evidence={
            "normal_window_count": report["normal_window_count"],
            "normal_false_positive_count": report["normal_false_positive_count"],
            "normal_false_positive_rate": report["normal_false_positive_rate"],
            "labels_available": report["labels_available"],
            "confusion_matrix": report.get("confusion_matrix"),
        },
        from_state="trained",
        actor=actor,
    )


def record_activation_gate(
    store: SQLiteEventStore,
    model_id: str,
    *,
    false_positive_count: int,
    normal_window_count: int,
    holdout_window_ids: Sequence[Any] | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Put the counts through the activation gate and record the verdict it returns.

    Takes raw counts, not a verdict: the gate is called here so that the recorded
    `activation_eligible` cannot be anything other than what
    `normal_fpr_acceptance` returned for these numbers. `is True` rather than a
    truthiness test, so no truthy stand-in can pass for the gate's boolean.

    `holdout_window_ids` is optional and, when given, names the windows the counts
    were measured over -- so the chained row commits to *which* sixty windows
    cleared the gate, not merely that sixty of something did. Without it the row
    records a bare count that no later reader can audit or reproduce. It must agree
    with `normal_window_count` and contain no repeats; a disagreement is refused
    rather than reconciled, because the two numbers disagreeing means the caller
    does not know what it measured.

    An ineligible verdict is recorded, not raised. "This model was measured and
    did not qualify" is the more useful audit record, and it is the record that
    stops the same model being quietly re-proposed later.
    """
    window_ids = None if holdout_window_ids is None else list(holdout_window_ids)
    if window_ids is not None:
        if len(set(window_ids)) != len(window_ids):
            raise ValueError("holdout_window_ids repeats a window; the gate's sample would be inflated")
        if len(window_ids) != int(normal_window_count):
            raise ValueError(
                f"holdout_window_ids names {len(window_ids)} windows but normal_window_count "
                f"is {int(normal_window_count)}"
            )
    acceptance = normal_fpr_acceptance(int(false_positive_count), int(normal_window_count))
    eligible = acceptance["activation_eligible"] is True
    return store.write_ml_lifecycle_transition(
        model_id,
        "eligible" if eligible else "ineligible",
        reason=(
            "activation gate satisfied"
            if eligible
            else f"activation gate not satisfied: {'; '.join(acceptance['reasons'])}"
        ),
        evidence={
            "acceptance": acceptance,
            "false_positive_count": int(false_positive_count),
            "normal_window_count": int(normal_window_count),
            "holdout_window_ids": window_ids,
        },
        from_state="evaluated",
        activation_eligible=eligible,
        actor=actor,
    )


def record_activation(
    store: SQLiteEventStore,
    model_id: str,
    *,
    false_positive_count: int,
    normal_window_count: int,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Activate a model, refusing unless the gate and its recorded history both allow it.

    Delegates to `storage/sqlite_store.py:activate_ml_model`, which sets
    `ml_models.active` and appends this row in one transaction. One door, so the
    flag and the justification for it cannot come apart: there is no way to reach
    an active model without this row, and no way to write this row without the
    model becoming active.

    The store re-runs the gate over these raw counts rather than trusting the
    earlier `eligible` row, so the numbers are re-checked at the moment the claim
    is made and the `active` row carries them itself; it additionally requires the
    model's latest recorded state to *be* `eligible`, which is what stops a
    retired model being re-activated by re-asserting its old counts. Raises
    `ValueError` if either refuses -- unlike the gate row above, an ungated
    activation claim is not a fact worth recording.
    """
    return store.activate_ml_model(
        model_id,
        false_positive_count=int(false_positive_count),
        normal_window_count=int(normal_window_count),
        actor=actor,
    )


def record_drift_assessment(
    store: SQLiteEventStore,
    assessment: Mapping[str, Any],
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Append a drift assessment, plus a `retraining_required` row when it found drift.

    The assessment and its chained `drift_assessed` row are written together by
    the store, in one transaction, so the unchained assessment cannot be edited
    without breaking the lifecycle chain. When drift was detected, a second row
    records the consequence separately -- an operator reading the log should see
    "retraining is indicated" as its own entry, not have to infer it from a
    status field.

    Returns `{"assessment", "lifecycle"}` where `lifecycle` is the list of rows
    appended, in order. Neither row can carry an eligibility claim; the store
    refuses that for drift-reachable states.
    """
    written = store.write_ml_drift_assessment(dict(assessment), actor=actor)
    appended = [written["lifecycle"]]
    if assessment["status"] == "drift_detected":
        appended.append(
            store.write_ml_lifecycle_transition(
                assessment["model_id"],
                "retraining_required",
                reason=(
                    f"{assessment['drifted_feature_count']} feature distributions "
                    "diverged from the training data"
                ),
                evidence={
                    "drift_assessment_id": written["assessment"]["id"],
                    "drifted_features": [
                        item["feature"] for item in assessment["features"] if item["drifted"]
                    ],
                    "comparison_dataset_id": assessment["comparison_dataset_id"],
                    "out_of_range_rate": assessment.get("out_of_range_rate"),
                    "limitations": [
                        "Retraining requires a fresh verified-normal dataset; drift does "
                        "not authorize reusing this model's own training data.",
                        "A retrained model is inactive until it passes the activation gate.",
                    ],
                },
                actor=actor,
            )
        )
    return {"assessment": written["assessment"], "lifecycle": appended}


def record_drifted(
    store: SQLiteEventStore,
    model_id: str,
    *,
    reason: str,
    evidence: Mapping[str, Any] | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Record an operator's judgment that a model is no longer fit for its host.

    Distinct from `retraining_required`, which drift writes on its own: this is a
    human conclusion, and `actor` is the claim about who reached it. The store
    clears `ml_models.active` in the same transaction, so a model judged unfit
    stops influencing findings as of this row.
    """
    return store.write_ml_lifecycle_transition(
        model_id, "drifted", reason=reason, evidence=dict(evidence or {}), actor=actor
    )


def record_retired(
    store: SQLiteEventStore,
    model_id: str,
    *,
    reason: str,
    evidence: Mapping[str, Any] | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """
    Close a model's history.

    Retirement is a log entry, not a deletion: the artifact, its training window
    provenance, and every finding it contributed to stay exactly where they are.
    A retired model that scored a finding last month must still be explainable
    next month. What it does stop is new scoring: the store clears
    `ml_models.active` in the same transaction, and reaching `active` again means
    going back through the gate.
    """
    return store.write_ml_lifecycle_transition(
        model_id, "retired", reason=reason, evidence=dict(evidence or {}), actor=actor
    )


def current_state(store: SQLiteEventStore, model_id: str) -> dict[str, Any] | None:
    """
    The latest lifecycle row for one model, or None if it has no history.

    "Latest row wins" is the same rule the triage layer uses. `drift_assessed`
    rows are skipped: an assessment is an observation about a model, not a stage
    it entered, and letting one shadow the model's real state would make a
    routine drift check look like a state change.
    """
    history = [row for row in store.read_ml_lifecycle(model_id) if row["to_state"] != "drift_assessed"]
    return history[-1] if history else None


def lifecycle_report(store: SQLiteEventStore, model_id: str) -> dict[str, Any]:
    """
    One model's history plus the verifications that say whether to trust it.

    The verification results are included rather than left to the caller because a
    history is only evidence if its chain verifies; reporting the rows without it
    invites treating an unverified log as an audit record.

    `training_windows` is the same argument applied one layer down. The lifecycle
    chain proves the *decisions* about a model were not rewritten; it says nothing
    about the data those decisions were made on. It is a set of independent digests
    rather than a chain, so it reports mismatched row ids instead of a break
    position -- see `verify_ml_training_windows`. Scoped to this model's own
    `training_window_ids`: an unknown model, or one whose provenance list is empty,
    verifies vacuously, which is the honest answer to "are these windows intact"
    when there are none.
    """
    history = store.read_ml_lifecycle(model_id)
    latest = current_state(store, model_id)
    metadata = store.read_ml_model(model_id)
    training_window_ids = list(metadata["training_window_ids"]) if metadata else []
    return {
        "model_id": model_id,
        "state": latest["to_state"] if latest else None,
        "activation_eligible": bool(latest["activation_eligible"]) if latest else False,
        "transition_count": len(history),
        "transitions": history,
        "drift_assessments": store.read_ml_drift_assessments(model_id),
        "chain": store.verify_ml_lifecycle_chain(),
        "training_windows": store.verify_ml_training_windows(window_ids=training_window_ids),
        "generated_at": time.time(),
    }


def eligible_model_ids(store: SQLiteEventStore, limit: int = 500) -> list[str]:
    """
    Model ids whose latest gate row granted eligibility, in the order granted.

    Reads the log; grants nothing. Present so an operator can ask "did anything
    ever pass the gate" without hand-reading the chain -- on a default install
    the honest answer is an empty list, and that is the expected answer.
    """
    granted: list[str] = []
    for row in store.read_ml_lifecycle(limit=limit):
        if row["to_state"] == "eligible" and row["activation_eligible"] and row["model_id"] not in granted:
            granted.append(row["model_id"])
    return granted
