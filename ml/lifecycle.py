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

This module records; it does not decide
---------------------------------------
The lifecycle log is one-way. Writing a row never causes anything: it does not
flip `ml_models.active`, does not change a threshold, and does not make a scorer
load. There is deliberately no method anywhere in the store to activate an
existing model -- `active` can only be set when a model row is first written -- and
this module does not add one. So the log is a witness, never a control surface,
and no sequence of appends can arrive at an activation.

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
`active` row without a gate verdict and refuses any eligibility claim on a
drift-reachable state. That duplication is intentional: the invariant holds even
for a writer that bypasses this module.

Drift's reach is bounded
------------------------
A drift assessment can append exactly two states, `drift_assessed` and
`retraining_required`. It cannot record `eligible`, cannot record `active`, and
cannot retire a model. Drift raises the question; a human answers it by training
a new model and putting it through the same gate.
"""

import time
from typing import Any, Dict, List, Mapping, Optional

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
    actor: Optional[str] = None,
) -> Dict[str, Any]:
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
    actor: Optional[str] = None,
) -> Dict[str, Any]:
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
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Put the counts through the activation gate and record the verdict it returns.

    Takes raw counts, not a verdict: the gate is called here so that the recorded
    `activation_eligible` cannot be anything other than what
    `normal_fpr_acceptance` returned for these numbers. `is True` rather than a
    truthiness test, so no truthy stand-in can pass for the gate's boolean.

    An ineligible verdict is recorded, not raised. "This model was measured and
    did not qualify" is the more useful audit record, and it is the record that
    stops the same model being quietly re-proposed later.
    """
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
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Record that a model became active, refusing unless the gate says it may.

    Re-runs the gate rather than trusting the earlier `eligible` row, so the
    numbers are re-checked at the moment the claim is made and the `active` row
    carries them itself. Raises `ValueError` if the gate refuses -- unlike the
    gate row above, an ungated activation claim is not a fact worth recording.

    Recording is all this does. Nothing here makes a model active: a model is
    active only if it was written that way by `write_ml_model`, and the store has
    no method to change that flag afterwards. This row states, for the audit
    record, that the gate had been satisfied at that point.
    """
    acceptance = normal_fpr_acceptance(int(false_positive_count), int(normal_window_count))
    if acceptance["activation_eligible"] is not True:
        raise ValueError(
            "refusing to record activation: activation gate not satisfied "
            f"({'; '.join(acceptance['reasons'])})"
        )
    return store.write_ml_lifecycle_transition(
        model_id,
        "active",
        reason="model activated after satisfying the activation gate",
        evidence={
            "acceptance": acceptance,
            "false_positive_count": int(false_positive_count),
            "normal_window_count": int(normal_window_count),
        },
        from_state="eligible",
        activation_eligible=True,
        actor=actor,
    )


def record_drift_assessment(
    store: SQLiteEventStore,
    assessment: Mapping[str, Any],
    *,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
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
    evidence: Optional[Mapping[str, Any]] = None,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Record an operator's judgment that a model is no longer fit for its host.

    Distinct from `retraining_required`, which drift writes on its own: this is a
    human conclusion, and `actor` is the claim about who reached it.
    """
    return store.write_ml_lifecycle_transition(
        model_id, "drifted", reason=reason, evidence=dict(evidence or {}), actor=actor
    )


def record_retired(
    store: SQLiteEventStore,
    model_id: str,
    *,
    reason: str,
    evidence: Optional[Mapping[str, Any]] = None,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Close a model's history.

    Retirement is a log entry, not a deletion: the artifact, its training window
    provenance, and every finding it contributed to stay exactly where they are.
    A retired model that scored a finding last month must still be explainable
    next month.
    """
    return store.write_ml_lifecycle_transition(
        model_id, "retired", reason=reason, evidence=dict(evidence or {}), actor=actor
    )


def current_state(store: SQLiteEventStore, model_id: str) -> Optional[Dict[str, Any]]:
    """
    The latest lifecycle row for one model, or None if it has no history.

    "Latest row wins" is the same rule the triage layer uses. `drift_assessed`
    rows are skipped: an assessment is an observation about a model, not a stage
    it entered, and letting one shadow the model's real state would make a
    routine drift check look like a state change.
    """
    history = [row for row in store.read_ml_lifecycle(model_id) if row["to_state"] != "drift_assessed"]
    return history[-1] if history else None


def lifecycle_report(store: SQLiteEventStore, model_id: str) -> Dict[str, Any]:
    """
    One model's history plus the chain verification that says whether to trust it.

    The verification result is included rather than left to the caller because a
    history is only evidence if its chain verifies; reporting the rows without it
    invites treating an unverified log as an audit record.
    """
    history = store.read_ml_lifecycle(model_id)
    latest = current_state(store, model_id)
    return {
        "model_id": model_id,
        "state": latest["to_state"] if latest else None,
        "activation_eligible": bool(latest["activation_eligible"]) if latest else False,
        "transition_count": len(history),
        "transitions": history,
        "drift_assessments": store.read_ml_drift_assessments(model_id),
        "chain": store.verify_ml_lifecycle_chain(),
        "generated_at": time.time(),
    }


def eligible_model_ids(store: SQLiteEventStore, limit: int = 500) -> List[str]:
    """
    Model ids whose latest gate row granted eligibility, in the order granted.

    Reads the log; grants nothing. Present so an operator can ask "did anything
    ever pass the gate" without hand-reading the chain -- on a default install
    the honest answer is an empty list, and that is the expected answer.
    """
    granted: List[str] = []
    for row in store.read_ml_lifecycle(limit=limit):
        if row["to_state"] == "eligible" and row["activation_eligible"] and row["model_id"] not in granted:
            granted.append(row["model_id"])
    return granted
