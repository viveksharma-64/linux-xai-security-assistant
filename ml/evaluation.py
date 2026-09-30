"""
Evaluation that decides whether a trained model is *eligible* to be activated.

Two questions, kept deliberately separate
-----------------------------------------
1. On verified-normal data the model has never seen, how often does it cry wolf?
   That false-positive rate, and its one-sided upper confidence bound, is the gate
   that governs activation: a detector that fires on normal behaviour is worse
   than none, so the *bound* -- not the point estimate -- has to clear the budget.
2. On labelled data, how well does it separate anomalous from normal (precision,
   recall, F1)? This is descriptive. It is never allowed to substitute for the
   normal-FPR gate above, because a good score against one labelled set says
   nothing about the false-positive cost on the far larger stream of ordinary
   activity the detector will actually run against.

Keeping the two apart is the point of the module: the acceptance decision reads
only the verified-normal track, and the labelled metrics are reported alongside
it without feeding into it.

Read-only
---------
Nothing here trains, mutates, or activates a model. The functions return verdicts
and numbers; the ML-lifecycle caller is what records or acts on them. This module
only measures.
"""

import math
from typing import Any, Sequence

from ml.scoring import MLScorer
from pipeline.event_stream import Event


MAX_NORMAL_FPR = 0.05
MIN_NORMAL_HOLDOUT_WINDOWS = 60


def _wilson_upper_bound(successes: int, observations: int, z: float = 1.644854) -> float | None:
    """One-sided 95% Wilson upper bound for the normal false-positive rate."""
    if observations <= 0:
        return None
    proportion = successes / observations
    denominator = 1.0 + z * z / observations
    centre = (proportion + z * z / (2.0 * observations)) / denominator
    radius = z * math.sqrt((proportion * (1.0 - proportion) + z * z / (4.0 * observations)) / observations) / denominator
    return min(1.0, centre + radius)


def normal_fpr_acceptance(false_positives: int, normal_windows: int) -> dict[str, Any]:
    """
    Decide whether the normal false-positive rate is low enough to activate.

    Three conditions must all hold: enough verified-normal holdout windows for the
    estimate to mean anything, an observed FPR within budget, and -- the binding
    one -- a one-sided 95% Wilson upper bound within budget, so a low rate seen on
    a small sample cannot buy activation the evidence does not support. Returns the
    verdict together with the numbers behind it; it never mutates a model or a
    threshold.
    """
    fpr = false_positives / normal_windows if normal_windows else None
    upper_bound = _wilson_upper_bound(false_positives, normal_windows)
    reasons = []
    if normal_windows < MIN_NORMAL_HOLDOUT_WINDOWS:
        reasons.append(f"requires at least {MIN_NORMAL_HOLDOUT_WINDOWS} independent verified-normal holdout windows")
    if fpr is None or fpr > MAX_NORMAL_FPR:
        reasons.append(f"observed normal FPR must be at most {MAX_NORMAL_FPR:.2%}")
    if upper_bound is None or upper_bound > MAX_NORMAL_FPR:
        reasons.append(f"one-sided 95% FPR upper bound must be at most {MAX_NORMAL_FPR:.2%}")
    return {
        "activation_eligible": not reasons,
        "max_normal_fpr": MAX_NORMAL_FPR,
        "minimum_normal_holdout_windows": MIN_NORMAL_HOLDOUT_WINDOWS,
        "normal_fpr_upper_95": upper_bound,
        "reasons": reasons,
    }


def evaluate_threshold(
    scorer: MLScorer,
    normal_windows: Sequence[Sequence[Event]],
    labeled_windows: Sequence[tuple[Sequence[Event], int]] | None = None,
) -> dict[str, Any]:
    """
    Score verified-normal windows (and optional labelled windows) into a report.

    The verified-normal track always runs and drives `acceptance`: it counts how
    often the model fires on data it should treat as normal, which is the only
    input the activation gate reads. Labelled windows are optional and purely
    descriptive -- they add a confusion matrix and precision/recall/F1 for judging
    a model -- and are deliberately kept out of the acceptance decision. Scores
    into no model and activates nothing; it only measures.
    """
    normal_scores = [scorer.score(window) for window in normal_windows]
    false_positives = sum(item["is_anomaly"] for item in normal_scores)
    report: dict[str, Any] = {
        "normal_window_count": len(normal_scores),
        "normal_false_positive_count": false_positives,
        "normal_false_positive_rate": false_positives / len(normal_scores) if normal_scores else None,
        "labels_available": bool(labeled_windows),
        "model_id": scorer.metadata["id"],
        "schema_hash": scorer.metadata["schema_hash"],
        "normal_window_scores": [
            {"raw_score": item["raw_score"], "normalized_score": item["normalized_score"], "is_anomaly": item["is_anomaly"]}
            for item in normal_scores
        ],
        "acceptance": normal_fpr_acceptance(false_positives, len(normal_scores)),
    }
    if not labeled_windows:
        return report
    outcomes = [(bool(scorer.score(events)["is_anomaly"]), int(label)) for events, label in labeled_windows]
    tp = sum(predicted and label == 1 for predicted, label in outcomes)
    fp = sum(predicted and label == 0 for predicted, label in outcomes)
    tn = sum(not predicted and label == 0 for predicted, label in outcomes)
    fn = sum(not predicted and label == 1 for predicted, label in outcomes)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    report.update(
        {
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        }
    )
    return report
