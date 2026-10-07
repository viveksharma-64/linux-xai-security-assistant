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
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from ml.scoring import MLScorer
from pipeline.event_stream import Event

MAX_NORMAL_FPR = 0.05
MIN_NORMAL_HOLDOUT_WINDOWS = 60


class MLEvaluationError(ValueError):
    pass


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


def evaluate_threshold_from_windows(
    scorer: MLScorer,
    windows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """
    The same verified-normal measurement, taken from *stored* holdout windows.

    `evaluate_threshold` wants live `Event` objects, which a holdout dataset does
    not have: a collected window persists its 34 feature values, and the events
    behind them live in whatever capture it was promoted from. So this is the
    entry point an operator-facing evaluation actually uses -- it reads what
    `read_ml_training_windows()` returns and scores each row's features directly
    through `MLScorer.score_features`.

    The report shape is the one `evaluate_threshold` produces, so
    `ml.lifecycle.record_evaluated` reads it unchanged, plus `normal_window_ids`:
    the measurement commits to *which* windows it measured, rather than to a bare
    count that no later reader can check. `labels_available` is always False --
    there are no labelled windows on this path, and the acceptance decision never
    read them anyway.

    Refuses rather than measures when the data cannot support the claim: a window
    that is not attested verified-normal is not evidence about false positives, a
    window built under a different feature schema is not comparable to this model,
    and a repeated window id would inflate the sample behind the Wilson bound.
    Scores into no model and activates nothing; it only measures.
    """
    expected_hash = scorer.metadata["schema_hash"]
    expected_version = scorer.metadata["schema_version"]
    window_ids = [window["id"] for window in windows]
    duplicates = sorted(str(wid) for wid, count in Counter(window_ids).items() if count > 1)
    if duplicates:
        raise MLEvaluationError(f"holdout windows repeat ids, which would inflate the sample: {duplicates}")
    unverified = [window["id"] for window in windows if not window.get("verified_normal")]
    if unverified:
        raise MLEvaluationError(f"holdout windows are not attested verified-normal: {unverified}")
    incompatible = [
        window["id"]
        for window in windows
        if window.get("schema_hash") != expected_hash or window.get("schema_version") != expected_version
    ]
    if incompatible:
        raise MLEvaluationError(
            f"holdout windows were built under a different feature schema than the model: {incompatible}"
        )
    normal_scores = [scorer.score_features(window["features"]) for window in windows]
    false_positives = sum(item["is_anomaly"] for item in normal_scores)
    return {
        "normal_window_count": len(normal_scores),
        "normal_window_ids": window_ids,
        "normal_false_positive_count": false_positives,
        "normal_false_positive_rate": false_positives / len(normal_scores) if normal_scores else None,
        "labels_available": False,
        "model_id": scorer.metadata["id"],
        "schema_hash": scorer.metadata["schema_hash"],
        "normal_window_scores": [
            {"raw_score": item["raw_score"], "normalized_score": item["normalized_score"], "is_anomaly": item["is_anomaly"]}
            for item in normal_scores
        ],
        "acceptance": normal_fpr_acceptance(false_positives, len(normal_scores)),
    }


def calibrate_threshold(
    scorer: MLScorer,
    holdout_windows: Sequence[Mapping[str, Any]],
    *,
    target_fpr: float,
) -> dict[str, Any]:
    """
    Find the threshold that yields `target_fpr` on these holdout windows.

    The trained threshold is 0.0 because that is where `contamination` put it --
    a hyperparameter choice, never a measurement. This is the alternative: score
    verified-normal windows, then pick the boundary that flags at most
    `target_fpr` of them. Returns the numbers; writes nothing. Applying the result
    means minting a *new* artifact and model row (`ml/training.py:rethreshold_model`),
    because artifacts are immutable and checksum-pinned.

    The honest statistical limit, which is why this is off by default
    -----------------------------------------------------------------
    Calibrating on the same holdout set the activation gate then measures is
    **in-sample**. The returned `quantile` is simultaneously "where the threshold
    sits in this distribution" and "the false positive rate the gate will observe
    on this distribution" -- they are the same number, computed from the same
    windows, which is exactly the problem. A gate run against a threshold fitted
    to its own holdout is not evidence; it is arithmetic restating the target.

    The clean form needs two disjoint splits: a calibration split to fit the
    threshold and a separate gate split to measure it. The verified-normal corpus
    cannot support that yet -- the gate alone wants 60 independent windows and the
    corpus has four candidates -- so this function is scaffolding for when it can,
    and the provenance string it returns says `in_sample` so no later reader
    mistakes the resulting number for an independent one.

    Selection rule: `is_anomaly` is `raw_score <= threshold`, so the flagged set
    grows with the threshold. Take the largest *observed* score whose flagged count
    still fits the budget `floor(target_fpr * n)`; if even the smallest score
    overruns it, sit just below the minimum so nothing is flagged. Choosing an
    observed score rather than interpolating between two means the realised rate is
    exactly a count over n and can never round past the target.
    """
    if not 0.0 < target_fpr < 1.0:
        raise MLEvaluationError(f"target false positive rate must be in (0, 1), got {target_fpr}")
    # Reuses the measurement path's refusals -- duplicate ids, unattested windows,
    # schema mismatch. Calibrating on data too weak to evaluate against would be
    # worse than evaluating on it, since the threshold would then carry the flaw
    # forward into every later score.
    measured = evaluate_threshold_from_windows(scorer, holdout_windows)
    scores = sorted(float(item["raw_score"]) for item in measured["normal_window_scores"])
    observations = len(scores)
    if not observations:
        raise MLEvaluationError("threshold calibration requires at least one verified-normal holdout window")

    budget = math.floor(target_fpr * observations)
    threshold: float | None = None
    for index in range(observations - 1, -1, -1):
        if index + 1 < observations and scores[index + 1] == scores[index]:
            continue  # not the last occurrence of this value; its true flagged count is higher
        if index + 1 <= budget:
            threshold = scores[index]
            break
    if threshold is None:
        threshold = math.nextafter(scores[0], -math.inf)

    flagged = sum(1 for value in scores if value <= threshold)
    quantile = flagged / observations
    return {
        "threshold": threshold,
        "target_fpr": float(target_fpr),
        "normal_window_count": observations,
        "normal_window_ids": measured["normal_window_ids"],
        "false_positive_count": flagged,
        # The empirical quantile the threshold sits at. Identical to the in-sample
        # false positive rate by construction -- see the docstring.
        "quantile": quantile,
        "in_sample": True,
        "threshold_provenance": (
            f"holdout_quantile(n={observations}, target_fpr={float(target_fpr)!r}, quantile={quantile!r}); "
            "in_sample -- calibrated on the same holdout a gate run would measure, so a gate FPR measured "
            "against this threshold is optimistic and is not independent evidence"
        ),
    }
