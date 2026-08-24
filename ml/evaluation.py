"""Evaluation utilities that keep verified-normal and labeled evaluation data distinct."""

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
    """Assess activation eligibility; this function never mutates a model or threshold."""
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


def evaluate_threshold(scorer: MLScorer, normal_windows: Sequence[Sequence[Event]], labeled_windows: Sequence[tuple[Sequence[Event], int]] | None = None) -> dict[str, Any]:
    normal_scores = [scorer.score(window) for window in normal_windows]
    false_positives = sum(item["is_anomaly"] for item in normal_scores)
    report: dict[str, Any] = {
        "normal_window_count": len(normal_scores), "normal_false_positive_count": false_positives,
        "normal_false_positive_rate": false_positives / len(normal_scores) if normal_scores else None,
        "labels_available": bool(labeled_windows), "model_id": scorer.metadata["id"], "schema_hash": scorer.metadata["schema_hash"],
        "normal_window_scores": [
            {"raw_score": item["raw_score"], "normalized_score": item["normalized_score"], "is_anomaly": item["is_anomaly"]}
            for item in normal_scores
        ],
        "acceptance": normal_fpr_acceptance(false_positives, len(normal_scores)),
    }
    if not labeled_windows:
        return report
    outcomes = [(bool(scorer.score(events)["is_anomaly"]), int(label)) for events, label in labeled_windows]
    tp = sum(predicted and label == 1 for predicted, label in outcomes); fp = sum(predicted and label == 0 for predicted, label in outcomes)
    tn = sum(not predicted and label == 0 for predicted, label in outcomes); fn = sum(not predicted and label == 1 for predicted, label in outcomes)
    precision = tp / (tp + fp) if tp + fp else 0.0; recall = tp / (tp + fn) if tp + fn else 0.0
    report.update({"confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0})
    return report
