"""
Model-faithful attribution for the native Isolation Forest anomaly score.

Advisory and explanatory only. This turns the forest's own scored quantity -- the
isolation-path length `depths` -- into a bounded, ranked FACT: which features the
forest *tested* on the path it placed a window on, and how many of the splits each
accounted for. It changes no score, activates nothing, persists nothing, and reads
only arrays already in memory for scoring.

It is deliberately not a causal or SHAP-additive explanation. Isolation Forest is
nonlinear; a split count is participation on one routed path, not a share of the
outcome. What it *is* is exact: `total_splits + leaf_correction` reconciles to the
same `depths` the score came from, the same reconcile-or-raise discipline the
deterministic scorer already lives by. See docs/ML_ATTRIBUTION.md.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from ml.iforest import NativeIsolationForest, average_path_length

# Versioned so a stored finding names the exact decomposition that produced its
# attribution; a future complementary view (e.g. score-space occlusion) would be a
# new method string, never a silent redefinition of this one.
METHOD = "path-length-split-attribution.v1"

# The forest tests far more features than an operator can read at a glance; the
# ranked head is what carries signal. `attributed_feature_count` still reports the
# full breadth so the cap is visible, not hidden.
DEFAULT_TOP_N = 8

# The reconciliation self-check tolerance. `total_splits + leaf_correction` differs
# from the scored `depths` only by the final float addition re-associating an exact
# integer with the residual, i.e. at most a few ULPs of a value below ~20.
_RECONCILE_ABS_TOL = 1e-9


def attribute_anomaly(
    model: NativeIsolationForest,
    feature_row: Sequence[float],
    feature_names: Sequence[str],
    *,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """
    Decompose one window's isolation-path length into per-feature split counts.

    `feature_row` is the unscaled feature vector in `feature_names` order -- the
    same vector handed to `decision_function`. Returns a bounded dict: the
    top-`top_n` features by split participation on the scored path, the exact
    reconciliation numbers, and a `reconciles` self-check.
    """
    names = list(feature_names)
    if len(names) != model.n_features:
        raise ValueError(
            f"feature_names has {len(names)} entries, model scores {model.n_features} features"
        )
    vector = np.asarray([list(feature_row)], dtype=float)
    attribution = model.path_length_attribution(vector)[0]

    split_counts: dict[int, int] = attribution["split_counts"]
    total_splits = int(attribution["total_splits"])
    leaf_correction = float(attribution["leaf_correction"])
    isolation_path_length = float(attribution["reconstructed_depths"])
    # c(max_samples): the expected isolation depth of an unremarkable point, the
    # yardstick a shorter (more anomalous) path is short *relative to*. Computed
    # from the public path-length function, not the cached private denominator.
    baseline_path_length = float(average_path_length([model.max_samples])[0])

    # Deterministic ranking: most-tested feature first, feature name as the
    # tie-break so equal counts never reorder run to run. Only features actually
    # tested on this path are reportable -- a feature the path never split on
    # attributed nothing, and emitting a zero row would imply it was considered.
    ranked = sorted(
        ((names[index], count) for index, count in split_counts.items()),
        key=lambda item: (-item[1], item[0]),
    )
    features = [
        {
            "feature": name,
            "split_count": int(count),
            "split_share": round(count / total_splits, 6) if total_splits else 0.0,
        }
        for name, count in ranked[:top_n]
    ]

    reconciles = abs((total_splits + leaf_correction) - isolation_path_length) <= _RECONCILE_ABS_TOL
    return {
        "method": METHOD,
        "features": features,
        "reported_feature_count": len(features),
        "attributed_feature_count": len(split_counts),
        "total_splits": total_splits,
        "leaf_correction": round(leaf_correction, 6),
        "isolation_path_length": round(isolation_path_length, 6),
        "baseline_path_length": round(baseline_path_length, 6),
        "reconciles": bool(reconciles),
    }
