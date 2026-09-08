"""
Feature-distribution drift between a model's training data and newer normal data.

What this answers, and what it does not
--------------------------------------
A trained model is only meaningful while the host still behaves like the host it
was trained on. This module answers one narrow, checkable question: for each of
the named features, is the distribution in a newer verified-normal dataset
distinguishable from the distribution the model was trained on? That is a
statistical FACT. Whether the model should be retrained is an INTERPRETATION, and
is reported as one, labelled, alongside its limitations.

Drift never scores, activates, deactivates, or re-thresholds anything. It is
read-only over the store, is run by an operator or a schedule (never on the
detection hot path), and returns a record for `ml/lifecycle.py` to append. In
particular a drift result can never make a model eligible for activation: the
activation gate in `ml/evaluation.py` is the only path to that, and it is fed by
reviewed-normal holdout false-positive measurement, not by this.

Method
------
Per feature, a two-sample two-sided Kolmogorov-Smirnov test between the
reference sample (the model's own training windows) and the comparison sample,
followed by a Holm-Bonferroni correction across the whole feature family. The
correction is not optional: 34 independent tests at alpha=0.01 would produce a
"drifted" feature about 30% of the time on two samples from the *same*
distribution, which is precisely the kind of false alarm that trains an operator
to ignore the signal.

The KS statistic is computed in exact integer arithmetic -- `max |i*m - j*n|`
over the merged sample rather than a float ECDF difference -- and the p-value is
the exact lattice-path probability while the lattice is small enough to enumerate
(`_EXACT_LATTICE_CELLS`), falling back to the Kolmogorov asymptotic series only
for samples large enough that it is accurate. Each feature records which method
produced its p-value, so the record never leaves that ambiguous. There is no
dependency on scipy: it happens to be installed here but is not a declared
dependency, and an offline host must be able to run this.

Refusing rather than guessing
-----------------------------
Too little data is reported as `insufficient_data` with explicit reasons, never as
`no_drift_detected`. One of those reasons is arithmetic rather than conventional:
with n and m small, the *smallest attainable* two-sided p-value can exceed the
Holm threshold for the first hypothesis, so no amount of separation in the data
could ever be called drift. Reporting "no drift" from a test that cannot reject
anything would be a lie of omission, so it is refused by name.
"""

import time
from math import comb, exp, sqrt
from typing import Any, Dict, List, Mapping, Sequence

from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, schema_hash
from storage.sqlite_store import SQLiteEventStore

# Bumped if the statistic, the correction, or the refusal rules change, so a
# stored assessment always records how it was produced.
DRIFT_METHOD = "two_sample_ks_holm_bonferroni.v1"

# Family-wise error rate for the Holm-corrected feature family. Deliberately
# tighter than a conventional 0.05: a drift report is an operator interruption,
# and this is a monitoring signal rather than a hypothesis under study.
DEFAULT_ALPHA = 0.01

# A model trained on fewer windows than `ml/training.py` requires cannot be
# assessed; kept as its own constant rather than imported so that drift does not
# depend on the training module (which needs scikit-learn to import).
MIN_REFERENCE_WINDOWS = 10

# Comparison-sample floor. Above the arithmetic attainability check below, this is
# an operational judgment: a handful of windows can differ from the training data
# for reasons that have nothing to do with the host drifting.
MIN_COMPARISON_WINDOWS = 30

# Largest lattice enumerated for an exact p-value, as (n+1)*(m+1) cells. Each cell
# is one big-integer addition, so this bounds the check at well under a second per
# feature; beyond it the asymptotic series is accurate anyway.
_EXACT_LATTICE_CELLS = 400_000

# Terms of the Kolmogorov series, and the point below which it is not used. The
# series converges geometrically in k^2; 100 terms is far past machine precision.
_ASYMPTOTIC_TERMS = 100


def _ks_integer_statistic(reference: Sequence[float], comparison: Sequence[float]) -> int:
    """
    The two-sample KS statistic as an integer: `max |i*m - j*n|` over the merged sample.

    `i` and `j` are the counts of each sample at or below the current value, so
    `i/n - j/m` is the ECDF difference and the integer form is that difference
    times `n*m`. Evaluated once per group of equal values, which is what the ECDF
    definition requires and what makes ties correct rather than merely tolerated.
    Integer throughout, so the comparison against the band in `_exact_two_sided_p`
    is exact and the statistic is reproducible across machines.
    """
    n, m = len(reference), len(comparison)
    merged = sorted({*reference, *comparison})
    reference_sorted = sorted(reference)
    comparison_sorted = sorted(comparison)
    largest = 0
    i = j = 0
    for value in merged:
        while i < n and reference_sorted[i] <= value:
            i += 1
        while j < m and comparison_sorted[j] <= value:
            j += 1
        largest = max(largest, abs(i * m - j * n))
    return largest


def _exact_two_sided_p(n: int, m: int, statistic: int) -> float:
    """
    Exact P(D >= observed) for the two-sided two-sample KS test.

    Counts the monotone lattice paths from (0,0) to (n,m) that stay strictly
    inside the band `|i*m - j*n| < statistic`; those are exactly the orderings of
    the merged sample whose statistic is smaller than the one observed. Under the
    null every ordering is equally likely, so the p-value is
    `1 - inside / C(n+m, n)`. Big integers throughout, and the final division is
    the only floating-point operation, so there is no accumulated error.
    """
    if statistic <= 0:
        return 1.0
    inside = [0] * (m + 1)
    inside[0] = 1
    for j in range(1, m + 1):
        inside[j] = inside[j - 1] if abs(-j * n) < statistic else 0
    for i in range(1, n + 1):
        previous = inside
        inside = [0] * (m + 1)
        inside[0] = previous[0] if abs(i * m) < statistic else 0
        for j in range(1, m + 1):
            if abs(i * m - j * n) < statistic:
                inside[j] = inside[j - 1] + previous[j]
    total = comb(n + m, n)
    # Integer division, not `float(a) / float(b)`: `total` outruns the float range
    # long before the lattice-cell bound does -- C(1262,631) is a 379-digit number,
    # and converting it raises OverflowError -- so a comparison of two samples of a
    # few hundred windows each would crash rather than return a p-value. Python
    # divides big integers with a single correct rounding, so this is also strictly
    # more accurate than converting each side first, which rounds twice.
    return (total - inside[m]) / total


def _asymptotic_two_sided_p(n: int, m: int, statistic: int) -> float:
    """
    Kolmogorov's limiting two-sided p-value, for samples too large to enumerate.

    `Q(x) = 2 * sum_k (-1)^(k-1) exp(-2 k^2 x^2)` evaluated at
    `x = D * sqrt(n*m/(n+m))`, clamped to [0, 1] because the truncated
    alternating series can overshoot slightly for very small `x`.

    The limiting form errs in the safe direction where a decision is made: for every
    attainable statistic whose exact p-value is at or below 0.05 -- the region every
    Holm threshold lives in, since `alpha` is 0.01 -- it returns a p-value greater
    than or equal to the exact lattice probability, so the fallback can only
    under-report drift, never manufacture it. Measured over the attainable statistics
    at (n,m) of 60x60, 30x90, 12x40, 150x150, and 632x632 (the first size this branch
    is actually reached at): never below the exact value in that region, and above it
    by at most 4.0e-5 at 632x632. Further from zero the two forms cross -- the
    asymptotic value runs up to 4.3e-4 low around p=0.75 at 632x632 -- which cannot
    change an outcome, because no threshold sits there.
    """
    d = statistic / float(n * m)
    x = d * sqrt(n * m / float(n + m))
    if x <= 0.0:
        return 1.0
    total = 0.0
    for k in range(1, _ASYMPTOTIC_TERMS + 1):
        term = exp(-2.0 * k * k * x * x)
        total += term if k % 2 else -term
        if term < 1e-18:
            break
    return min(1.0, max(0.0, 2.0 * total))


def two_sample_ks(reference: Sequence[float], comparison: Sequence[float]) -> Dict[str, Any]:
    """
    Two-sided two-sample KS test, returning the statistic, p-value, and method used.

    `statistic` is the familiar float D (the integer statistic divided by `n*m`);
    `p_value_method` records whether the p-value is exact or asymptotic, so a
    stored assessment is never ambiguous about how it was computed.
    """
    n, m = len(reference), len(comparison)
    if n == 0 or m == 0:
        raise ValueError("the two-sample KS test requires a non-empty sample on both sides")
    integer_statistic = _ks_integer_statistic(reference, comparison)
    exact = (n + 1) * (m + 1) <= _EXACT_LATTICE_CELLS
    p_value = (
        _exact_two_sided_p(n, m, integer_statistic)
        if exact
        else _asymptotic_two_sided_p(n, m, integer_statistic)
    )
    return {
        "statistic": integer_statistic / float(n * m),
        "p_value": p_value,
        "p_value_method": "exact_lattice" if exact else "kolmogorov_asymptotic",
    }


def holm_bonferroni(p_values: Sequence[float], alpha: float) -> List[Dict[str, Any]]:
    """
    Holm-Bonferroni step-down correction over a family of p-values.

    Returns one record per input position (input order preserved) with the
    `holm_threshold` that position was actually compared against and whether it was
    rejected. Step-down: the p-values are ranked ascending and compared against
    `alpha / (k - rank)`; the first failure stops the procedure and every
    remaining hypothesis is retained. Uniformly more powerful than plain
    Bonferroni at the same family-wise error rate, and it needs no independence
    assumption -- which matters here, because the features are correlated by
    construction (event counts and per-second rates over the same window).
    """
    count = len(p_values)
    order = sorted(range(count), key=lambda index: p_values[index])
    records: List[Dict[str, Any]] = [{} for _ in range(count)]
    still_rejecting = True
    for rank, index in enumerate(order):
        threshold = alpha / float(count - rank)
        if still_rejecting and p_values[index] > threshold:
            still_rejecting = False
        records[index] = {
            "holm_rank": rank,
            "holm_threshold": threshold,
            "rejected": still_rejecting,
        }
    return records


def _minimum_attainable_p(n: int, m: int) -> float:
    """
    The smallest two-sided p-value these sample sizes can produce.

    Attained when the two samples separate completely: exactly two of the
    `C(n+m, n)` orderings do that. If this exceeds the Holm threshold for the
    first hypothesis, the test cannot reject anything no matter what the data
    looks like, and reporting "no drift" from it would be meaningless.

    Divided as integers rather than via `float(comb(...))`, which overflows from
    515 windows a side -- under nine hours of 60-second windows, so well inside
    what a real capture produces -- and would crash every assessment at that size.
    Underflowing to 0.0 for a large family is the right answer, not a silent one:
    samples that big can attain any threshold, so the refusal below correctly
    does not fire.
    """
    return 2 / comb(n + m, n)


def _feature_columns(windows: Sequence[Mapping[str, Any]]) -> Dict[str, List[float]]:
    return {
        name: [float(window["features"][name]) for window in windows]
        for name in FEATURE_NAMES
    }


def _window_fingerprint(window: Mapping[str, Any]) -> tuple:
    """
    Content identity for one training window, for detecting a reused window.

    Deliberately not the row `id`: ids are per-database autoincrements, so they
    would false-positive when the comparison dataset lives in a different store
    and would miss a window that was re-imported under a new id. Two windows with
    the same bounds and the same 34 feature values are the same window.
    """
    return (
        float(window["window_start"]),
        float(window["window_end"]),
        tuple(float(window["features"][name]) for name in FEATURE_NAMES),
    )


def _refusal(
    model_id: str,
    comparison_dataset_id: str,
    alpha: float,
    reference_count: int,
    comparison_count: int,
    reasons: List[str],
) -> Dict[str, Any]:
    """An assessment that declines to conclude, with the reasons stated."""
    return {
        "model_id": model_id,
        "comparison_dataset_id": comparison_dataset_id,
        "status": "insufficient_data",
        "method": DRIFT_METHOD,
        "alpha": float(alpha),
        "reference_window_count": reference_count,
        "comparison_window_count": comparison_count,
        "drifted_feature_count": 0,
        "out_of_range_rate": None,
        "features": [],
        "reasons": reasons,
        "factors": [
            {
                "label": "FACT",
                "factor": "drift_assessment_refused",
                "statement": "Drift could not be assessed from the available data.",
                "evidence": {
                    "reasons": reasons,
                    "reference_window_count": reference_count,
                    "comparison_window_count": comparison_count,
                },
            },
            {
                "label": "INTERPRETATION",
                "factor": "drift_advisory",
                "statement": (
                    "No conclusion about drift is available. This is not evidence that the "
                    "model's training distribution still holds."
                ),
                "evidence": {"status": "insufficient_data"},
            },
        ],
        "created_at": time.time(),
    }


def assess_drift(
    store: SQLiteEventStore,
    model_id: str,
    comparison_dataset_id: str,
    *,
    comparison_store: Any = None,
    alpha: float = DEFAULT_ALPHA,
) -> Dict[str, Any]:
    """
    Compare a model's training feature distributions against a newer normal dataset.

    Read-only: reads the model's metadata, its own training windows as the
    reference sample, and the comparison dataset's windows, and returns a record.
    It writes nothing -- `ml/lifecycle.py` appends the result -- and it cannot
    change a threshold, an artifact, or a model's `active` flag.

    `comparison_store` reads the comparison dataset from a different store than
    the model, which is the normal case: new verified-normal windows are collected
    into a corpus database (`scripts/collect_normal_window.py`) rather than into
    whichever database the model was trained in. Defaults to `store`.

    The comparison dataset must be a *verified-normal* dataset on the same feature
    schema, and must not reuse the model's own training windows: comparing a
    sample against itself is guaranteed to find nothing, which would look like
    reassurance. Any of those failing is an `insufficient_data` refusal with the
    reason named, never a "no drift" result.
    """
    metadata = store.read_ml_model(model_id)
    if metadata is None:
        return _refusal(model_id, comparison_dataset_id, alpha, 0, 0, ["ML model metadata was not found"])

    reasons: List[str] = []
    if metadata["schema_version"] != SCHEMA_VERSION or metadata["schema_hash"] != schema_hash():
        reasons.append("model feature schema is incompatible with this runtime")

    training_ids = list(metadata["training_window_ids"])
    reference_windows = store.read_ml_training_windows_by_ids(training_ids)
    if len(reference_windows) != len(training_ids):
        reasons.append("model training-window provenance is incomplete")

    comparison_windows = (comparison_store or store).read_ml_training_windows(comparison_dataset_id)
    if any(not window["verified_normal"] for window in comparison_windows):
        reasons.append("comparison dataset contains unverified windows")
    if any(window["schema_hash"] != metadata["schema_hash"] for window in comparison_windows):
        reasons.append("comparison dataset uses a different feature schema than the model")
    reference_fingerprints = {_window_fingerprint(window) for window in reference_windows}
    overlap = sum(1 for window in comparison_windows if _window_fingerprint(window) in reference_fingerprints)
    if overlap:
        reasons.append(f"comparison dataset reuses {overlap} of the model's own training windows")

    reference_count, comparison_count = len(reference_windows), len(comparison_windows)
    if reference_count < MIN_REFERENCE_WINDOWS:
        reasons.append(f"fewer than {MIN_REFERENCE_WINDOWS} reference windows")
    if comparison_count < MIN_COMPARISON_WINDOWS:
        reasons.append(f"fewer than {MIN_COMPARISON_WINDOWS} comparison windows")
    if reference_count and comparison_count:
        attainable = _minimum_attainable_p(reference_count, comparison_count)
        if attainable > alpha / float(len(FEATURE_NAMES)):
            reasons.append(
                f"sample sizes cannot attain a Holm-corrected p-value at alpha={alpha} "
                f"(smallest attainable p is {attainable:.3g})"
            )
    if reasons:
        return _refusal(model_id, comparison_dataset_id, alpha, reference_count, comparison_count, reasons)

    reference_columns = _feature_columns(reference_windows)
    comparison_columns = _feature_columns(comparison_windows)
    tests = [two_sample_ks(reference_columns[name], comparison_columns[name]) for name in FEATURE_NAMES]
    corrections = holm_bonferroni([test["p_value"] for test in tests], alpha)

    features: List[Dict[str, Any]] = []
    out_of_range_total = 0
    for name, test, correction in zip(FEATURE_NAMES, tests, corrections):
        reference_values = reference_columns[name]
        comparison_values = comparison_columns[name]
        lower, upper = min(reference_values), max(reference_values)
        out_of_range = sum(1 for value in comparison_values if value < lower or value > upper)
        out_of_range_total += out_of_range
        features.append({
            "feature": name,
            "statistic": test["statistic"],
            "p_value": test["p_value"],
            "p_value_method": test["p_value_method"],
            "holm_rank": correction["holm_rank"],
            "holm_threshold": correction["holm_threshold"],
            "drifted": correction["rejected"],
            "reference_min": lower,
            "reference_max": upper,
            "reference_mean": sum(reference_values) / len(reference_values),
            "comparison_mean": sum(comparison_values) / len(comparison_values),
            "out_of_training_range_count": out_of_range,
        })

    drifted = [item for item in features if item["drifted"]]
    # A plain, non-statistical companion signal: the share of observed comparison
    # values that fall outside the range the model has ever seen. Reported because
    # a feature can move entirely outside its training range without the KS test
    # reaching significance at this sample size, and an operator should see both.
    out_of_range_rate = out_of_range_total / float(comparison_count * len(FEATURE_NAMES))
    return {
        "model_id": model_id,
        "comparison_dataset_id": comparison_dataset_id,
        "status": "drift_detected" if drifted else "no_drift_detected",
        "method": DRIFT_METHOD,
        "alpha": float(alpha),
        "reference_window_count": reference_count,
        "comparison_window_count": comparison_count,
        "drifted_feature_count": len(drifted),
        "out_of_range_rate": out_of_range_rate,
        "features": features,
        "reasons": [],
        # Same FACT/INTERPRETATION split the explainer uses: the statistics are
        # facts, and what they imply for the model is bounded interpretation.
        "factors": [
            {
                "label": "FACT",
                "factor": "feature_distribution_shift",
                "statement": (
                    f"{len(drifted)} of {len(FEATURE_NAMES)} features differ from the model's "
                    f"training distribution at a Holm-corrected alpha of {alpha}."
                ),
                "evidence": {
                    "drifted_features": [item["feature"] for item in drifted],
                    "reference_window_count": reference_count,
                    "comparison_window_count": comparison_count,
                    "method": DRIFT_METHOD,
                },
            },
            {
                "label": "FACT",
                "factor": "out_of_training_range",
                "statement": (
                    f"{out_of_range_rate:.2%} of comparison feature values fall outside the "
                    "range present in the model's training data."
                ),
                "evidence": {"out_of_training_range_rate": out_of_range_rate},
            },
            {
                "label": "INTERPRETATION",
                "factor": "drift_advisory",
                "statement": (
                    "Retraining on current verified-normal data is advisable."
                    if drifted
                    else "No retraining is indicated by this comparison."
                ),
                "evidence": {
                    "limitations": [
                        "Distribution shift is not evidence of compromise; a legitimate "
                        "workload change produces the same signal.",
                        "A retrained model must still pass the activation gate on reviewed-normal "
                        "holdout data before it can influence findings.",
                        "Absence of detected drift is bounded by these sample sizes, not proof "
                        "that the training distribution still holds.",
                    ],
                },
            },
        ],
        "created_at": time.time(),
    }


def drift_summary(assessment: Mapping[str, Any]) -> Dict[str, Any]:
    """The few fields an operator or API caller needs, without the per-feature detail."""
    return {
        "status": assessment["status"],
        "model_id": assessment["model_id"],
        "comparison_dataset_id": assessment["comparison_dataset_id"],
        "drifted_feature_count": assessment["drifted_feature_count"],
        "drifted_features": [item["feature"] for item in assessment["features"] if item["drifted"]],
        "out_of_range_rate": assessment["out_of_range_rate"],
        "reference_window_count": assessment["reference_window_count"],
        "comparison_window_count": assessment["comparison_window_count"],
        "alpha": assessment["alpha"],
        "method": assessment["method"],
        "reasons": list(assessment["reasons"]),
    }
