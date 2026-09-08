"""
Tests for drift detection: the statistics, the refusals, and the read-only posture.

Three layers, none of which needs scikit-learn -- drift compares stored feature
values against stored feature values, so it runs wherever the scorer does:

* **The statistics.** The exact two-sample KS p-values are pinned as literals,
  verified offline against `scipy.stats.ks_2samp(..., method="exact")` (agreement
  to 3.3e-16 on the pinned cases). The asymptotic fallback is checked for the one
  property a fallback needs -- that where a decision is made it errs towards *not*
  reporting drift -- rather than for closeness, and the branch boundary between the
  two is pinned so a change to `_EXACT_LATTICE_CELLS` shows up as a test failure
  instead of a silent switch of method. Two regressions guard sizes that used to
  raise `OverflowError`.
* **The refusals.** Every `insufficient_data` path, each asserted on the reason
  string an operator would read. A refusal must never be reachable as
  "no_drift_detected", because the two look identical on a dashboard and mean
  opposite things.
* **The posture.** `assess_drift` writes nothing: every table's row count is
  snapshotted before and after. Recording is `ml/lifecycle.py`'s job, and drift
  cannot activate, deactivate, or re-threshold a model.

Fixtures build training windows directly through the store rather than through
`add_verified_normal_window`, because the tests need control over the feature
*distributions* and window extraction gives control only over the events.
"""

import sqlite3
from math import gcd

import pytest

from ml.drift import (
    DEFAULT_ALPHA,
    DRIFT_METHOD,
    MIN_COMPARISON_WINDOWS,
    MIN_REFERENCE_WINDOWS,
    _asymptotic_two_sided_p,
    _exact_two_sided_p,
    _minimum_attainable_p,
    _window_fingerprint,
    assess_drift,
    drift_summary,
    holm_bonferroni,
    two_sample_ks,
)
from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, schema_hash
from storage.sqlite_store import SQLiteEventStore

# The Holm threshold the first-ranked feature is compared against at the default
# alpha: 0.01 / 34. Written out so the tests below fail loudly if the feature
# schema grows, rather than quietly testing a different correction.
FIRST_HOLM_THRESHOLD = DEFAULT_ALPHA / len(FEATURE_NAMES)


def _features(**overrides):
    values = {name: 1.0 for name in FEATURE_NAMES}
    values.update(overrides)
    return values


def _store(tmp_path):
    return SQLiteEventStore(str(tmp_path / "drift.db"))


def _dataset(store, name, schema=None):
    dataset_id = f"verified-normal-{name}"
    store.create_ml_dataset({
        "id": dataset_id,
        "name": name,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema or schema_hash(),
        "environment": {"host": "test-host"},
        "verification": {"verified_normal": True, "operator": "test"},
        "created_at": 1000.0,
    })
    return dataset_id


def _window(store, dataset_id, start, features, schema=None):
    return store.write_ml_training_window({
        "dataset_id": dataset_id,
        "window_start": start,
        "window_end": start + 60.0,
        "event_ids": [int(start)],
        "features": features,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema or schema_hash(),
        "collector_context": {"source": "test"},
        "verified_normal": True,
        "verification": {"verified_normal": True, "operator": "test"},
        "created_at": start,
    })


def _model(store, window_ids, model_id="model-1", schema=None):
    store.write_ml_model({
        "id": model_id,
        "version": "1",
        "algorithm": "IsolationForest",
        "hyperparameters": {"n_estimators": 100},
        # Never opened: drift reads stored feature values, not the artifact.
        "artifact_path": "/nonexistent/model.model.json",
        "artifact_checksum": "0" * 64,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema or schema_hash(),
        "training_window_ids": window_ids,
        "runtime": {"python": "3.11"},
        "evaluation": {},
        "active": False,
        "created_at": 2000.0,
    })
    return model_id


def _reference(store, count=12):
    """`count` windows whose `event_count` runs 10.0 upward, everything else flat."""
    dataset_id = _dataset(store, "train")
    return [
        _window(store, dataset_id, 1000.0 + index * 60.0, _features(event_count=10.0 + index))
        for index in range(count)
    ]


def _comparison(store, name, base, count=40, span=None):
    dataset_id = _dataset(store, name)
    for index in range(count):
        value = base + (index if span is None else index % span)
        _window(store, dataset_id, 500000.0 + index * 60.0, _features(event_count=value))
    return dataset_id


def _table_counts(path):
    """Row count of every table, for proving a read path wrote nothing."""
    connection = sqlite3.connect(path)
    try:
        tables = [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if not row[0].startswith("sqlite_")
        ]
        return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
    finally:
        connection.close()


# --- the statistics ------------------------------------------------------------

def test_exact_ks_p_values_match_the_published_reference():
    # Complete separation of 12 against 40: D = 1, and exactly two of the
    # C(52,12) orderings achieve it. scipy's exact method agrees to 3.3e-16.
    complete = two_sample_ks([10.0 + index for index in range(12)], [500.0 + index for index in range(40)])
    assert complete == {
        "statistic": 1.0,
        "p_value": 9.690889368917586e-12,
        "p_value_method": "exact_lattice",
    }
    assert complete["p_value"] == _minimum_attainable_p(12, 40)
    # The same two samples drawn from one distribution: D = 1/15, p ~ 1.
    overlapping = two_sample_ks(
        [10.0 + index for index in range(12)], [10.0 + (index % 12) for index in range(40)]
    )
    assert overlapping == {
        "statistic": 0.06666666666666667,
        "p_value": 0.9999999987595661,
        "p_value_method": "exact_lattice",
    }


def test_ks_refuses_an_empty_sample():
    with pytest.raises(ValueError, match="non-empty sample on both sides"):
        two_sample_ks([1.0, 2.0], [])


def test_exact_branch_boundary_is_where_the_lattice_bound_puts_it():
    # (n+1)*(m+1) <= 400_000: 632*632 = 399_424 fits, 633*633 = 400_689 does not.
    small = two_sample_ks([float(v) for v in range(631)], [v + 0.5 for v in range(631)])
    large = two_sample_ks([float(v) for v in range(632)], [v + 0.5 for v in range(632)])
    assert small["p_value_method"] == "exact_lattice"
    assert large["p_value_method"] == "kolmogorov_asymptotic"


def test_large_balanced_samples_do_not_overflow():
    """
    Regression: `C(1262,631)` is a 379-digit integer.

    Both the exact lattice p-value and the minimum-attainable-p check used to
    convert such a value to float first, which raises `OverflowError` -- so a
    comparison of a few hundred windows a side crashed instead of returning a
    result. Balanced sizes from 515 up are affected, which is under nine hours of
    60-second windows.
    """
    result = two_sample_ks([float(v) for v in range(631)], [v + 0.5 for v in range(631)])
    assert result["p_value_method"] == "exact_lattice"
    assert 0.0 <= result["p_value"] <= 1.0
    # Underflow to 0.0 is the correct answer, not a swallowed error: samples this
    # large can attain any threshold, so the refusal must not fire.
    assert _minimum_attainable_p(631, 631) == 0.0
    assert _minimum_attainable_p(1440, 1440) == 0.0
    assert _minimum_attainable_p(12, 40) == 9.690889368917586e-12


@pytest.mark.parametrize(
    ("n", "m", "max_overshoot"),
    [(12, 40, 0.0175), (30, 90, 0.0051), (60, 60, 0.00043)],
)
def test_asymptotic_fallback_never_under_reports_a_significant_p_value(n, m, max_overshoot):
    """
    The fallback errs towards silence in the region where a decision is made.

    Every Holm threshold is at or below `alpha` (0.01), so only p-values near zero
    can change an outcome. Over every *attainable* statistic -- the integer
    statistic is always a multiple of gcd(n, m), and scanning the unreachable ones
    invents deviations that no data can produce -- whose exact p-value is at or
    below 0.05, the asymptotic form is never smaller than the exact one. It can
    therefore miss drift, never manufacture it.
    """
    step = gcd(n, m)
    compared = 0
    for statistic in range(step, n * m + 1, step):
        exact = _exact_two_sided_p(n, m, statistic)
        if exact > 0.05:
            continue
        compared += 1
        difference = _asymptotic_two_sided_p(n, m, statistic) - exact
        assert difference >= 0.0
        assert difference <= max_overshoot
    assert compared > 0


def test_holm_bonferroni_steps_down_and_preserves_input_order():
    records = holm_bonferroni([0.04, 0.001, 0.2], 0.05)
    assert records == [
        {"holm_rank": 1, "holm_threshold": 0.025, "rejected": False},
        {"holm_rank": 0, "holm_threshold": 0.016666666666666666, "rejected": True},
        {"holm_rank": 2, "holm_threshold": 0.05, "rejected": False},
    ]
    # 0.04 fails its own threshold of 0.025, which stops the procedure -- so 0.2
    # is retained even though its threshold (0.05) is the loosest of the three.
    assert holm_bonferroni([0.001, 0.002], 0.05) == [
        {"holm_rank": 0, "holm_threshold": 0.025, "rejected": True},
        {"holm_rank": 1, "holm_threshold": 0.05, "rejected": True},
    ]


# --- assessments ---------------------------------------------------------------

def test_shifted_feature_is_reported_as_drift_with_its_statistics(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    assessment = assess_drift(store, model_id, dataset_id)
    assert set(assessment) == {
        "model_id", "comparison_dataset_id", "status", "method", "alpha",
        "reference_window_count", "comparison_window_count", "drifted_feature_count",
        "out_of_range_rate", "features", "reasons", "factors", "created_at",
    }
    assert assessment["status"] == "drift_detected"
    assert assessment["method"] == DRIFT_METHOD
    assert assessment["alpha"] == DEFAULT_ALPHA
    assert assessment["reference_window_count"] == 12
    assert assessment["comparison_window_count"] == 40
    assert assessment["reasons"] == []
    # One feature moved; the other 33 were held constant on both sides.
    assert assessment["drifted_feature_count"] == 1
    assert [item["feature"] for item in assessment["features"] if item["drifted"]] == ["event_count"]
    assert len(assessment["features"]) == len(FEATURE_NAMES)
    # Every comparison window is out of range on that one feature: 1/34.
    assert assessment["out_of_range_rate"] == 1 / 34
    shifted = next(item for item in assessment["features"] if item["feature"] == "event_count")
    assert set(shifted) == {
        "feature", "statistic", "p_value", "p_value_method", "holm_rank", "holm_threshold",
        "drifted", "reference_min", "reference_max", "reference_mean", "comparison_mean",
        "out_of_training_range_count",
    }
    assert shifted["statistic"] == 1.0
    assert shifted["p_value"] == 9.690889368917586e-12
    assert shifted["p_value_method"] == "exact_lattice"
    assert shifted["holm_rank"] == 0
    assert shifted["holm_threshold"] == FIRST_HOLM_THRESHOLD == 0.00029411764705882356
    assert shifted["reference_min"] == 10.0
    assert shifted["reference_max"] == 21.0
    assert shifted["reference_mean"] == 15.5
    assert shifted["comparison_mean"] == 519.5
    assert shifted["out_of_training_range_count"] == 40


def test_same_distribution_reports_no_drift(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "same", 10.0, span=12)
    assessment = assess_drift(store, model_id, dataset_id)
    assert assessment["status"] == "no_drift_detected"
    assert assessment["drifted_feature_count"] == 0
    assert assessment["out_of_range_rate"] == 0.0
    assert assessment["reasons"] == []
    # Every feature still carries a full record: "no drift" has to be auditable.
    assert all(item["p_value"] > item["holm_threshold"] for item in assessment["features"])
    assert all(item["out_of_training_range_count"] == 0 for item in assessment["features"])


def test_drift_factors_separate_fact_from_interpretation(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    assessment = assess_drift(store, model_id, _comparison(store, "shifted", 500.0))
    labels = [(factor["label"], factor["factor"]) for factor in assessment["factors"]]
    assert labels == [
        ("FACT", "feature_distribution_shift"),
        ("FACT", "out_of_training_range"),
        ("INTERPRETATION", "drift_advisory"),
    ]
    advisory = assessment["factors"][-1]
    # Every factor has the same shape as an explainer contributing factor, so the
    # dashboard renders them without a drift-specific branch.
    assert all(set(factor) == {"label", "factor", "statement", "evidence"} for factor in assessment["factors"])
    # The advisory is bounded in writing: drift is not a verdict on the model, and
    # nothing here retrains, re-thresholds, or deactivates anything.
    limitations = advisory["evidence"]["limitations"]
    assert len(limitations) == 3
    assert all(isinstance(limitation, str) and limitation for limitation in limitations)
    assert any("activation gate" in limitation for limitation in limitations)


def test_drift_summary_is_the_assessment_without_the_per_feature_detail(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    assessment = assess_drift(store, model_id, dataset_id)
    assert drift_summary(assessment) == {
        "status": "drift_detected",
        "model_id": model_id,
        "comparison_dataset_id": dataset_id,
        "drifted_feature_count": 1,
        "drifted_features": ["event_count"],
        "out_of_range_rate": 1 / 34,
        "reference_window_count": 12,
        "comparison_window_count": 40,
        "alpha": DEFAULT_ALPHA,
        "method": DRIFT_METHOD,
        "reasons": [],
    }


def test_assess_drift_writes_nothing(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    before = _table_counts(store.db_path)
    assessment = assess_drift(store, model_id, dataset_id)
    assert assessment["status"] == "drift_detected"
    assert _table_counts(store.db_path) == before
    # In particular: no assessment row, and no lifecycle transition. Appending is
    # `ml/lifecycle.py`'s job, and it is the only thing that touches the chain.
    assert store.read_ml_drift_assessments() == []
    assert store.read_ml_lifecycle() == []


# --- refusals ------------------------------------------------------------------

def _reasons(store, model_id, dataset_id, **kwargs):
    assessment = assess_drift(store, model_id, dataset_id, **kwargs)
    assert assessment["status"] == "insufficient_data"
    assert assessment["drifted_feature_count"] == 0
    assert assessment["out_of_range_rate"] is None
    assert assessment["features"] == []
    return assessment["reasons"]


def test_unknown_model_is_refused(tmp_path):
    store = _store(tmp_path)
    _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    assert _reasons(store, "no-such-model", dataset_id) == ["ML model metadata was not found"]


def test_model_on_a_foreign_feature_schema_is_refused(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store), schema="f" * 64)
    dataset_id = _comparison(store, "shifted", 500.0)
    reasons = _reasons(store, model_id, dataset_id)
    assert "model feature schema is incompatible with this runtime" in reasons


def test_missing_training_window_provenance_is_refused(tmp_path):
    store = _store(tmp_path)
    window_ids = _reference(store)
    model_id = _model(store, [*window_ids, 999999])
    dataset_id = _comparison(store, "shifted", 500.0)
    assert "model training-window provenance is incomplete" in _reasons(store, model_id, dataset_id)


def test_comparison_dataset_on_a_different_schema_is_refused(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    foreign = _dataset(store, "foreign", schema="f" * 64)
    for index in range(MIN_COMPARISON_WINDOWS + 10):
        _window(store, foreign, 700000.0 + index * 60.0, _features(), schema="f" * 64)
    reasons = _reasons(store, model_id, foreign)
    assert "comparison dataset uses a different feature schema than the model" in reasons


def test_unverified_comparison_windows_are_refused(tmp_path):
    """
    The store refuses to persist an unverified training window, so the unverified
    case can only arrive through the `comparison_store` seam that
    `scripts/ml_drift_check.py` uses to read a separate corpus database. Drift must
    re-check the flag rather than trusting the source that handed it over.
    """
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    windows = store.read_ml_training_windows(dataset_id)
    tainted = [{**window, "verified_normal": False} for window in windows]

    class _UnverifiedSource:
        def read_ml_training_windows(self, requested):
            assert requested == dataset_id
            return tainted

    reasons = _reasons(store, model_id, dataset_id, comparison_store=_UnverifiedSource())
    assert "comparison dataset contains unverified windows" in reasons


def test_comparison_dataset_reusing_training_windows_is_refused(tmp_path):
    """
    Overlap is detected by content, not row id: the same window re-imported into
    another dataset gets a new id, and comparing a sample against itself is
    guaranteed to find nothing -- which reads as reassurance.
    """
    store = _store(tmp_path)
    window_ids = _reference(store)
    model_id = _model(store, window_ids)
    reused = _dataset(store, "reused")
    for index in range(MIN_COMPARISON_WINDOWS + 10):
        # The first 12 are byte-identical copies of the training windows.
        start = 1000.0 + index * 60.0 if index < 12 else 800000.0 + index * 60.0
        _window(store, reused, start, _features(event_count=10.0 + index))
    reasons = _reasons(store, model_id, reused)
    assert "comparison dataset reuses 12 of the model's own training windows" in reasons
    # Independent of the ids, which differ between the two datasets.
    original = store.read_ml_training_windows_by_ids(window_ids)
    copies = [window for window in store.read_ml_training_windows(reused) if window["window_start"] < 500000.0]
    assert {window["id"] for window in original}.isdisjoint({window["id"] for window in copies})
    assert {_window_fingerprint(window) for window in original} == {
        _window_fingerprint(window) for window in copies
    }


def test_small_samples_are_refused_on_both_floors(tmp_path):
    store = _store(tmp_path)
    model_id = _model(store, _reference(store, count=MIN_REFERENCE_WINDOWS - 1))
    sparse = _dataset(store, "sparse")
    for index in range(5):
        _window(store, sparse, 800000.0 + index * 60.0, _features(event_count=float(index)))
    reasons = _reasons(store, model_id, sparse)
    assert f"fewer than {MIN_REFERENCE_WINDOWS} reference windows" in reasons
    assert f"fewer than {MIN_COMPARISON_WINDOWS} comparison windows" in reasons


def test_sample_sizes_that_cannot_reach_the_corrected_alpha_are_refused(tmp_path):
    """
    Both window floors pass here; the arithmetic check refuses anyway.

    12 against 40 cannot produce a p-value below 2.94e-14 no matter how far the
    distributions separate, so at that alpha "no drift" would be a statement about
    the sample size, not about the data.
    """
    store = _store(tmp_path)
    model_id = _model(store, _reference(store))
    dataset_id = _comparison(store, "shifted", 500.0)
    reasons = _reasons(store, model_id, dataset_id, alpha=1e-12)
    assert reasons == [
        "sample sizes cannot attain a Holm-corrected p-value at alpha=1e-12 "
        "(smallest attainable p is 9.69e-12)"
    ]
    # The same data at the default alpha does reach a conclusion.
    assert assess_drift(store, model_id, dataset_id)["status"] == "drift_detected"


def test_refusal_factors_state_that_no_conclusion_is_available(tmp_path):
    store = _store(tmp_path)
    assessment = assess_drift(store, "no-such-model", "no-such-dataset")
    labels = [(factor["label"], factor["factor"]) for factor in assessment["factors"]]
    assert labels == [("FACT", "drift_assessment_refused"), ("INTERPRETATION", "drift_advisory")]
    # The distinction that matters operationally: a refusal is not a clean bill of
    # health, and the record says so in the words an operator reads.
    assert "not evidence" in assessment["factors"][-1]["statement"]
