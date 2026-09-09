"""
Exactness and parity gate for model-faithful anomaly attribution.

The attribution's whole claim is that it explains the *model*, not just the input:
it decomposes the Isolation Forest's own scored quantity (the isolation-path length
`depths`) by the feature tested at each split, and the decomposition reconciles to
that path length exactly. These tests hold it to that -- the integer split total
plus the leaf-correction residual reproduces the scored path length, and the path
attributed is bitwise the path `decision_function` scored, including on values sat
exactly on a split threshold where the float32 routing cast decides the branch.

Scoring -- and therefore attribution -- needs no scikit-learn (only training
does), so the exactness and parity claims are proven directly against a hand-built
NativeIsolationForest in the sklearn-free section at the foot of this file, and run
in every environment. The trained-model tests above additionally exercise the same
claims end-to-end on a real sklearn-exported forest, and skip where sklearn is
absent.
"""

from __future__ import annotations

import numpy as np
import pytest

from ml.attribution import DEFAULT_TOP_N, METHOD, attribute_anomaly
from ml.feature_schema import FEATURE_NAMES, feature_vector
from ml.iforest import NativeIsolationForest
from ml.scoring import MLScorer
from ml.training import (
    SKLEARN_AVAILABLE,
    add_verified_normal_window,
    create_verified_normal_dataset,
    train_isolation_forest,
)
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


def _event(timestamp, event_type="process_exec", **values):
    raw = {"event_type": event_type, "timestamp": timestamp, "pid": 10, "uid": 1000, "comm": "python3", **values}
    return Event.from_raw_json(raw)


def _normal_windows():
    return [
        [_event(100.0, executable="/usr/bin/python3"), _event(102.0, "tcp_connect", dest_ip="127.0.0.1", dest_port=18080)],
        [_event(200.0, executable="/usr/bin/python3"), _event(203.0, "ipc_event", action="pipe_created", kind="anonymous_pipe", success=True, read_fd=3, write_fd=4)],
        [_event(300.0, "auth_session", action="session_opened", result="success", service="sudo", account="root")],
    ]


def _training_windows():
    base = _normal_windows()
    windows = []
    for index in range(10):
        source = base[index % len(base)]
        windows.append([
            Event.from_raw_json({
                **event.to_dict(),
                "event_type": event.event_type.value,
                "timestamp": event.timestamp + index * 10.0,
                "pid": (event.pid or 0) + index,
            })
            for event in source
        ])
    return windows


def _trained_model(tmp_path):
    if not SKLEARN_AVAILABLE:
        pytest.skip("scikit-learn is not installed in the active Python environment")
    store = SQLiteEventStore(str(tmp_path / "ml.db"))
    verification = {"verified_normal": True, "operator": "test", "method": "controlled normal workload"}
    dataset_id = create_verified_normal_dataset(store, "test-normal", verification)
    for index, events in enumerate(_training_windows()):
        add_verified_normal_window(store, dataset_id, events, [index * 10 + offset for offset in range(len(events))], verification)
    metadata = train_isolation_forest(store, dataset_id, str(tmp_path / "models"))
    # The native forest, loaded through the real verify-then-parse path.
    return store, metadata, MLScorer(store, metadata["id"]).model


def _raw_from_depths(model, depths):
    """decision_function's tail verbatim, so the only variable under test is `depths`."""
    depths_arr = np.asarray(depths, dtype=np.float64)
    scores = 2 ** (
        -np.divide(depths_arr, model._denominator, out=np.ones_like(depths_arr), where=model._denominator != 0)
    )
    return -scores - model.offset


def test_attribution_reconciles_to_the_scored_path_length(tmp_path):
    _, _, model = _trained_model(tmp_path)
    for events in _normal_windows():
        vector = np.asarray([feature_vector(events)], dtype=float)
        attribution = model.path_length_attribution(vector)[0]
        # The split total is the exact sum of the per-feature counts -- pure integer
        # bookkeeping, no float slack.
        assert attribution["total_splits"] == sum(attribution["split_counts"].values())
        # And total_splits + leaf_correction reconstructs the scored path length,
        # the reconcile-or-raise identity the whole method rests on.
        reconstructed = attribution["total_splits"] + attribution["leaf_correction"]
        assert reconstructed == pytest.approx(attribution["reconstructed_depths"], abs=1e-9)


def test_attributed_path_is_bitwise_the_scored_path(tmp_path):
    # If attribution re-routed in float64 instead of reusing decision_function's
    # float32 cast, any row within float32 resolution of a threshold would take the
    # other branch and land on a different depth -- a different score. Reconstructing
    # the raw score from the attributed depths and demanding bitwise equality with
    # decision_function proves the attributed path is the path that was scored.
    _, _, model = _trained_model(tmp_path)

    windows = np.asarray([feature_vector(events) for events in _normal_windows()], dtype=float)
    attributed = model.path_length_attribution(windows)
    depths = np.array([row["reconstructed_depths"] for row in attributed])
    assert np.array_equal(_raw_from_depths(model, depths), model.decision_function(windows))

    # A broad seeded sweep across scaled space, where the thresholds live, so many
    # values land near a split boundary.
    rng = np.random.default_rng(20260909)
    scaled = rng.uniform(-4.0, 4.0, size=(256, model.n_features))
    unscaled = model.scaler_mean + model.scaler_scale * scaled
    attributed = model.path_length_attribution(unscaled)
    depths = np.array([row["reconstructed_depths"] for row in attributed])
    assert np.array_equal(_raw_from_depths(model, depths), model.decision_function(unscaled))

    # Rows placed *exactly* on split thresholds and one ULP either side, in both
    # float64 and float32 resolution: the pointed version of the boundary case.
    boundary_rows = []
    for tree in model.trees:
        internal = tree["children_left"] != -1
        for node in np.nonzero(internal)[0][:4]:
            global_feature = int(tree["features"][int(tree["feature"][node])])
            threshold = float(tree["threshold"][node])
            for value in (
                threshold,
                float(np.float64(np.float32(threshold))),
                float(np.nextafter(np.float32(threshold), np.float32(np.inf))),
                np.nextafter(threshold, np.inf),
                np.nextafter(threshold, -np.inf),
            ):
                scaled_row = np.zeros(model.n_features, dtype=float)
                scaled_row[global_feature] = value
                boundary_rows.append(model.scaler_mean + model.scaler_scale * scaled_row)
        if len(boundary_rows) > 400:
            break
    boundary = np.asarray(boundary_rows, dtype=float)
    attributed = model.path_length_attribution(boundary)
    depths = np.array([row["reconstructed_depths"] for row in attributed])
    assert np.array_equal(_raw_from_depths(model, depths), model.decision_function(boundary))


def test_attribution_is_order_independent(tmp_path):
    # Matches the deterministic-scoring guarantee (test_ml_integration.py:94): the
    # window is a set, so reversing its event order must not move any number,
    # attribution included.
    store, metadata, _ = _trained_model(tmp_path)
    scorer = MLScorer(store, metadata["id"], attribute=True)
    events = _normal_windows()[0]
    first = scorer.score(events)
    second = scorer.score(list(reversed(events)))
    assert first == second
    assert first["attribution"] == second["attribution"]


def test_attribution_payload_is_bounded_named_and_reconciles(tmp_path):
    _, _, model = _trained_model(tmp_path)
    row = feature_vector(_normal_windows()[0])
    attribution = attribute_anomaly(model, row, FEATURE_NAMES)

    assert attribution["method"] == METHOD
    assert attribution["reconciles"] is True
    assert attribution["baseline_path_length"] > 0.0

    features = attribution["features"]
    assert len(features) <= DEFAULT_TOP_N
    assert attribution["reported_feature_count"] == len(features)
    assert attribution["attributed_feature_count"] >= attribution["reported_feature_count"]
    # Every reported feature is a real schema feature, never a fabricated index.
    assert all(item["feature"] in FEATURE_NAMES for item in features)
    # Deterministically ranked: split_count descending, feature name as tie-break.
    order = [(-item["split_count"], item["feature"]) for item in features]
    assert order == sorted(order)
    # Shares over the reported head cannot exceed the whole path's splits.
    assert sum(item["split_share"] for item in features) <= 1.0 + 1e-9
    assert all(item["split_count"] >= 1 for item in features)


def test_attribution_respects_top_n_cap(tmp_path):
    _, _, model = _trained_model(tmp_path)
    row = feature_vector(_normal_windows()[0])
    capped = attribute_anomaly(model, row, FEATURE_NAMES, top_n=2)
    assert len(capped["features"]) <= 2
    # Capping the display never touches the reconciliation numbers.
    full = attribute_anomaly(model, row, FEATURE_NAMES)
    assert capped["total_splits"] == full["total_splits"]
    assert capped["reconciles"] is True


def test_attribution_rejects_mismatched_feature_names(tmp_path):
    _, _, model = _trained_model(tmp_path)
    row = feature_vector(_normal_windows()[0])
    with pytest.raises(ValueError, match="feature_names"):
        attribute_anomaly(model, row, FEATURE_NAMES[:-1])


# ---------------------------------------------------------------------------
# sklearn-free exactness gate.
#
# The two load-bearing claims -- the split decomposition reconciles to the scored
# path length, and the attributed path is bitwise the scored path -- are properties
# of NativeIsolationForest, which by design scores with numpy alone. So they are
# provable by building a forest straight from tree arrays, the same shape
# ml/artifact.py hands the class once the checksum verifies. These run everywhere,
# sklearn present or not, and pin the *exact* per-feature counts against a hand-
# computed expectation the trained-model tests cannot (they never see the trees).
# ---------------------------------------------------------------------------


def _tree(children_left, children_right, feature, threshold, n_node_samples, features):
    return {
        "children_left": np.asarray(children_left, dtype=np.int64),
        "children_right": np.asarray(children_right, dtype=np.int64),
        "feature": np.asarray(feature, dtype=np.int64),
        "threshold": np.asarray(threshold, dtype=np.float64),
        "n_node_samples": np.asarray(n_node_samples, dtype=np.int64),
        "features": np.asarray(features, dtype=np.int64),
    }


def _leaf_tree(n_features, *, samples=1, features=None):
    """A single-node (root-is-leaf) tree: no splits, only a leaf correction."""
    features = list(range(n_features)) if features is None else list(features)
    return _tree([-1], [-1], [-2], [-2.0], [samples], features)


def _caterpillar(local_features, n_features, *, threshold=1e9, leaf_samples=1, features=None):
    """
    A left-spine tree that tests `local_features` in order down its left edge.

    Each internal node's right child is a leaf; the left edge runs split -> split
    -> ... -> leaf. Routed with the default huge threshold against a zero row,
    every comparison goes left, so the scored path tests exactly `local_features`
    once each -- a known-answer path the assertions check by hand. The terminal
    leaf carries `leaf_samples`, so its correction term c(leaf_samples) is
    controllable; `features` may be a non-identity permutation to prove the split
    feature is recorded in *global* schema indices.
    """
    k = len(local_features)
    assert k >= 1
    n_nodes = 2 * k + 1
    children_left = [-1] * n_nodes
    children_right = [-1] * n_nodes
    feature = [-2] * n_nodes
    threshold_arr = [-2.0] * n_nodes
    n_node_samples = [1] * n_nodes
    leaf_cursor = k
    for i in range(k):
        feature[i] = int(local_features[i])
        threshold_arr[i] = float(threshold)
        children_right[i] = leaf_cursor  # right child: a leaf
        leaf_cursor += 1
        if i < k - 1:
            children_left[i] = i + 1  # left child: the next split
        else:
            children_left[i] = leaf_cursor  # left child: the terminal leaf
            n_node_samples[leaf_cursor] = leaf_samples
            leaf_cursor += 1
    features = list(range(n_features)) if features is None else list(features)
    return _tree(children_left, children_right, feature, threshold_arr, n_node_samples, features)


def _forest(trees, *, n_features, mean=None, scale=None, offset=0.5, max_samples=256):
    mean = np.zeros(n_features, dtype=float) if mean is None else np.asarray(mean, dtype=float)
    scale = np.ones(n_features, dtype=float) if scale is None else np.asarray(scale, dtype=float)
    return NativeIsolationForest(
        trees, offset=offset, max_samples=max_samples, scaler_mean=mean, scaler_scale=scale
    )


def _many_feature_model(n_features):
    # Caterpillars whose union covers 12 distinct features with varied counts, so
    # more features are attributed than a top-N cap reports.
    trees = [
        _caterpillar([0, 1, 2, 3, 4, 5], n_features, leaf_samples=4),
        _caterpillar([3, 4, 5, 6, 7, 8], n_features, leaf_samples=6),
        _caterpillar([6, 7, 8, 9, 10, 11], n_features, leaf_samples=2),
        _caterpillar([0, 2, 4, 6, 8, 10], n_features, leaf_samples=8),
    ]
    return _forest(trees, n_features=n_features)


def test_synthetic_reconciliation_and_exact_split_counts():
    # Three caterpillars over 6 features plus a bare leaf tree, scored on a zero
    # row: every comparison goes left, so the path tests each tree's feature list
    # once and the exact split_counts are known in advance.
    n_features = 6
    trees = [
        _caterpillar([0, 1, 2], n_features, leaf_samples=1),      # +3 splits, c(1)=0
        _caterpillar([2, 3], n_features, leaf_samples=10),        # +2 splits, c(10)>0
        _caterpillar([0, 5, 4, 2], n_features, leaf_samples=2),   # +4 splits, c(2)=1
        _leaf_tree(n_features, samples=8),                        # +0 splits, c(8)>0
    ]
    model = _forest(trees, n_features=n_features)
    row = np.zeros((1, n_features), dtype=float)
    attribution = model.path_length_attribution(row)[0]

    expected = {0: 2, 1: 1, 2: 3, 3: 1, 4: 1, 5: 1}
    assert attribution["split_counts"] == expected
    assert attribution["total_splits"] == sum(expected.values()) == 9
    # total_splits + leaf_correction reconstructs the scored path length exactly.
    reconstructed = attribution["total_splits"] + attribution["leaf_correction"]
    assert reconstructed == pytest.approx(attribution["reconstructed_depths"], abs=1e-9)
    # And that path length reproduces the score decision_function computed, bitwise.
    assert np.array_equal(
        _raw_from_depths(model, [attribution["reconstructed_depths"]]),
        model.decision_function(row),
    )


def test_synthetic_split_counts_use_global_feature_indices():
    # A non-identity feature permutation: the split at local index l tests global
    # feature features[l], and the counts must be reported in global indices so
    # they name to the shared schema and are comparable across trees.
    n_features = 4
    perm = [2, 0, 3, 1]
    model = _forest([_caterpillar([0, 1, 2], n_features, features=perm)], n_features=n_features)
    attribution = model.path_length_attribution(np.zeros((1, n_features), dtype=float))[0]
    # locals 0,1,2 -> globals perm[0],perm[1],perm[2] = 2,0,3
    assert attribution["split_counts"] == {2: 1, 0: 1, 3: 1}


def test_synthetic_routing_parity_on_float32_boundaries():
    # Non-float32-exact thresholds and an identity scaler, then rows placed exactly
    # on each threshold and one ULP either side in both float32 and float64. If
    # path_length_attribution routed in float64 instead of reusing decision_function's
    # float32 cast, these rows would take the other branch and diverge; bitwise
    # equality of the reconstructed raw score proves it does not.
    n_features = 4
    trees = [
        _tree(
            children_left=[1, 3, 5, -1, -1, -1, -1],
            children_right=[2, 4, 6, -1, -1, -1, -1],
            feature=[0, 1, 2, -2, -2, -2, -2],
            threshold=[0.1, 1.0 / 3.0, 0.2, -2.0, -2.0, -2.0, -2.0],
            n_node_samples=[7, 3, 3, 1, 2, 1, 5],
            features=[0, 1, 2, 3],
        ),
        _tree(
            children_left=[1, -1, 3, -1, -1],
            children_right=[2, -1, 4, -1, -1],
            feature=[3, -2, 0, -2, -2],
            threshold=[2.0 / 7.0, -2.0, 0.7, -2.0, -2.0],
            n_node_samples=[6, 4, 2, 1, 1],
            features=[0, 1, 2, 3],
        ),
    ]
    model = _forest(trees, n_features=n_features)

    boundary_rows = []
    for tree in model.trees:
        internal = tree["children_left"] != -1
        for node in np.nonzero(internal)[0]:
            global_feature = int(tree["features"][int(tree["feature"][node])])
            threshold = float(tree["threshold"][node])
            for value in (
                threshold,
                float(np.float64(np.float32(threshold))),
                float(np.nextafter(np.float32(threshold), np.float32(np.inf))),
                np.nextafter(threshold, np.inf),
                np.nextafter(threshold, -np.inf),
            ):
                scaled_row = np.zeros(n_features, dtype=float)
                scaled_row[global_feature] = value
                boundary_rows.append(model.scaler_mean + model.scaler_scale * scaled_row)
    boundary = np.asarray(boundary_rows, dtype=float)
    attributed = model.path_length_attribution(boundary)
    depths = np.array([row["reconstructed_depths"] for row in attributed])
    assert np.array_equal(_raw_from_depths(model, depths), model.decision_function(boundary))


def test_synthetic_degenerate_leaf_tree_contributes_only_leaf_correction():
    n_features = 3
    model = _forest(
        [_caterpillar([0, 1], n_features, leaf_samples=1), _leaf_tree(n_features, samples=16)],
        n_features=n_features,
    )
    attribution = model.path_length_attribution(np.zeros((1, n_features), dtype=float))[0]
    # Two splits from the caterpillar, none from the leaf tree.
    assert attribution["total_splits"] == 2
    assert attribution["split_counts"] == {0: 1, 1: 1}
    # The leaf tree's entire contribution is its correction, carried in the residual.
    assert attribution["leaf_correction"] > 0.0
    assert attribution["total_splits"] + attribution["leaf_correction"] == pytest.approx(
        attribution["reconstructed_depths"], abs=1e-9
    )


def test_synthetic_attribute_anomaly_is_bounded_named_and_reconciles():
    names = list(FEATURE_NAMES)
    n_features = len(names)
    model = _many_feature_model(n_features)
    attribution = attribute_anomaly(model, [0.0] * n_features, names)

    assert attribution["method"] == METHOD
    assert attribution["reconciles"] is True
    assert attribution["baseline_path_length"] > 0.0

    features = attribution["features"]
    assert 0 < len(features) <= DEFAULT_TOP_N
    assert attribution["reported_feature_count"] == len(features)
    # 12 distinct features participate; the cap reports only the top DEFAULT_TOP_N.
    assert attribution["attributed_feature_count"] == 12
    assert attribution["attributed_feature_count"] > attribution["reported_feature_count"]
    # Every reported feature is a provided name, never a fabricated index.
    assert all(item["feature"] in names for item in features)
    # Deterministically ranked: split_count descending, feature name as tie-break.
    order = [(-item["split_count"], item["feature"]) for item in features]
    assert order == sorted(order)
    # Shares over the reported head cannot exceed the whole path's splits.
    assert sum(item["split_share"] for item in features) <= 1.0 + 1e-9
    assert all(item["split_count"] >= 1 for item in features)


def test_synthetic_attribute_anomaly_respects_top_n_and_rejects_bad_names():
    names = list(FEATURE_NAMES)
    n_features = len(names)
    model = _many_feature_model(n_features)
    row = [0.0] * n_features
    capped = attribute_anomaly(model, row, names, top_n=3)
    full = attribute_anomaly(model, row, names)
    assert len(capped["features"]) == 3
    # Capping the display never touches the reconciliation numbers.
    assert capped["total_splits"] == full["total_splits"]
    assert capped["reconciles"] is True
    with pytest.raises(ValueError, match="feature_names"):
        attribute_anomaly(model, row, names[:-1])


def test_synthetic_attribution_is_deterministic():
    n_features = len(FEATURE_NAMES)
    model = _many_feature_model(n_features)
    names = list(FEATURE_NAMES)
    assert attribute_anomaly(model, [0.0] * n_features, names) == attribute_anomaly(model, [0.0] * n_features, names)
    twice = model.path_length_attribution(np.zeros((2, n_features), dtype=float))
    assert twice[0] == twice[1]
