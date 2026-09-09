"""
Isolation Forest scoring in plain numpy, bitwise-identical to scikit-learn.

Why this exists
---------------
The trained model used to be persisted with `pickle`, which makes loading a
model artifact equivalent to executing whatever the artifact says. The checksum
check in front of the load mitigated that, but "we verify a hash before handing
bytes to a code-executing deserializer" is a weaker property than "the loader
cannot execute code at all". This module removes the deserializer: an Isolation
Forest is reduced to the numbers that define it -- tree topology, split features
and thresholds, per-node sample counts, and the scaler's mean/scale -- and
scoring is arithmetic over those numbers.

The consequence that makes it safe to swap: scores do not change. `_decisions`
reimplements `IsolationForest.decision_function` operation for operation, in
float64, and `tests/test_ml_artifact.py` asserts bitwise equality against
scikit-learn on a fitted model. Removing pickle is therefore not a behaviour
change -- `is_anomaly`, `raw_score`, and `normalized_score` are the same values a
pickled artifact produced.

A second consequence: scikit-learn is no longer needed to *score*, only to
*train*. The scoring path depends on numpy alone.

Reference (scikit-learn 1.9, sklearn/ensemble/_iforest.py)
----------------------------------------------------------
    decision_function(X) = score_samples(X) - offset_
    score_samples(X)     = -2 ** (-depths / (n_estimators * c(max_samples)))
    depths               = sum over trees of
                             node_depth(leaf) + c(n_node_samples[leaf]) - 1
    c(n)                 = 0                                  n <= 1
                           1                                  n == 2
                           2*(ln(n-1) + gamma) - 2*(n-1)/n     n >  2

`node_depth` counts the root as 1 (sklearn's `compute_node_depths`), and `c` is
sklearn's `_average_path_length`. The three-way split in `c` is reproduced
exactly, including the `n <= 1` case, because a leaf reached by a single training
sample contributes no correction term. Routing reproduces sklearn's float32 cast
of X (see `decision_function`), which is what makes the parity bitwise rather
than merely close.
"""

from typing import Any, Mapping, Sequence

import numpy as np

# The arrays that define one tree. Fixed order: `ARRAY_KEYS` drives both the
# export and the load-time validation, so a tree cannot be serialized with a
# member missing and silently score as something else.
TREE_ARRAY_KEYS: Sequence[str] = (
    "children_left",
    "children_right",
    "feature",
    "threshold",
    "n_node_samples",
    "features",
)

# Integer-typed tree arrays; `threshold` is the only float64 member.
_TREE_INT_KEYS = frozenset({"children_left", "children_right", "feature", "n_node_samples", "features"})

# np.euler_gamma, written out so the constant is visible and the module does not
# depend on numpy exposing it. Asserted equal to np.euler_gamma in the tests.
EULER_GAMMA = 0.5772156649015329


class NativeIsolationForestError(ValueError):
    pass


def average_path_length(n_samples_leaf: Any) -> np.ndarray:
    """
    sklearn's `_average_path_length`: expected path length of an unsuccessful BST search.

    The correction term added at each leaf, accounting for the subtree that was
    not built because the tree hit its depth limit. Reproduced with sklearn's
    exact three-way split so the sum of corrections matches term for term.
    """
    counts = np.asarray(n_samples_leaf, dtype=np.float64)
    lengths = np.zeros(counts.shape, dtype=np.float64)
    lengths[counts == 2] = 1.0
    beyond = counts > 2
    remaining = counts[beyond]
    lengths[beyond] = (
        2.0 * (np.log(remaining - 1.0) + EULER_GAMMA) - 2.0 * (remaining - 1.0) / remaining
    )
    return lengths


def node_depths(children_left: np.ndarray, children_right: np.ndarray) -> np.ndarray:
    """
    Depth of every node, root counted as 1 (sklearn's `compute_node_depths`).

    Iterative rather than recursive: a tree built from many training windows can
    be deeper than Python's recursion limit, and the depth of every node is
    needed anyway, so an explicit stack is both safer and no slower.
    """
    depths = np.zeros(children_left.shape[0], dtype=np.int64)
    stack = [(0, 1)]
    while stack:
        node, depth = stack.pop()
        depths[node] = depth
        left = int(children_left[node])
        if left != -1:
            stack.append((left, depth + 1))
            stack.append((int(children_right[node]), depth + 1))
    return depths


def _apply_tree(tree: Mapping[str, np.ndarray], samples: np.ndarray) -> np.ndarray:
    """Route every row to its leaf, breadth-wise over the still-descending rows."""
    children_left = tree["children_left"]
    children_right = tree["children_right"]
    feature = tree["feature"]
    threshold = tree["threshold"]
    node = np.zeros(samples.shape[0], dtype=np.int64)
    descending = children_left[node] != -1
    while descending.any():
        rows = np.nonzero(descending)[0]
        current = node[rows]
        # `<=` is scikit-learn's split convention; flipping it would silently
        # reroute every sample that lands exactly on a threshold.
        go_left = samples[rows, feature[current]] <= threshold[current]
        node[rows] = np.where(go_left, children_left[current], children_right[current])
        descending = children_left[node] != -1
    return node


class NativeIsolationForest:
    """
    A fitted Isolation Forest plus its StandardScaler, as numbers only.

    Constructed from validated arrays (see `ml/artifact.py`, which is what checks
    the checksums and shapes before anything reaches here). Holds no sklearn
    object and imports no sklearn; `decision_function` is the only behaviour.
    """

    def __init__(
        self,
        trees: Sequence[Mapping[str, np.ndarray]],
        *,
        offset: float,
        max_samples: int,
        scaler_mean: np.ndarray,
        scaler_scale: np.ndarray,
    ):
        if not trees:
            raise NativeIsolationForestError("an Isolation Forest requires at least one tree")
        self.trees = list(trees)
        self.offset = float(offset)
        self.max_samples = int(max_samples)
        self.scaler_mean = np.asarray(scaler_mean, dtype=np.float64)
        self.scaler_scale = np.asarray(scaler_scale, dtype=np.float64)
        if self.scaler_mean.shape != self.scaler_scale.shape:
            raise NativeIsolationForestError("scaler mean and scale must have the same shape")
        # Precomputed per tree, exactly as sklearn caches `_decision_path_lengths`
        # and `_average_path_length_per_tree` at fit time. Depth-plus-correction
        # is a property of the tree, not of the row being scored.
        self._path_lengths = [
            node_depths(tree["children_left"], tree["children_right"]).astype(np.float64)
            + average_path_length(tree["n_node_samples"])
            for tree in self.trees
        ]
        self._denominator = len(self.trees) * average_path_length([self.max_samples])[0]

    @property
    def n_features(self) -> int:
        return int(self.scaler_mean.shape[0])

    def transform(self, matrix: np.ndarray) -> np.ndarray:
        """StandardScaler.transform: (x - mean) / scale, in float64."""
        return (np.asarray(matrix, dtype=np.float64) - self.scaler_mean) / self.scaler_scale

    def decision_function(self, matrix: np.ndarray) -> np.ndarray:
        """
        `IsolationForest.decision_function` over *unscaled* feature rows.

        Folds in the scaler, because the two were always applied as a pair and
        splitting them invites scoring raw features against a scaled forest.
        Negative is more anomalous, as in sklearn.
        """
        # Checked before `transform`, not after: the scaler broadcasts, so a row of
        # the wrong width fails inside numpy with a shape message that names
        # neither the model nor the feature schema.
        rows = np.asarray(matrix, dtype=np.float64)
        if rows.ndim != 2 or rows.shape[1] != self.n_features:
            raise NativeIsolationForestError(
                f"expected rows of {self.n_features} features, got shape {rows.shape}"
            )
        scaled = self.transform(rows)
        # sklearn's `score_samples` casts X to float32 before routing
        # (`validate_data(..., dtype=np.float32)`), and the Cython `apply` then
        # compares those float32 values against the float64 split thresholds. The
        # cast is reproduced rather than skipped because it decides routing for any
        # value within float32 resolution of a threshold: scoring in full float64
        # sends such a row down the other branch and returns a different score than
        # the pickled artifact did. Widening back to float64 is exact and leaves the
        # comparison itself in double, as sklearn's is. Only routing is affected --
        # `transform` stays float64, so the z-score diagnostics are unrounded.
        routed = scaled.astype(np.float32).astype(np.float64)
        depths = np.zeros(scaled.shape[0], dtype=np.float64)
        for tree, path_lengths in zip(self.trees, self._path_lengths):
            leaves = _apply_tree(tree, routed[:, tree["features"]])
            depths += path_lengths[leaves] - 1.0
        # sklearn guards a zero denominator the same way rather than dividing;
        # it can only be zero for a degenerate max_samples <= 1 forest.
        scores = 2 ** (
            -np.divide(
                depths, self._denominator, out=np.ones_like(depths), where=self._denominator != 0
            )
        )
        return -scores - self.offset

    def path_length_attribution(self, matrix: np.ndarray) -> list[dict[str, Any]]:
        """
        Decompose each row's isolation-path length by the feature tested at each split.

        `decision_function` sums, over trees, `path_lengths[leaf] - 1`, where
        `path_lengths[leaf] = node_depth(leaf) + c(n_node_samples[leaf])`. So each
        tree contributes `(node_depth(leaf) - 1) + c(...)`: an integer count of the
        internal splits on the row's root->leaf path -- each testing exactly one
        feature -- plus the leaf's average-path-length correction. Regrouping the
        integer terms by feature is therefore an *exact* additive decomposition of
        the scored `depths` into per-feature split counts plus a leaf-correction
        residual, and `total_splits + leaf_correction` reproduces the same `depths`
        (hence the same score) `decision_function` computed for the row.

        The routing block below is `decision_function`'s verbatim: the same shape
        check, the same `transform`, and -- load-bearing -- the same float32 cast
        before comparison. The attributed path is thus bitwise the scored path, so
        a value within float32 resolution of a threshold is attributed down the
        branch it was actually scored on, never a divergent float64 re-route.

        Presentation-free by design: returns raw counts and the reconciliation
        numbers, one dict per row, leaving naming/ranking/capping to
        `ml/attribution.py`.
        """
        rows = np.asarray(matrix, dtype=np.float64)
        if rows.ndim != 2 or rows.shape[1] != self.n_features:
            raise NativeIsolationForestError(
                f"expected rows of {self.n_features} features, got shape {rows.shape}"
            )
        scaled = self.transform(rows)
        # Identical to decision_function (:200): routing sees the float32-cast values.
        routed = scaled.astype(np.float32).astype(np.float64)
        results: list[dict[str, Any]] = []
        for row_index in range(routed.shape[0]):
            split_counts: dict[int, int] = {}
            total_splits = 0
            depths = 0.0
            for tree, path_lengths in zip(self.trees, self._path_lengths):
                children_left = tree["children_left"]
                children_right = tree["children_right"]
                feature = tree["feature"]
                threshold = tree["threshold"]
                tree_features = tree["features"]
                # Column-permute exactly as decision_function does with
                # `routed[:, tree["features"]]`, so `feature[node]` indexes the
                # same value `_apply_tree` would compare.
                permuted = routed[row_index, tree_features]
                node = 0
                while children_left[node] != -1:
                    local = int(feature[node])
                    # The global feature index, mapped back through the per-tree
                    # permutation, so counts are comparable across trees and name
                    # to the shared schema.
                    global_feature = int(tree_features[local])
                    split_counts[global_feature] = split_counts.get(global_feature, 0) + 1
                    total_splits += 1
                    # `<=` is _apply_tree's convention (:123); flipping it would
                    # reroute a sample that lands exactly on a threshold.
                    if permuted[local] <= threshold[node]:
                        node = int(children_left[node])
                    else:
                        node = int(children_right[node])
                # Exactly decision_function's per-tree term (:204); accumulated in
                # the same tree order and the same float64 arithmetic, so `depths`
                # is bitwise the value it scored.
                depths += float(path_lengths[node]) - 1.0
            results.append(
                {
                    "split_counts": split_counts,
                    "total_splits": total_splits,
                    # The residual, by definition: depths minus the integer split
                    # total. Equals the summed leaf corrections up to float order.
                    "leaf_correction": depths - float(total_splits),
                    "reconstructed_depths": depths,
                }
            )
        return results


def export_from_sklearn(model: Any, scaler: Any) -> dict[str, Any]:
    """
    Reduce a fitted sklearn IsolationForest and StandardScaler to plain arrays.

    The only place that reads sklearn's private fitted attributes, so the
    coupling to a specific sklearn version is confined to one function that runs
    at training time on the machine that has sklearn installed. Returns the
    arrays `ml/artifact.py` serializes and `NativeIsolationForest` consumes.
    """
    n_features = int(scaler.mean_.shape[0])
    trees = []
    for estimator, features in zip(model.estimators_, model.estimators_features_):
        internals = estimator.tree_
        feature_indices = np.asarray(features, dtype=np.int64)
        # IsolationForest fits with max_features=1.0, so this is the identity
        # permutation today. It is exported and applied anyway: the tree's split
        # indices are positions within *this* array, and hard-coding the identity
        # would silently mis-score if a future sklearn ever subsampled features.
        if feature_indices.shape[0] != n_features or sorted(feature_indices.tolist()) != list(range(n_features)):
            raise NativeIsolationForestError(
                "unsupported feature subsampling: each tree must cover every feature exactly once"
            )
        trees.append(
            {
                "children_left": np.asarray(internals.children_left, dtype=np.int64),
                "children_right": np.asarray(internals.children_right, dtype=np.int64),
                "feature": np.asarray(internals.feature, dtype=np.int64),
                "threshold": np.asarray(internals.threshold, dtype=np.float64),
                "n_node_samples": np.asarray(internals.n_node_samples, dtype=np.int64),
                "features": feature_indices,
            }
        )
    return {
        "trees": trees,
        "offset": float(model.offset_),
        # `_max_samples` is the resolved sample count sklearn scores against, not
        # the `max_samples` hyperparameter (which may be "auto" or a fraction).
        "max_samples": int(model._max_samples),
        "scaler_mean": np.asarray(scaler.mean_, dtype=np.float64),
        "scaler_scale": np.asarray(scaler.scale_, dtype=np.float64),
    }


def validate_tree(index: int, tree: Mapping[str, Any], n_features: int) -> dict[str, np.ndarray]:
    """
    Check one deserialized tree is structurally sound, and normalise its dtypes.

    Called on the load path after the checksums verify: a checksum proves the
    bytes are the ones that were written, not that they describe a usable tree.
    Everything a malformed tree could do at score time -- index out of bounds,
    ragged arrays, a feature index past the schema, a child pointer into
    nowhere -- is rejected here instead, so `decision_function` cannot raise
    from deep inside the descent loop or, worse, read a neighbouring row.
    """
    arrays: dict[str, np.ndarray] = {}
    for key in TREE_ARRAY_KEYS:
        if key not in tree:
            raise NativeIsolationForestError(f"tree {index} is missing array {key!r}")
        dtype = np.int64 if key in _TREE_INT_KEYS else np.float64
        array = np.asarray(tree[key])
        if array.dtype == object or not np.issubdtype(array.dtype, np.number):
            raise NativeIsolationForestError(f"tree {index} array {key!r} is not numeric")
        arrays[key] = array.astype(dtype, copy=False)

    n_nodes = arrays["children_left"].shape[0]
    if n_nodes < 1:
        raise NativeIsolationForestError(f"tree {index} has no nodes")
    for key in ("children_right", "feature", "threshold", "n_node_samples"):
        if arrays[key].shape != (n_nodes,):
            raise NativeIsolationForestError(
                f"tree {index} array {key!r} has shape {arrays[key].shape}, expected ({n_nodes},)"
            )
    if arrays["features"].shape != (n_features,):
        raise NativeIsolationForestError(
            f"tree {index} covers {arrays['features'].shape[0]} features, expected {n_features}"
        )
    if sorted(arrays["features"].tolist()) != list(range(n_features)):
        raise NativeIsolationForestError(f"tree {index} feature map is not a permutation of the schema")

    left, right = arrays["children_left"], arrays["children_right"]
    internal = left != -1
    if not np.array_equal(internal, right != -1):
        raise NativeIsolationForestError(f"tree {index} has a node with exactly one child")
    for side, children in (("left", left), ("right", right)):
        pointers = children[internal]
        if pointers.size and (pointers.min() < 1 or pointers.max() >= n_nodes):
            raise NativeIsolationForestError(f"tree {index} has an out-of-range {side} child pointer")
    split_features = arrays["feature"][internal]
    if split_features.size and (split_features.min() < 0 or split_features.max() >= n_features):
        raise NativeIsolationForestError(f"tree {index} splits on a feature outside the schema")
    if np.any(arrays["n_node_samples"] < 0):
        raise NativeIsolationForestError(f"tree {index} has a negative node sample count")
    if not np.all(np.isfinite(arrays["threshold"][internal])):
        raise NativeIsolationForestError(f"tree {index} has a non-finite split threshold")

    # Every node reachable from the root exactly once, and no cycles: `node_depths`
    # would otherwise loop forever or leave a node at depth 0.
    reached = np.zeros(n_nodes, dtype=bool)
    stack = [0]
    while stack:
        node = stack.pop()
        if reached[node]:
            raise NativeIsolationForestError(f"tree {index} is not a tree: node {node} is reachable twice")
        reached[node] = True
        if internal[node]:
            stack.append(int(left[node]))
            stack.append(int(right[node]))
    if not reached.all():
        raise NativeIsolationForestError(f"tree {index} has {int((~reached).sum())} unreachable nodes")
    return arrays
