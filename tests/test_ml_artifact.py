"""
Tests for the code-free model artifact and the native Isolation Forest scorer.

Four layers, deliberately separated by what they need to run:

* **Scoring arithmetic**, checked against the formulas published in
  `ml/iforest.py`'s docstring, re-derived here in plain Python. The reference is
  written out rather than imported so the module is checked against the reference
  it claims to implement, not against itself.
* **Verify-then-parse ordering and the refusals** around it -- a bad descriptor
  checksum, a bad array checksum, an `arrays_file` that tries to leave the
  descriptor's directory, a missing required descriptor key, a payload that is not
  a loadable numpy archive. Each tamper re-checksums what it edited, so the
  refusal is attributable to the property under test and not to a stale digest.
* **Source-level invariants**: nothing in `ml/` imports a code-executing
  deserializer, and every `np.load` in the package passes `allow_pickle=False`.
  Asserted over the parsed AST rather than the text, because the modules discuss
  pickle at length in their docstrings and a grep cannot tell prose from an
  import.
* **Bitwise parity with scikit-learn**, the one test that needs sklearn and so the
  one that skips without it. Everything above runs on numpy alone -- which is the
  same property the scoring path now has, so the test suite exercises the real
  deployment configuration rather than only the training host's.

The toy artifact is hand-built: two features, one three-node tree plus one
single-leaf tree. Small enough that the expected path lengths can be derived on
paper, which is what makes the arithmetic tests independent evidence.
"""

import ast
import hashlib
import io
import json
import math
import stat
from pathlib import Path

import numpy as np
import pytest

from ml.artifact import ARTIFACT_FORMAT, MLArtifactError, load_artifact, write_artifact
from ml.iforest import (
    EULER_GAMMA,
    NativeIsolationForest,
    NativeIsolationForestError,
    average_path_length,
    export_from_sklearn,
    node_depths,
    validate_tree,
)
from ml.training import SKLEARN_AVAILABLE

# Euler-Mascheroni gamma = 0.57721566490153286060651209... , written to the
# nearest float64 by hand so the reference below does not borrow the module's
# constant. `test_average_path_length_matches_the_published_formula` asserts the
# module agrees with numpy's, and with this.
_EULER_GAMMA = 0.5772156649015329

_FEATURE_NAMES = ("alpha", "beta")


def _toy_tree(features=(1, 0)):
    """
    One three-node tree: the root splits, both children are leaves.

    `features` is the tree's feature map and defaults to a non-identity
    permutation on purpose. A split index is a position *within* that map, so an
    identity map would hide it if the indirection were ever dropped.
    """
    return {
        "children_left": np.asarray([1, -1, -1], dtype=np.int64),
        "children_right": np.asarray([2, -1, -1], dtype=np.int64),
        "feature": np.asarray([0, -2, -2], dtype=np.int64),
        "threshold": np.asarray([0.0, -2.0, -2.0], dtype=np.float64),
        "n_node_samples": np.asarray([4, 3, 1], dtype=np.int64),
        "features": np.asarray(features, dtype=np.int64),
    }


def _toy_leaf():
    """A degenerate tree whose root is already a leaf, as sklearn produces for tiny samples."""
    return {
        "children_left": np.asarray([-1], dtype=np.int64),
        "children_right": np.asarray([-1], dtype=np.int64),
        "feature": np.asarray([-2], dtype=np.int64),
        "threshold": np.asarray([-2.0], dtype=np.float64),
        "n_node_samples": np.asarray([4], dtype=np.int64),
        "features": np.asarray([0, 1], dtype=np.int64),
    }


def _toy_export(**overrides):
    export = {
        "trees": [_toy_tree(), _toy_leaf()],
        "offset": -0.5,
        "max_samples": 4,
        "scaler_mean": np.asarray([1.0, 2.0], dtype=np.float64),
        "scaler_scale": np.asarray([2.0, 4.0], dtype=np.float64),
    }
    export.update(overrides)
    return export


def _write(tmp_path, export=None, model_id="toy-model", **overrides):
    fields = {
        "feature_names": list(_FEATURE_NAMES),
        "schema_version": "toy-window.v1",
        "schema_hash": "0" * 64,
        "threshold": -0.05,
        "threshold_provenance": "experimental_percentile_of_training_scores",
        "calibration": {"method": "toy", "normal_windows": 3},
        "decision_min": -0.3,
        "decision_max": 0.2,
    }
    fields.update(overrides)
    return write_artifact(str(tmp_path), model_id, export if export is not None else _toy_export(), **fields)


def _reference_decision(rows, export, *, route_float32=True):
    """
    `decision_function` re-derived from the reference in `ml/iforest.py`'s docstring.

    Plain Python and `math`, no numpy vectorization and no call into the module
    under test. `route_float32` exists so a test can ask what the score *would* be
    without sklearn's float32 cast of X: that is how the parity test proves its
    engineered rows really do sit on a routing boundary, rather than passing
    because the cast never mattered.
    """

    def c(n):
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (math.log(n - 1.0) + _EULER_GAMMA) - 2.0 * (n - 1.0) / n

    trees = list(export["trees"])
    mean = np.asarray(export["scaler_mean"], dtype=np.float64)
    scale = np.asarray(export["scaler_scale"], dtype=np.float64)
    denominator = len(trees) * c(int(export["max_samples"]))

    decisions = []
    for row in rows:
        scaled = [(float(value) - float(mean[index])) / float(scale[index]) for index, value in enumerate(row)]
        routed = [float(np.float32(value)) for value in scaled] if route_float32 else scaled
        total = 0.0
        for tree in trees:
            node, depth = 0, 1
            while int(tree["children_left"][node]) != -1:
                column = int(tree["features"][int(tree["feature"][node])])
                inside = routed[column] <= float(tree["threshold"][node])
                node = int(tree["children_left"][node] if inside else tree["children_right"][node])
                depth += 1
            total += depth + c(int(tree["n_node_samples"][node])) - 1.0
        decisions.append(-(2.0 ** (-(total / denominator))) - float(export["offset"]))
    return decisions


def _rewrite_descriptor(paths, mutate):
    """
    Edit the descriptor in place and re-checksum it, then return the new digest.

    Models an attacker (or a well-meaning operator) with write access to the
    artifact *and* to the checksum recorded alongside it. Passing the new digest
    back as `expected_checksum` is what makes the resulting refusal evidence about
    the property being tested; tampering that leaves the digest stale is covered
    separately, by the checksum tests.
    """
    path = Path(paths["artifact_path"])
    descriptor = json.loads(path.read_bytes())
    mutate(descriptor)
    payload = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _replace_arrays(paths, payload, *, arrays_path=None):
    """Swap the array file's bytes and re-point the descriptor's checksum at them."""
    Path(arrays_path or paths["arrays_path"]).write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    def repoint(descriptor):
        descriptor["arrays_checksum"] = digest

    return _rewrite_descriptor(paths, repoint)


def _arrays_payload(paths, **overrides):
    """The artifact's own arrays with named members replaced, re-serialized the same way."""
    with np.load(paths["arrays_path"]) as loaded:
        arrays = {name: loaded[name] for name in loaded.files}
    arrays.update(overrides)
    buffer = io.BytesIO()
    np.savez(buffer, **arrays)
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Round trip and scoring arithmetic (numpy only)
# --------------------------------------------------------------------------


def test_write_then_load_round_trips_the_descriptor(tmp_path):
    paths = _write(tmp_path)
    loaded = load_artifact(paths["artifact_path"], paths["artifact_checksum"])
    descriptor = loaded["descriptor"]

    assert descriptor["artifact_format"] == ARTIFACT_FORMAT
    assert descriptor["algorithm"] == "IsolationForest"
    assert descriptor["feature_names"] == list(_FEATURE_NAMES)
    assert descriptor["schema_version"] == "toy-window.v1"
    assert descriptor["threshold"] == -0.05
    assert descriptor["threshold_provenance"] == "experimental_percentile_of_training_scores"
    assert descriptor["calibration"] == {"method": "toy", "normal_windows": 3}
    assert descriptor["forest"] == {"n_estimators": 2, "max_samples": 4, "offset": -0.5}
    assert descriptor["trees"] == [{"n_nodes": 3}, {"n_nodes": 1}]
    assert loaded["arrays_path"] == paths["arrays_path"]

    # The two digests recorded at write time must be the digests of the bytes on
    # disk -- that is the whole basis for `ml_models.artifact_checksum` committing
    # to both files.
    assert hashlib.sha256(Path(paths["artifact_path"]).read_bytes()).hexdigest() == paths["artifact_checksum"]
    assert hashlib.sha256(Path(paths["arrays_path"]).read_bytes()).hexdigest() == paths["arrays_checksum"]
    assert descriptor["arrays_checksum"] == paths["arrays_checksum"]


def test_both_artifact_files_are_written_owner_only(tmp_path):
    paths = _write(tmp_path)
    for key in ("artifact_path", "arrays_path"):
        mode = stat.S_IMODE(Path(paths[key]).stat().st_mode)
        assert mode == 0o600, f"{key} is mode {oct(mode)}"


def test_loaded_model_scores_by_the_published_formula(tmp_path):
    export = _toy_export()
    paths = _write(tmp_path, export)
    model = load_artifact(paths["artifact_path"], paths["artifact_checksum"])["model"]

    rows = [[0.0, 10.0], [1.0, 2.0], [-5.0, -5.0], [3.5, 0.25], [100.0, -100.0]]
    produced = model.decision_function(np.asarray(rows, dtype=np.float64))
    assert produced.tolist() == _reference_decision(rows, export)


def test_average_path_length_matches_the_published_formula():
    # The three-way split, including both degenerate cases: a leaf reached by one
    # training sample contributes no correction, and n == 2 is a special case
    # rather than a limit of the n > 2 branch.
    assert average_path_length([0, 1, 2, 3, 4, 64, 256]).tolist() == [
        0.0,
        0.0,
        1.0,
        1.207392357589623,
        1.8516559071392855,
        7.471950782586131,
        10.244770920119917,
    ]
    assert EULER_GAMMA == np.euler_gamma == _EULER_GAMMA


def test_node_depths_count_the_root_as_one():
    tree = _toy_tree()
    assert node_depths(tree["children_left"], tree["children_right"]).tolist() == [1, 2, 2]
    leaf = _toy_leaf()
    assert node_depths(leaf["children_left"], leaf["children_right"]).tolist() == [1]


def test_hand_derived_path_lengths_are_what_the_forest_precomputes():
    # Derived on paper from the toy tree: depth + c(n_node_samples) per node, with
    # c(4) and c(3) as pinned above. Checking the cached table directly, because a
    # wrong cache is otherwise only visible as a slightly wrong score.
    model = NativeIsolationForest(
        [validate_tree(0, _toy_tree(), 2)],
        offset=-0.5,
        max_samples=4,
        scaler_mean=np.asarray([1.0, 2.0]),
        scaler_scale=np.asarray([2.0, 4.0]),
    )
    assert model._path_lengths[0].tolist() == [
        1.0 + 1.8516559071392855,
        2.0 + 1.207392357589623,
        2.0 + 0.0,
    ]
    assert model._denominator == 1 * 1.8516559071392855


def test_tree_feature_map_is_applied_not_assumed(tmp_path):
    """A permuted feature map must change which raw column the root splits on."""
    permuted = _toy_export(trees=[_toy_tree(features=(1, 0))])
    identity = _toy_export(trees=[_toy_tree(features=(0, 1))])
    # scaled = ((0 - 1)/2, (10 - 2)/4) = (-0.5, 2.0): one side of the 0.0 split
    # each, so the two maps route this row to different leaves.
    row = np.asarray([[0.0, 10.0]], dtype=np.float64)

    permuted_paths = _write(tmp_path / "permuted", permuted)
    identity_paths = _write(tmp_path / "identity", identity)
    permuted_model = load_artifact(permuted_paths["artifact_path"], permuted_paths["artifact_checksum"])["model"]
    identity_model = load_artifact(identity_paths["artifact_path"], identity_paths["artifact_checksum"])["model"]

    assert permuted_model.decision_function(row)[0] != identity_model.decision_function(row)[0]
    assert permuted_model.decision_function(row).tolist() == _reference_decision(row.tolist(), permuted)
    assert identity_model.decision_function(row).tolist() == _reference_decision(row.tolist(), identity)


def test_artifact_bytes_are_reproducible(tmp_path):
    """Same arrays in, same digests out -- so the checksum doubles as a rebuild check."""
    first = _write(tmp_path / "first")
    second = _write(tmp_path / "second")
    assert first["arrays_checksum"] == second["arrays_checksum"]
    assert first["artifact_checksum"] == second["artifact_checksum"]


def test_routing_cast_does_not_reach_the_scaled_diagnostics(tmp_path):
    """
    `transform` stays float64 even though routing is float32.

    The z-scores in `ml/scoring.py`'s FACT-labelled feature diagnostics come from
    `transform`, so rounding them to float32 resolution would coarsen reported
    evidence. The cast exists to reproduce sklearn's routing, and only that.
    """
    paths = _write(tmp_path)
    model = load_artifact(paths["artifact_path"], paths["artifact_checksum"])["model"]
    # A value whose float32 image is not itself: (x - 1)/2 lands just off 0.3.
    row = np.asarray([[1.6000000001, 2.0]], dtype=np.float64)
    scaled = model.transform(row)[0]
    assert scaled[0] == (1.6000000001 - 1.0) / 2.0
    assert scaled[0] != float(np.float32(scaled[0]))


def test_scoring_refuses_a_row_of_the_wrong_width(tmp_path):
    paths = _write(tmp_path)
    model = load_artifact(paths["artifact_path"], paths["artifact_checksum"])["model"]
    with pytest.raises(NativeIsolationForestError, match="expected rows of 2 features"):
        model.decision_function(np.asarray([[1.0, 2.0, 3.0]], dtype=np.float64))


# --------------------------------------------------------------------------
# Verify-then-parse: provenance, checksums, and the refusals
# --------------------------------------------------------------------------


def test_missing_artifact_is_refused(tmp_path):
    with pytest.raises(MLArtifactError, match="artifact is missing"):
        load_artifact(str(tmp_path / "absent.model.json"), "0" * 64)


def test_descriptor_checksum_is_checked_before_parse(tmp_path):
    paths = _write(tmp_path)
    Path(paths["artifact_path"]).write_bytes(b"corrupt")
    with pytest.raises(MLArtifactError, match="artifact is checksum-invalid"):
        load_artifact(paths["artifact_path"], paths["artifact_checksum"])


def test_a_swapped_but_well_formed_descriptor_is_refused(tmp_path):
    """
    Valid JSON is not the bar; matching the recorded digest is.

    The interesting case, because a swapped artifact that happens to parse is
    exactly what a checksum-after-parse ordering would accept.
    """
    paths = _write(tmp_path)
    other = _write(tmp_path / "other", _toy_export(offset=-0.25), model_id="toy-model")
    Path(paths["artifact_path"]).write_bytes(Path(other["artifact_path"]).read_bytes())
    with pytest.raises(MLArtifactError, match="artifact is checksum-invalid"):
        load_artifact(paths["artifact_path"], paths["artifact_checksum"])


def test_tampered_array_file_is_refused_with_the_descriptor_intact(tmp_path):
    """The second hop of the chain: one recorded digest has to cover both files."""
    paths = _write(tmp_path)
    Path(paths["arrays_path"]).write_bytes(Path(paths["arrays_path"]).read_bytes() + b"\x00")
    with pytest.raises(MLArtifactError, match="array file is checksum-invalid"):
        load_artifact(paths["artifact_path"], paths["artifact_checksum"])


def test_missing_array_file_is_refused(tmp_path):
    paths = _write(tmp_path)
    Path(paths["arrays_path"]).unlink()
    with pytest.raises(MLArtifactError, match="array file is missing"):
        load_artifact(paths["artifact_path"], paths["artifact_checksum"])


@pytest.mark.parametrize(
    "arrays_file, expected",
    [
        ("../escaped.arrays.npz", "bare filename"),
        ("nested/escaped.arrays.npz", "bare filename"),
        ("/etc/escaped.arrays.npz", "bare filename"),
        ("..", "bare filename"),
        ("toy-model.npz", "must end in .arrays.npz"),
        ("", "no arrays_file"),
        (None, "no arrays_file"),
        (17, "no arrays_file"),
    ],
)
def test_arrays_file_cannot_steer_the_loader(tmp_path, arrays_file, expected):
    """
    An authenticated filename is still a filename read from a file.

    Each case re-checksums the descriptor, so the load reaches the path check with
    a *valid* digest -- the refusal is the basename constraint doing the work, not
    the checksum catching the edit.
    """
    paths = _write(tmp_path)

    def repoint(descriptor):
        descriptor["arrays_file"] = arrays_file

    checksum = _rewrite_descriptor(paths, repoint)
    with pytest.raises(MLArtifactError, match=expected):
        load_artifact(paths["artifact_path"], checksum)


@pytest.mark.parametrize(
    "key",
    [
        "feature_names",
        "schema_version",
        "schema_hash",
        "threshold",
        "threshold_provenance",
        "calibration",
        "decision_min",
        "decision_max",
    ],
)
def test_missing_descriptor_keys_fail_closed(tmp_path, key):
    """
    No defaults on the load path.

    A defaulted threshold or a defaulted calibration block would score as
    something -- probably as something permissive -- instead of refusing, and the
    absent provenance would be indistinguishable from a calibrated one.
    """
    paths = _write(tmp_path)

    def drop(descriptor):
        descriptor.pop(key)

    checksum = _rewrite_descriptor(paths, drop)
    with pytest.raises(MLArtifactError, match=f"descriptor is missing {key}"):
        load_artifact(paths["artifact_path"], checksum)


def test_calibration_must_be_an_object(tmp_path):
    paths = _write(tmp_path)

    def flatten(descriptor):
        descriptor["calibration"] = "calibrated, trust me"

    checksum = _rewrite_descriptor(paths, flatten)
    with pytest.raises(MLArtifactError, match="calibration block must be a JSON object"):
        load_artifact(paths["artifact_path"], checksum)


def test_unknown_artifact_format_is_refused_rather_than_guessed(tmp_path):
    paths = _write(tmp_path)

    def bump(descriptor):
        descriptor["artifact_format"] = "iforest-native.v2"

    checksum = _rewrite_descriptor(paths, bump)
    with pytest.raises(MLArtifactError, match="unsupported artifact format 'iforest-native.v2'"):
        load_artifact(paths["artifact_path"], checksum)


def test_descriptor_must_agree_with_its_own_tree_count(tmp_path):
    paths = _write(tmp_path)

    def lie(descriptor):
        descriptor["forest"]["n_estimators"] = 3

    checksum = _rewrite_descriptor(paths, lie)
    with pytest.raises(MLArtifactError, match="disagrees with its own tree count"):
        load_artifact(paths["artifact_path"], checksum)


def test_descriptor_must_agree_with_the_stored_node_count(tmp_path):
    """The redundant shape in the descriptor is what makes a shape swap a refusal."""
    paths = _write(tmp_path)

    def shrink(descriptor):
        descriptor["trees"][0]["n_nodes"] = 1

    checksum = _rewrite_descriptor(paths, shrink)
    with pytest.raises(MLArtifactError, match="tree 0 node count disagrees"):
        load_artifact(paths["artifact_path"], checksum)


def test_object_array_payload_is_refused(tmp_path):
    """
    The `allow_pickle=False` guarantee, exercised end to end.

    `np.load` returns a lazy archive, so an object array is only refused when a
    member is read -- and the refusal has to surface as `MLArtifactError`, because
    that is the only exception `ml/scoring.py` translates. Reaching this at all
    requires a payload whose checksum was crafted to match, which is why the
    helper re-points the descriptor.
    """
    buffer = io.BytesIO()
    np.savez(buffer, **{"tree0_children_left": np.asarray([{"code": "here"}], dtype=object)})
    paths = _write(tmp_path)
    checksum = _replace_arrays(paths, buffer.getvalue())
    with pytest.raises(MLArtifactError, match="not a loadable numpy archive"):
        load_artifact(paths["artifact_path"], checksum)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not a numpy archive at all", id="not-an-archive"),
        pytest.param(b"PK\x03\x04truncated", id="truncated-zip"),
    ],
)
def test_unloadable_array_payloads_are_refused(tmp_path, payload):
    paths = _write(tmp_path)
    checksum = _replace_arrays(paths, payload)
    with pytest.raises(MLArtifactError, match="not a loadable numpy archive"):
        load_artifact(paths["artifact_path"], checksum)


def test_missing_array_member_is_refused(tmp_path):
    paths = _write(tmp_path)
    with np.load(paths["arrays_path"]) as loaded:
        arrays = {name: loaded[name] for name in loaded.files if name != "tree0_threshold"}
    buffer = io.BytesIO()
    np.savez(buffer, **arrays)
    checksum = _replace_arrays(paths, buffer.getvalue())
    with pytest.raises(MLArtifactError, match="missing tree0_threshold"):
        load_artifact(paths["artifact_path"], checksum)


@pytest.mark.parametrize(
    "overrides, expected",
    [
        (
            {"tree0_children_right": np.asarray([99, -1, -1], dtype=np.int64)},
            "out-of-range right child pointer",
        ),
        (
            {"tree0_children_right": np.asarray([-1, -1, -1], dtype=np.int64)},
            "node with exactly one child",
        ),
        (
            {"tree0_feature": np.asarray([7, -2, -2], dtype=np.int64)},
            "splits on a feature outside the schema",
        ),
        (
            {"tree0_threshold": np.asarray([float("nan"), -2.0, -2.0], dtype=np.float64)},
            "non-finite split threshold",
        ),
        (
            {"tree0_n_node_samples": np.asarray([4, -3, 1], dtype=np.int64)},
            "negative node sample count",
        ),
        (
            {"tree0_features": np.asarray([1, 1], dtype=np.int64)},
            "feature map is not a permutation",
        ),
        (
            {
                "tree0_children_left": np.asarray([1, -1, -1], dtype=np.int64),
                "tree0_children_right": np.asarray([1, -1, -1], dtype=np.int64),
            },
            "node 1 is reachable twice",
        ),
    ],
)
def test_structurally_invalid_trees_are_refused(tmp_path, overrides, expected):
    """
    A good checksum proves provenance, not sanity.

    Every one of these would otherwise fail somewhere inside the descent loop, or
    read a neighbouring row's memory, at score time. They have to be built by
    editing the array file directly, because `write_artifact` validates on the way
    out as well.
    """
    paths = _write(tmp_path)
    checksum = _replace_arrays(paths, _arrays_payload(paths, **overrides))
    with pytest.raises(MLArtifactError, match=expected):
        load_artifact(paths["artifact_path"], checksum)


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"scaler_scale": np.asarray([2.0, 0.0])}, "scale must be finite and non-zero"),
        ({"scaler_scale": np.asarray([2.0, float("inf")])}, "scale must be finite and non-zero"),
        ({"scaler_mean": np.asarray([1.0, float("nan")])}, "mean must be finite"),
        ({"scaler_mean": np.asarray([1.0, 2.0, 3.0])}, "scaler_mean covers"),
    ],
)
def test_unusable_scalers_are_refused(tmp_path, overrides, expected):
    paths = _write(tmp_path)
    checksum = _replace_arrays(paths, _arrays_payload(paths, **overrides))
    with pytest.raises(MLArtifactError, match=expected):
        load_artifact(paths["artifact_path"], checksum)


def test_writing_refuses_a_forest_with_no_trees(tmp_path):
    with pytest.raises(MLArtifactError, match="no trees"):
        _write(tmp_path, _toy_export(trees=[]))


def test_writing_refuses_a_scaler_that_disagrees_with_the_schema(tmp_path):
    with pytest.raises(MLArtifactError, match="scaler covers"):
        _write(tmp_path, _toy_export(scaler_mean=np.asarray([1.0, 2.0, 3.0])))


# --------------------------------------------------------------------------
# Source-level invariants: the loader cannot execute code
# --------------------------------------------------------------------------


def _ml_sources():
    directory = Path(__import__("ml").__file__).parent
    return sorted(path for path in directory.glob("*.py"))


def test_no_ml_module_imports_a_code_executing_deserializer():
    """
    Asserted over the AST, not the text.

    These modules discuss pickle at length in their docstrings -- that is the
    point of them -- so a grep would flag prose and a reader could not tell a
    regression from a comment.
    """
    forbidden = {"pickle", "cPickle", "_pickle", "dill", "cloudpickle", "joblib", "shelve", "marshal"}
    offenders = []
    for path in _ml_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if name in forbidden:
                    offenders.append(f"{path.name}:{node.lineno} imports {name}")
    assert offenders == []
    assert _ml_sources(), "the ml package sources were not found, so this test proved nothing"


def test_every_numpy_load_in_ml_disallows_pickle():
    checked = 0
    for path in _ml_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
            if name not in ("load", "loads"):
                continue
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "json":
                continue
            keywords = {keyword.arg: keyword.value for keyword in node.keywords}
            assert "allow_pickle" in keywords, f"{path.name}:{node.lineno} calls {name} without allow_pickle"
            value = keywords["allow_pickle"]
            assert isinstance(value, ast.Constant) and value.value is False, (
                f"{path.name}:{node.lineno} does not pass allow_pickle=False"
            )
            checked += 1
    assert checked == 1, f"expected exactly one guarded np.load in ml/, found {checked}"


# --------------------------------------------------------------------------
# Bitwise parity with scikit-learn (the one test that needs it)
# --------------------------------------------------------------------------


@pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn is not installed in the active Python environment")
def test_native_scoring_is_bitwise_identical_to_sklearn(tmp_path):
    """
    The claim that makes dropping pickle a format change and not a behaviour change.

    Three row populations, because the third is the one that used to disagree:

    * the rows the forest was fitted on;
    * fresh rows from the same distribution;
    * rows engineered to land within float32 resolution of a real split threshold.
      sklearn's `score_samples` validates X as float32 before the tree descent, so
      those rows route on the truncated value. The last two assertions establish
      that the engineered rows really are boundary rows -- without them this test
      would still pass if the cast were dropped, and `is_anomaly` would then flip
      for exactly the rows sitting on a decision boundary.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    generator = np.random.default_rng(20260908)
    n_features = 12
    training = generator.normal(size=(300, n_features)) * generator.uniform(0.5, 4.0, size=n_features)
    scaler = StandardScaler().fit(training)
    forest = IsolationForest(n_estimators=12, max_samples=64, random_state=7).fit(scaler.transform(training))

    export = export_from_sklearn(forest, scaler)
    paths = _write(
        tmp_path,
        export,
        model_id="parity-model",
        feature_names=[f"feature_{index}" for index in range(n_features)],
    )
    model = load_artifact(paths["artifact_path"], paths["artifact_checksum"])["model"]

    def sklearn_decisions(rows):
        return forest.decision_function(scaler.transform(np.asarray(rows, dtype=np.float64)))

    fresh = generator.normal(size=(120, n_features)) * generator.uniform(0.5, 4.0, size=n_features)
    boundary = _threshold_boundary_rows(export, generator, count=120)

    for label, rows in (("training", training), ("fresh", fresh), ("boundary", boundary)):
        expected = sklearn_decisions(rows)
        produced = model.decision_function(np.asarray(rows, dtype=np.float64))
        assert np.array_equal(produced, expected), (
            f"{label} rows: max abs difference {np.max(np.abs(produced - expected))}"
        )
        # The published formula, re-derived in plain Python, agrees too -- so the
        # parity is with sklearn's documented definition and not with a shared
        # implementation quirk.
        assert _reference_decision(np.asarray(rows).tolist(), export) == expected.tolist()

    # Self-check: routing in full float64 must disagree somewhere on the boundary
    # rows, or they are not boundary rows and the parity above is vacuous.
    unrounded = _reference_decision(np.asarray(boundary).tolist(), export, route_float32=False)
    differing = sum(1 for produced, want in zip(unrounded, sklearn_decisions(boundary)) if produced != want)
    assert differing > 0, "engineered rows did not land on any routing boundary"


def _threshold_boundary_rows(export, generator, count):
    """
    Rows whose scaled features sit on, or within float32 resolution of, a split threshold.

    Built by choosing a real internal split from a real tree, placing the scaled
    feature at the threshold plus a sub-float32 offset, and inverting the scaler to
    get the unscaled row the scorer is actually handed. The inversion is not exact,
    which is fine: the aim is a population dense in near-threshold values, not one
    exact hit.
    """
    mean = np.asarray(export["scaler_mean"], dtype=np.float64)
    scale = np.asarray(export["scaler_scale"], dtype=np.float64)
    splits = [
        (int(tree["features"][int(tree["feature"][node])]), float(tree["threshold"][node]))
        for tree in export["trees"]
        for node in range(tree["children_left"].shape[0])
        if int(tree["children_left"][node]) != -1
    ]
    offsets = [0.0, 1e-9, -1e-9, 1e-12, -1e-12, float(np.spacing(np.float32(1.0))) / 4.0]

    rows = []
    for index in range(count):
        scaled = generator.normal(size=mean.shape[0])
        column, threshold = splits[index % len(splits)]
        scaled[column] = threshold + offsets[index % len(offsets)]
        rows.append(scaled * scale + mean)
    return np.asarray(rows, dtype=np.float64)
