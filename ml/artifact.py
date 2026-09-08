"""
The on-disk model artifact: a code-free format with checksums verified before parse.

Format `iforest-native.v1` -- two files per model
------------------------------------------------
* `<model_id>.model.json` -- the descriptor: feature schema identity, the
  threshold and its provenance, the calibration block, forest scalars, and the
  checksum of the array file. Serialized with `sort_keys=True` and compact
  separators, so the bytes are stable and the checksum is reproducible. Python's
  `json` round-trips float64 exactly, so `offset`, `threshold`, and the decision
  bounds survive the trip bit for bit.
* `<model_id>.arrays.npz` -- the numbers: per-tree topology and splits, plus the
  scaler's mean and scale. Uncompressed `np.savez`, which pins its archive
  timestamps to a constant, so identical arrays produce byte-identical files and
  the checksum doubles as a rebuild check: retraining from the same data with the
  same seed reproduces the same digest. `pickle` never offered that.

Neither file can carry code. The descriptor is JSON (data only) and the arrays
are loaded with `allow_pickle=False`, which numpy enforces by refusing object
arrays outright. Compare the previous format, where the loader was
`pickle.loads` and the checksum was the *only* thing standing between a swapped
artifact and arbitrary code execution.

One root of trust, one hop
--------------------------
`ml_models.artifact_checksum` pins the descriptor's bytes; the descriptor pins
the array file's bytes. So a single value already recorded in the database
commits to both files, and no schema change was needed to gain the second one.
The order matters and is enforced below: **verify, then parse.** The descriptor's
checksum is checked before `json.loads`, and the array checksum -- read from the
now-trusted descriptor -- before `np.load`.

The descriptor names the array file, which makes it an untrusted filename until
it has been authenticated. It is constrained to a bare basename resolved in the
descriptor's own directory (`_resolve_arrays_path`), so a descriptor cannot point
the loader at `../../etc/anything` even before its checksum is known good.
"""

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ml.iforest import TREE_ARRAY_KEYS, NativeIsolationForest, NativeIsolationForestError, validate_tree

# Bumped only for an incompatible change to either file's layout. The loader
# refuses any other value rather than guessing.
ARTIFACT_FORMAT = "iforest-native.v1"

_JSON_SUFFIX = ".model.json"
_ARRAYS_SUFFIX = ".arrays.npz"

# Scalars the descriptor must carry for a forest to be scoreable at all.
_REQUIRED_FOREST_KEYS = ("n_estimators", "max_samples", "offset")

# Top-level descriptor keys the scorer reads directly. Absent any one of them the
# artifact is refused rather than defaulted: a missing threshold or calibration
# block must fail closed, not silently score as permissive.
_REQUIRED_DESCRIPTOR_KEYS = (
    "feature_names",
    "schema_version",
    "schema_hash",
    "threshold",
    "threshold_provenance",
    "calibration",
    "decision_min",
    "decision_max",
)


class MLArtifactError(ValueError):
    pass


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    """The exact byte encoding the checksum covers."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _tree_array_name(index: int, key: str) -> str:
    return f"tree{index}_{key}"


def _resolve_arrays_path(descriptor_path: Path, arrays_file: Any) -> Path:
    """
    Resolve the descriptor's `arrays_file` to a sibling path, refusing anything else.

    The checksum is already verified by the time this runs, so the filename is
    authenticated -- but a filename read from a file is still the kind of value
    that should never be able to steer a loader, and the check is two lines. It
    must be a bare basename with the expected suffix, and it is joined to the
    descriptor's own directory, so no descriptor can reach outside it.
    """
    if not isinstance(arrays_file, str) or not arrays_file:
        raise MLArtifactError("artifact descriptor has no arrays_file")
    if arrays_file != os.path.basename(arrays_file) or arrays_file in (os.curdir, os.pardir):
        raise MLArtifactError(f"arrays_file must be a bare filename, got {arrays_file!r}")
    if os.sep in arrays_file or (os.altsep and os.altsep in arrays_file):
        raise MLArtifactError(f"arrays_file must not contain a path separator, got {arrays_file!r}")
    if not arrays_file.endswith(_ARRAYS_SUFFIX):
        raise MLArtifactError(f"arrays_file must end in {_ARRAYS_SUFFIX}, got {arrays_file!r}")
    return descriptor_path.parent / arrays_file


def write_artifact(
    artifact_directory: str,
    model_id: str,
    export: Mapping[str, Any],
    *,
    feature_names: Sequence[str],
    schema_version: str,
    schema_hash: str,
    threshold: float,
    threshold_provenance: str,
    calibration: Mapping[str, Any],
    decision_min: float,
    decision_max: float,
) -> dict[str, Any]:
    """
    Serialize one model to the two-file format and return its paths and checksums.

    `export` is `ml/iforest.py:export_from_sklearn`'s output. Returns the values
    the caller records in `ml_models`: `artifact_path` (the descriptor) and
    `artifact_checksum` (its digest), plus the array file's path and digest for
    reporting. Both files are written `0600`, matching the store's posture -- a
    model artifact is derived from host telemetry.
    """
    trees = list(export["trees"])
    if not trees:
        raise MLArtifactError("refusing to write an artifact with no trees")
    n_features = len(feature_names)

    arrays: dict[str, np.ndarray] = {
        "scaler_mean": np.asarray(export["scaler_mean"], dtype=np.float64),
        "scaler_scale": np.asarray(export["scaler_scale"], dtype=np.float64),
    }
    if arrays["scaler_mean"].shape != (n_features,):
        raise MLArtifactError(
            f"scaler covers {arrays['scaler_mean'].shape} features, expected ({n_features},)"
        )
    for index, tree in enumerate(trees):
        validated = validate_tree(index, tree, n_features)
        for key in TREE_ARRAY_KEYS:
            arrays[_tree_array_name(index, key)] = validated[key]

    # Serialized to memory first so the checksum covers exactly the bytes that
    # land on disk, with no second serialization to disagree with.
    buffer = io.BytesIO()
    np.savez(buffer, **arrays)
    arrays_payload = buffer.getvalue()

    descriptor = {
        "artifact_format": ARTIFACT_FORMAT,
        "algorithm": "IsolationForest",
        "arrays_file": f"{model_id}{_ARRAYS_SUFFIX}",
        "arrays_checksum": hashlib.sha256(arrays_payload).hexdigest(),
        "feature_names": list(feature_names),
        "schema_version": schema_version,
        "schema_hash": schema_hash,
        "forest": {
            "n_estimators": len(trees),
            "max_samples": int(export["max_samples"]),
            "offset": float(export["offset"]),
        },
        # Carried over verbatim from the previous artifact: the threshold is still
        # an experimental decision boundary, and the calibration block still says
        # what it would take to change that.
        "threshold": float(threshold),
        "threshold_provenance": threshold_provenance,
        "calibration": dict(calibration),
        "decision_min": float(decision_min),
        "decision_max": float(decision_max),
        # Redundant with the array file, deliberately: the descriptor is what the
        # database checksum authenticates, so having it commit to the shape as
        # well means a shape disagreement is a refusal rather than a mis-score.
        "trees": [{"n_nodes": int(tree["children_left"].shape[0])} for tree in trees],
    }
    descriptor_payload = _canonical_json(descriptor)

    directory = Path(artifact_directory)
    directory.mkdir(parents=True, exist_ok=True)
    arrays_path = directory / f"{model_id}{_ARRAYS_SUFFIX}"
    descriptor_path = directory / f"{model_id}{_JSON_SUFFIX}"
    arrays_path.write_bytes(arrays_payload)
    descriptor_path.write_bytes(descriptor_payload)
    for path in (arrays_path, descriptor_path):
        os.chmod(path, 0o600)

    return {
        "artifact_path": str(descriptor_path),
        "artifact_checksum": hashlib.sha256(descriptor_payload).hexdigest(),
        "arrays_path": str(arrays_path),
        "arrays_checksum": descriptor["arrays_checksum"],
    }


def load_artifact(artifact_path: str, expected_checksum: str) -> dict[str, Any]:
    """
    Verify and load one artifact, returning its descriptor and a native scorer.

    Verification order, which is the point of this function:

    1. read the descriptor's bytes and check them against `expected_checksum`
       (the value recorded in `ml_models`) -- **before** `json.loads`;
    2. read the array file named by the now-authenticated descriptor and check it
       against the descriptor's `arrays_checksum` -- **before** `np.load`;
    3. load the arrays with `allow_pickle=False`, so no object array and hence no
       deserialization of code is possible even in principle;
    4. validate every tree structurally (`ml/iforest.py:validate_tree`), because a
       good checksum proves provenance, not sanity.

    Raises `MLArtifactError` at the first failure. Callers translate that into
    their own error type; the messages name the failing property ("checksum",
    "arrays_file", "schema") so the reason survives the translation.
    """
    descriptor_path = Path(artifact_path)
    if not descriptor_path.exists():
        raise MLArtifactError("ML model artifact is missing")
    descriptor_payload = descriptor_path.read_bytes()
    if hashlib.sha256(descriptor_payload).hexdigest() != expected_checksum:
        raise MLArtifactError("ML model artifact is checksum-invalid")

    try:
        descriptor = json.loads(descriptor_payload)
    except ValueError as error:
        raise MLArtifactError(f"ML model artifact is not valid JSON: {error}") from error
    if not isinstance(descriptor, dict):
        raise MLArtifactError("ML model artifact descriptor must be a JSON object")
    if descriptor.get("artifact_format") != ARTIFACT_FORMAT:
        raise MLArtifactError(
            f"unsupported artifact format {descriptor.get('artifact_format')!r}; "
            f"this build reads {ARTIFACT_FORMAT}"
        )
    missing = [key for key in _REQUIRED_DESCRIPTOR_KEYS if key not in descriptor]
    if missing:
        raise MLArtifactError(f"ML model artifact descriptor is missing {', '.join(missing)}")
    if not isinstance(descriptor["calibration"], dict):
        raise MLArtifactError("ML model artifact calibration block must be a JSON object")

    arrays_path = _resolve_arrays_path(descriptor_path, descriptor.get("arrays_file"))
    if not arrays_path.exists():
        raise MLArtifactError("ML model array file is missing")
    arrays_payload = arrays_path.read_bytes()
    if hashlib.sha256(arrays_payload).hexdigest() != descriptor.get("arrays_checksum"):
        raise MLArtifactError("ML model array file is checksum-invalid")

    forest = descriptor.get("forest")
    if not isinstance(forest, dict) or any(key not in forest for key in _REQUIRED_FOREST_KEYS):
        raise MLArtifactError("ML model artifact descriptor has an incomplete forest block")
    declared_trees = descriptor.get("trees")
    if not isinstance(declared_trees, list) or len(declared_trees) != int(forest["n_estimators"]):
        raise MLArtifactError("ML model artifact descriptor disagrees with its own tree count")
    feature_names = descriptor.get("feature_names")
    if not isinstance(feature_names, list) or not feature_names:
        raise MLArtifactError("ML model artifact descriptor has no feature names")
    n_features = len(feature_names)

    # allow_pickle=False is the load-time guarantee that no code can be
    # reconstructed from this file; numpy raises on any object array. Note the
    # member read is what enforces it -- `np.load` returns a lazy `NpzFile`, so
    # an object array is only refused when it is indexed, which is why the
    # dict comprehension is inside the guarded block. The other malformed-archive
    # cases numpy signals (`zipfile.BadZipFile` for a truncated archive,
    # `EOFError` for an empty one, `ValueError` for a non-archive) are translated
    # too: they can only be reached by a payload whose checksum was crafted to
    # match, and the caller in `ml/scoring.py` catches `MLArtifactError` alone.
    try:
        with np.load(io.BytesIO(arrays_payload), allow_pickle=False) as loaded:
            stored = {name: loaded[name] for name in loaded.files}
    except (ValueError, OSError, EOFError, zipfile.BadZipFile) as error:
        raise MLArtifactError(f"ML model array file is not a loadable numpy archive: {error}") from error

    trees = []
    for index, declared in enumerate(declared_trees):
        raw = {}
        for key in TREE_ARRAY_KEYS:
            name = _tree_array_name(index, key)
            if name not in stored:
                raise MLArtifactError(f"ML model array file is missing {name}")
            raw[key] = stored[name]
        try:
            validated = validate_tree(index, raw, n_features)
        except NativeIsolationForestError as error:
            raise MLArtifactError(f"ML model artifact is structurally invalid: {error}") from error
        if not isinstance(declared, dict) or int(declared.get("n_nodes", -1)) != validated["children_left"].shape[0]:
            raise MLArtifactError(f"tree {index} node count disagrees with the descriptor")
        trees.append(validated)

    for name in ("scaler_mean", "scaler_scale"):
        if name not in stored:
            raise MLArtifactError(f"ML model array file is missing {name}")
        if stored[name].shape != (n_features,):
            raise MLArtifactError(f"{name} covers {stored[name].shape} features, expected ({n_features},)")
    if np.any(stored["scaler_scale"] == 0.0) or not np.all(np.isfinite(stored["scaler_scale"])):
        raise MLArtifactError("scaler scale must be finite and non-zero")
    if not np.all(np.isfinite(stored["scaler_mean"])):
        raise MLArtifactError("scaler mean must be finite")

    try:
        model = NativeIsolationForest(
            trees,
            offset=float(forest["offset"]),
            max_samples=int(forest["max_samples"]),
            scaler_mean=stored["scaler_mean"],
            scaler_scale=stored["scaler_scale"],
        )
    except NativeIsolationForestError as error:
        raise MLArtifactError(f"ML model artifact is unusable: {error}") from error

    return {"descriptor": descriptor, "model": model, "arrays_path": str(arrays_path)}
