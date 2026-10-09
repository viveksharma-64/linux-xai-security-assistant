"""Explicit verified-normal dataset capture and Isolation Forest training."""

import platform
import sys
import time
import uuid
from collections.abc import Sequence
from typing import Any

try:
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    np = None
    sklearn = None
    IsolationForest = None
    StandardScaler = None
    SKLEARN_AVAILABLE = False

from ml.artifact import ARTIFACT_FORMAT, MLArtifactError, decision_percentiles, load_artifact, write_artifact
from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, extract_features, schema_hash
from ml.iforest import export_from_sklearn
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore

MIN_TRAINING_WINDOWS = 10
MIN_DISTINCT_TRAINING_WINDOWS = 3

# What a freshly trained model claims about its own threshold: nothing. The
# boundary is wherever `contamination` put it, which is a hyperparameter choice,
# not a measurement against data the model has not seen.
UNCALIBRATED_THRESHOLD_PROVENANCE = "isolation_forest_decision_boundary; not independently calibrated"


class MLTrainingError(ValueError):
    pass


def create_verified_normal_dataset(store: SQLiteEventStore, name: str, verification: dict[str, Any], environment: dict[str, Any] | None = None) -> str:
    if not verification.get("verified_normal"):
        raise MLTrainingError("explicit verified_normal=True verification metadata is required")
    dataset_id = f"verified-normal-{uuid.uuid4()}"
    store.create_ml_dataset({
        "id": dataset_id, "name": name, "schema_version": SCHEMA_VERSION, "schema_hash": schema_hash(),
        "environment": environment or {"platform": platform.platform(), "python": sys.version.split()[0]},
        "verification": verification, "created_at": time.time(),
    })
    return dataset_id


def add_verified_normal_window(
    store: SQLiteEventStore, dataset_id: str, events: Sequence[Event], event_ids: Sequence[int],
    verification: dict[str, Any], collector_context: dict[str, Any] | None = None,
) -> int:
    if not verification.get("verified_normal"):
        raise MLTrainingError("training window rejected: verified_normal=True is required")
    if len(events) != len(event_ids):
        raise MLTrainingError("event_ids must correspond one-to-one with canonical events")
    if not events:
        raise MLTrainingError("empty windows cannot enter verified-normal training data")
    timestamps = [float(event.timestamp) for event in events]
    return store.write_ml_training_window({
        "dataset_id": dataset_id, "window_start": min(timestamps), "window_end": max(timestamps),
        "event_ids": list(event_ids), "features": extract_features(events),
        "schema_version": SCHEMA_VERSION, "schema_hash": schema_hash(),
        "collector_context": collector_context or {"sources": sorted({event.source for event in events}), "versions": sorted({event.version for event in events})},
        "verified_normal": True, "verification": verification, "created_at": time.time(),
    })


def train_isolation_forest(
    store: SQLiteEventStore, dataset_id: str, artifact_directory: str, *, n_estimators: int = 200,
    contamination: float = 0.01, random_state: int = 42,
) -> dict[str, Any]:
    """
    Train only from an explicit all-verified-normal, schema-compatible dataset.

    Training cannot activate, and there is no parameter asking it to. This used to
    take `activate: bool = False`, which was the one reachable route to an active
    model that consulted no gate. It is deleted rather than gated because no honest
    caller could ever satisfy a gated version: the activation gate measures a false
    positive rate on *held-out* verified-normal windows, and that measurement
    cannot exist at the moment training returns -- the model whose errors are being
    counted is the value being constructed. That is the whole reason training and
    activation are separate steps.

    So the row this writes is always inactive. `storage/sqlite_store.py:activate_ml_model`
    is the only door to `active = 1`, and reaching it means evaluating this model
    and recording the verdict first.

    Why `contamination` defaults to 0.01
    ------------------------------------
    `contamination` is not a side knob here -- it *is* the decision threshold.
    `IsolationForest.decision_function` is centred on the fitted contamination
    quantile and this function thresholds at 0.0, so a forest fitted at
    `contamination=c` declares that it will flag about `c` of windows drawn from
    its own training distribution. The activation gate's budget is a 5% false
    positive rate at a one-sided 95% Wilson upper bound, which at the minimum 60
    holdout windows permits **zero** false positives (1/60 bounds to 7.13%).

    A default of 0.05 therefore aimed the model at exactly the ceiling it had to
    clear: 60 independent draws at p=0.05 land on zero failures about 4.6% of the
    time, so the expected outcome was a refusal, and the previous default spent
    every training run demonstrating that. At 0.01 the same arithmetic gives about
    55%, so a genuinely quiet model has a real chance of clearing a gate that has
    not moved. Lower is not automatically better: a very low contamination on a
    larger training set buys eligibility with a model too permissive to flag a
    deliberate outlier, and the gate -- which only measures false positives --
    cannot see that. 0.01 is the point where the gate is reachable without the
    model becoming vacuous; `--contamination` exists to sweep around it, and the
    recorded `training_decision_percentiles` are how the resulting boundary's
    position in the training distribution is read back.
    """
    if not SKLEARN_AVAILABLE:
        raise MLTrainingError("scikit-learn is required for Isolation Forest training but is not installed")
    windows = store.read_ml_training_windows(dataset_id)
    if len(windows) < MIN_TRAINING_WINDOWS:
        raise MLTrainingError(
            f"at least {MIN_TRAINING_WINDOWS} verified-normal windows are required for Isolation Forest training"
        )
    expected_hash = schema_hash()
    if any(not window["verified_normal"] or not window["verification"].get("verified_normal") for window in windows):
        raise MLTrainingError("dataset contains unverified training windows")
    if any(window["schema_version"] != SCHEMA_VERSION or window["schema_hash"] != expected_hash for window in windows):
        raise MLTrainingError("dataset contains an incompatible feature schema")
    matrix = np.asarray([[float(window["features"][name]) for name in FEATURE_NAMES] for window in windows], dtype=float)
    if np.unique(matrix, axis=0).shape[0] < MIN_DISTINCT_TRAINING_WINDOWS:
        raise MLTrainingError(
            f"at least {MIN_DISTINCT_TRAINING_WINDOWS} distinct verified-normal feature windows are required"
        )
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state, n_jobs=1)
    model.fit(scaled)
    decisions = model.decision_function(scaled)
    # IsolationForest.decision_function() is centered on its fitted contamination
    # boundary. This is a fixed experimental decision boundary, not independent
    # calibration; activation must be assessed from separate reviewed-normal data.
    threshold = 0.0
    model_id = f"iforest-{uuid.uuid4()}"
    # Persisted as numbers, not as pickled objects: see ml/artifact.py. The
    # sklearn estimator is reduced to tree arrays here, on the machine that has
    # sklearn, and never needs to be reconstructed to score.
    written = write_artifact(
        artifact_directory,
        model_id,
        export_from_sklearn(model, scaler),
        feature_names=FEATURE_NAMES,
        schema_version=SCHEMA_VERSION,
        schema_hash=expected_hash,
        threshold=threshold,
        threshold_provenance=UNCALIBRATED_THRESHOLD_PROVENANCE,
        calibration={
            "status": "requires_independent_verified_normal_holdouts",
            "max_normal_fpr": 0.05,
            "minimum_holdout_windows": 60,
        },
        decision_min=float(np.min(decisions)),
        decision_max=float(np.max(decisions)),
        # The distribution the threshold above sits in. `p1` of a forest fitted at
        # the 0.01 default should land near 0.0, which is the coupling between
        # `contamination` and the threshold made legible.
        training_decision_percentiles=decision_percentiles(decisions),
    )
    metadata = {
        "id": model_id, "version": "iforest.canonical-window.v1", "algorithm": "IsolationForest",
        "hyperparameters": {"n_estimators": n_estimators, "contamination": contamination, "random_state": random_state, "n_jobs": 1},
        "artifact_path": written["artifact_path"], "artifact_checksum": written["artifact_checksum"],
        "schema_version": SCHEMA_VERSION, "schema_hash": expected_hash,
        "training_window_ids": [window["id"] for window in windows],
        "runtime": {"python": sys.version.split()[0], "sklearn": sklearn.__version__, "numpy": np.__version__},
        "evaluation": {
            "status": "not_evaluated",
            "training_window_count": len(windows),
            "calibration_status": "requires_independent_verified_normal_holdouts",
            "activation_eligible": False,
        },
        # Always inactive. Not `bool(activate)` -- see the docstring: a model cannot
        # have been evaluated at the moment it is trained, so an active row here
        # could only ever be an ungated one.
        "active": False, "created_at": time.time(),
    }
    store.write_ml_model(metadata)
    # The artifact format and the array file's own digest are reported but not
    # stored in a new column: `artifact_checksum` pins the descriptor, and the
    # descriptor pins the arrays, so one recorded value covers both files.
    return {**metadata, "artifact_format": ARTIFACT_FORMAT, "arrays_path": written["arrays_path"],
            "arrays_checksum": written["arrays_checksum"]}


# Keys `ml/evaluation.py:calibrate_threshold` returns that this function needs.
# Checked rather than assumed so a hand-built dict cannot smuggle in a threshold
# with no account of where it came from -- `threshold_provenance` is the whole
# reason a recalibrated model is distinguishable from an arbitrary one.
_REQUIRED_CALIBRATION_KEYS = (
    "threshold", "threshold_provenance", "target_fpr", "quantile", "normal_window_count", "in_sample",
)


def rethreshold_model(
    store: SQLiteEventStore, model_id: str, artifact_directory: str, *, calibration: dict[str, Any],
) -> dict[str, Any]:
    """
    Apply a calibrated threshold by minting a *new* model, never by editing one.

    Artifacts are immutable and checksum-pinned in both directions -- the database
    pins the descriptor, the descriptor pins the arrays -- so "move the threshold"
    cannot mean rewriting a file in place without breaking the only chain that
    makes a loaded model trustworthy. It means writing a second artifact and a
    second `ml_models` row that shares the first's forest, scaler, training window
    ids, and training-score distribution, and differs in exactly three fields:
    `threshold`, `threshold_provenance`, and `calibration`.

    No scikit-learn required. The forest is rebuilt from the loaded artifact's own
    validated arrays, which are the same five values `export_from_sklearn` produces
    (`ml/iforest.py:NativeIsolationForest` stores them under the same names), so
    the arrays written are the arrays read. `decision_min`, `decision_max`, and
    `training_decision_percentiles` carry over verbatim: the training distribution
    is a property of the fitted forest and the data, and neither moved.

    The new row is inactive, like every row this module writes. Recalibrating is
    not evaluating, and `storage/sqlite_store.py:activate_ml_model` remains the
    only door to `active = 1`.

    Note what the caller is responsible for: `calibration` is almost always
    in-sample (see `ml/evaluation.py:calibrate_threshold`), which means a gate run
    against this new model measured on the *same* holdout that produced the
    threshold is circular. This function records the provenance string saying so
    and takes no position beyond that; the CLI is where the two are kept apart.
    """
    missing = [key for key in _REQUIRED_CALIBRATION_KEYS if key not in calibration]
    if missing:
        raise MLTrainingError(f"calibration result is missing {', '.join(missing)}")
    row = store.read_ml_model(model_id)
    if row is None:
        raise MLTrainingError(f"unknown model {model_id!r}")
    try:
        loaded = load_artifact(row["artifact_path"], row["artifact_checksum"])
    except MLArtifactError as error:
        raise MLTrainingError(f"cannot rethreshold {model_id!r}: {error}") from error
    descriptor = loaded["descriptor"]
    percentiles = descriptor.get("training_decision_percentiles")
    if not percentiles:
        # Only an artifact written before `training_decision_percentiles` existed
        # can land here, and the distribution cannot be recovered from the forest
        # alone. Refuse rather than fabricate one or drop the field: a derived
        # model that silently knows less about itself than its parent did is the
        # kind of quiet loss this whole format is built to prevent.
        raise MLTrainingError(
            f"model {model_id!r} predates training_decision_percentiles; retrain it rather than rethresholding"
        )

    forest = loaded["model"]
    threshold = float(calibration["threshold"])
    derived_id = f"iforest-{uuid.uuid4()}"
    written = write_artifact(
        artifact_directory,
        derived_id,
        # The same five values `export_from_sklearn` returns, read back off the
        # verified artifact instead of off a fitted estimator.
        {
            "trees": forest.trees, "offset": forest.offset, "max_samples": forest.max_samples,
            "scaler_mean": forest.scaler_mean, "scaler_scale": forest.scaler_scale,
        },
        feature_names=descriptor["feature_names"],
        schema_version=descriptor["schema_version"],
        schema_hash=descriptor["schema_hash"],
        threshold=threshold,
        threshold_provenance=str(calibration["threshold_provenance"]),
        calibration={
            "method": "holdout_quantile",
            "target_fpr": float(calibration["target_fpr"]),
            "quantile": float(calibration["quantile"]),
            "normal_window_count": int(calibration["normal_window_count"]),
            "normal_window_ids": list(calibration.get("normal_window_ids", [])),
            "in_sample": bool(calibration["in_sample"]),
            "derived_from": model_id,
        },
        # Unchanged by construction: same forest, same training data, same scores.
        decision_min=descriptor["decision_min"],
        decision_max=descriptor["decision_max"],
        training_decision_percentiles=percentiles,
    )
    metadata = {
        "id": derived_id, "version": row["version"], "algorithm": row["algorithm"],
        # `ml_models` has no provenance column and this is not worth a migration:
        # the parent id belongs with the knobs, since the threshold it replaces is
        # the one hyperparameter that changed.
        "hyperparameters": {**row["hyperparameters"], "derived_from": model_id, "threshold": threshold},
        "artifact_path": written["artifact_path"], "artifact_checksum": written["artifact_checksum"],
        "schema_version": row["schema_version"], "schema_hash": row["schema_hash"],
        "training_window_ids": list(row["training_window_ids"]),
        "runtime": dict(row["runtime"]),
        "evaluation": {
            "status": "not_evaluated",
            "training_window_count": len(row["training_window_ids"]),
            "calibration_status": "holdout_quantile",
            "calibration_in_sample": bool(calibration["in_sample"]),
            "activation_eligible": False,
            "derived_from": model_id,
        },
        "active": False, "created_at": time.time(),
    }
    store.write_ml_model(metadata)
    return {**metadata, "artifact_format": ARTIFACT_FORMAT, "arrays_path": written["arrays_path"],
            "arrays_checksum": written["arrays_checksum"], "derived_from": model_id}
