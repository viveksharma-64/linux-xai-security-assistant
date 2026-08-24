"""Explicit verified-normal dataset capture and Isolation Forest training."""

import hashlib
import os
import pickle
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

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

from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, extract_features, schema_hash
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


MIN_TRAINING_WINDOWS = 10
MIN_DISTINCT_TRAINING_WINDOWS = 3


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
    contamination: float = 0.05, random_state: int = 42, activate: bool = False,
) -> dict[str, Any]:
    """Train only from an explicit all-verified-normal, schema-compatible dataset."""
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
    artifact = {
        "model": model, "scaler": scaler, "feature_names": list(FEATURE_NAMES),
        "schema_version": SCHEMA_VERSION, "schema_hash": expected_hash,
        "decision_min": float(np.min(decisions)), "decision_max": float(np.max(decisions)), "threshold": threshold,
        "threshold_provenance": "isolation_forest_decision_boundary; not independently calibrated",
        "calibration": {
            "status": "requires_independent_verified_normal_holdouts",
            "max_normal_fpr": 0.05,
            "minimum_holdout_windows": 60,
        },
    }
    directory = Path(artifact_directory)
    directory.mkdir(parents=True, exist_ok=True)
    artifact_path = directory / f"{model_id}.pkl"
    payload = pickle.dumps(artifact, protocol=pickle.HIGHEST_PROTOCOL)
    checksum = hashlib.sha256(payload).hexdigest()
    artifact_path.write_bytes(payload)
    metadata = {
        "id": model_id, "version": "iforest.canonical-window.v1", "algorithm": "IsolationForest",
        "hyperparameters": {"n_estimators": n_estimators, "contamination": contamination, "random_state": random_state, "n_jobs": 1},
        "artifact_path": str(artifact_path), "artifact_checksum": checksum,
        "schema_version": SCHEMA_VERSION, "schema_hash": expected_hash,
        "training_window_ids": [window["id"] for window in windows],
        "runtime": {"python": sys.version.split()[0], "sklearn": sklearn.__version__, "numpy": np.__version__},
        "evaluation": {
            "status": "not_evaluated",
            "training_window_count": len(windows),
            "calibration_status": "requires_independent_verified_normal_holdouts",
            "activation_eligible": False,
        },
        "active": bool(activate), "created_at": time.time(),
    }
    store.write_ml_model(metadata)
    return metadata
