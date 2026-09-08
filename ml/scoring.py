"""Schema-checked optional Isolation Forest inference over canonical windows."""

from typing import Any, Sequence

import numpy as np

from ml.artifact import MLArtifactError, load_artifact
from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, extract_features, schema_hash
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


class MLScoringError(RuntimeError):
    pass


class MLScorer:
    def __init__(self, store: SQLiteEventStore, model_id: str):
        self.metadata = store.read_ml_model(model_id)
        if self.metadata is None:
            raise MLScoringError("ML model metadata was not found")
        if self.metadata["schema_version"] != SCHEMA_VERSION or self.metadata["schema_hash"] != schema_hash():
            raise MLScoringError("ML model feature schema is incompatible with this runtime")
        # ml/artifact.py owns the verify-then-parse ordering and refuses anything
        # that cannot be authenticated; its messages name the failing property, so
        # they are carried through rather than replaced.
        try:
            loaded = load_artifact(self.metadata["artifact_path"], self.metadata["artifact_checksum"])
        except MLArtifactError as error:
            raise MLScoringError(str(error)) from error
        self.artifact = loaded["descriptor"]
        self.model = loaded["model"]
        if self.artifact["feature_names"] != list(FEATURE_NAMES) or self.artifact["schema_hash"] != schema_hash():
            raise MLScoringError("ML artifact feature schema is incompatible with this runtime")
        self.training_windows = store.read_ml_training_windows_by_ids(self.metadata["training_window_ids"])
        if len(self.training_windows) != len(self.metadata["training_window_ids"]):
            raise MLScoringError("ML training-window provenance is incomplete")

    def _feature_diagnostics(self, features: dict[str, float], scaled: np.ndarray) -> list[dict[str, Any]]:
        diagnostics = []
        for index, name in enumerate(FEATURE_NAMES):
            values = [float(window["features"][name]) for window in self.training_windows]
            value = float(features[name])
            lower, upper = min(values), max(values)
            diagnostics.append({
                "feature": name,
                "value": value,
                "training_min": lower,
                "training_max": upper,
                "training_mean": sum(values) / len(values),
                "absolute_zscore": round(float(abs(scaled[index])), 6),
                "in_training_range": lower <= value <= upper,
            })
        return diagnostics

    def score(self, events: Sequence[Event]) -> dict[str, Any]:
        features = extract_features(events)
        vector = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=float)
        # The native forest folds the scaler into decision_function, so the two can
        # no longer be applied out of order or independently of each other.
        raw = float(self.model.decision_function(vector)[0])
        lower, upper = self.artifact["decision_min"], self.artifact["decision_max"]
        normalized = 1.0 - ((raw - lower) / (upper - lower)) if upper > lower else 0.0
        normalized = float(min(1.0, max(0.0, normalized)))
        scaled = self.model.transform(vector)[0]
        diagnostics = self._feature_diagnostics(features, scaled)
        deviations = sorted(diagnostics, key=lambda item: item["absolute_zscore"], reverse=True)[:5]
        return {
            "available": True, "model_id": self.metadata["id"], "model_version": self.metadata["version"],
            "schema_version": SCHEMA_VERSION, "schema_hash": schema_hash(), "raw_score": raw,
            "normalized_score": normalized, "threshold": float(self.artifact["threshold"]),
            "is_anomaly": raw <= float(self.artifact["threshold"]), "feature_values": features,
            "contributing_feature_deviations": deviations, "feature_diagnostics": diagnostics,
            "training_window_ids": self.metadata["training_window_ids"], "model_active": self.metadata["active"],
            "threshold_provenance": self.artifact["threshold_provenance"],
            "calibration": self.artifact["calibration"],
            "artifact_format": self.artifact["artifact_format"],
        }


def unavailable_evidence(reason: str = "no compatible ML model is configured") -> dict[str, Any]:
    return {"available": False, "reason": reason}
