"""Schema-checked optional Isolation Forest inference over canonical windows."""

from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from ml.artifact import MLArtifactError, load_artifact
from ml.attribution import attribute_anomaly
from ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, extract_features, schema_hash
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


class MLScoringError(RuntimeError):
    pass


class MLScorer:
    def __init__(
        self,
        store: SQLiteEventStore,
        model_id: str,
        *,
        attribute: bool = False,
        allow_inactive: bool = False,
    ):
        # Opt-in-within-opt-in: a scorer must be configured *and* attribution
        # enabled. Default-off keeps the shipped payload byte-for-byte unchanged
        # and attribution off the default hot path -- it is advisory metadata an
        # operator turns on, never a scoring behaviour.
        self.attribute = attribute
        metadata = store.read_ml_model(model_id)
        if metadata is None:
            raise MLScoringError("ML model metadata was not found")
        # Declared non-optional on purpose: the raise above *is* the invariant, so
        # every later `self.metadata[...]` is unconditional rather than guarded.
        # There is no such thing as a constructed scorer without its metadata, and
        # saying so here is what lets a type checker agree.
        self.metadata: dict[str, Any] = metadata
        # Activation gates scoring, and this is where it is enforced: refusing to
        # *construct* the scorer means an inactive model has no scoring path at
        # all, rather than one whose output a caller is trusted to discard. The
        # activation gate is only a gate if something is actually shut by it.
        #
        # `metadata["active"]` only, not the lifecycle state: `ml.scoring` cannot
        # import `ml.lifecycle` without closing the cycle
        # `ml.lifecycle -> ml.evaluation -> ml.scoring`. The flag is the right thing
        # to read anyway -- `storage/sqlite_store.py:activate_ml_model` is the only
        # writer that can set it, and it already requires both the gate verdict and
        # a recorded `eligible` state, so the flag *is* that check's conclusion.
        #
        # `allow_inactive` is the one legitimate exception, named so it greps:
        # evaluation must score an inactive model, because scoring it against
        # holdout windows is how it becomes eligible in the first place. A gate
        # that refused that would be unsatisfiable. Nothing on the detection path
        # passes it.
        if not allow_inactive and self.metadata["active"] is not True:
            raise MLScoringError("ML model is not active; refusing to construct a scoring path")
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
        # The windows are present -- but present is not intact. These rows are the
        # scorer's attribution baseline (the per-feature training min/max/mean built
        # just below), so an edited one silently relabels which feature looks
        # unusual. Verified here, at construction, for the same reason activation is:
        # a model whose provenance does not verify should have no scoring path at
        # all, rather than one producing explanations drawn from altered data.
        #
        # Scoped to this model's own `training_window_ids`, so the cost is its
        # provenance list and not the corpus table. The reason string names
        # *tampering* specifically because the detector catches `MLScoringError` and
        # degrades to deterministic scoring; "provenance is incomplete" and "a row
        # was edited" call for different operator responses, and a generic message
        # would make them indistinguishable in the degradation reason.
        verification = store.verify_ml_training_windows(window_ids=self.metadata["training_window_ids"])
        if not verification["ok"]:
            raise MLScoringError(
                "ML training-window provenance is tampered: "
                f"{len(verification['mismatched_ids'])} of {verification['checked']} windows "
                "fail hash verification"
            )
        # Per-feature training min/max/mean depend only on the fixed training
        # windows, never on the scored event, so they are identical on every
        # score() call. Memoise them on first use: the first score() still runs
        # the build -- preserving the original call-time semantics, including the
        # ValueError an empty training set would raise -- and every later call
        # reuses the result instead of re-folding all windows per feature.
        self._training_stats: dict[str, tuple[float, float, float]] | None = None

    def _training_feature_stats(self) -> dict[str, tuple[float, float, float]]:
        stats = self._training_stats
        if stats is None:
            stats = {}
            for name in FEATURE_NAMES:
                values = [float(window["features"][name]) for window in self.training_windows]
                stats[name] = (min(values), max(values), sum(values) / len(values))
            self._training_stats = stats
        return stats

    def _feature_diagnostics(self, features: dict[str, float], scaled: np.ndarray) -> list[dict[str, Any]]:
        stats = self._training_feature_stats()
        diagnostics = []
        for index, name in enumerate(FEATURE_NAMES):
            value = float(features[name])
            lower, upper, mean = stats[name]
            diagnostics.append({
                "feature": name,
                "value": value,
                "training_min": lower,
                "training_max": upper,
                "training_mean": mean,
                "absolute_zscore": round(float(abs(scaled[index])), 6),
                "in_training_range": lower <= value <= upper,
            })
        return diagnostics

    def score(self, events: Sequence[Event]) -> dict[str, Any]:
        """Extract features from a canonical window and score them. The hot path."""
        return self.score_features(extract_features(events))

    def score_features(self, features: Mapping[str, float]) -> dict[str, Any]:
        """
        Score an already-extracted feature mapping, for callers holding one.

        This is the body of `score()` with feature extraction lifted out, so a
        caller holding *stored* features -- an `ml_training_windows` row, which
        persists the 34 values computed when the window was collected -- can score
        them without reconstructing the events they came from. Evaluation is that
        caller: a holdout dataset is rows of features, and rebuilding `Event`
        objects from them is not possible. `score()` is the only caller that
        extracts, and both produce the identical payload.

        Soundness rests on a check made elsewhere, so name it here: reusing a stored
        vector is only equivalent to re-extracting it if the schema that produced it
        is the schema running now. `__init__` refuses a model whose `schema_hash`
        differs from this runtime's, and `storage/sqlite_store.py:write_ml_training_window`
        refuses to store a window under a different one -- together, that is what
        makes the two interchangeable. If the feature set is ever changed without
        bumping `schema_hash`, this path silently scores stale vectors; the hash
        bump is load-bearing, not bookkeeping.
        """
        missing = [name for name in FEATURE_NAMES if name not in features]
        unexpected = sorted(set(features) - set(FEATURE_NAMES))
        if missing or unexpected:
            # Fail closed rather than defaulting an absent feature to zero: a
            # partial vector scores as a *plausible* window, and a wrong score is
            # worse than a refusal.
            raise MLScoringError(
                "feature mapping does not match the active feature schema "
                f"(missing: {missing}; unexpected: {unexpected})"
            )
        # Re-keyed into FEATURE_NAMES order with values passed through untouched. A
        # mapping decoded from stored JSON carries no order guarantee, and
        # `feature_values` below is part of the payload; coercing the values instead
        # would change `score()`'s output, which must stay identical.
        values: dict[str, float] = {name: features[name] for name in FEATURE_NAMES}
        vector = np.asarray([[values[name] for name in FEATURE_NAMES]], dtype=float)
        # The native forest folds the scaler into decision_function, so the two can
        # no longer be applied out of order or independently of each other.
        raw = float(self.model.decision_function(vector)[0])
        lower, upper = self.artifact["decision_min"], self.artifact["decision_max"]
        normalized = 1.0 - ((raw - lower) / (upper - lower)) if upper > lower else 0.0
        normalized = float(min(1.0, max(0.0, normalized)))
        scaled = self.model.transform(vector)[0]
        diagnostics = self._feature_diagnostics(values, scaled)
        deviations = sorted(diagnostics, key=lambda item: item["absolute_zscore"], reverse=True)[:5]
        result = {
            "available": True, "model_id": self.metadata["id"], "model_version": self.metadata["version"],
            "schema_version": SCHEMA_VERSION, "schema_hash": schema_hash(), "raw_score": raw,
            "normalized_score": normalized, "threshold": float(self.artifact["threshold"]),
            "is_anomaly": raw <= float(self.artifact["threshold"]), "feature_values": values,
            "contributing_feature_deviations": deviations, "feature_diagnostics": diagnostics,
            "training_window_ids": self.metadata["training_window_ids"], "model_active": self.metadata["active"],
            "threshold_provenance": self.artifact["threshold_provenance"],
            "calibration": self.artifact["calibration"],
            "artifact_format": self.artifact["artifact_format"],
        }
        if self.attribute:
            # Model-faithful decomposition of the same forest path this score came
            # from, reusing the already-built feature vector. Additive to the
            # payload only when enabled; the default dict above is unchanged.
            result["attribution"] = attribute_anomaly(self.model, vector[0], FEATURE_NAMES)
        return result


def unavailable_evidence(reason: str = "no compatible ML model is configured") -> dict[str, Any]:
    return {"available": False, "reason": reason}
