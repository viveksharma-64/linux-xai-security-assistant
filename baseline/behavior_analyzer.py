from collections import Counter, defaultdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence

from baseline.behavioral_baseline import BehavioralBaseline
from pipeline.event_stream import CanonicalNormalizer, Event, EventType
from storage.sqlite_store import SQLiteEventStore


class AnalysisMode(str, Enum):
    LEARNING = "learning"
    MONITORING = "monitoring"


class BehaviorAnalyzer:
    """
    Phase 3 windowed behavior analysis around the Phase 2 baseline engine.

    Normal data enters only through learn_normal(..., verified_normal=True).
    Monitoring never mutates the normal sample set or promotes a baseline.
    """

    def __init__(
        self,
        store: SQLiteEventStore,
        window_seconds: int = 300,
        minimum_normal_execs: int = 500,
        detection_threshold: float = 0.45,
    ):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if minimum_normal_execs <= 0:
            raise ValueError("minimum_normal_execs must be positive")
        if not 0.0 <= detection_threshold <= 1.0:
            raise ValueError("detection_threshold must be between 0 and 1")

        self.store = store
        self.window_seconds = window_seconds
        self.detection_threshold = detection_threshold
        self.baseline = BehavioralBaseline(
            minimum_samples=minimum_normal_execs,
            time_window_seconds=window_seconds,
        )
        self._normal_events: List[Event] = []
        self._baseline_summary: Optional[Dict[str, Any]] = None

    def _normalize_events(self, events: Iterable[Any]) -> List[Event]:
        normalizer = CanonicalNormalizer()
        normalized = []
        for event in events:
            if isinstance(event, Event):
                parsed = event
            elif isinstance(event, dict):
                parsed = normalizer.normalize(event)
            else:
                parsed = None
            if parsed is not None:
                normalized.append(parsed)
        return sorted(
            normalized,
            key=lambda item: (
                float(item.timestamp),
                item.event_type.value,
                item.pid if item.pid is not None else -1,
                item.comm or "",
            ),
        )

    def _execution_events(self, events: Sequence[Event]) -> List[Event]:
        return [event for event in events if event.event_type == EventType.PROCESS_EXEC]

    def _window_start(self, timestamp: float) -> float:
        return float(int(timestamp // self.window_seconds) * self.window_seconds)

    def aggregate_windows(self, events: Iterable[Any]) -> List[Dict[str, Any]]:
        normalized = self._normalize_events(events)
        grouped: Dict[float, List[Event]] = defaultdict(list)
        for event in self._execution_events(normalized):
            grouped[self._window_start(float(event.timestamp))].append(event)

        windows = []
        for window_start in sorted(grouped):
            window_events = grouped[window_start]
            command_frequency = Counter(event.comm or "unknown" for event in window_events)
            uid_activity = Counter(
                str(event.uid) if event.uid is not None else "unknown"
                for event in window_events
            )
            second_activity = Counter(int(float(event.timestamp)) for event in window_events)
            windows.append(
                {
                    "window_start": window_start,
                    "window_end": window_start + self.window_seconds,
                    "total_execs": len(window_events),
                    "unique_commands": len(command_frequency),
                    "unique_uids": len(uid_activity),
                    "command_frequency": dict(sorted(command_frequency.items())),
                    "uid_activity": dict(sorted(uid_activity.items())),
                    "burst_activity": {
                        "active_seconds": len(second_activity),
                        "peak_execs_per_second": max(second_activity.values()) if second_activity else 0,
                    },
                    "events": window_events,
                }
            )
        return windows

    def _persist_learning_state(self, result: Dict[str, Any]) -> None:
        feature_summary = result.get("feature_summary", {})
        self.store.write_baseline_record(
            {
                "baseline_name": "default",
                "window_start": result.get("baseline", {}).get("window_start"),
                "window_end": result.get("baseline", {}).get("window_end"),
                "normal_count": result.get("normal_exec_count", 0),
                "feature_summary": feature_summary,
                "status": result["status"],
            }
        )

    def learn_normal(self, events: Iterable[Any], verified_normal: bool = False) -> Dict[str, Any]:
        """Add explicitly verified normal events and attempt baseline promotion."""
        if not verified_normal:
            return {
                "mode": AnalysisMode.LEARNING.value,
                "status": "normal_verification_required",
                "normal_exec_count": len(self._execution_events(self._normal_events)),
            }

        if self._baseline_summary is not None:
            return {
                "mode": AnalysisMode.MONITORING.value,
                "status": "baseline_ready",
                "normal_exec_count": len(self._execution_events(self._normal_events)),
            }

        self._normal_events.extend(self._normalize_events(events))
        result = self.baseline.learn(self._normal_events)
        self._persist_learning_state(result)
        if result["status"] == "ready":
            self._baseline_summary = result["feature_summary"]
            return {
                "mode": AnalysisMode.MONITORING.value,
                "status": "baseline_ready",
                "normal_exec_count": result["normal_exec_count"],
                "minimum_required": result["minimum_required"],
            }

        return {
            "mode": AnalysisMode.LEARNING.value,
            "status": "insufficient_normal_data",
            "normal_exec_count": result["normal_exec_count"],
            "minimum_required": result["minimum_required"],
        }

    def _load_baseline_summary(self) -> Optional[Dict[str, Any]]:
        if self._baseline_summary is not None:
            return self._baseline_summary
        stored = self.store.read_latest_ready_baseline()
        if stored is None:
            return None
        self._baseline_summary = stored["feature_summary"]
        return self._baseline_summary

    def _risk_level(self, score: float) -> str:
        if score >= 0.75:
            return "high"
        if score >= self.detection_threshold:
            return "medium"
        return "normal"

    def monitor(self, events: Iterable[Any], persist: bool = True) -> Dict[str, Any]:
        """Compare current events against a READY baseline without learning from them."""
        baseline_summary = self._load_baseline_summary()
        if baseline_summary is None:
            return {
                "mode": AnalysisMode.LEARNING.value,
                "status": "baseline_not_ready",
                "risks": [],
            }

        normalized = self._normalize_events(events)
        risks = []
        for window in self.aggregate_windows(normalized):
            scored = self.baseline.score_events(window["events"], baseline_summary)
            by_entity: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
            for score in scored:
                by_entity[("command", score["comm"] or "unknown")].append(score)
                by_entity[("uid", str(score["uid"]) if score["uid"] is not None else "unknown")].append(score)

            for (entity_type, entity_key), entity_scores in sorted(by_entity.items()):
                max_score_record = max(
                    entity_scores,
                    key=lambda item: (item["anomaly_score"], item["timestamp"], item["pid"] or -1),
                )
                anomaly_score = float(max_score_record["anomaly_score"])
                if anomaly_score < self.detection_threshold:
                    continue

                features = {
                    "execution_frequency": window["total_execs"],
                    "unique_commands": window["unique_commands"],
                    "unique_uids": window["unique_uids"],
                    "command_frequency": window["command_frequency"],
                    "uid_activity": window["uid_activity"],
                    "burst_activity": window["burst_activity"],
                    "entity_event_count": len(entity_scores),
                    "event_max_score": anomaly_score,
                }
                explanation = (
                    f"{entity_type}={entity_key}; window_execs={window['total_execs']}; "
                    f"entity_event_count={len(entity_scores)}; "
                    f"peak_execs_per_second={window['burst_activity']['peak_execs_per_second']}; "
                    f"source={max_score_record['explanation']}"
                )
                risk = {
                    "window_start": window["window_start"],
                    "window_end": window["window_end"],
                    "entity_type": entity_type,
                    "entity_key": entity_key,
                    "anomaly_score": anomaly_score,
                    "risk_level": self._risk_level(anomaly_score),
                    "contributing_features": features,
                    "explanation": explanation,
                    "mode": AnalysisMode.MONITORING.value,
                }
                risks.append(risk)
                if persist:
                    self.store.write_risk_record(risk)

        return {
            "mode": AnalysisMode.MONITORING.value,
            "status": "monitoring",
            "risks": risks,
        }
