import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence

from pipeline.event_stream import CanonicalNormalizer, Event, EventType


class BehavioralBaseline:
    """
    Lightweight, explainable behavioral baseline for verified Linux telemetry.

    The design intentionally avoids training on a tiny one-off capture as if it were
    a complete normal dataset. Instead, the system learns from a rolling window of
    verified normal telemetry and only considers the baseline ready when it has
    collected enough samples.
    """

    def __init__(self, minimum_samples: int = 500, time_window_seconds: int = 300):
        self.minimum_samples = minimum_samples
        self.time_window_seconds = time_window_seconds

    def _normalize_event(self, event: Any) -> Optional[Event]:
        if isinstance(event, Event):
            return event
        if isinstance(event, dict):
            return CanonicalNormalizer().normalize(event)
        return None

    def _extract_exec_events(self, events: Sequence[Event]) -> List[Event]:
        return [event for event in events if event and event.event_type == EventType.PROCESS_EXEC]

    def _window_counts(self, events: Sequence[Event], bucket_seconds: int = 60) -> Counter:
        bucketed = Counter()
        for event in events:
            if event.timestamp is None:
                continue
            bucket = int(float(event.timestamp) // bucket_seconds)
            bucketed[bucket] += 1
        return bucketed

    def _safe_ratio(self, numerator: float, denominator: float) -> float:
        if denominator == 0 or not math.isfinite(denominator):
            return 0.0
        return float(numerator) / float(denominator)

    def feature_summary(self, events: Sequence[Event]) -> Dict[str, Any]:
        exec_events = self._extract_exec_events(events)
        command_counts = Counter(event.comm for event in exec_events if event.comm)
        executable_counts = Counter(event.executable for event in exec_events if event.executable)
        uid_counts = Counter(event.uid for event in exec_events if event.uid is not None)
        gid_counts = Counter(event.gid for event in exec_events if event.gid is not None)
        ppid_counts = Counter(event.ppid for event in exec_events if event.ppid is not None)
        unique_commands = len(command_counts)
        unique_uids = len(uid_counts)
        total_execs = len(exec_events)
        top_commands = dict(command_counts.most_common(10))
        top_executables = dict(executable_counts.most_common(10))
        top_uids = dict(uid_counts.most_common(10))
        top_gids = dict(gid_counts.most_common(10))
        top_ppids = dict(ppid_counts.most_common(10))

        if exec_events:
            bucket_counts = self._window_counts(exec_events)
            peak_window_count = max(bucket_counts.values()) if bucket_counts else 0
            avg_window_count = sum(bucket_counts.values()) / len(bucket_counts) if bucket_counts else 0.0
        else:
            bucket_counts = Counter()
            peak_window_count = 0
            avg_window_count = 0.0

        return {
            "total_execs": total_execs,
            "unique_commands": unique_commands,
            "unique_uids": unique_uids,
            "top_commands": top_commands,
            "top_executables": top_executables,
            "top_uids": top_uids,
            "top_gids": top_gids,
            "top_ppids": top_ppids,
            "peak_window_count": peak_window_count,
            "avg_window_count": avg_window_count,
            "window_count_buckets": dict(sorted(bucket_counts.items())),
            "sample_window_seconds": self.time_window_seconds,
        }

    def learn(self, events: Iterable[Any]) -> Dict[str, Any]:
        normalized_events = []
        for event in events:
            parsed = self._normalize_event(event)
            if parsed is not None:
                normalized_events.append(parsed)

        normal_count = len(normalized_events)
        exec_events = self._extract_exec_events(normalized_events)
        normal_exec_count = len(exec_events)
        if normal_exec_count < self.minimum_samples:
            return {
                "status": "insufficient_normal_data",
                "normal_count": normal_count,
                "normal_exec_count": normal_exec_count,
                "minimum_required": self.minimum_samples,
                "feature_summary": self.feature_summary(normalized_events),
            }

        summary = self.feature_summary(normalized_events)
        baseline = {
            "baseline_name": "default",
            "window_start": min(float(event.timestamp) for event in exec_events),
            "window_end": max(float(event.timestamp) for event in exec_events),
            "normal_count": normal_exec_count,
            "feature_summary": summary,
            "status": "ready",
        }
        return {
            "status": "ready",
            "normal_count": normal_count,
            "normal_exec_count": normal_exec_count,
            "minimum_required": self.minimum_samples,
            "feature_summary": summary,
            "baseline": baseline,
        }

    def _event_feature_vector(
        self,
        event: Event,
        baseline_summary: Dict[str, Any],
        current_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        command_name = event.comm or "unknown"
        uid_value = event.uid if event.uid is not None else -1

        command_frequency = baseline_summary.get("top_commands", {}).get(command_name, 0)
        executable_name = event.executable or "unknown"
        executable_frequency = baseline_summary.get("top_executables", {}).get(executable_name, 0)
        uid_counts = baseline_summary.get("top_uids", {})
        uid_frequency = uid_counts.get(uid_value, uid_counts.get(str(uid_value), 0))
        gid_value = event.gid if event.gid is not None else -1
        gid_frequency = baseline_summary.get("top_gids", {}).get(gid_value, baseline_summary.get("top_gids", {}).get(str(gid_value), 0))
        ppid_value = event.ppid if event.ppid is not None else -1
        ppid_frequency = baseline_summary.get("top_ppids", {}).get(ppid_value, baseline_summary.get("top_ppids", {}).get(str(ppid_value), 0))
        total_execs = float(baseline_summary.get("total_execs", 1) or 1)
        baseline_peak = float(baseline_summary.get("peak_window_count", 0) or 0)
        current_peak = float(current_summary.get("peak_window_count", 0) or 0)
        burst_excess = self._safe_ratio(max(0.0, current_peak - baseline_peak), max(baseline_peak, 1.0))

        return {
            "event_type": event.event_type.value,
            "timestamp": event.timestamp,
            "uid": uid_value,
            "comm": command_name,
            "command_frequency": command_frequency,
            "executable": executable_name,
            "executable_frequency": executable_frequency,
            "uid_frequency": uid_frequency,
            "gid_frequency": gid_frequency,
            "ppid_frequency": ppid_frequency,
            "command_ratio": self._safe_ratio(command_frequency, total_execs),
            "executable_ratio": self._safe_ratio(executable_frequency, total_execs),
            "process_context_ratio": self._safe_ratio(gid_frequency + ppid_frequency, max(total_execs * 2.0, 1.0)),
            "burst_ratio": min(1.0, burst_excess),
        }

    def score_events(self, events: Iterable[Any], baseline_summary: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        normalized_events = []
        for event in events:
            parsed = self._normalize_event(event)
            if parsed is not None:
                normalized_events.append(parsed)

        if not normalized_events:
            return []

        if baseline_summary is None:
            baseline_summary = self.feature_summary(normalized_events)
        current_summary = self.feature_summary(normalized_events)

        scored = []
        exec_events = self._extract_exec_events(normalized_events)
        if not exec_events:
            return scored

        total_execs = float(baseline_summary.get("total_execs", 1) or 1)
        avg_window_count = float(baseline_summary.get("avg_window_count", 1) or 1)
        peak_window_count = float(baseline_summary.get("peak_window_count", 1) or 1)

        for event in exec_events:
            feature_vector = self._event_feature_vector(event, baseline_summary, current_summary)
            command_ratio = feature_vector["command_ratio"]
            executable_ratio = feature_vector["executable_ratio"]
            uid_frequency = feature_vector["uid_frequency"]
            process_context_ratio = feature_vector["process_context_ratio"]
            burst_ratio = feature_vector["burst_ratio"]
            unusual_command_score = max(0.0, 1.0 - (0.70 * command_ratio + 0.30 * executable_ratio))
            unusual_uid_score = max(0.0, 1.0 - (0.80 * self._safe_ratio(uid_frequency, max(total_execs, 1.0)) + 0.20 * process_context_ratio))
            score = min(1.0, 0.45 * unusual_command_score + 0.35 * unusual_uid_score + 0.20 * burst_ratio)

            if event.comm in {"bash", "sh", "timeout", "sudo"}:
                score *= 0.65

            bucket = "normal"
            if score > 0.75:
                bucket = "high"
            elif score > 0.45:
                bucket = "medium"

            scored.append({
                "event_type": event.event_type.value,
                "timestamp": event.timestamp,
                "pid": event.pid,
                "uid": event.uid,
                "comm": event.comm,
                "anomaly_score": round(score, 4),
                "score_bucket": bucket,
                "explanation": (
                    f"command_frequency={feature_vector['command_frequency']}; "
                    f"executable={feature_vector['executable']}; "
                    f"executable_frequency={feature_vector['executable_frequency']}; "
                    f"ppid_frequency={feature_vector['ppid_frequency']}; "
                    f"gid_frequency={feature_vector['gid_frequency']}; "
                    f"command_ratio={command_ratio:.6f}; "
                    f"uid_frequency={uid_frequency}; "
                    f"uid_deviation={unusual_uid_score:.6f}; "
                    f"burst_ratio={burst_ratio:.6f}; "
                    f"command_deviation={unusual_command_score:.6f}; "
                    f"weights=0.45,0.35,0.20; "
                    f"common_command_discount={event.comm in {'bash', 'sh', 'timeout', 'sudo'}}"
                ),
            })

        return scored
