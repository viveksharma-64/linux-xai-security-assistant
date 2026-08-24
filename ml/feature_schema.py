"""Deterministic, named behavioral-window features for canonical Events."""

import hashlib
import json
import math
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

from pipeline.event_stream import Event, EventType


SCHEMA_VERSION = "canonical-window.v1"
FEATURE_DEFINITIONS = {
    "event_count": "Number of canonical events in the window.",
    "window_seconds": "Observed timestamp span, zero for fewer than two events.",
    "events_per_minute": "Event count divided by observed span, normalized to a minute.",
    "interevent_mean_seconds": "Mean adjacent timestamp interval.",
    "interevent_std_seconds": "Population standard deviation of adjacent timestamp intervals.",
    "interevent_max_seconds": "Maximum adjacent timestamp interval.",
    "unique_event_types": "Distinct canonical event types.",
    "unique_pids": "Distinct non-null process IDs.",
    "unique_uids": "Distinct non-null user IDs.",
    "unique_commands": "Distinct non-null command names.",
    "privileged_event_count": "Events with uid equal to zero.",
    "process_exec_count": "process_exec events.",
    "process_executable_diversity": "Distinct known executable paths on process events.",
    "process_parent_diversity": "Distinct known parent command names on process events.",
    "file_event_count": "file_open plus file_write events.",
    "file_unique_path_count": "Distinct known file paths.",
    "file_operation_diversity": "Distinct known file operations.",
    "network_connection_count": "tcp_connect events.",
    "network_unique_destination_ip_count": "Distinct known TCP destination IPs.",
    "network_unique_destination_port_count": "Distinct known TCP destination ports.",
    "network_repeated_destination_count": "Destination IP/port pairs observed more than once.",
    "auth_event_count": "auth_session events.",
    "auth_failure_count": "Authentication/session records with result=failure.",
    "auth_successful_session_count": "Successful session_opened/session_closed records.",
    "auth_service_diversity": "Distinct known PAM service names.",
    "service_event_count": "service_state events.",
    "service_started_count": "Service lifecycle records with action=started.",
    "service_stopped_count": "Service lifecycle records with action=stopped.",
    "service_failed_count": "Service lifecycle records with action=failed.",
    "service_restarted_count": "Service lifecycle records with action=restarted.",
    "service_unique_unit_count": "Distinct known affected systemd units.",
    "ipc_event_count": "ipc_event records.",
    "ipc_pipe_created_count": "IPC records with action=pipe_created.",
    "ipc_process_diversity": "Distinct PIDs associated with IPC events.",
}
FEATURE_NAMES = tuple(FEATURE_DEFINITIONS)


def schema_document() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES), "definitions": FEATURE_DEFINITIONS}


def schema_hash() -> str:
    encoded = json.dumps(schema_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payload(event: Event) -> Mapping[str, Any]:
    return event.payload if isinstance(event.payload, dict) else {}


def _distinct(values: Iterable[Any]) -> int:
    return len({value for value in values if value is not None and value != ""})


def extract_features(events: Sequence[Event]) -> dict[str, float]:
    """Return the complete ordered named feature mapping for one event window."""
    ordered = sorted(events, key=lambda event: (float(event.timestamp), event.event_type.value, event.pid or -1))
    timestamps = [float(event.timestamp) for event in ordered if math.isfinite(float(event.timestamp))]
    intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
    span = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
    variance = sum((value - mean_interval) ** 2 for value in intervals) / len(intervals) if intervals else 0.0
    by_type = Counter(event.event_type for event in ordered)
    process = [event for event in ordered if event.event_type == EventType.PROCESS_EXEC]
    files = [event for event in ordered if event.event_type in (EventType.FILE_OPEN, EventType.FILE_WRITE)]
    network = [event for event in ordered if event.event_type == EventType.TCP_CONNECT]
    auth = [event for event in ordered if event.event_type == EventType.AUTH_SESSION]
    service = [event for event in ordered if event.event_type == EventType.SERVICE_STATE]
    ipc = [event for event in ordered if event.event_type == EventType.IPC_EVENT]
    destinations = [( _payload(event).get("dest_ip"), _payload(event).get("dest_port")) for event in network]
    destination_counts = Counter(pair for pair in destinations if pair[0] is not None and pair[1] is not None)
    values = {
        "event_count": len(ordered), "window_seconds": span,
        "events_per_minute": len(ordered) * 60.0 / span if span > 0 else 0.0,
        "interevent_mean_seconds": mean_interval, "interevent_std_seconds": math.sqrt(variance),
        "interevent_max_seconds": max(intervals) if intervals else 0.0,
        "unique_event_types": len(by_type), "unique_pids": _distinct(event.pid for event in ordered),
        "unique_uids": _distinct(event.uid for event in ordered), "unique_commands": _distinct(event.comm for event in ordered),
        "privileged_event_count": sum(event.uid == 0 for event in ordered),
        "process_exec_count": len(process), "process_executable_diversity": _distinct(event.executable for event in process),
        "process_parent_diversity": _distinct(event.parent_comm for event in process),
        "file_event_count": len(files), "file_unique_path_count": _distinct(_payload(event).get("path") or _payload(event).get("filename") for event in files),
        "file_operation_diversity": _distinct(_payload(event).get("operation") for event in files),
        "network_connection_count": len(network), "network_unique_destination_ip_count": _distinct(pair[0] for pair in destinations),
        "network_unique_destination_port_count": _distinct(pair[1] for pair in destinations),
        "network_repeated_destination_count": sum(count > 1 for count in destination_counts.values()),
        "auth_event_count": len(auth), "auth_failure_count": sum(_payload(event).get("result") == "failure" for event in auth),
        "auth_successful_session_count": sum(_payload(event).get("result") == "success" and str(_payload(event).get("action", "")).startswith("session_") for event in auth),
        "auth_service_diversity": _distinct(_payload(event).get("service") for event in auth),
        "service_event_count": len(service), "service_started_count": sum(_payload(event).get("action") == "started" for event in service),
        "service_stopped_count": sum(_payload(event).get("action") == "stopped" for event in service),
        "service_failed_count": sum(_payload(event).get("action") == "failed" for event in service),
        "service_restarted_count": sum(_payload(event).get("action") == "restarted" for event in service),
        "service_unique_unit_count": _distinct(_payload(event).get("unit") for event in service),
        "ipc_event_count": len(ipc), "ipc_pipe_created_count": sum(_payload(event).get("action") == "pipe_created" for event in ipc),
        "ipc_process_diversity": _distinct(event.pid for event in ipc),
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_vector(events: Sequence[Event]) -> list[float]:
    values = extract_features(events)
    return [values[name] for name in FEATURE_NAMES]
