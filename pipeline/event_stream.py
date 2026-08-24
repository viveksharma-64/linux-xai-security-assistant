#!/usr/bin/env python3
"""
pipeline/event_stream.py

Canonical event interface for Phase 1 → Phase 2 integration.

Phase 1 (telemetry_collector.py) emits JSON lines matching these schemas.
Phase 2 (Event Normalizer) consumes these and produces canonical Event objects.

This interface ensures:
- Telemetry is independent of downstream processing
- Phase 1 can be replaced/enhanced without breaking Phase 2+
- Events are structured, typed, and version-controlled
- All relevant context is captured at collection time
"""

import json
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, Iterator, Optional, Union


def _coerce_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """Safely coerce numeric values while rejecting invalid input."""
    if value is None:
        return default
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _coerce_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# =============================================================================
# CANONICAL EVENT TYPES (from Phase 1 telemetry)
# =============================================================================


class EventType(str, Enum):
    """All event types emitted by Phase 1 telemetry layer."""

    # Kernel-level events
    PROCESS_EXEC = "process_exec"
    TCP_CONNECT = "tcp_connect"
    FILE_OPEN = "file_open"
    FILE_WRITE = "file_write"
    AUTH_SESSION = "auth_session"
    SERVICE_STATE = "service_state"
    IPC_EVENT = "ipc_event"

    # System health
    SYSTEM_HEALTH = "system_health"

    # Telemetry lifecycle (diagnostic)
    TELEMETRY_STARTUP = "telemetry_startup"
    TELEMETRY_SHUTDOWN = "telemetry_shutdown"
    TELEMETRY_INFO = "telemetry_info"
    TELEMETRY_WARNING = "telemetry_warning"


@dataclass
class Event:
    """
    Canonical event representation.

    All telemetry events normalize to this structure for Phase 2+ processing.
    """

    # Core fields (present in all events)
    event_type: EventType
    timestamp: float  # Unix timestamp (seconds)
    timestamp_ns: Optional[int] = None  # Kernel clock (nanoseconds, if available)

    # Process context (present in kernel events)
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    comm: Optional[str] = None  # Process name
    executable: Optional[str] = None
    parent_comm: Optional[str] = None
    ancestry: Optional[list] = None

    # Event-specific payload
    payload: Dict[str, Any] = None  # Event-specific data

    # Metadata
    source: str = "telemetry_bcc"  # Origin (BCC, auditd, etc.)
    version: str = "1.0"  # Event schema version

    def __post_init__(self):
        if self.payload is None:
            self.payload = {}
        if self.ancestry is None:
            self.ancestry = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert event to JSON string."""
        data = self.to_dict()
        # Convert enum to string
        data["event_type"] = data["event_type"].value
        return json.dumps(data)

    @classmethod
    def from_raw_json(cls, raw_json: dict) -> "Event":
        """
        Factory method: parse raw JSON from Phase 1 telemetry into canonical Event.

        Handles all event types and normalizes to common structure.
        """
        event_type_str = raw_json.get("event_type", "")

        # Try to match event type
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            # Unknown event type; skip
            return None

        # Common fields
        timestamp = raw_json.get("timestamp", 0.0)
        timestamp_ns = raw_json.get("timestamp_ns", None)
        pid = raw_json.get("pid", None)
        ppid = raw_json.get("ppid", None)
        uid = raw_json.get("uid", None)
        gid = raw_json.get("gid", None)
        comm = raw_json.get("comm", None)
        executable = raw_json.get("executable") or raw_json.get("filename", None)
        parent_comm = raw_json.get("parent_comm", None)
        ancestry = raw_json.get("ancestry", [])
        if not isinstance(ancestry, list):
            ancestry = []

        # Build event-specific payload
        payload = {}

        if event_type == EventType.PROCESS_EXEC:
            payload = {
                "filename": raw_json.get("filename"),
            }

        elif event_type == EventType.TCP_CONNECT:
            payload = {
                "dest_ip": raw_json.get("dest_ip"),
                "dest_port": raw_json.get("dest_port"),
            }

        elif event_type in (EventType.FILE_OPEN, EventType.FILE_WRITE):
            filename = raw_json.get("filename", raw_json.get("path"))
            payload = {
                "filename": filename,
                "path": raw_json.get("path", filename),
                "operation": raw_json.get("operation"),
                "success": raw_json.get("success"),
            }

        elif event_type == EventType.AUTH_SESSION:
            payload = {
                "action": raw_json.get("action"),
                "result": raw_json.get("result"),
                "service": raw_json.get("service"),
                "account": raw_json.get("account"),
                "message": raw_json.get("message"),
            }

        elif event_type == EventType.SERVICE_STATE:
            payload = {
                "unit": raw_json.get("unit"),
                "reporter_unit": raw_json.get("reporter_unit"),
                "action": raw_json.get("action"),
                "result": raw_json.get("result"),
                "message": raw_json.get("message"),
            }

        elif event_type == EventType.IPC_EVENT:
            payload = {
                "action": raw_json.get("action"),
                "kind": raw_json.get("kind"),
                "endpoint": raw_json.get("endpoint"),
                "read_fd": raw_json.get("read_fd"),
                "write_fd": raw_json.get("write_fd"),
                "success": raw_json.get("success"),
                "errno": raw_json.get("errno"),
            }

        elif event_type == EventType.SYSTEM_HEALTH:
            payload = {
                "cpu_percent": raw_json.get("cpu_percent"),
                "mem_percent": raw_json.get("mem_percent"),
                "disk_percent": raw_json.get("disk_percent"),
                "mem_available_mb": raw_json.get("mem_available_mb"),
            }

        elif event_type in (
            EventType.TELEMETRY_STARTUP,
            EventType.TELEMETRY_SHUTDOWN,
            EventType.TELEMETRY_INFO,
            EventType.TELEMETRY_WARNING,
        ):
            payload = {
                "message": raw_json.get("message"),
            }

        return cls(
            event_type=event_type,
            timestamp=timestamp,
            timestamp_ns=timestamp_ns,
            pid=pid,
            ppid=ppid,
            uid=uid,
            gid=gid,
            comm=comm,
            executable=executable,
            parent_comm=parent_comm,
            ancestry=ancestry,
            payload=payload,
            source=raw_json.get("source", "telemetry_bcc"),
            version=raw_json.get("version", "1.0"),
        )


# =============================================================================
# ABSTRACT PIPELINE INTERFACES
# =============================================================================


class EventCollector(ABC):
    """
    Abstract base for telemetry collection.

    Phase 1: telemetry_collector.py implements this via BCC probes.
    Produces JSON lines to stdout/file.
    """

    @abstractmethod
    def collect(self) -> Iterator[Dict[str, Any]]:
        """
        Collect raw events (as dicts/JSON).

        Yields: Raw event dictionary (as parsed from JSON line).
        Raises: Exception if telemetry fails.
        """
        pass


class EventNormalizer(ABC):
    """
    Abstract base for event normalization.

    Phase 2: Converts raw telemetry into canonical Event objects.
    Handles schema validation, missing fields, type coercion.
    """

    @abstractmethod
    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Event]:
        """
        Normalize a raw event to canonical Event.

        Args:
            raw_event: Raw event dictionary from collector.

        Returns:
            Canonical Event object, or None if event is invalid/skipped.
        """
        pass


class EventStore(ABC):
    """
    Abstract base for event persistence.

    Phase 2+: Stores canonical events for later analysis.
    Implementations: SQLite, parquet, etc.
    """

    @abstractmethod
    def write(self, event: Event) -> None:
        """Write a single canonical event to storage."""
        pass

    @abstractmethod
    def read_all(self) -> Iterator[Event]:
        """Read all stored events (for batch analysis)."""
        pass

    @abstractmethod
    def query(self, filters: Dict[str, Any]) -> Iterator[Event]:
        """
        Query events by filter criteria.

        Example filters:
            {"event_type": "tcp_connect", "uid": 1000}
        """
        pass


# =============================================================================
# CONCRETE IMPLEMENTATIONS (Phase 2 stubs)
# =============================================================================


class JSONLineCollector(EventCollector):
    """
    Collects events from a JSON lines file (e.g., telemetry_collector.py output).

    Phase 1 PoC output → Phase 2 normalizer input.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def collect(self) -> Iterator[Dict[str, Any]]:
        """Yield raw events from JSON lines file."""
        with open(self.file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    # Log and skip malformed lines
                    print(f"WARNING: Skipped malformed JSON: {e}", flush=True)
                    continue


class CanonicalNormalizer(EventNormalizer):
    """
    Normalizes raw telemetry to canonical Event objects.

    Implements: type validation, field coercion, filtering.
    """

    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Event]:
        """Convert raw event to canonical Event or None if invalid."""
        try:
            if "event_type" not in raw_event or not raw_event.get("event_type"):
                raise ValueError("event_type is required")

            timestamp = _coerce_float(raw_event.get("timestamp"), default=None)
            if timestamp is None or not math.isfinite(timestamp):
                raise ValueError("timestamp must be numeric")

            uid = raw_event.get("uid")
            if uid is not None and not isinstance(uid, int):
                try:
                    uid = int(uid)
                except (TypeError, ValueError):
                    raise ValueError("uid must be numeric")

            for field in ("pid", "ppid", "gid"):
                raw_event[field] = _coerce_int(raw_event.get(field))
            parent_comm = raw_event.get("parent_comm")
            raw_event["parent_comm"] = parent_comm if isinstance(parent_comm, str) else None
            ancestry = raw_event.get("ancestry", [])
            raw_event["ancestry"] = ancestry if isinstance(ancestry, list) else []

            event = Event.from_raw_json(raw_event)
            if event is None:
                return None
            event.timestamp = timestamp
            if uid is not None:
                event.uid = uid
            return event
        except Exception as e:
            print(f"WARNING: Normalization failed: {e}", flush=True)
            return None


class InMemoryEventStore(EventStore):
    """
    Simple in-memory event store (for testing/small datasets).

    Phase 2 PoC; replaced by SQLite in Phase 3+.
    """

    def __init__(self):
        self.events = []

    def write(self, event: Event) -> None:
        """Append event to memory."""
        self.events.append(event)

    def read_all(self) -> Iterator[Event]:
        """Yield all stored events."""
        yield from self.events

    def query(self, filters: Dict[str, Any]) -> Iterator[Event]:
        """Simple in-memory filter."""
        for event in self.events:
            match = True
            for key, value in filters.items():
                if getattr(event, key, None) != value:
                    match = False
                    break
            if match:
                yield event


# =============================================================================
# PIPELINE ORCHESTRATOR (Phase 2 stub)
# =============================================================================


class TelemetryPipeline:
    """
    Orchestrates telemetry collection → normalization → storage.

    Phase 2: Connects Phase 1 output to Phase 3+ processing.
    """

    def __init__(
        self,
        collector: EventCollector,
        normalizer: EventNormalizer,
        store: EventStore,
    ):
        self.collector = collector
        self.normalizer = normalizer
        self.store = store
        self.processed_count = 0
        self.skipped_count = 0

    def run(self) -> None:
        """Execute pipeline: collect → normalize → store."""
        for raw_event in self.collector.collect():
            event = self.normalizer.normalize(raw_event)
            if event:
                self.store.write(event)
                self.processed_count += 1
            else:
                self.skipped_count += 1

        print(
            f"Pipeline complete: {self.processed_count} processed, {self.skipped_count} skipped"
        )


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    """
    Example: Load Phase 1 output, normalize, store in memory.

    Usage:
        python3 pipeline/event_stream.py /path/to/phase1_events.jsonl
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 pipeline/event_stream.py <jsonl_file>")
        sys.exit(1)

    jsonl_file = sys.argv[1]

    # Setup pipeline
    collector = JSONLineCollector(jsonl_file)
    normalizer = CanonicalNormalizer()
    store = InMemoryEventStore()
    pipeline = TelemetryPipeline(collector, normalizer, store)

    # Run pipeline
    pipeline.run()

    # Example queries
    print("\n=== Sample Events ===")
    for i, event in enumerate(store.read_all()):
        if i < 10:
            print(event.to_json())
        else:
            break

    print("\n=== TCP Connects ===")
    for event in store.query({"event_type": EventType.TCP_CONNECT}):
        print(event.to_json())
