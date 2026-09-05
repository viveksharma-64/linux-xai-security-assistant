#!/usr/bin/env python3
"""
Canonical event contract between the telemetry layer and everything downstream.

Collectors emit JSON lines; this module defines the `Event` they are normalized
into, and the collector/normalizer/store interfaces that the batch and live
ingestion paths implement. Baseline learning, detection, explanation, and policy
all read `Event`, so it is the single point at which telemetry becomes typed.

The contract exists so collectors can be replaced without touching downstream
stages: an added or reworked probe changes only its own raw schema and the
normalizer's handling of it.

Diagnostics go to logging, never to stdout. Stdout is a data channel here --
collectors write JSON lines to it and `pipeline/live_ingestion.py:main` writes a
single health object to it -- so a warning printed there corrupts a consumer's
parse.
"""

import json
import logging
import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, Iterator, Optional, Union

from pipeline import identity

LOGGER = logging.getLogger(__name__)


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
# CANONICAL EVENT TYPES (emitted by the telemetry collectors)
# =============================================================================


class EventType(str, Enum):
    """All event types emitted by the telemetry collectors."""

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


@dataclass(frozen=True)
class Event:
    """
    Canonical event representation.

    All telemetry events normalize to this structure before any analysis stage.

    Immutable on purpose
    --------------------
    This is the evidence record behind a security finding, and it is read
    concurrently: the ingestion consumer, the detection stages, and the feature
    extractor all see the same object. A mutable evidence record means a value
    an analyst reads in an explanation is not provably the value that produced
    the score -- any stage could have adjusted it in between, and nothing in the
    stored finding would show that it had. Freezing makes the record
    write-once, and makes sharing one `Event` across stages safe without
    defensive copying.

    Freezing is shallow: `payload` and `ancestry` are still mutable containers.
    Making them deeply immutable would mean converting every payload to a
    mapping type that no longer round-trips through `json.dumps`, which costs
    more than it buys. The attribute rebinding that actually caused trouble --
    reassigning `timestamp` or `uid` after construction, in the normalizer -- is
    what this prevents.

    Timestamps
    ----------
    Three clocks, because no one of them answers every question.
    `timestamp` is wall clock: comparable across hosts, and the only one an
    analyst can line up against an external log, but it can step backwards under
    NTP correction. `timestamp_monotonic` never steps and is therefore the one
    that can measure a duration honestly -- but it is only comparable within a
    single boot, which is why it is meaningless without `boot_id`. `timestamp_ns`
    stays what it always was: the kernel clock reading a probe reported, present
    only when the collector supplied one.
    Identity, equality, and what "the same event" means
    ---------------------------------------------------
    `timestamp_monotonic`, `boot_id`, and `agent_id` are excluded from equality
    and hashing. They describe the observation session -- which agent run
    noticed this event, on which boot, how far into that boot -- not the event
    itself. Two normalizations of one collector record describe the same thing
    that happened on the host even though the agent read them microseconds
    apart, and code that aggregates or compares events must be able to say so;
    `baseline/behavior_analyzer.aggregate_windows` is documented as
    deterministic and would otherwise stop being so.

    That exclusion set is deliberately identical to the one
    `SQLiteEventStore._event_hash` leaves out of the deduplication key, so
    "equal events" and "events the store treats as duplicates" cannot drift
    apart. `host_id` is on the other side of that line in both places: two hosts
    doing the same thing at the same instant are two events, not one.
    """

    # Core fields (present in all events)
    event_type: EventType
    timestamp: float  # Unix timestamp (seconds)
    timestamp_ns: Optional[int] = None  # Kernel clock (nanoseconds, if available)
    # CLOCK_MONOTONIC, valid only within boot_id. compare=False: see above.
    timestamp_monotonic: Optional[float] = field(default=None, compare=False)

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

    # Observation identity. Nullable because a container without /etc/machine-id
    # must still be able to ingest: an event with unknown provenance is worth
    # more than no event. See pipeline/identity.py.
    host_id: Optional[str] = None
    boot_id: Optional[str] = field(default=None, compare=False)
    agent_id: Optional[str] = field(default=None, compare=False)

    def __post_init__(self):
        # object.__setattr__ because the dataclass is frozen. These are
        # normalizations of the value the caller passed, applied once at
        # construction, not mutation of a constructed event.
        if self.payload is None:
            object.__setattr__(self, "payload", {})
        if self.ancestry is None:
            object.__setattr__(self, "ancestry", [])

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
        Factory method: parse raw collector JSON into a canonical Event.

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
            timestamp_monotonic=raw_json.get("timestamp_monotonic"),
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
            # Read from the record rather than stamped here. A collector that
            # knows its own identity -- or a replayed capture that recorded one
            # -- must keep it; `CanonicalNormalizer` supplies this host's
            # identity only when the record carries none.
            host_id=raw_json.get("host_id"),
            boot_id=raw_json.get("boot_id"),
            agent_id=raw_json.get("agent_id"),
        )


# =============================================================================
# ABSTRACT PIPELINE INTERFACES
# =============================================================================


class EventCollector(ABC):
    """
    Abstract base for telemetry collection.

    Implemented by the collectors under telemetry/ (BCC, journald, auditd).
    Produces JSON lines to stdout or a file.
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

    Converts raw telemetry into canonical Event objects.
    Handles schema validation, missing fields, and type coercion.
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

    Implementations: SQLiteEventStore (production), InMemoryEventStore (tests).
    """

    @abstractmethod
    def write(self, event: Event) -> bool:
        """
        Write a single canonical event to storage.

        Returns True if the event was newly stored, False if it was rejected or
        already present. `LiveIngestionService._consume` counts a False as a
        duplicate, so an implementation returning None reports every event as one.
        """
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
# CONCRETE IMPLEMENTATIONS
# =============================================================================


class JSONLineCollector(EventCollector):
    """
    Collects events from a JSON lines file (e.g., telemetry_collector.py output).

    Reads a captured collector JSONL file for the normalizer to consume.
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
                    LOGGER.warning(
                        "jsonl_malformed_line path=%s error=%s", self.file_path, e
                    )
                    continue


class CanonicalNormalizer(EventNormalizer):
    """
    Normalizes raw telemetry to canonical Event objects.

    Implements: type validation, field coercion, filtering.

    This is also where an event acquires the identity of the host observing it
    and a monotonic companion to its wall clock, because it is the one point
    every telemetry source passes through. Stamping in each collector instead
    would mean seven places to keep correct and seven ways to forget.
    """

    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Event]:
        """Convert raw event to canonical Event or None if invalid."""
        try:
            if "event_type" not in raw_event or not raw_event.get("event_type"):
                raise ValueError("event_type is required")

            # Coercion writes back several fields, so it operates on a copy. The
            # caller's dict is telemetry it may still log, retry, or route
            # elsewhere; normalization must not edit it underneath them.
            record = dict(raw_event)

            timestamp = _coerce_float(record.get("timestamp"), default=None)
            if timestamp is None or not math.isfinite(timestamp):
                raise ValueError("timestamp must be numeric")
            record["timestamp"] = timestamp

            uid = record.get("uid")
            if uid is not None and not isinstance(uid, int):
                try:
                    uid = int(uid)
                except (TypeError, ValueError):
                    raise ValueError("uid must be numeric")
            record["uid"] = uid

            for field in ("pid", "ppid", "gid"):
                record[field] = _coerce_int(record.get(field))
            parent_comm = record.get("parent_comm")
            record["parent_comm"] = parent_comm if isinstance(parent_comm, str) else None
            ancestry = record.get("ancestry", [])
            # Copied, not aliased: the Event would otherwise share the caller's
            # list and later mutation on either side would be visible to both.
            record["ancestry"] = list(ancestry) if isinstance(ancestry, list) else []

            self._stamp_observation(record)
            return Event.from_raw_json(record)
        except Exception as e:
            LOGGER.warning(
                "normalization_failed event_type=%s pid=%s error=%s",
                raw_event.get("event_type") if isinstance(raw_event, dict) else None,
                raw_event.get("pid") if isinstance(raw_event, dict) else None,
                e,
            )
            return None

    @staticmethod
    def _stamp_observation(record: Dict[str, Any]) -> None:
        """
        Record who observed this event and when, on the monotonic clock.

        Only fills what the record does not already carry. A replayed capture
        arrives with the identity of the host that originally saw it, and
        overwriting that would relabel another machine's evidence as this one's
        -- which is worse than having no identity at all, because it is a
        confident false statement rather than a null.

        The monotonic reading is taken at normalization, so it measures when the
        agent saw the event rather than when the kernel produced it. That is the
        honest reading available here: nothing upstream reports a monotonic
        timestamp, and inventing one from the wall clock would just launder an
        adjustable clock into a field that promises not to be.
        """
        for field, value in (
            ("host_id", identity.host_id()),
            ("boot_id", identity.boot_id()),
            ("agent_id", identity.agent_id()),
        ):
            if record.get(field) is None:
                record[field] = value
        if record.get("timestamp_monotonic") is None:
            record["timestamp_monotonic"] = time.monotonic()


class InMemoryEventStore(EventStore):
    """
    Simple in-memory event store, for tests and small batch datasets.

    Not a persistence path: SQLiteEventStore is the durable implementation.
    """

    def __init__(self):
        self.events = []

    def write(self, event: Event) -> bool:
        """Append event to memory. No deduplication, so a store always succeeds."""
        if event is None:
            return False
        self.events.append(event)
        return True

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
# BATCH PIPELINE ORCHESTRATOR
# =============================================================================


class TelemetryPipeline:
    """
    Orchestrates telemetry collection → normalization → storage for a finite
    source, such as a captured JSONL file.

    The streaming counterpart is `pipeline/live_ingestion.LiveIngestionService`,
    which adds a bounded queue, supervision, and health reporting.
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

        LOGGER.info(
            "batch_pipeline_complete processed=%d skipped=%d",
            self.processed_count,
            self.skipped_count,
        )


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    """
    Example: load a collector JSONL file, normalize, store in memory.

    Usage:
        python3 pipeline/event_stream.py /path/to/capture.jsonl
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
