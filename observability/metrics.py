"""
Metrics exposition and health snapshots, derived from persisted state.

Why the database is the source of truth
--------------------------------------
The collector, the supervisor, and the API are separate processes. In-process
counters would therefore mean the API can only report on itself -- it would say
"0 events dropped" while a collector in another process was shedding load. Every
figure here is read from the tables the ingestion side already writes to, so what
the operator scrapes is the same record an analyst reads afterwards.

The cost is scrape latency: `/metrics` does a handful of indexed queries per
request. That is acceptable at Prometheus intervals (15-60s) and is the reason
`snapshot()` collects everything in one pass rather than each gauge fetching its
own row.

Why plain text and no client library
------------------------------------
The Prometheus text exposition format is a stable, trivially generated contract,
and `prometheus_client` would add a dependency an offline Kali host has to
satisfy for output that is 40 lines of string formatting. Writing it directly also
keeps the metric names and help strings next to the reasons they exist.

Liveness versus readiness
-------------------------
They answer different questions and must not be merged. Liveness is "is this
process wedged?" -- it must not depend on the collector, because restarting the
API cannot fix a dead probe and would only add an outage to an existing one.
Readiness is "should this instance be trusted to answer?" -- it fails when the
database is unreachable, its permissions are wrong, or telemetry is stale enough
that answers would be misleading.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from observability.config import Settings
from observability.config import settings as load_process_settings

LOGGER = logging.getLogger(__name__)

# Supervision states that mean telemetry is missing and will stay missing without
# an operator. Kept here rather than imported from pipeline.supervisor so the API
# process does not pull the ingestion stack in to render a gauge.
DEGRADED_STATUS = "degraded"
RUNNING_STATUS = "running"


@dataclass
class DiskUsage:
    """Free space on the filesystem holding the database."""

    total_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0

    @property
    def free_ratio(self) -> float:
        if self.total_bytes <= 0:
            return 1.0
        return self.free_bytes / self.total_bytes


@dataclass
class MetricsSnapshot:
    """
    Everything the metrics endpoint, the health probes, and the alert rules need,
    gathered in one pass.

    Shared so that a scrape, a readiness probe, and an alert evaluation performed
    a millisecond apart cannot disagree with each other -- three independent
    reads would let "ready" and "stale data" be true at the same time.
    """

    collected_at: float = 0.0
    event_count: int = 0
    latest_event_timestamp: Optional[float] = None
    oldest_event_timestamp: Optional[float] = None
    finding_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    database_bytes: int = 0
    file_permissions: Dict[str, Optional[int]] = field(default_factory=dict)
    collector: Dict[str, Any] = field(default_factory=dict)
    sources: List[Dict[str, Any]] = field(default_factory=list)
    disk: DiskUsage = field(default_factory=DiskUsage)
    database_error: Optional[str] = None

    @property
    def data_age_seconds(self) -> Optional[float]:
        if self.latest_event_timestamp is None:
            return None
        return max(self.collected_at - self.latest_event_timestamp, 0.0)

    @property
    def collector_age_seconds(self) -> Optional[float]:
        updated_at = self.collector.get("updated_at")
        if updated_at is None:
            return None
        return max(self.collected_at - float(updated_at), 0.0)

    @property
    def degraded_sources(self) -> List[str]:
        return [
            str(source.get("name"))
            for source in self.sources
            if source.get("status") == DEGRADED_STATUS
        ]

    @property
    def insecure_files(self) -> List[str]:
        """Database files whose mode grants group or other any access."""
        return [
            path
            for path, mode in sorted(self.file_permissions.items())
            if mode is not None and mode & 0o077
        ]

    @property
    def queue_fill_ratio(self) -> Optional[float]:
        capacity = self.collector.get("queue_capacity") or 0
        if not capacity:
            return None
        return float(self.collector.get("queue_depth") or 0) / float(capacity)

    @property
    def dropped_event_count(self) -> int:
        return int(self.collector.get("dropped_event_count") or 0)

    @property
    def kernel_lost_event_count(self) -> int:
        return int(self.collector.get("kernel_lost_event_count") or 0)

    @property
    def quarantined_event_count(self) -> int:
        return int(self.collector.get("quarantined_event_count") or 0)


def _disk_usage(db_path: str) -> DiskUsage:
    """
    Free space where the database lives, falling back to the working directory.

    The database file may not exist yet on a fresh install, and `shutil.disk_usage`
    needs an existing path, so the directory is measured rather than the file.
    """
    target = os.path.dirname(os.path.abspath(db_path)) or "."
    try:
        usage = shutil.disk_usage(target)
    except OSError as error:
        # Disk pressure that cannot be measured is reported as unknown (zeros)
        # rather than as healthy: the alert rule treats a zero total as "no data"
        # and stays quiet, and the scrape still carries every other figure.
        LOGGER.warning("disk_usage_unavailable path=%s error=%s", target, error)
        return DiskUsage()
    return DiskUsage(total_bytes=usage.total, used_bytes=usage.used, free_bytes=usage.free)


def collect_snapshot(store: Any, config: Optional[Settings] = None) -> MetricsSnapshot:
    """
    Read the current operational picture from one store.

    Database failures are captured into `database_error` instead of raised: the
    endpoints built on this must be able to *report* that the database is
    unreachable, and an exception here would turn the only channel that could say
    so into a 500 with no detail.
    """
    resolved = config or load_process_settings()
    snapshot = MetricsSnapshot(collected_at=time.time())
    snapshot.disk = _disk_usage(getattr(store, "db_path", resolved.db_path))
    try:
        snapshot.event_count = store.count_events()
        snapshot.latest_event_timestamp = store.latest_event_timestamp()
        snapshot.oldest_event_timestamp = store.oldest_event_timestamp()
        findings = store.read_detection_findings()
        snapshot.finding_count = len(findings)
        counts: Dict[str, int] = {}
        for finding in findings:
            severity = str(finding.get("severity", "unknown"))
            counts[severity] = counts.get(severity, 0) + 1
        snapshot.severity_counts = counts
        snapshot.database_bytes = store.database_bytes()
        snapshot.file_permissions = store.file_permissions()
        snapshot.collector = store.read_collector_health() or {}
        snapshot.sources = store.read_source_states()
    except Exception as error:
        snapshot.database_error = f"{type(error).__name__}: {error}"
        LOGGER.error("metrics_collection_failed error=%s", snapshot.database_error)
    return snapshot


# ------------------------------------------------------------------ exposition

_METRIC_PREFIX = "linux_xai"


def _line(name: str, value: Any, labels: Optional[Dict[str, str]] = None) -> str:
    if labels:
        rendered = ",".join(f'{key}="{_escape(value_)}"' for key, value_ in sorted(labels.items()))
        return f"{_METRIC_PREFIX}_{name}{{{rendered}}} {_number(value)}"
    return f"{_METRIC_PREFIX}_{name} {_number(value)}"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _number(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        # Prometheus has no null. NaN is the format's own "no value", and it keeps
        # a missing figure from being averaged in as a zero.
        return "NaN"
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


def render_prometheus(snapshot: MetricsSnapshot) -> str:
    """
    Render one snapshot in the Prometheus text exposition format.

    Counters are named `_total` and gauges are not, per convention, because that
    is what makes `rate()` legal on the former in a query the operator did not
    write themselves.
    """
    lines: List[str] = []

    def emit(name: str, kind: str, help_text: str, value: Any, labels: Optional[Dict[str, str]] = None) -> None:
        lines.append(f"# HELP {_METRIC_PREFIX}_{name} {help_text}")
        lines.append(f"# TYPE {_METRIC_PREFIX}_{name} {kind}")
        lines.append(_line(name, value, labels))

    emit("up", "gauge", "1 when the API can read its database.", 0 if snapshot.database_error else 1)
    emit("scrape_timestamp_seconds", "gauge", "Unix time at which this snapshot was collected.", snapshot.collected_at)
    emit("events_stored", "gauge", "Canonical events currently retained in the database.", snapshot.event_count)
    emit(
        "event_age_seconds",
        "gauge",
        "Age of the newest stored event; NaN when no events exist.",
        snapshot.data_age_seconds,
    )
    emit(
        "oldest_event_timestamp_seconds",
        "gauge",
        "Timestamp of the oldest retained event, i.e. the investigation coverage floor.",
        snapshot.oldest_event_timestamp,
    )
    emit("database_bytes", "gauge", "On-disk size of the database including WAL sidecars.", snapshot.database_bytes)
    emit("disk_free_bytes", "gauge", "Free space on the filesystem holding the database.", snapshot.disk.free_bytes)
    emit("disk_total_bytes", "gauge", "Total size of the filesystem holding the database.", snapshot.disk.total_bytes)
    emit("findings_total", "gauge", "Detection findings persisted.", snapshot.finding_count)

    lines.append(f"# HELP {_METRIC_PREFIX}_findings_by_severity Detection findings by severity.")
    lines.append(f"# TYPE {_METRIC_PREFIX}_findings_by_severity gauge")
    for severity, count in sorted(snapshot.severity_counts.items()):
        lines.append(_line("findings_by_severity", count, {"severity": severity}))

    collector = snapshot.collector
    emit(
        "events_processed_total",
        "counter",
        "Events accepted by the ingestion consumer since the collector started.",
        int(collector.get("processed_count") or 0),
    )
    emit(
        "events_dropped_total",
        "counter",
        "Events discarded because the ingestion queue stayed full past the backpressure timeout.",
        snapshot.dropped_event_count,
    )
    emit(
        "events_malformed_total",
        "counter",
        "Records rejected by normalization or refused by the writer.",
        int(collector.get("malformed_count") or 0),
    )
    emit(
        "events_duplicate_total",
        "counter",
        "Events already present, identified by content hash.",
        int(collector.get("duplicate_count") or 0),
    )
    emit(
        "kernel_lost_events_total",
        "counter",
        "Samples the kernel perf ring discarded before userspace read them.",
        snapshot.kernel_lost_event_count,
    )
    emit(
        "quarantined_batches_total",
        "counter",
        "Batches written aside after a failed database write, awaiting replay.",
        int(collector.get("quarantined_batch_count") or 0),
    )
    emit(
        "quarantined_events_total",
        "counter",
        "Events held in quarantine batches.",
        snapshot.quarantined_event_count,
    )
    emit(
        "ingest_throughput_events_per_second",
        "gauge",
        "Mean events per second over the current collector lifetime.",
        float(collector.get("throughput") or 0.0),
    )
    emit("queue_depth", "gauge", "Events waiting in the ingestion queue.", int(collector.get("queue_depth") or 0))
    emit("queue_capacity", "gauge", "Ingestion queue capacity.", int(collector.get("queue_capacity") or 0))
    emit(
        "queue_high_water_mark",
        "gauge",
        "Deepest the ingestion queue has been since the collector started.",
        int(collector.get("queue_high_water_mark") or 0),
    )
    emit(
        "backpressure_wait_seconds_total",
        "counter",
        "Seconds the producer spent blocked on a full queue.",
        float(collector.get("backpressure_wait_seconds") or 0.0),
    )
    emit(
        "collector_health_age_seconds",
        "gauge",
        "Age of the last collector health report; NaN when none has been written.",
        snapshot.collector_age_seconds,
    )

    lines.append(f"# HELP {_METRIC_PREFIX}_source_up 1 when a supervised collector is running.")
    lines.append(f"# TYPE {_METRIC_PREFIX}_source_up gauge")
    for source in snapshot.sources:
        labels = {"source": str(source.get("name"))}
        lines.append(_line("source_up", 1 if source.get("status") == RUNNING_STATUS else 0, labels))
    lines.append(f"# HELP {_METRIC_PREFIX}_source_degraded 1 when a collector has been given up on.")
    lines.append(f"# TYPE {_METRIC_PREFIX}_source_degraded gauge")
    for source in snapshot.sources:
        labels = {"source": str(source.get("name"))}
        lines.append(_line("source_degraded", 1 if source.get("status") == DEGRADED_STATUS else 0, labels))
    lines.append(f"# HELP {_METRIC_PREFIX}_source_restarts_total Collector restarts performed by the supervisor.")
    lines.append(f"# TYPE {_METRIC_PREFIX}_source_restarts_total counter")
    for source in snapshot.sources:
        labels = {"source": str(source.get("name"))}
        lines.append(_line("source_restarts_total", int(source.get("restart_count") or 0), labels))

    emit(
        "database_files_insecure",
        "gauge",
        "Database files whose mode grants group or other access; must be 0.",
        len(snapshot.insecure_files),
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- probes


def liveness(snapshot: MetricsSnapshot) -> Tuple[bool, Dict[str, Any]]:
    """
    Whether this process should keep running.

    Deliberately independent of collector state and of data freshness. A restart
    cannot revive a dead eBPF probe, and killing the only component still able to
    report the outage would make the incident harder to see, not easier to fix.
    """
    return True, {"status": "alive", "collected_at": snapshot.collected_at}


def readiness(
    snapshot: MetricsSnapshot, config: Optional[Settings] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Whether this instance's answers can be trusted right now.

    Three failing conditions, each one a way for a served answer to be wrong
    rather than merely incomplete: an unreadable database (no answer), a database
    other local accounts can read (the evidence store is no longer confidential,
    so serving from it endorses a broken control), and telemetry older than the
    staleness window (answers that look current and are not).
    """
    resolved = config or load_process_settings()
    reasons: List[str] = []
    if snapshot.database_error:
        reasons.append(f"database unavailable: {snapshot.database_error}")
    if snapshot.insecure_files:
        reasons.append(
            "database file permissions grant group or other access: " + ", ".join(snapshot.insecure_files)
        )
    age = snapshot.data_age_seconds
    if age is None:
        reasons.append("no telemetry has been ingested")
    elif age > resolved.stale_after_seconds:
        reasons.append(f"newest event is {age:.0f}s old (limit {resolved.stale_after_seconds:.0f}s)")
    detail = {
        "status": "ready" if not reasons else "not_ready",
        "reasons": reasons,
        "event_count": snapshot.event_count,
        "data_age_seconds": age,
        "degraded_sources": snapshot.degraded_sources,
        "collected_at": snapshot.collected_at,
    }
    return not reasons, detail
