"""
Alert rules over the metrics snapshot.

Why rules live in the service, not only in Prometheus
----------------------------------------------------
The scrape endpoint is the right integration for a host that has monitoring. Many
hosts that need this service do not, and "the operator was supposed to write an
alerting rule" is how silent telemetry loss stays silent for a month. The same
conditions are therefore evaluated in-process, logged at their own severity, and
exposed on `/api/alerts` so a bare install still says out loud when it has
stopped working.

Keeping one implementation for both matters: if the endpoint and the internal
evaluation could disagree, the operator would have two answers to "is it healthy"
and no way to choose.

What is alertable
-----------------
Only conditions that mean the record is incomplete, is about to be, or cannot be
trusted -- the four failures Phase B exists to make impossible to miss:

  event loss        drops, kernel ring overruns, quarantined batches
  collector death   a source degraded, or health reports gone silent
  stale data        nothing ingested inside the freshness window
  disk pressure     free space below either an absolute or a relative floor

Deliberately excluded: high queue depth on its own (that is backpressure working
as designed), and detection findings (those are the product, not a fault).

Severity
--------
`critical` means evidence is being lost or cannot be trusted now. `warning` means
a trajectory that becomes critical if nothing changes. The split exists so paging
policy can be written against the field rather than against message text.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from observability.config import Settings
from observability.config import settings as load_process_settings
from observability.metrics import MetricsSnapshot

LOGGER = logging.getLogger(__name__)

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"


@dataclass(frozen=True)
class Alert:
    """One firing condition, in the form an operator has to act on."""

    name: str
    severity: str
    summary: str
    # The measured value and the threshold it crossed, so the alert is
    # self-justifying: an operator should not have to query anything to see why it
    # fired or what would clear it.
    value: Optional[float] = None
    threshold: Optional[float] = None
    labels: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "summary": self.summary,
            "value": self.value,
            "threshold": self.threshold,
            "labels": dict(self.labels or {}),
        }


def evaluate(snapshot: MetricsSnapshot, config: Optional[Settings] = None) -> List[Alert]:
    """
    All conditions currently firing, worst first.

    Pure: takes a snapshot, returns alerts, touches nothing. That is what lets the
    rules be tested against constructed states -- including states that are hard
    to produce on a real host, like a full disk -- instead of only against
    whatever the local database happens to contain.
    """
    resolved = config or load_process_settings()
    alerts: List[Alert] = []

    if snapshot.database_error:
        alerts.append(
            Alert(
                name="database_unavailable",
                severity=SEVERITY_CRITICAL,
                summary=f"the event database could not be read: {snapshot.database_error}",
            )
        )

    if snapshot.insecure_files:
        alerts.append(
            Alert(
                name="database_permissions_insecure",
                severity=SEVERITY_CRITICAL,
                summary=(
                    "database files readable beyond their owner: "
                    + ", ".join(snapshot.insecure_files)
                ),
                value=float(len(snapshot.insecure_files)),
                threshold=0.0,
            )
        )

    # --- event loss --------------------------------------------------------
    if snapshot.dropped_event_count:
        alerts.append(
            Alert(
                name="events_dropped",
                severity=SEVERITY_CRITICAL,
                summary=(
                    f"{snapshot.dropped_event_count} events were dropped under backpressure; "
                    "the record has gaps"
                ),
                value=float(snapshot.dropped_event_count),
                threshold=0.0,
            )
        )
    if snapshot.kernel_lost_event_count:
        alerts.append(
            Alert(
                name="kernel_events_lost",
                severity=SEVERITY_CRITICAL,
                summary=(
                    f"{snapshot.kernel_lost_event_count} samples were discarded by the kernel perf "
                    "ring before userspace read them"
                ),
                value=float(snapshot.kernel_lost_event_count),
                threshold=0.0,
            )
        )
    if snapshot.quarantined_event_count:
        alerts.append(
            Alert(
                name="events_quarantined",
                severity=SEVERITY_WARNING,
                summary=(
                    f"{snapshot.quarantined_event_count} events are held in quarantine batches after "
                    "failed writes and need replaying"
                ),
                value=float(snapshot.quarantined_event_count),
                threshold=0.0,
            )
        )

    # --- collector death ---------------------------------------------------
    for name in snapshot.degraded_sources:
        alerts.append(
            Alert(
                name="collector_degraded",
                severity=SEVERITY_CRITICAL,
                summary=f"collector {name!r} crash-looped and has been given up on; telemetry is missing",
                labels={"source": name},
            )
        )
    silence_limit = resolved.alert_collector_silence_seconds
    collector_age = snapshot.collector_age_seconds
    if silence_limit > 0 and collector_age is not None and collector_age > silence_limit:
        alerts.append(
            Alert(
                name="collector_health_stale",
                severity=SEVERITY_CRITICAL,
                summary=(
                    f"no collector health report for {collector_age:.0f}s; the ingestion process is "
                    "wedged or gone"
                ),
                value=collector_age,
                threshold=silence_limit,
            )
        )

    # --- stale data --------------------------------------------------------
    data_age = snapshot.data_age_seconds
    if data_age is not None and data_age > resolved.stale_after_seconds:
        alerts.append(
            Alert(
                name="telemetry_stale",
                severity=SEVERITY_CRITICAL,
                summary=f"no events ingested for {data_age:.0f}s",
                value=data_age,
                threshold=resolved.stale_after_seconds,
            )
        )

    # --- disk pressure -----------------------------------------------------
    disk = snapshot.disk
    if disk.total_bytes > 0:
        if disk.free_bytes < resolved.alert_min_free_disk_bytes:
            alerts.append(
                Alert(
                    name="disk_space_low",
                    severity=SEVERITY_CRITICAL,
                    summary=(
                        f"{disk.free_bytes} bytes free where the database lives; ingestion stops when "
                        "the filesystem fills"
                    ),
                    value=float(disk.free_bytes),
                    threshold=float(resolved.alert_min_free_disk_bytes),
                )
            )
        elif disk.free_ratio < resolved.alert_min_free_disk_ratio:
            alerts.append(
                Alert(
                    name="disk_space_low_ratio",
                    severity=SEVERITY_WARNING,
                    summary=f"only {disk.free_ratio * 100:.1f}% of the database filesystem is free",
                    value=disk.free_ratio,
                    threshold=resolved.alert_min_free_disk_ratio,
                )
            )

    # Queue fill is a warning and only a warning: a deep queue means the producer
    # is outrunning the writer, which is the condition backpressure exists to
    # absorb. It is worth saying because sustained fill precedes drops.
    fill = snapshot.queue_fill_ratio
    if fill is not None and fill > resolved.alert_max_queue_fill_ratio:
        alerts.append(
            Alert(
                name="ingest_queue_saturated",
                severity=SEVERITY_WARNING,
                summary=f"ingestion queue is {fill * 100:.0f}% full; drops follow if this is sustained",
                value=fill,
                threshold=resolved.alert_max_queue_fill_ratio,
            )
        )

    alerts.sort(key=lambda alert: (0 if alert.severity == SEVERITY_CRITICAL else 1, alert.name))
    return alerts


def log_alerts(alerts: List[Alert]) -> None:
    """
    Emit each alert to the log at a level matching its severity.

    Written as `alert=<name>` key=value so a journald-only host can grep for
    `alert=` and get every condition the service has ever raised. Called by the
    long-running service; the API does not log on scrape, because a scrape every
    15 seconds would turn one condition into 5,760 log lines a day.
    """
    for alert in alerts:
        message = "alert=%s severity=%s value=%s threshold=%s summary=%s"
        args = (alert.name, alert.severity, alert.value, alert.threshold, alert.summary)
        if alert.severity == SEVERITY_CRITICAL:
            LOGGER.error(message, *args)
        else:
            LOGGER.warning(message, *args)
