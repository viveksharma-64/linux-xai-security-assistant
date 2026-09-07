"""
Data lifecycle management: retention, pruning, size caps, and scheduled vacuum.

Why this exists
---------------
An always-on collector writes forever. Without a lifecycle policy the database
grows until the filesystem fills, and the first symptom is the collector failing
to write -- so the failure mode of "no retention" is silent, total telemetry loss
at an unpredictable time. Bounding growth deliberately is what makes unattended
operation possible.

Two bounds, not one
-------------------
Age alone is not enough. A host under a burst can write a month's worth of events
in an hour, all of them newer than the retention window, and an age-only policy
would watch the disk fill while reporting compliance. A byte cap alone is not
enough either: it says nothing about how far back an investigation can reach, so
coverage would silently vary with load. Both bounds are enforced, age first
(cheaper, and it is the policy an operator can reason about), then size as the
backstop.

Why deletion is logged
----------------------
Retention destroys evidence. An analyst who cannot find an event needs to be able
to tell "never collected" from "aged out at 03:00 on Tuesday", because those lead
to different next steps. Every action writes a row to `maintenance_log` recording
what was deleted, why, and the coverage floor that remains.

Why vacuum is scheduled separately
----------------------------------
Deleting rows frees pages inside the file but does not shrink the file, so the
size cap cannot be satisfied by deletion alone. VACUUM rebuilds the database: it
takes an exclusive lock and needs roughly the database's own size in free space,
which makes it the most disruptive operation here. It therefore runs on its own
slower schedule, and immediately after a size-cap prune where reclaiming space is
the entire point.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from observability.config import Settings, settings as load_process_settings
from storage.sqlite_store import SQLiteEventStore

LOGGER = logging.getLogger(__name__)

SECONDS_PER_DAY = 86400.0

# Prune to this fraction of the byte cap rather than exactly to it. Deleting just
# enough to reach the limit means the next arriving event crosses it again and the
# next pass deletes again -- a prune-per-event treadmill that costs more I/O than
# the events themselves. Leaving headroom makes the pass amortise.
SIZE_CAP_TARGET_RATIO = 0.9


@dataclass
class MaintenanceAction:
    """One retention decision, as recorded and as returned to the caller."""

    action: str
    reason: str
    events_deleted: int = 0
    rows_deleted: int = 0
    cutoff_timestamp: Optional[float] = None
    oldest_retained_timestamp: Optional[float] = None
    db_bytes_before: Optional[int] = None
    db_bytes_after: Optional[int] = None
    duration_seconds: float = 0.0
    detail: Optional[str] = None
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "events_deleted": self.events_deleted,
            "rows_deleted": self.rows_deleted,
            "cutoff_timestamp": self.cutoff_timestamp,
            "oldest_retained_timestamp": self.oldest_retained_timestamp,
            "db_bytes_before": self.db_bytes_before,
            "db_bytes_after": self.db_bytes_after,
            "duration_seconds": self.duration_seconds,
            "detail": self.detail,
            "created_at": self.created_at,
        }


class RetentionManager:
    """
    Applies the configured lifecycle policy to one database.

    Designed to be driven three ways without behaving differently: once from a
    systemd timer (`python3 -m storage.retention`), periodically from inside the
    ingestion service via `maybe_run()`, and directly from tests with an injected
    clock. `run_once()` is the single implementation all three share, so a policy
    the timer applies is exactly the policy the service applies.
    """

    def __init__(
        self,
        store: SQLiteEventStore,
        config: Optional[Settings] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.store = store
        self.settings = config or load_process_settings()
        self.clock = clock
        self._last_run = 0.0
        self._last_vacuum = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------- scheduling

    def maybe_run(self, force: bool = False) -> List[Dict[str, Any]]:
        """
        Run the policy if the interval has elapsed, otherwise do nothing.

        Cheap enough to call from a hot loop: the common case is one monotonic
        subtraction. The lock makes overlapping runs impossible if two threads
        both decide it is time -- two concurrent prunes would each hold the write
        lock and stall ingest twice over.
        """
        now = time.monotonic()
        with self._lock:
            if not force and self._last_run and now - self._last_run < self.settings.retention_interval_seconds:
                return []
            self._last_run = now
        return self.run_once()

    def run_once(self) -> List[Dict[str, Any]]:
        actions: List[MaintenanceAction] = []
        age_action = self._prune_by_age()
        if age_action is not None:
            actions.append(age_action)
        size_action = self._enforce_size_cap()
        if size_action is not None:
            actions.append(size_action)
        vacuum_action = self._maybe_vacuum(forced=size_action is not None)
        if vacuum_action is not None:
            actions.append(vacuum_action)
        return [self._record(action) for action in actions]

    # ---------------------------------------------------------------- policies

    def _prune_by_age(self) -> Optional[MaintenanceAction]:
        """Delete everything older than the retention window, events first."""
        max_age_days = self.settings.retention_max_age_days
        if max_age_days <= 0:
            # 0 means "keep indefinitely". Spelled as a disabled policy rather
            # than an infinite window so an unset value cannot read as "delete
            # everything now", which is the failure a cutoff of `now - 0` would be.
            return None
        cutoff = self.clock() - max_age_days * SECONDS_PER_DAY
        started = time.monotonic()
        bytes_before = self.store.database_bytes()
        events_deleted = self.store.delete_events_older_than(
            cutoff, batch=self.settings.retention_prune_batch
        )
        rows_deleted = self.store.delete_analytics_older_than(cutoff)
        if events_deleted == 0 and rows_deleted == 0:
            return None
        action = MaintenanceAction(
            action="prune_age",
            reason=f"retention_max_age_days={max_age_days:g}",
            events_deleted=events_deleted,
            rows_deleted=rows_deleted,
            cutoff_timestamp=cutoff,
            oldest_retained_timestamp=self.store.oldest_event_timestamp(),
            db_bytes_before=bytes_before,
            db_bytes_after=self.store.database_bytes(),
            duration_seconds=time.monotonic() - started,
        )
        LOGGER.info(
            "retention_prune_age events_deleted=%d rows_deleted=%d cutoff=%.3f duration_seconds=%.3f",
            events_deleted,
            rows_deleted,
            cutoff,
            action.duration_seconds,
        )
        return action

    def _enforce_size_cap(self) -> Optional[MaintenanceAction]:
        """
        Delete the oldest events until the database fits its byte budget.

        The number to delete is estimated from the current average bytes per
        event, then re-measured after a vacuum, because there is no way to ask
        SQLite how many bytes a given row occupies once indexes, the WAL, and page
        slack are counted. The estimate is corrected by iteration rather than
        trusted: each round measures the real file size again, and the loop is
        bounded so a pathological estimate cannot spin.
        """
        cap = self.settings.retention_max_db_bytes
        if cap <= 0:
            return None
        bytes_before = self.store.database_bytes()
        if bytes_before <= cap:
            return None

        started = time.monotonic()
        target = int(cap * SIZE_CAP_TARGET_RATIO)
        total_deleted = 0
        rounds = 0
        current_bytes = bytes_before
        while current_bytes > cap and rounds < 8:
            rounds += 1
            event_count = self.store.count_events()
            if event_count == 0:
                # Over budget with no events left to delete: the space is schema,
                # indexes, or analytics, and deleting more events cannot help.
                # Reported rather than looped on.
                break
            bytes_per_event = max(current_bytes / event_count, 1.0)
            excess = current_bytes - target
            to_delete = min(event_count, max(1, int(excess / bytes_per_event)))
            deleted, _ = self.store.delete_oldest_events(to_delete)
            total_deleted += deleted
            # Vacuum inside the loop: without it the file size does not change and
            # the loop would delete the entire table chasing a number that cannot
            # move until pages are released.
            self.store.vacuum()
            current_bytes = self.store.database_bytes()
            if deleted == 0:
                break

        if total_deleted == 0 and current_bytes >= bytes_before:
            detail = (
                f"database is {bytes_before} bytes against a cap of {cap} but no events could be "
                "reclaimed; space is held by schema, indexes, or analytics rows"
            )
            LOGGER.warning("retention_size_cap_ineffective detail=%r", detail)
            return MaintenanceAction(
                action="size_cap",
                reason=f"retention_max_db_bytes={cap}",
                db_bytes_before=bytes_before,
                db_bytes_after=current_bytes,
                duration_seconds=time.monotonic() - started,
                oldest_retained_timestamp=self.store.oldest_event_timestamp(),
                detail=detail,
            )

        action = MaintenanceAction(
            action="size_cap",
            reason=f"retention_max_db_bytes={cap}",
            events_deleted=total_deleted,
            oldest_retained_timestamp=self.store.oldest_event_timestamp(),
            db_bytes_before=bytes_before,
            db_bytes_after=current_bytes,
            duration_seconds=time.monotonic() - started,
            detail=f"rounds={rounds}",
        )
        LOGGER.warning(
            "retention_size_cap events_deleted=%d db_bytes_before=%d db_bytes_after=%d cap=%d",
            total_deleted,
            bytes_before,
            current_bytes,
            cap,
        )
        return action

    def _maybe_vacuum(self, forced: bool) -> Optional[MaintenanceAction]:
        interval = self.settings.retention_vacuum_interval_seconds
        now = time.monotonic()
        if not forced:
            if interval <= 0:
                return None
            if self._last_vacuum and now - self._last_vacuum < interval:
                return None
            if not self._last_vacuum:
                # First call after start: record the time and skip. Otherwise every
                # service restart would vacuum, which is the most expensive
                # operation here and would make a crash-looping service hammer the
                # disk it is already struggling with.
                self._last_vacuum = now
                return None
        started = time.monotonic()
        bytes_before = self.store.database_bytes()
        self.store.vacuum()
        self._last_vacuum = time.monotonic()
        bytes_after = self.store.database_bytes()
        action = MaintenanceAction(
            action="vacuum",
            reason="size_cap_reclaim" if forced else f"retention_vacuum_interval_seconds={interval:g}",
            db_bytes_before=bytes_before,
            db_bytes_after=bytes_after,
            oldest_retained_timestamp=self.store.oldest_event_timestamp(),
            duration_seconds=time.monotonic() - started,
        )
        LOGGER.info(
            "retention_vacuum db_bytes_before=%d db_bytes_after=%d duration_seconds=%.3f",
            bytes_before,
            bytes_after,
            action.duration_seconds,
        )
        return action

    def _record(self, action: MaintenanceAction) -> Dict[str, Any]:
        action.created_at = self.clock()
        payload = action.to_dict()
        try:
            payload["id"] = self.store.write_maintenance_record(payload)
        except Exception as error:
            # The action already happened; failing to log it must not turn a
            # successful prune into an exception that aborts the remaining
            # policies. Reported at warning level and returned without an id.
            LOGGER.warning(
                "maintenance_log_write_failed action=%s error=%s", action.action, f"{type(error).__name__}: {error}"
            )
        return payload


def main() -> int:
    """Entry point for the systemd timer: apply the policy once and exit."""
    import argparse
    import json

    from observability import configure_logging
    from observability.config import load_settings

    parser = argparse.ArgumentParser(description="Apply the data retention policy once.")
    parser.add_argument("--db", default=None, help="database path (defaults to configured db_path)")
    args = parser.parse_args()

    configure_logging()
    config = load_settings()
    if args.db:
        config = config.replace(db_path=args.db)
    store = SQLiteEventStore(
        config.db_path, file_mode=config.db_file_mode, enforce_file_mode=config.db_enforce_mode
    )
    try:
        actions = RetentionManager(store, config).run_once()
    finally:
        store.close()
    print(json.dumps({"actions": actions}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
