"""
Versioned schema migrations for the SQLite store.

Why a framework rather than more `ALTER TABLE` conditionals
-----------------------------------------------------------
The schema was previously built by a single `_init_db` that combined
`CREATE TABLE IF NOT EXISTS` for the current shape with a growing set of
`PRAGMA table_info` + `ALTER TABLE ADD COLUMN` checks for columns added later.
That works, but it records nothing: there is no way to ask a database file what
shape it is in, no way to tell a fresh database from a migrated one, and no way
to refuse a file written by a newer build. For a system whose database is the
evidence record behind security findings, "silently write into a schema we do
not understand" is the wrong default.

Design
------
* Every migration is idempotent. An existing database predating this framework
  has no version row, so it is treated as version 0 and every migration is
  replayed over it. Replay must therefore be a no-op on an already-correct
  database -- hence `IF NOT EXISTS` and `_add_column_if_absent` throughout.
* Each migration commits with its version row in one transaction, so an
  interrupted upgrade never records work it did not finish.
* `BEGIN IMMEDIATE` plus a re-check under the lock makes concurrent startup by
  two processes safe: the loser sees the version already applied and skips.
* A database recording a version newer than this build understands is refused
  rather than opened. See `SchemaVersionError`.

Adding a migration
------------------
Append a `Migration` with the next version number. Never edit or renumber a
released migration: databases in the field have already recorded it as applied,
so an edit would silently never run.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Tuple

SCHEMA_MIGRATIONS_TABLE = "schema_migrations"


class SchemaVersionError(RuntimeError):
    """
    Raised when a database was written by a newer build than this one.

    Fail-closed on purpose: an older build cannot know what invariants a newer
    schema carries, and writing findings into it could corrupt the audit record.
    """


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    apply: Callable[[sqlite3.Connection], None]


def _add_column_if_absent(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    """
    Add a column only when it is missing.

    SQLite has no `ADD COLUMN IF NOT EXISTS`, and this has to stay idempotent so
    a pre-framework database can replay the baseline migration safely.
    """
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _apply_baseline(conn: sqlite3.Connection) -> None:
    """
    The schema as it stood before migrations were introduced.

    Reproduced verbatim from the former `_init_db`, including the retrofitted
    columns, so that adopting this framework changes no table definition. The
    `ADD COLUMN` calls are dead on a fresh database and only matter to files
    created before those columns existed.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            timestamp REAL NOT NULL,
            timestamp_ns INTEGER,
            pid INTEGER,
            ppid INTEGER,
            uid INTEGER,
            gid INTEGER,
            comm TEXT,
            executable TEXT,
            parent_comm TEXT,
            ancestry_json TEXT NOT NULL DEFAULT '[]',
            source TEXT,
            version TEXT,
            payload_json TEXT NOT NULL,
            event_hash TEXT
        )
        """
    )
    _add_column_if_absent(conn, "events", "ppid", "INTEGER")
    _add_column_if_absent(conn, "events", "executable", "TEXT")
    _add_column_if_absent(conn, "events", "event_hash", "TEXT")
    _add_column_if_absent(conn, "events", "parent_comm", "TEXT")
    _add_column_if_absent(conn, "events", "ancestry_json", "TEXT NOT NULL DEFAULT '[]'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash) WHERE event_hash IS NOT NULL"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS collector_runtime (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT NOT NULL,
            detail TEXT,
            error TEXT,
            started_at REAL,
            stopped_at REAL,
            last_event_timestamp REAL,
            processed_count INTEGER NOT NULL DEFAULT 0,
            malformed_count INTEGER NOT NULL DEFAULT 0,
            dropped_event_count INTEGER NOT NULL DEFAULT 0,
            duplicate_count INTEGER NOT NULL DEFAULT 0,
            throughput REAL NOT NULL DEFAULT 0.0,
            updated_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS event_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            window_start REAL,
            window_end REAL,
            total_events INTEGER,
            unique_commands INTEGER,
            unique_uids INTEGER,
            command_frequency TEXT,
            uid_activity TEXT,
            anomaly_score REAL,
            created_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS behavior_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_name TEXT,
            window_start REAL,
            window_end REAL,
            normal_count INTEGER,
            feature_summary TEXT,
            status TEXT,
            created_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            event_type TEXT,
            timestamp REAL,
            anomaly_score REAL,
            score_bucket TEXT,
            explanation TEXT,
            created_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS behavior_risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start REAL NOT NULL,
            window_end REAL NOT NULL,
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            anomaly_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            contributing_features TEXT NOT NULL,
            explanation TEXT NOT NULL,
            mode TEXT NOT NULL,
            created_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_risk_id INTEGER,
            window_start REAL NOT NULL,
            window_end REAL NOT NULL,
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            risk_score REAL NOT NULL,
            severity TEXT NOT NULL,
            behavior_score REAL NOT NULL,
            rule_score REAL NOT NULL,
            context_score REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            explanation TEXT NOT NULL,
            mode TEXT NOT NULL,
            provenance_hash TEXT,
            detector_version TEXT,
            created_at REAL
        )
        """
    )
    _add_column_if_absent(conn, "detection_findings", "provenance_hash", "TEXT")
    _add_column_if_absent(conn, "detection_findings", "detector_version", "TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_findings_provenance "
        "ON detection_findings(provenance_hash) WHERE provenance_hash IS NOT NULL"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL UNIQUE,
            explanation_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            policy_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score REAL NOT NULL,
            severity TEXT NOT NULL,
            required_approval INTEGER NOT NULL,
            proposed_action TEXT NOT NULL,
            limitations_json TEXT NOT NULL,
            timestamp REAL NOT NULL,
            dry_run INTEGER NOT NULL,
            advisory_rejection TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assistant_responses (
            finding_id INTEGER PRIMARY KEY,
            response_json TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_datasets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            schema_hash TEXT NOT NULL,
            environment_json TEXT NOT NULL,
            verification_json TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_training_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_id TEXT NOT NULL REFERENCES ml_datasets(id),
            window_start REAL NOT NULL,
            window_end REAL NOT NULL,
            event_ids_json TEXT NOT NULL,
            features_json TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            schema_hash TEXT NOT NULL,
            collector_context_json TEXT NOT NULL,
            verified_normal INTEGER NOT NULL CHECK (verified_normal IN (0, 1)),
            verification_json TEXT NOT NULL,
            immutable_hash TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ml_training_windows_dataset ON ml_training_windows(dataset_id, id)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_models (
            id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            hyperparameters_json TEXT NOT NULL,
            artifact_path TEXT NOT NULL,
            artifact_checksum TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            schema_hash TEXT NOT NULL,
            training_window_ids_json TEXT NOT NULL,
            runtime_json TEXT NOT NULL,
            evaluation_json TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_models_active ON ml_models(active, created_at)")


def _apply_backpressure_telemetry(conn: sqlite3.Connection) -> None:
    """
    Columns recording backpressure and event-loss accounting.

    The ingestion producer used to drop an event the instant its queue was full
    and increment one counter. These columns record what the supervisor does
    instead: how close the queue came to saturation, how long the producer
    waited for space rather than losing the event, and -- when an event was lost
    anyway -- when loss began and when it last happened. A bare count cannot
    tell an analyst whether loss is ongoing or an hour stale, and a count
    sampled after the fact cannot show a queue that filled and drained between
    two health writes.
    """
    for column, declaration in (
        ("queue_depth", "INTEGER NOT NULL DEFAULT 0"),
        ("queue_capacity", "INTEGER NOT NULL DEFAULT 0"),
        ("queue_high_water_mark", "INTEGER NOT NULL DEFAULT 0"),
        ("backpressure_wait_seconds", "REAL NOT NULL DEFAULT 0.0"),
        ("backpressure_wait_count", "INTEGER NOT NULL DEFAULT 0"),
        ("first_drop_timestamp", "REAL"),
        ("last_drop_timestamp", "REAL"),
    ):
        _add_column_if_absent(conn, "collector_runtime", column, declaration)


def _apply_event_identity(conn: sqlite3.Connection) -> None:
    """
    Columns recording which host, boot, and agent observed each event.

    An event used to describe only what happened, never where it was seen. With
    one host's telemetry in the file that is merely incomplete; with two it is
    wrong, because the deduplicating unique index on `event_hash` cannot tell
    the same pid/comm/second on two machines apart and silently merges them.
    `host_id` closes that, and is the only one of these that joins the hash --
    see `SQLiteEventStore._event_hash`.

    `timestamp_monotonic` is the clock that does not step backwards under NTP
    correction, so it is the one that can measure an interval honestly. It is
    only comparable within a single boot, which is why `boot_id` sits beside it;
    a monotonic reading without one cannot be ordered against anything.

    Every column is nullable. Rows written before this migration have no
    identity to backfill, and a host without `/etc/machine-id` has none to
    supply -- a NULL states that plainly, where a default would invent a shared
    identity for every unidentified event and reintroduce the collision this
    exists to prevent.
    """
    for column, declaration in (
        ("timestamp_monotonic", "REAL"),
        ("host_id", "TEXT"),
        ("boot_id", "TEXT"),
        ("agent_id", "TEXT"),
    ):
        _add_column_if_absent(conn, "events", column, declaration)
    # Per-host queries are the common analyst filter once a database holds more
    # than one host, and the column is low-cardinality enough for the index to
    # stay small.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id, timestamp)")


def _apply_kernel_loss_telemetry(conn: sqlite3.Connection) -> None:
    """
    Columns recording samples the kernel discarded before userspace saw them.

    Migration 2 made queue drops visible, which covers events this process
    received and then could not hold. It cannot see the layer below: when a BCC
    perf ring buffer overruns, the kernel destroys samples before the collector
    reads them, so no counter in this process ever observes them. The collectors
    now report those overruns and the supervisor accumulates them here.

    Held apart from `dropped_event_count` rather than folded into one total,
    because the two have different causes and different remedies -- an overrun
    means the collector could not drain the kernel fast enough, a queue drop means
    the consumer could not keep up with the collector. A single number would
    average the two into an answer that points at neither.

    The count defaults to 0 and the two timestamps are nullable: a database
    written before this migration has no loss history to backfill, and a NULL
    first-loss time states "never observed" where 0.0 would claim loss at the
    epoch.
    """
    for column, declaration in (
        ("kernel_lost_event_count", "INTEGER NOT NULL DEFAULT 0"),
        ("first_kernel_loss_timestamp", "REAL"),
        ("last_kernel_loss_timestamp", "REAL"),
    ):
        _add_column_if_absent(conn, "collector_runtime", column, declaration)


def _apply_hot_path_indexes(conn: sqlite3.Connection) -> None:
    """
    Indexes matching the queries the service actually runs, and no more.

    Every index is a tax on the ingest path: each row inserted has to be written
    into each one. So this migration *replaces* two single-column indexes rather
    than adding to them.

    `idx_events_event_type` and `idx_events_timestamp` are both left-prefixes of
    the composite indexes created here, and SQLite will use a composite index for
    a query that constrains only its leading column. Keeping them would cost two
    extra B-tree writes per event for lookups the new indexes already serve.

    What each new index is for:

    * `idx_events_type_timestamp` -- `read_event_records(event_type=...)` filters
      on type and orders by timestamp DESC. With only `(event_type)` SQLite had to
      sort the matched rows; with the composite it walks the index backwards.
    * `idx_events_timestamp_id` -- the keyset pagination in `_stream_event_rows`
      and the age-based delete in `storage.retention`, both of which order by
      `(timestamp, id)`. A `(timestamp)`-only index leaves the tiebreak unindexed,
      which on a busy host means many rows sharing one timestamp.
    * the analytics indexes -- every `read_*` on findings, risks, decisions, and
      baselines orders by its window/timestamp column, and those tables are read
      on the dashboard's polling path. They are written orders of magnitude less
      often than `events`, so the write cost is not the concern there.
    """
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp_id ON events(timestamp, id)")
    conn.execute("DROP INDEX IF EXISTS idx_events_event_type")
    conn.execute("DROP INDEX IF EXISTS idx_events_timestamp")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_detection_findings_window ON detection_findings(window_start, id)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_behavior_risks_window ON behavior_risks(window_start, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_decisions_time ON policy_decisions(timestamp, id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_behavior_baselines_ready "
        "ON behavior_baselines(baseline_name, status, id)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_scores_event ON anomaly_scores(event_id)")


def _apply_maintenance_log(conn: sqlite3.Connection) -> None:
    """
    A record of what data lifecycle management has deleted.

    Retention deletes evidence. Doing that without a durable record would mean an
    analyst who cannot find an event has no way to distinguish "it was never
    collected" from "it aged out on Tuesday" -- and the second answer is the one
    that tells them to widen the retention window before the next investigation.

    Single row per action rather than a running total, because the useful question
    is "what happened at 03:00 when the disk filled", which a counter cannot
    answer. `oldest_retained_timestamp` is recorded after each prune so the log
    also states the coverage the database still has.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            events_deleted INTEGER NOT NULL DEFAULT 0,
            rows_deleted INTEGER NOT NULL DEFAULT 0,
            cutoff_timestamp REAL,
            oldest_retained_timestamp REAL,
            db_bytes_before INTEGER,
            db_bytes_after INTEGER,
            duration_seconds REAL NOT NULL DEFAULT 0.0,
            detail TEXT,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_maintenance_log_time ON maintenance_log(created_at, id)")


def _apply_collector_sources(conn: sqlite3.Connection) -> None:
    """
    Per-source supervision state, alongside the aggregate in `collector_runtime`.

    `collector_runtime` is a single row on purpose: it answers "is ingestion
    working". It cannot answer "which collector died", and on a host running
    several collectors that is the only question worth asking -- an aggregate that
    reads "running" because three of four sources are alive is precisely the
    reassuring lie that lets a blind spot persist for a week.

    Keyed by source name rather than an autoincrement id, and upserted: the useful
    read is "what is the current state of `exec`", and a table of state
    transitions would make that a query over history instead of a lookup. The
    transitions that matter are already durable in the log stream and in
    `restart_count`.

    `crash_looping` is stored as a flag rather than inferred from
    `consecutive_failures` at read time, because the threshold that produced it is
    configuration -- an operator who lowers `crash_loop_threshold` should not
    retroactively change what the database says happened.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS collector_sources (
            name TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            detail TEXT,
            error TEXT,
            started_at REAL,
            stopped_at REAL,
            last_event_timestamp REAL,
            processed_count INTEGER NOT NULL DEFAULT 0,
            restart_count INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            last_failure_at REAL,
            next_restart_at REAL,
            backoff_seconds REAL NOT NULL DEFAULT 0.0,
            crash_looping INTEGER NOT NULL DEFAULT 0,
            quarantined_batch_count INTEGER NOT NULL DEFAULT 0,
            quarantined_event_count INTEGER NOT NULL DEFAULT 0,
            updated_at REAL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_collector_sources_status ON collector_sources(status, name)")
    # Quarantine accounting on the aggregate row as well. A quarantined batch is
    # the one loss figure that is recoverable -- the events are still on disk -- so
    # it has to be visible next to the counters an operator already watches, not
    # only in the per-source table.
    for column, declaration in (
        ("quarantined_batch_count", "INTEGER NOT NULL DEFAULT 0"),
        ("quarantined_event_count", "INTEGER NOT NULL DEFAULT 0"),
    ):
        _add_column_if_absent(conn, "collector_runtime", column, declaration)


MIGRATIONS: Tuple[Migration, ...] = (
    Migration(
        version=1,
        description="baseline schema as of the introduction of versioned migrations",
        apply=_apply_baseline,
    ),
    Migration(
        version=2,
        description="collector_runtime backpressure and event-loss telemetry",
        apply=_apply_backpressure_telemetry,
    ),
    Migration(
        version=3,
        description="event observation identity and monotonic timestamp",
        apply=_apply_event_identity,
    ),
    Migration(
        version=4,
        description="collector_runtime kernel perf-buffer loss accounting",
        apply=_apply_kernel_loss_telemetry,
    ),
    Migration(
        version=5,
        description="hot-path composite indexes, replacing redundant single-column indexes",
        apply=_apply_hot_path_indexes,
    ),
    Migration(
        version=6,
        description="maintenance log for retention, pruning, and vacuum actions",
        apply=_apply_maintenance_log,
    ),
    Migration(
        version=7,
        description="per-source collector supervision state and batch quarantine accounting",
        apply=_apply_collector_sources,
    ),
)

LATEST_VERSION = MIGRATIONS[-1].version


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA_MIGRATIONS_TABLE} (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at REAL NOT NULL
        )
        """
    )


def current_version(conn: sqlite3.Connection) -> int:
    """
    Highest applied migration, or 0 for a new or pre-framework database.

    0 is not distinguishable from "created before versioning existed", which is
    why every migration must be idempotent.
    """
    row = conn.execute(f"SELECT MAX(version) FROM {SCHEMA_MIGRATIONS_TABLE}").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def migrate(conn: sqlite3.Connection) -> int:
    """
    Bring a database up to LATEST_VERSION and return the resulting version.

    The connection is switched to autocommit so transactions can be managed
    explicitly: Python's sqlite3 legacy isolation does not open a transaction for
    DDL, so `with conn:` alone would leave schema changes uncommitted-but-applied
    and defeat the all-or-nothing guarantee each migration needs.
    """
    conn.isolation_level = None
    _ensure_version_table(conn)

    version = current_version(conn)
    if version > LATEST_VERSION:
        raise SchemaVersionError(
            f"database schema version {version} is newer than this build supports "
            f"({LATEST_VERSION}); refusing to open it"
        )

    for migration in MIGRATIONS:
        if migration.version <= version:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Re-checked under the write lock: another process may have applied
            # this migration between our read above and acquiring the lock.
            if current_version(conn) >= migration.version:
                conn.execute("ROLLBACK")
                continue
            migration.apply(conn)
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
                "VALUES (?, ?, ?)",
                (migration.version, migration.description, time.time()),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    return current_version(conn)
