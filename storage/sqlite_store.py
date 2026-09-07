import json
import hashlib
import logging
import os
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from pipeline.event_stream import CanonicalNormalizer, Event, EventStore
from storage.migrations import migrate


LOGGER = logging.getLogger(__name__)

# Rows fetched per page when streaming. Large enough that per-page overhead is
# amortised, small enough that a full-table scan of a multi-gigabyte database
# holds only a bounded slice in memory.
STREAM_PAGE_SIZE = 2000


class DatabasePermissionError(RuntimeError):
    """
    Raised when the database file's mode cannot be brought within policy.

    Fail-closed: the file holds command lines, file paths, and usernames from the
    monitored host. Running with it world-readable would turn the audit record
    into a local information-disclosure primitive, which is worse than not
    running.
    """


@dataclass
class BatchWriteResult:
    """
    Outcome of one batched insert.

    `rejected` carries the events that could not be encoded at all, paired with
    the reason, so the caller can quarantine exactly those and still commit the
    rest. Returning a count instead would force the caller to choose between
    losing the whole batch and losing the identity of the bad record.
    """

    attempted: int = 0
    inserted: int = 0
    duplicates: int = 0
    rejected: List[Tuple[Any, str]] = field(default_factory=list)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


class SQLiteEventStore(EventStore):
    """
    SQLite-backed persistence for canonical events and the analytics records
    derived from them: features, baselines, risks, findings, explanations,
    policy decisions, assistant responses, and ML provenance.

    The schema is versioned; see storage/migrations.py.

    Connection lifetime
    -------------------
    One connection per thread, opened on first use and reused thereafter. The
    previous design opened and closed a connection for every operation, which is
    correct but costs a file open, a WAL header read, and four PRAGMA round-trips
    per event on the ingest path. Reuse removes that per-event cost while keeping
    the property the per-call design was protecting: no connection is ever *used*
    from more than the thread that opened it, so SQLite never sees concurrent use
    of one handle.

    Connections are registered so `close()` can shut down handles belonging to
    threads that have already exited -- a thread-local alone would leak those
    until interpreter shutdown. Reclaiming a handle from a thread other than its
    owner is why the connections are opened with `check_same_thread=False` (see
    `_new_connection`); the thread-local cache, not that assertion, is what keeps
    a handle single-threaded in use.
    """

    # Columns accepted as `query()` filter keys. Filter keys are interpolated
    # into SQL (only values can be bound as parameters), so an unrestricted key
    # is an injection vector reachable from any caller-supplied dict.
    QUERYABLE_EVENT_COLUMNS = frozenset({
        "id", "event_type", "timestamp", "timestamp_ns", "timestamp_monotonic",
        "pid", "ppid", "uid", "gid",
        "comm", "executable", "parent_comm",
        "source", "version", "event_hash",
        "host_id", "boot_id", "agent_id",
    })

    EVENT_INSERT_SQL = """
        INSERT OR IGNORE INTO events (
            event_type, timestamp, timestamp_ns, timestamp_monotonic,
            pid, ppid, uid, gid,
            comm, executable, parent_comm, ancestry_json, source, version,
            payload_json, event_hash, host_id, boot_id, agent_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    def __init__(
        self,
        db_path: str = "phase2_events.db",
        file_mode: Optional[int] = 0o600,
        enforce_file_mode: bool = True,
    ):
        self.db_path = db_path
        self.file_mode = file_mode
        self.enforce_file_mode = enforce_file_mode
        self._local = threading.local()
        self._connections: "set[sqlite3.Connection]" = set()
        self._connections_lock = threading.Lock()
        self._closed = False
        self._init_db()
        self._apply_file_mode()

    # ---------------------------------------------------------------- plumbing

    def _new_connection(self) -> sqlite3.Connection:
        # check_same_thread=False so close() can reclaim a connection from a
        # thread other than the one that opened it. Each connection is still only
        # *used* by its owning thread (see _connect's thread-local cache); this
        # only lifts CPython's same-thread assertion, which otherwise makes
        # close() raise ProgrammingError for a pooled handle opened on a worker
        # thread (e.g. an API request thread) and leak it -- exactly the set that
        # close()/__del__ and self._connections exist to reclaim.
        conn = sqlite3.connect(self.db_path, check_same_thread=False)

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA foreign_keys = ON")
            # Group commits at WAL checkpoints instead of fsyncing every
            # transaction. Under WAL, NORMAL keeps atomicity and integrity across
            # a process crash; the exposure is a power loss losing the last
            # commits, which for continuously-arriving telemetry costs a fraction
            # of a second of events and buys roughly an order of magnitude in
            # sustained insert throughput.
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _connect(self) -> sqlite3.Connection:
        """
        This thread's connection, opened on first use.

        Kept as `_connect()` because the whole store is written against it; the
        difference from before is that the handle is cached rather than created
        per call, and callers must not close it (see `_transaction`).
        """
        if self._closed:
            raise sqlite3.ProgrammingError("event store is closed")
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = self._new_connection()
        self._local.conn = conn
        with self._connections_lock:
            self._connections.add(conn)
        return conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Yield this thread's connection, committed on success and rolled back on
        failure.

        `sqlite3.Connection.__exit__` ends the transaction without closing the
        connection, which is exactly what is wanted now that the handle is
        long-lived and owned by the store rather than by the call.
        """
        conn = self._connect()
        with conn:
            yield conn

    def close(self) -> None:
        """
        Close every connection this store has opened, from any thread.

        Idempotent, and safe to call from a thread that never touched the store:
        SQLite forbids *using* a connection from another thread but `close()` on
        an idle handle is what shutdown needs, and leaving handles open holds WAL
        read marks that block checkpointing.
        """
        self._closed = True
        with self._connections_lock:
            connections = list(self._connections)
            self._connections.clear()
        self._local = threading.local()
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                # A handle still in use by a live thread refuses to close. Losing
                # it at interpreter shutdown is strictly better than raising out
                # of a shutdown path and skipping the remaining handles.
                pass

    def __enter__(self) -> "SQLiteEventStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        """
        Last-resort close for a store that was never closed explicitly.

        Connections are now long-lived, so an abandoned store would otherwise hold
        its handles -- and its WAL read marks -- until interpreter exit. Guarded
        broadly because finalizers run during shutdown when module globals may
        already be gone, and an exception here is unraisable noise on a path that
        cannot fix anything.
        """
        try:
            self.close()
        except BaseException:
            pass

    def _init_db(self) -> None:
        """
        Bring the database schema up to date.

        Schema definition lives in storage/migrations.py, which records what has
        been applied so a file can report its own shape and a database written by
        a newer build is refused rather than written into. See that module for
        why versioning replaced the in-place `CREATE IF NOT EXISTS` + `ALTER`
        sequence that used to live here.

        Runs on a dedicated connection that is closed afterwards: `migrate()`
        switches the handle to autocommit to manage DDL transactions explicitly,
        and that setting must not leak into the pooled connections the rest of the
        store relies on for implicit transactions.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL")
            self.schema_version = migrate(conn)
        finally:
            conn.close()

    def _apply_file_mode(self) -> None:
        """
        Restrict the database file, and the WAL sidecars, to the owner.

        The sidecars matter as much as the main file: `-wal` holds the most recent
        commits verbatim, so a world-readable `-wal` leaks the newest evidence
        even when the database itself is 0600. SQLite creates them with the
        process umask, which on a default Kali install is 0022.

        Verified after chmod rather than assumed. On a filesystem that cannot
        represent Unix modes -- a mounted FAT volume, some container overlays --
        `chmod` succeeds and changes nothing, and a security control that reports
        success without taking effect is worse than one that is absent.
        """
        if self.file_mode is None or self.db_path == ":memory:":
            return
        problems: List[str] = []
        for path in self._database_files():
            try:
                os.chmod(path, self.file_mode)
                actual = stat.S_IMODE(os.stat(path).st_mode)
            except FileNotFoundError:
                continue
            except OSError as error:
                problems.append(f"{path}: {type(error).__name__}: {error}")
                continue
            if actual & 0o077:
                problems.append(f"{path}: mode is {actual:04o} after chmod to {self.file_mode:04o}")
        if not problems:
            return
        message = "database file permissions could not be enforced: " + "; ".join(problems)
        if self.enforce_file_mode:
            raise DatabasePermissionError(message)
        LOGGER.warning("db_permissions_unenforced detail=%r", message)

    def _database_files(self) -> List[str]:
        """The main database file and the WAL sidecars that may hold its data."""
        return [self.db_path, f"{self.db_path}-wal", f"{self.db_path}-shm"]

    def file_permissions(self) -> Dict[str, Optional[int]]:
        """
        Current mode of each database file, for the readiness endpoint to report.

        None for a file that does not exist -- a database with no `-wal` has no
        permission problem there, and reporting 0 would read as "no access".
        """
        modes: Dict[str, Optional[int]] = {}
        for path in self._database_files():
            try:
                modes[path] = stat.S_IMODE(os.stat(path).st_mode)
            except OSError:
                modes[path] = None
        return modes

    def database_bytes(self) -> int:
        """Total on-disk size including WAL sidecars, which is what fills a disk."""
        total = 0
        for path in self._database_files():
            try:
                total += os.path.getsize(path)
            except OSError:
                continue
        return total


    def _row_to_event(self, row: sqlite3.Row) -> Event:
        payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
        event_type = row["event_type"]
        if event_type is None:
            event_type = "process_exec"
        from pipeline.event_stream import EventType

        return Event(
            event_type=EventType(event_type),
            timestamp=float(row["timestamp"]),
            timestamp_ns=row["timestamp_ns"],
            timestamp_monotonic=row["timestamp_monotonic"],
            pid=row["pid"],
            ppid=row["ppid"],
            uid=row["uid"],
            gid=row["gid"],
            comm=row["comm"],
            executable=row["executable"],
            parent_comm=row["parent_comm"],
            ancestry=json.loads(row["ancestry_json"] or "[]"),
            payload=payload,
            source=row["source"] or "telemetry_bcc",
            version=row["version"] or "1.0",
            host_id=row["host_id"],
            boot_id=row["boot_id"],
            agent_id=row["agent_id"],
        )

    def _event_hash(self, event: Event) -> str:
        """
        Deduplication key for an event.

        `host_id` is in the material and the other identity fields are not, and
        the split is the whole point. Two hosts can genuinely produce the same
        pid, comm, and timestamp; without the host in the key the unique index
        would treat one as a duplicate of the other and drop a real event from a
        real machine. So host must be here.

        `boot_id`, `agent_id`, and `timestamp_monotonic` describe the
        observation session rather than the observed event, and they change
        every time the agent restarts. Including them would mean re-ingesting
        the same capture inserts a second copy of every row, which is exactly
        the restart behaviour `test_subprocess_shutdown_is_clean_and_service_can_restart`
        pins down. They stay out.

        Note that adding host_id changes the hash of events stored before this
        column existed. That is correct and harmless: old rows keep their old
        hashes, the unique index still holds, and re-ingesting a pre-identity
        capture writes one new row. Silently deduplicating across hosts would be
        the actual harm.
        """
        material = {
            "event_type": event.event_type.value,
            "timestamp": float(event.timestamp),
            "timestamp_ns": event.timestamp_ns,
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "comm": event.comm,
            "executable": event.executable,
            "parent_comm": event.parent_comm,
            "ancestry": event.ancestry,
            "payload": event.payload,
            "source": event.source,
            "version": event.version,
            "host_id": event.host_id,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _event_row(self, event: Event) -> Tuple[Any, ...]:
        """
        Bind parameters for one event, in `EVENT_INSERT_SQL` column order.

        Extracted so the single-event and batched paths cannot diverge: a column
        added to one and not the other would silently drop a field on whichever
        path the caller happens to use.
        """
        try:
            timestamp = float(event.timestamp)
        except (TypeError, ValueError):
            raise ValueError("event timestamp must be numeric")

        if event.event_type is None or event.event_type.value is None:
            raise ValueError("event_type is required")

        return (
            event.event_type.value,
            timestamp,
            event.timestamp_ns,
            event.timestamp_monotonic,
            event.pid,
            event.ppid,
            event.uid,
            event.gid,
            event.comm,
            event.executable,
            event.parent_comm,
            json.dumps(event.ancestry, sort_keys=True),
            event.source,
            event.version,
            json.dumps(event.payload, sort_keys=True),
            self._event_hash(event),
            event.host_id,
            event.boot_id,
            event.agent_id,
        )

    def write(self, event: Event) -> bool:
        if event is None:
            return False

        row = self._event_row(event)
        with self._transaction() as conn:
            cursor = conn.execute(self.EVENT_INSERT_SQL, row)
            return cursor.rowcount == 1

    def write_events(self, events: Sequence[Event]) -> BatchWriteResult:
        """
        Insert many events in one transaction.

        Why batching matters here: with `synchronous = NORMAL` under WAL, a commit
        still costs a WAL write and page-cache work, and the per-statement
        overhead of `execute` plus an implicit transaction dominates once events
        arrive faster than a few hundred per second. One `executemany` inside one
        transaction turns N commits into one.

        Events that cannot be encoded are separated out *before* the transaction
        opens and returned in `rejected`, so one malformed record cannot cost the
        whole batch. Errors raised by SQLite itself (a full disk, a corrupt page)
        are allowed to propagate: those are batch-level failures, the transaction
        has rolled back, and the caller's quarantine path is the right handler.

        `inserted` comes from `Connection.total_changes` because `executemany`
        does not report a per-statement rowcount, and `INSERT OR IGNORE` makes the
        difference between attempted and inserted exactly the duplicate count --
        which is a number the collector health record publishes, so it has to be
        measured rather than assumed.
        """
        result = BatchWriteResult()
        if not events:
            return result

        rows: List[Tuple[Any, ...]] = []
        for event in events:
            if event is None:
                result.rejected.append((event, "event is None"))
                continue
            try:
                rows.append(self._event_row(event))
            except (ValueError, TypeError) as error:
                result.rejected.append((event, f"{type(error).__name__}: {error}"))
        result.attempted = len(rows)
        if not rows:
            return result

        with self._transaction() as conn:
            before = conn.total_changes
            conn.executemany(self.EVENT_INSERT_SQL, rows)
            result.inserted = conn.total_changes - before
        result.duplicates = result.attempted - result.inserted
        return result


    def write_raw(self, raw_event: Dict[str, Any]) -> bool:
        try:
            normalized = CanonicalNormalizer().normalize(raw_event)
            if normalized is None:
                return False
            self.write(normalized)
            return True
        except ValueError:
            return False

    def create_ml_dataset(self, dataset: Dict[str, Any]) -> str:
        """Create immutable metadata for an explicitly verified-normal dataset."""
        required = ("id", "name", "schema_version", "schema_hash", "environment", "verification", "created_at")
        missing = [key for key in required if key not in dataset]
        if missing:
            raise ValueError(f"ML dataset missing fields: {', '.join(missing)}")
        if not dataset["verification"].get("verified_normal"):
            raise ValueError("ML dataset must be explicitly verified_normal")
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO ml_datasets (id, name, schema_version, schema_hash, environment_json, verification_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (dataset["id"], dataset["name"], dataset["schema_version"], dataset["schema_hash"],
                 json.dumps(dataset["environment"], sort_keys=True), json.dumps(dataset["verification"], sort_keys=True), float(dataset["created_at"])),
            )
        return str(dataset["id"])

    def write_ml_training_window(self, window: Dict[str, Any]) -> int:
        """Append a verified-normal feature window; rows intentionally have no update API."""
        required = ("dataset_id", "window_start", "window_end", "event_ids", "features", "schema_version", "schema_hash", "collector_context", "verified_normal", "verification", "created_at")
        missing = [key for key in required if key not in window]
        if missing:
            raise ValueError(f"ML training window missing fields: {', '.join(missing)}")
        if window["verified_normal"] is not True or not window["verification"].get("verified_normal"):
            raise ValueError("training windows require explicit verified_normal=True")
        material = {key: window[key] for key in required if key != "created_at"}
        immutable_hash = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        with self._transaction() as conn:
            dataset = conn.execute("SELECT schema_version, schema_hash FROM ml_datasets WHERE id = ?", (window["dataset_id"],)).fetchone()
            if dataset is None:
                raise ValueError("unknown ML dataset")
            if dataset["schema_version"] != window["schema_version"] or dataset["schema_hash"] != window["schema_hash"]:
                raise ValueError("training window schema does not match dataset schema")
            cursor = conn.execute(
                "INSERT INTO ml_training_windows (dataset_id, window_start, window_end, event_ids_json, features_json, schema_version, schema_hash, collector_context_json, verified_normal, verification_json, immutable_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (window["dataset_id"], float(window["window_start"]), float(window["window_end"]), json.dumps(window["event_ids"], sort_keys=True), json.dumps(window["features"], sort_keys=True), window["schema_version"], window["schema_hash"], json.dumps(window["collector_context"], sort_keys=True), 1, json.dumps(window["verification"], sort_keys=True), immutable_hash, float(window["created_at"])),
            )
            return int(cursor.lastrowid)

    def read_ml_training_windows(self, dataset_id: str) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute("SELECT * FROM ml_training_windows WHERE dataset_id = ? ORDER BY window_start, id", (dataset_id,)).fetchall()
        return self._decode_ml_training_windows(rows)

    def read_ml_training_windows_by_ids(self, window_ids: List[int]) -> List[Dict[str, Any]]:
        """Read immutable training windows for scorer diagnostics without changing them."""
        if not window_ids:
            return []
        placeholders = ", ".join("?" for _ in window_ids)
        with self._transaction() as conn:
            rows = conn.execute(
                f"SELECT * FROM ml_training_windows WHERE id IN ({placeholders}) ORDER BY id",
                [int(window_id) for window_id in window_ids],
            ).fetchall()
        return self._decode_ml_training_windows(rows)

    @staticmethod
    def _decode_ml_training_windows(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        records = []
        for row in rows:
            record = dict(row)
            for key in ("event_ids_json", "features_json", "collector_context_json", "verification_json"):
                record[key.removesuffix("_json")] = json.loads(record.pop(key))
            record["verified_normal"] = bool(record["verified_normal"])
            records.append(record)
        return records

    def write_ml_model(self, model: Dict[str, Any]) -> str:
        required = ("id", "version", "algorithm", "hyperparameters", "artifact_path", "artifact_checksum", "schema_version", "schema_hash", "training_window_ids", "runtime", "evaluation", "active", "created_at")
        missing = [key for key in required if key not in model]
        if missing:
            raise ValueError(f"ML model missing fields: {', '.join(missing)}")
        with self._transaction() as conn:
            if model["active"]:
                conn.execute("UPDATE ml_models SET active = 0 WHERE active = 1")
            conn.execute(
                "INSERT INTO ml_models (id, version, algorithm, hyperparameters_json, artifact_path, artifact_checksum, schema_version, schema_hash, training_window_ids_json, runtime_json, evaluation_json, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (model["id"], model["version"], model["algorithm"], json.dumps(model["hyperparameters"], sort_keys=True), model["artifact_path"], model["artifact_checksum"], model["schema_version"], model["schema_hash"], json.dumps(model["training_window_ids"], sort_keys=True), json.dumps(model["runtime"], sort_keys=True), json.dumps(model["evaluation"], sort_keys=True), int(bool(model["active"])), float(model["created_at"])),
            )
        return str(model["id"])

    def read_ml_model(self, model_id: str) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM ml_models WHERE id = ?", (model_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        for key in ("hyperparameters_json", "training_window_ids_json", "runtime_json", "evaluation_json"):
            record[key.removesuffix("_json")] = json.loads(record.pop(key))
        record["active"] = bool(record["active"])
        return record

    def write_feature_record(self, feature_data: Dict[str, Any]) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO event_features (
                    event_type, window_start, window_end, total_events,
                    unique_commands, unique_uids, command_frequency,
                    uid_activity, anomaly_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feature_data.get("event_type"),
                    feature_data.get("window_start"),
                    feature_data.get("window_end"),
                    feature_data.get("total_events"),
                    feature_data.get("unique_commands"),
                    feature_data.get("unique_uids"),
                    json.dumps(feature_data.get("command_frequency", {}), sort_keys=True),
                    json.dumps(feature_data.get("uid_activity", {}), sort_keys=True),
                    feature_data.get("anomaly_score"),
                    feature_data.get("created_at"),
                ),
            )

    def write_baseline_record(self, baseline_data: Dict[str, Any]) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO behavior_baselines (
                    baseline_name, window_start, window_end, normal_count,
                    feature_summary, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    baseline_data.get("baseline_name", "default"),
                    baseline_data.get("window_start"),
                    baseline_data.get("window_end"),
                    baseline_data.get("normal_count"),
                    json.dumps(baseline_data.get("feature_summary", {}), sort_keys=True),
                    baseline_data.get("status"),
                    baseline_data.get("created_at"),
                ),
            )

    def write_anomaly_record(self, anomaly_data: Dict[str, Any]) -> None:
        anomaly_score = anomaly_data.get("anomaly_score")
        if anomaly_score is not None:
            anomaly_score = float(anomaly_score)
            if not 0.0 <= anomaly_score <= 1.0:
                raise ValueError("anomaly_score must be between 0 and 1")

        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_scores (
                    event_id, event_type, timestamp, anomaly_score,
                    score_bucket, explanation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    anomaly_data.get("event_id"),
                    anomaly_data.get("event_type"),
                    anomaly_data.get("timestamp"),
                    anomaly_score,
                    anomaly_data.get("score_bucket"),
                    anomaly_data.get("explanation"),
                    anomaly_data.get("created_at"),
                ),
            )

    def read_anomaly_records(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM anomaly_scores ORDER BY id ASC"
            ).fetchall()
            return [dict(row) for row in rows]

    def write_risk_record(self, risk_data: Dict[str, Any]) -> None:
        anomaly_score = float(risk_data["anomaly_score"])
        if not 0.0 <= anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be between 0 and 1")

        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO behavior_risks (
                    window_start, window_end, entity_type, entity_key,
                    anomaly_score, risk_level, contributing_features,
                    explanation, mode, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(risk_data["window_start"]),
                    float(risk_data["window_end"]),
                    risk_data["entity_type"],
                    str(risk_data["entity_key"]),
                    anomaly_score,
                    risk_data["risk_level"],
                    json.dumps(risk_data["contributing_features"], sort_keys=True),
                    risk_data["explanation"],
                    risk_data["mode"],
                    risk_data.get("created_at"),
                ),
            )

    def read_risk_records(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM behavior_risks ORDER BY window_start ASC, id ASC"
            ).fetchall()
            records = []
            for row in rows:
                record = dict(row)
                record["contributing_features"] = json.loads(record["contributing_features"])
                records.append(record)
            return records

    def write_detection_finding(self, finding: Dict[str, Any]) -> int:
        score_fields = ("risk_score", "behavior_score", "rule_score", "context_score")
        scores = {field: float(finding[field]) for field in score_fields}
        if any(not 0.0 <= score <= 1.0 for score in scores.values()):
            raise ValueError("detection scores must be between 0 and 1")

        with self._transaction() as conn:
            provenance_hash = finding.get("provenance_hash")
            if provenance_hash:
                existing = conn.execute(
                    "SELECT id FROM detection_findings WHERE provenance_hash = ?",
                    (provenance_hash,),
                ).fetchone()
                if existing is not None:
                    return int(existing["id"])
            cursor = conn.execute(
                """
                INSERT INTO detection_findings (
                    source_risk_id, window_start, window_end, entity_type,
                    entity_key, risk_score, severity, behavior_score,
                    rule_score, context_score, evidence_json, explanation,
                    mode, provenance_hash, detector_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.get("source_risk_id"),
                    float(finding["window_start"]),
                    float(finding["window_end"]),
                    finding["entity_type"],
                    str(finding["entity_key"]),
                    scores["risk_score"],
                    finding["severity"],
                    scores["behavior_score"],
                    scores["rule_score"],
                    scores["context_score"],
                    json.dumps(finding["evidence"], sort_keys=True),
                    finding["explanation"],
                    finding["mode"],
                    provenance_hash,
                    finding.get("detector_version"),
                    finding.get("created_at"),
                ),
            )
            return int(cursor.lastrowid)

    def read_detection_findings(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM detection_findings ORDER BY window_start ASC, id ASC"
            ).fetchall()
            findings = []
            for row in rows:
                finding = dict(row)
                finding["evidence"] = json.loads(finding.pop("evidence_json"))
                findings.append(finding)
            return findings

    def read_detection_finding(self, finding_id: int) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM detection_findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                return None
            finding = dict(row)
            finding["evidence"] = json.loads(finding.pop("evidence_json"))
            return finding

    def write_explanation(self, explanation: Dict[str, Any]) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO finding_explanations (finding_id, explanation_json)
                VALUES (?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET explanation_json = excluded.explanation_json
                """,
                (
                    int(explanation["finding_id"]),
                    json.dumps(explanation, sort_keys=True),
                ),
            )

    def read_explanations(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT explanation_json FROM finding_explanations ORDER BY finding_id ASC"
            ).fetchall()
            return [json.loads(row["explanation_json"]) for row in rows]

    def read_explanation(self, finding_id: int) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT explanation_json FROM finding_explanations WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            return json.loads(row["explanation_json"]) if row else None

    def write_policy_decision(self, decision: Dict[str, Any]) -> int:
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO policy_decisions (
                    finding_id, policy_id, decision, reason, risk_score,
                    severity, required_approval, proposed_action,
                    limitations_json, timestamp, dry_run, advisory_rejection
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("finding_id"),
                    decision["policy_id"],
                    decision["decision"],
                    decision["reason"],
                    float(decision["risk_score"]),
                    decision["severity"],
                    int(bool(decision["required_approval"])),
                    decision["proposed_action"],
                    json.dumps(decision["limitations"], sort_keys=True),
                    float(decision["timestamp"]),
                    int(bool(decision["dry_run"])),
                    decision.get("advisory_rejection"),
                ),
            )
            return int(cursor.lastrowid)

    def read_policy_decisions(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM policy_decisions ORDER BY timestamp ASC, id ASC"
            ).fetchall()
            decisions = []
            for row in rows:
                decision = dict(row)
                decision["required_approval"] = bool(decision["required_approval"])
                decision["dry_run"] = bool(decision["dry_run"])
                decision["limitations"] = json.loads(decision.pop("limitations_json"))
                decisions.append(decision)
            return decisions

    def write_assistant_response(self, response: Dict[str, Any], created_at: Optional[float] = None) -> None:
        import time

        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO assistant_responses (finding_id, response_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    response_json = excluded.response_json,
                    created_at = excluded.created_at
                """,
                (
                    int(response["finding_id"]),
                    json.dumps(response, sort_keys=True),
                    float(created_at if created_at is not None else time.time()),
                ),
            )

    def read_assistant_response(self, finding_id: int) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT response_json FROM assistant_responses WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            return json.loads(row["response_json"]) if row else None

    def read_latest_ready_baseline(self, baseline_name: str = "default") -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute(
                """
                SELECT * FROM behavior_baselines
                WHERE baseline_name = ? AND status = 'ready'
                ORDER BY id DESC LIMIT 1
                """,
                (baseline_name,),
            ).fetchone()
            if row is None:
                return None
            record = dict(row)
            record["feature_summary"] = json.loads(record["feature_summary"])
            return record

    def _stream_event_rows(
        self,
        clauses: Sequence[str] = (),
        values: Sequence[Any] = (),
        page_size: int = STREAM_PAGE_SIZE,
    ) -> Iterator[sqlite3.Row]:
        """
        Walk matching event rows in `(timestamp, id)` order, one page at a time.

        The previous implementation ran `fetchall()` and yielded from the list.
        That is bounded by the size of the table, so a month of retained telemetry
        turns a baseline rebuild into an out-of-memory kill -- and it was written
        that way for a real reason: holding a cursor open across a consumer's
        iteration pins a WAL read mark and blocks checkpointing for as long as the
        consumer takes.

        Keyset pagination gets both properties. Each page is a complete, committed
        read that ends before the yield, so nothing is pinned between pages, and
        memory is bounded by `page_size` rather than by the table. The cursor is
        `(timestamp, id)` rather than `id` alone because that is the order callers
        see, and `id` order is not `timestamp` order once a collector restarts and
        re-ingests slightly older events.

        The trade-off, stated plainly: this is not a snapshot. Rows committed
        after the walk began and sorting after the cursor will be seen. For the
        readers here -- baseline and analytics passes over historical telemetry --
        seeing a few extra recent events is harmless, and a stalled WAL checkpoint
        on a live collector is not.
        """
        base = "SELECT * FROM events"
        conditions = list(clauses)
        cursor_timestamp: Optional[float] = None
        cursor_id: Optional[int] = None

        while True:
            page_conditions = list(conditions)
            page_values = list(values)
            if cursor_id is not None:
                page_conditions.append("(timestamp > ? OR (timestamp = ? AND id > ?))")
                page_values.extend([cursor_timestamp, cursor_timestamp, cursor_id])
            sql = base
            if page_conditions:
                sql += " WHERE " + " AND ".join(page_conditions)
            sql += " ORDER BY timestamp ASC, id ASC LIMIT ?"
            page_values.append(page_size)

            with self._transaction() as conn:
                rows = conn.execute(sql, page_values).fetchall()
            if not rows:
                return
            for row in rows:
                yield row
            cursor_timestamp = rows[-1]["timestamp"]
            cursor_id = rows[-1]["id"]
            if len(rows) < page_size:
                return

    def read_all(self) -> Iterator[Event]:
        for row in self._stream_event_rows():
            yield self._row_to_event(row)


    def read_event_records(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._transaction() as conn:
            if event_type is None:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE event_type = ?
                    ORDER BY timestamp DESC, id DESC LIMIT ?
                    """,
                    (event_type, limit),
                ).fetchall()
            records = []
            for row in rows:
                record = dict(row)
                record["ancestry"] = json.loads(record.pop("ancestry_json") or "[]")
                record["payload"] = json.loads(record.pop("payload_json"))
                records.append(record)
            return records

    def read_event_record(self, event_id: int) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            record = dict(row)
            record["ancestry"] = json.loads(record.pop("ancestry_json") or "[]")
            record["payload"] = json.loads(record.pop("payload_json"))
            return record

    def query(self, filters: Dict[str, Any]) -> Iterator[Event]:
        if not filters:
            yield from self.read_all()
            return

        clauses = []
        values = []
        for key, value in filters.items():
            if value is None:
                continue
            if key not in self.QUERYABLE_EVENT_COLUMNS:
                raise ValueError(f"unsupported query column: {key!r}")
            clauses.append(f"{key} = ?")
            values.append(value)

        if not clauses:
            yield from self.read_all()
            return

        for row in self._stream_event_rows(clauses, values):
            yield self._row_to_event(row)

    def get_recent_events(self, limit: int = 100) -> List[Event]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_event(row) for row in rows]

    def count_events(self) -> int:
        with self._transaction() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
            return int(row["c"])

    def latest_event_timestamp(self) -> Optional[float]:
        with self._transaction() as conn:
            row = conn.execute("SELECT MAX(timestamp) AS latest FROM events").fetchone()
            return float(row["latest"]) if row["latest"] is not None else None

    def oldest_event_timestamp(self) -> Optional[float]:
        """Coverage floor of the database, and the number retention moves."""
        with self._transaction() as conn:
            row = conn.execute("SELECT MIN(timestamp) AS oldest FROM events").fetchone()
            return float(row["oldest"]) if row["oldest"] is not None else None

    def write_maintenance_record(self, record: Dict[str, Any]) -> int:
        """Append one data-lifecycle action to the durable maintenance log."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO maintenance_log (
                    action, reason, events_deleted, rows_deleted, cutoff_timestamp,
                    oldest_retained_timestamp, db_bytes_before, db_bytes_after,
                    duration_seconds, detail, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["action"],
                    record["reason"],
                    int(record.get("events_deleted", 0)),
                    int(record.get("rows_deleted", 0)),
                    record.get("cutoff_timestamp"),
                    record.get("oldest_retained_timestamp"),
                    record.get("db_bytes_before"),
                    record.get("db_bytes_after"),
                    float(record.get("duration_seconds", 0.0)),
                    record.get("detail"),
                    float(record.get("created_at", time.time())),
                ),
            )
            return int(cursor.lastrowid)

    def read_maintenance_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM maintenance_log ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_events_older_than(self, cutoff: float, batch: int = 5000) -> int:
        """
        Delete events at or before `cutoff`, in bounded batches.

        Batched because a single unbounded `DELETE` holds the write lock for the
        whole scan; on a large table that stalls the ingest path long past the
        5-second `busy_timeout` and the collector starts dropping events -- data
        loss caused by the retention pass that exists to prevent data loss.

        The subselect uses `idx_events_timestamp_id` (migration 5), so each batch
        is an index range scan rather than a table scan.
        """
        cutoff = float(cutoff)
        batch = max(1, int(batch))
        deleted = 0
        while True:
            with self._transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM events WHERE id IN ("
                    "SELECT id FROM events WHERE timestamp <= ? ORDER BY timestamp ASC, id ASC LIMIT ?"
                    ")",
                    (cutoff, batch),
                )
                removed = cursor.rowcount or 0
            deleted += removed
            if removed < batch:
                return deleted

    def delete_oldest_events(self, count: int) -> Tuple[int, Optional[float]]:
        """
        Delete the `count` oldest events, returning how many went and the new floor.

        Used by the size cap, which has to free space regardless of age: a host
        under a burst can exceed the byte budget with telemetry that is all newer
        than the retention window, and refusing to act there means filling the
        disk while claiming to be within policy.
        """
        count = max(0, int(count))
        if count == 0:
            return 0, self.oldest_event_timestamp()
        with self._transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM events WHERE id IN ("
                "SELECT id FROM events ORDER BY timestamp ASC, id ASC LIMIT ?"
                ")",
                (count,),
            )
            deleted = cursor.rowcount or 0
        return deleted, self.oldest_event_timestamp()

    def delete_analytics_older_than(self, cutoff: float) -> int:
        """
        Drop derived analytics whose window ended at or before `cutoff`.

        Derived rows are pruned on the same clock as the events they were derived
        from. Keeping a finding whose evidence has aged out would leave the
        dashboard showing a detection an analyst cannot investigate, which is
        worse than showing nothing: the explanation cites event ids that no longer
        resolve.

        Explanations, assistant responses, and policy decisions are removed by
        finding id rather than by their own timestamps, so the four tables stay
        mutually consistent.
        """
        cutoff = float(cutoff)
        with self._transaction() as conn:
            findings = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM detection_findings WHERE window_end <= ?", (cutoff,)
                ).fetchall()
            ]
            rows_deleted = 0
            for start in range(0, len(findings), 500):
                chunk = findings[start:start + 500]
                placeholders = ", ".join("?" for _ in chunk)
                for table in ("finding_explanations", "assistant_responses", "policy_decisions"):
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE finding_id IN ({placeholders})", chunk
                    )
                    rows_deleted += cursor.rowcount or 0
                cursor = conn.execute(
                    f"DELETE FROM detection_findings WHERE id IN ({placeholders})", chunk
                )
                rows_deleted += cursor.rowcount or 0
            for table, column in (
                ("behavior_risks", "window_end"),
                ("event_features", "window_end"),
                ("anomaly_scores", "timestamp"),
            ):
                cursor = conn.execute(f"DELETE FROM {table} WHERE {column} <= ?", (cutoff,))
                rows_deleted += cursor.rowcount or 0
            # behavior_baselines is deliberately not pruned here: a ready baseline
            # is the reference the detector scores against, and deleting the only
            # one because it is old would silently disable detection.
            return rows_deleted

    def vacuum(self) -> None:
        """
        Return free pages to the filesystem.

        Deleting rows leaves the pages allocated to the file, so a database that
        has pruned half its events still occupies the disk it did before. VACUUM
        rebuilds the file, which needs roughly its own size in free space and
        takes an exclusive lock -- so it is scheduled (see `storage.retention`)
        rather than run after every prune.

        Runs on its own autocommit connection: VACUUM cannot execute inside a
        transaction, and the pooled connections are in Python's legacy implicit
        transaction mode.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.isolation_level = None
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("VACUUM")
            # VACUUM rebuilds the database *through* the WAL, so the log ends up
            # holding a copy of everything just rewritten. Without a truncating
            # checkpoint the total on-disk footprint can be larger after a vacuum
            # than before it, which would make the size cap in `storage.retention`
            # chase a number that vacuuming moves the wrong way. A busy
            # checkpoint is not fatal: another reader holding the WAL open only
            # defers the reclaim to the next pass.
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
        self._apply_file_mode()

    # Fields of a health snapshot that reach the database, paired with the value
    # used when a caller omits one. Declared rather than spelled out inside the
    # INSERT because the previous fixed column list meant a new health field was
    # silently unpersisted -- the supervisor would count something the API and
    # dashboard could never show. `tests/test_live_ingestion.py` asserts every
    # CollectorHealth field appears here, so adding one without a migration is a
    # test failure rather than a quiet hole in the record.
    COLLECTOR_HEALTH_COLUMNS: Dict[str, Any] = {
        "status": "unknown",
        "detail": None,
        "error": None,
        "started_at": None,
        "stopped_at": None,
        "last_event_timestamp": None,
        "processed_count": 0,
        "malformed_count": 0,
        "dropped_event_count": 0,
        "duplicate_count": 0,
        "throughput": 0.0,
        "updated_at": None,
        "queue_depth": 0,
        "queue_capacity": 0,
        "queue_high_water_mark": 0,
        "backpressure_wait_seconds": 0.0,
        "backpressure_wait_count": 0,
        "first_drop_timestamp": None,
        "last_drop_timestamp": None,
        "kernel_lost_event_count": 0,
        "first_kernel_loss_timestamp": None,
        "last_kernel_loss_timestamp": None,
        "quarantined_batch_count": 0,
        "quarantined_event_count": 0,
    }

    def write_collector_health(self, health: Dict[str, Any]) -> None:
        columns = list(self.COLLECTOR_HEALTH_COLUMNS)
        placeholders = ", ".join("?" for _ in columns)
        assignments = ", ".join(f"{column}=excluded.{column}" for column in columns)
        # An explicit None on a NOT NULL counter falls back to the default too,
        # not just a missing key: a partial snapshot must not fail the write that
        # records why the collector is unhealthy.
        values = []
        for column, default in self.COLLECTOR_HEALTH_COLUMNS.items():
            value = health.get(column, default)
            values.append(default if value is None else value)
        with self._transaction() as conn:
            conn.execute(
                f"""
                INSERT INTO collector_runtime (id, {", ".join(columns)})
                VALUES (1, {placeholders})
                ON CONFLICT(id) DO UPDATE SET {assignments}
                """,
                tuple(values),
            )

    def read_collector_health(self) -> Optional[Dict[str, Any]]:
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM collector_runtime WHERE id = 1").fetchone()
            return dict(row) if row else None

    # Per-source supervision state, paired with the value used when a caller
    # omits one. Same declared-columns approach as COLLECTOR_HEALTH_COLUMNS, and
    # for the same reason: a supervision field the supervisor tracks but never
    # persists is a field the API and the operator cannot see.
    COLLECTOR_SOURCE_COLUMNS: Dict[str, Any] = {
        "status": "unknown",
        "detail": None,
        "error": None,
        "started_at": None,
        "stopped_at": None,
        "last_event_timestamp": None,
        "processed_count": 0,
        "restart_count": 0,
        "consecutive_failures": 0,
        "last_failure_at": None,
        "next_restart_at": None,
        "backoff_seconds": 0.0,
        "crash_looping": 0,
        "quarantined_batch_count": 0,
        "quarantined_event_count": 0,
        "updated_at": None,
    }

    def write_source_state(self, name: str, state: Dict[str, Any]) -> None:
        """
        Upsert one collector's supervision state.

        Called on every transition (start, failure, backoff, degradation), so it
        is the record an operator reads to find out which collector is down and
        for how long. Writes the whole row rather than a delta: a partial update
        would leave a stale `next_restart_at` next to a fresh `status`, which reads
        as a restart that is already overdue.
        """
        if not name:
            raise ValueError("source name is required")
        columns = list(self.COLLECTOR_SOURCE_COLUMNS)
        placeholders = ", ".join("?" for _ in columns)
        assignments = ", ".join(f"{column}=excluded.{column}" for column in columns)
        values: List[Any] = []
        for column, default in self.COLLECTOR_SOURCE_COLUMNS.items():
            value = state.get(column, default)
            if value is None and default is not None:
                value = default
            if column == "crash_looping":
                value = int(bool(value))
            values.append(value)
        with self._transaction() as conn:
            conn.execute(
                f"""
                INSERT INTO collector_sources (name, {", ".join(columns)})
                VALUES (?, {placeholders})
                ON CONFLICT(name) DO UPDATE SET {assignments}
                """,
                (name, *values),
            )

    def read_source_states(self) -> List[Dict[str, Any]]:
        with self._transaction() as conn:
            rows = conn.execute("SELECT * FROM collector_sources ORDER BY name ASC").fetchall()
        states = []
        for row in rows:
            state = dict(row)
            state["crash_looping"] = bool(state.get("crash_looping"))
            states.append(state)
        return states

    def reset(self) -> None:
        with self._transaction() as conn:
            conn.execute("DELETE FROM anomaly_scores")
            conn.execute("DELETE FROM behavior_risks")
            conn.execute("DELETE FROM detection_findings")
            conn.execute("DELETE FROM finding_explanations")
            conn.execute("DELETE FROM policy_decisions")
            conn.execute("DELETE FROM assistant_responses")
            conn.execute("DELETE FROM behavior_baselines")
            conn.execute("DELETE FROM event_features")
            conn.execute("DELETE FROM events")
