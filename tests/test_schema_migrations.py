"""
Schema migration tests.

The database is the evidence record behind security findings, so these pin the
properties that make it trustworthy: a file reports the shape it is in, a
database written before versioning existed is adopted without damage, and one
written by a newer build is refused rather than written into.
"""

import sqlite3

import pytest

from storage import migrations
from storage.migrations import (
    LATEST_VERSION,
    MIGRATIONS,
    SCHEMA_MIGRATIONS_TABLE,
    SchemaVersionError,
    current_version,
    migrate,
)
from storage.sqlite_store import SQLiteEventStore

# Tables the baseline migration is responsible for. Named explicitly rather than
# derived from the schema, so dropping one is a test failure and not a silently
# smaller assertion.
_BASELINE_TABLES = {
    "events",
    "collector_runtime",
    "event_features",
    "behavior_baselines",
    "anomaly_scores",
    "behavior_risks",
    "detection_findings",
    "finding_explanations",
    "policy_decisions",
    "assistant_responses",
    "ml_datasets",
    "ml_training_windows",
    "ml_models",
}


def _tables(path) -> set:
    conn = sqlite3.connect(str(path))
    try:
        return {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        conn.close()


def _columns(path, table) -> set:
    conn = sqlite3.connect(str(path))
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_migration_versions_are_ordered_and_unique():
    """
    A duplicated or out-of-order version would be skipped by the `<=` check in
    migrate(), so the schema change would silently never run.
    """
    versions = [m.version for m in MIGRATIONS]

    assert versions == sorted(set(versions)), versions
    assert versions[0] == 1
    assert LATEST_VERSION == versions[-1]


def test_fresh_database_is_created_at_the_latest_version(tmp_path):
    db = tmp_path / "fresh.db"

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    assert _BASELINE_TABLES <= _tables(db)
    assert SCHEMA_MIGRATIONS_TABLE in _tables(db)


def test_reopening_a_database_applies_nothing(tmp_path):
    """
    Re-running migrations must not re-apply work. A second applied_at row would
    mean the version table records history that did not happen.
    """
    db = tmp_path / "reopen.db"
    SQLiteEventStore(str(db))

    conn = sqlite3.connect(str(db))
    try:
        before = conn.execute(
            f"SELECT version, applied_at FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
        ).fetchall()
    finally:
        conn.close()

    SQLiteEventStore(str(db))

    conn = sqlite3.connect(str(db))
    try:
        after = conn.execute(
            f"SELECT version, applied_at FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
        ).fetchall()
    finally:
        conn.close()

    assert after == before


def test_data_survives_reopening(tmp_path):
    """Migrating an existing database must not touch the events already in it."""
    db = tmp_path / "data.db"
    store = SQLiteEventStore(str(db))
    from pipeline.event_stream import CanonicalNormalizer

    event = CanonicalNormalizer().normalize(
        {"event_type": "process_exec", "timestamp": 1.0, "pid": 42, "comm": "bash"}
    )
    assert store.write(event) is True

    reopened = SQLiteEventStore(str(db))

    stored = list(reopened.read_all())
    assert len(stored) == 1
    assert stored[0].pid == 42 and stored[0].comm == "bash"


def test_unversioned_database_is_adopted_in_place(tmp_path):
    """
    Databases created before this framework have no version row, so they read as
    version 0 and the baseline replays over them. That replay must preserve the
    rows already there and leave the schema correct, not fail on the tables it
    finds already present.
    """
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    try:
        # The pre-framework shape: events without the columns that were later
        # retrofitted by ad-hoc ALTERs.
        conn.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                timestamp REAL NOT NULL,
                timestamp_ns INTEGER,
                pid INTEGER,
                uid INTEGER,
                gid INTEGER,
                comm TEXT,
                source TEXT,
                version TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO events (event_type, timestamp, pid, comm, payload_json) "
            "VALUES ('process_exec', 1.0, 99, 'legacy', '{}')"
        )
        conn.commit()
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    # The retrofitted columns were added rather than the table recreated.
    assert {"ppid", "executable", "event_hash", "parent_comm", "ancestry_json"} <= _columns(
        db, "events"
    )
    assert _BASELINE_TABLES <= _tables(db)

    stored = list(store.read_all())
    assert len(stored) == 1, "adopting an unversioned database dropped its events"
    assert stored[0].pid == 99 and stored[0].comm == "legacy"


def test_database_from_a_newer_build_is_refused(tmp_path):
    """
    Fail-closed. An older build does not know what invariants a newer schema
    carries, so writing findings into it could corrupt the audit record.
    """
    db = tmp_path / "future.db"
    SQLiteEventStore(str(db))

    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
            "VALUES (?, 'from the future', 0.0)",
            (LATEST_VERSION + 1,),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(SchemaVersionError) as excinfo:
        SQLiteEventStore(str(db))

    assert str(LATEST_VERSION + 1) in str(excinfo.value)


def test_a_failing_migration_records_nothing(tmp_path, monkeypatch):
    """
    Version and schema change commit together. If they did not, an interrupted
    upgrade would record work it never finished and the next start would skip it.
    """

    def _explode(conn):
        conn.execute("CREATE TABLE partial_work (id INTEGER)")
        raise RuntimeError("migration failed midway")

    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (migrations.Migration(version=1, description="explodes", apply=_explode),),
    )

    db = tmp_path / "failed.db"
    conn = sqlite3.connect(str(db))
    try:
        with pytest.raises(RuntimeError, match="migration failed midway"):
            migrate(conn)

        assert current_version(conn) == 0, "a failed migration recorded a version"
        remaining = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "partial_work" not in remaining, "a failed migration left DDL behind"
    finally:
        conn.close()


def test_a_stale_version_read_does_not_reapply_a_migration(tmp_path, monkeypatch):
    """
    Pins the re-check under the write lock.

    Two processes starting together both read the version before either commits,
    so both decide a migration is pending. The winner applies it; the loser then
    acquires the lock holding a stale answer. Only the re-check inside the
    transaction stops it from applying the same migration twice -- which would
    fail on the version primary key and take a starting service down.

    The race is reproduced deterministically by making the first read stale: that
    is exactly the state the loser is in when it acquires the lock. A timing-based
    test would pass whether or not the guard existed.
    """
    db = tmp_path / "race.db"
    SQLiteEventStore(str(db))  # already at LATEST_VERSION

    real_current_version = migrations.current_version
    calls = []

    def stale_first_read(conn):
        calls.append(None)
        return 0 if len(calls) == 1 else real_current_version(conn)

    monkeypatch.setattr(migrations, "current_version", stale_first_read)

    conn = sqlite3.connect(str(db))
    try:
        assert migrate(conn) == LATEST_VERSION
        applied = conn.execute(
            f"SELECT version, COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE} GROUP BY version"
        ).fetchall()
    finally:
        conn.close()

    assert all(count == 1 for _, count in applied), f"a migration was applied twice: {applied}"


def test_concurrent_migration_of_one_database_is_safe(tmp_path):
    """
    The real racing path, as opposed to the simulated one above.

    Whichever thread wins, every caller must return the same version and the
    version table must hold exactly one row per migration. This cannot pin the
    guard on its own -- the interleaving is not guaranteed -- so it runs
    alongside the deterministic test rather than in place of it.
    """
    import threading

    db = tmp_path / "concurrent.db"
    workers = 6
    barrier = threading.Barrier(workers)
    results: list = []
    errors: list = []
    lock = threading.Lock()

    def worker():
        conn = sqlite3.connect(str(db), timeout=10.0)
        try:
            barrier.wait(timeout=10)
            version = migrate(conn)
            with lock:
                results.append(version)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            with lock:
                errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"concurrent migration raised: {errors}"
    assert results == [LATEST_VERSION] * workers

    conn = sqlite3.connect(str(db))
    try:
        applied = conn.execute(
            f"SELECT version, COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE} GROUP BY version"
        ).fetchall()
    finally:
        conn.close()

    assert applied == [(version, 1) for version in range(1, LATEST_VERSION + 1)], applied
    assert _BASELINE_TABLES <= _tables(db)


def test_backpressure_columns_are_added_to_an_existing_database(tmp_path):
    """
    Migration 2 must reach databases that already exist, not just fresh ones --
    an upgraded deployment is the normal case. The columns are named explicitly
    so removing one from the migration is a failure here rather than a counter
    the supervisor maintains and no reader can ever see.
    """
    db = tmp_path / "upgrade.db"

    # A database at version 1 only: the shape a deployment upgrading into this
    # release is actually in.
    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._ensure_version_table(conn)
        migrations._apply_baseline(conn)
        conn.execute(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
            "VALUES (1, 'baseline', 0.0)"
        )
        conn.execute(
            "INSERT INTO collector_runtime (id, status, processed_count) VALUES (1, 'running', 5)"
        )
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    assert {
        "queue_depth",
        "queue_capacity",
        "queue_high_water_mark",
        "backpressure_wait_seconds",
        "backpressure_wait_count",
        "first_drop_timestamp",
        "last_drop_timestamp",
    } <= _columns(db, "collector_runtime")

    health = store.read_collector_health()
    assert health["processed_count"] == 5, "upgrading discarded the recorded health"
    # New counters default rather than nulling a NOT NULL column on an existing row.
    assert health["dropped_event_count"] == 0
    assert health["queue_capacity"] == 0
    assert health["first_drop_timestamp"] is None


def test_identity_columns_are_added_to_an_existing_database(tmp_path):
    """
    Migration 3 over a version-2 database, which is the shape a deployment
    upgrading into this release is in.

    Events already stored have no identity to backfill, so the new columns must
    be nullable and those rows must survive with NULLs rather than being
    rewritten with this host's identity -- that would attribute another
    machine's evidence to whoever happened to run the upgrade.
    """
    db = tmp_path / "identity_upgrade.db"

    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._ensure_version_table(conn)
        migrations._apply_baseline(conn)
        migrations._apply_backpressure_telemetry(conn)
        for version, description in ((1, "baseline"), (2, "backpressure")):
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
                "VALUES (?, ?, 0.0)",
                (version, description),
            )
        conn.execute(
            "INSERT INTO events (event_type, timestamp, pid, comm, payload_json, event_hash) "
            "VALUES ('process_exec', 7.0, 314, 'preexisting', '{}', 'pre-identity-hash')"
        )
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    assert {"timestamp_monotonic", "host_id", "boot_id", "agent_id"} <= _columns(db, "events")

    stored = list(store.read_all())
    assert len(stored) == 1, "upgrading discarded stored events"
    assert stored[0].pid == 314 and stored[0].comm == "preexisting"
    assert stored[0].host_id is None, "an upgrade invented identity for an unattributed event"
    assert stored[0].boot_id is None
    assert stored[0].agent_id is None
    assert stored[0].timestamp_monotonic is None


def test_evidence_chain_columns_and_backfill_over_an_existing_database(tmp_path):
    """
    Migration 8 over a version-7 database -- the shape a deployment upgrading
    into this release is in.

    Two properties matter here beyond "the columns appear". First, the
    disposition columns (`suppressed` especially, which is NOT NULL) must default
    on rows that predate them rather than nulling the write. Second, every
    evidence row already present must be folded into the chain in `id` order: a
    database migrated in the field has to carry the same tamper-evident chain a
    freshly written one would, or it fails its own verification the first time an
    operator checks it. Reopening must not fold a second time.
    """
    db = tmp_path / "evidence_chain_upgrade.db"

    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._ensure_version_table(conn)
        migrations._apply_baseline(conn)
        migrations._apply_backpressure_telemetry(conn)
        migrations._apply_event_identity(conn)
        migrations._apply_kernel_loss_telemetry(conn)
        migrations._apply_hot_path_indexes(conn)
        migrations._apply_maintenance_log(conn)
        migrations._apply_collector_sources(conn)
        for version, description in (
            (1, "baseline"),
            (2, "backpressure"),
            (3, "identity"),
            (4, "kernel-loss"),
            (5, "hot-path indexes"),
            (6, "maintenance log"),
            (7, "collector sources"),
        ):
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
                "VALUES (?, ?, 0.0)",
                (version, description),
            )
        # Two findings and two policy decisions written before the chain existed,
        # in the pre-v8 column shape.
        for i in range(2):
            conn.execute(
                """
                INSERT INTO detection_findings (
                    source_risk_id, window_start, window_end, entity_type,
                    entity_key, risk_score, severity, behavior_score,
                    rule_score, context_score, evidence_json, explanation,
                    mode, provenance_hash, detector_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (1, 1000.0, 1300.0, "command", f"cmd{i}", 0.7, "HIGH",
                 0.7, 0.7, 0.7, "[]", f"finding {i}", "detection",
                 f"seed-{i}", "detector.v1", 100.0 + i),
            )
            conn.execute(
                """
                INSERT INTO policy_decisions (
                    finding_id, policy_id, decision, reason, risk_score,
                    severity, required_approval, proposed_action,
                    limitations_json, timestamp, dry_run, advisory_rejection
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (i + 1, f"p{i}", "advisory_only", "dry-run", 0.7, "HIGH",
                 1, "notify_operator", "{}", 200.0 + i, 1, None),
            )
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    assert {
        "correlation_id",
        "suppressed",
        "suppression_reason",
        "chain_seq",
        "chain_prev_hash",
        "chain_hash",
    } <= _columns(db, "detection_findings")
    assert {"chain_seq", "chain_prev_hash", "chain_hash"} <= _columns(db, "policy_decisions")

    # Pre-existing rows survived and were folded into a valid chain in id order.
    findings = store.read_detection_findings()
    assert [f["entity_key"] for f in findings] == ["cmd0", "cmd1"]
    assert [f["chain_seq"] for f in findings] == [0, 1]
    # The disposition columns default rather than nulling a NOT NULL column on an
    # existing row, and never invent a suppression on data that predates them.
    assert findings[0]["suppressed"] is False
    assert findings[0]["suppression_reason"] is None
    assert findings[0]["correlation_id"] is None
    assert store.verify_findings_chain() == {
        "ok": True,
        "checked": 2,
        "break_seq": None,
        "reason": None,
    }

    decisions = store.read_policy_decisions()
    assert [d["chain_seq"] for d in decisions] == [0, 1]
    assert store.verify_policy_chain()["ok"] is True
    assert store.verify_policy_chain()["checked"] == 2

    # Reopening re-runs migrate(): version 8 must not apply twice, and the
    # backfilled chain must be left byte-for-byte as first written.
    hashes_before = [f["chain_hash"] for f in findings]
    reopened = SQLiteEventStore(str(db))
    hashes_after = [f["chain_hash"] for f in reopened.read_detection_findings()]
    assert hashes_after == hashes_before
    assert reopened.verify_findings_chain()["ok"] is True

    conn = sqlite3.connect(str(db))
    try:
        (v8_rows,) = conn.execute(
            f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE} WHERE version = ?",
            (LATEST_VERSION,),
        ).fetchone()
    finally:
        conn.close()
    assert v8_rows == 1, "migration 8 recorded itself more than once"


def test_migration_8_backfill_skips_already_chained_rows(tmp_path):
    """
    The chain backfill must be idempotent at the row level: a row already
    carrying a `chain_seq` is skipped, so replaying it over a database the
    runtime writer already chained recomputes no hash and duplicates no link.
    Without the `WHERE chain_seq IS NULL` guard a second pass would re-fold every
    row from a fresh genesis and silently rewrite the chain.
    """
    from storage.evidence_chain import FINDING_CHAIN_COLUMNS, POLICY_CHAIN_COLUMNS

    db = tmp_path / "backfill_idempotent.db"
    store = SQLiteEventStore(str(db))
    for i in range(3):
        store.write_detection_finding(
            {
                "source_risk_id": 1,
                "window_start": 1000.0,
                "window_end": 1300.0,
                "entity_type": "command",
                "entity_key": f"cmd{i}",
                "risk_score": 0.7,
                "severity": "HIGH",
                "behavior_score": 0.7,
                "rule_score": 0.7,
                "context_score": 0.7,
                "evidence": [],
                "explanation": "x",
                "mode": "detection",
                "provenance_hash": f"ph{i}",
                "detector_version": "detector.v1",
            }
        )
    before = [f["chain_hash"] for f in store.read_detection_findings()]
    store.close()

    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._backfill_chain(conn, "detection_findings", FINDING_CHAIN_COLUMNS)
        migrations._backfill_chain(conn, "policy_decisions", POLICY_CHAIN_COLUMNS)
    finally:
        conn.close()

    reopened = SQLiteEventStore(str(db))
    after = [f["chain_hash"] for f in reopened.read_detection_findings()]
    assert after == before
    assert reopened.verify_findings_chain()["ok"] is True


def test_triage_annotations_table_is_created_at_the_latest_version(tmp_path):
    """
    Migration 9 adds the append-only triage layer. On a fresh database it is
    present with its chain columns from the start (nothing to backfill), indexed
    for per-finding history, and verifies as an empty chain.
    """
    db = tmp_path / "triage_fresh.db"
    store = SQLiteEventStore(str(db))

    assert "triage_annotations" in _tables(db)
    assert {
        "id",
        "finding_id",
        "action",
        "disposition",
        "note",
        "actor",
        "created_at",
        "chain_seq",
        "chain_prev_hash",
        "chain_hash",
    } <= _columns(db, "triage_annotations")

    conn = sqlite3.connect(str(db))
    try:
        indexes = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    finally:
        conn.close()
    assert "idx_triage_annotations_finding" in indexes
    assert "idx_triage_annotations_chain" in indexes
    assert store.verify_triage_chain()["ok"] is True


def test_triage_annotations_added_to_an_existing_database(tmp_path):
    """
    Migration 9 over a version-8 database -- the shape a deployment upgrading into
    this release is in. The table is created empty (no backfill), the evidence
    already present is untouched, and reopening does not apply migration 9 twice.
    """
    db = tmp_path / "triage_upgrade.db"

    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._ensure_version_table(conn)
        migrations._apply_baseline(conn)
        migrations._apply_backpressure_telemetry(conn)
        migrations._apply_event_identity(conn)
        migrations._apply_kernel_loss_telemetry(conn)
        migrations._apply_hot_path_indexes(conn)
        migrations._apply_maintenance_log(conn)
        migrations._apply_collector_sources(conn)
        # A finding written before the evidence-chain migration -- no chain columns
        # yet. The migration-8 backfill will fold it into the chain, exactly as a
        # real v7 database upgrading into this release would be.
        conn.execute(
            """
            INSERT INTO detection_findings (
                source_risk_id, window_start, window_end, entity_type,
                entity_key, risk_score, severity, behavior_score,
                rule_score, context_score, evidence_json, explanation,
                mode, provenance_hash, detector_version, created_at
            ) VALUES (1, 1000.0, 1300.0, 'command', 'nc', 0.7, 'HIGH',
                      0.7, 0.7, 0.7, '[]', 'seed', 'detection', 'ph', 'detector.v1', 100.0)
            """
        )
        migrations._apply_evidence_chain(conn)
        for version in range(1, 9):
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
                "VALUES (?, ?, 0.0)",
                (version, f"v{version}"),
            )
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION
    assert "triage_annotations" in _tables(db)
    # No backfill: a brand-new table starts empty and verifies as an empty chain.
    assert store.verify_triage_chain() == {
        "ok": True,
        "checked": 0,
        "break_seq": None,
        "reason": None,
    }
    # The finding chain that predated migration 9 is left intact.
    assert store.verify_findings_chain()["ok"] is True
    assert len(store.read_detection_findings()) == 1

    # Reopening re-runs migrate(): version 9 must not apply twice.
    SQLiteEventStore(str(db))
    conn = sqlite3.connect(str(db))
    try:
        (rows,) = conn.execute(
            f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE} WHERE version = ?",
            (LATEST_VERSION,),
        ).fetchone()
    finally:
        conn.close()
    assert rows == 1, "migration 9 recorded itself more than once"


def test_triage_action_and_disposition_are_constrained_at_the_schema(tmp_path):
    """
    The append-only vocabulary is pinned by CHECK constraints at the storage
    layer, matching how the schema already pins other enumerated columns. This is
    defense-in-depth beneath the API's Literal validation: even a direct writer
    cannot record an action or disposition outside the allowlist.
    """
    db = tmp_path / "triage_checks.db"
    SQLiteEventStore(str(db)).close()

    conn = sqlite3.connect(str(db))
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO triage_annotations (finding_id, action, created_at) "
                "VALUES (1, 'delete', 100.0)"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO triage_annotations (finding_id, action, disposition, created_at) "
                "VALUES (1, 'disposition', 'maybe', 100.0)"
            )
        # A valid action with a valid disposition is accepted.
        conn.execute(
            "INSERT INTO triage_annotations (finding_id, action, disposition, created_at) "
            "VALUES (1, 'disposition', 'true-positive', 100.0)"
        )
    finally:
        conn.close()


def test_ml_lifecycle_tables_are_created_at_the_latest_version(tmp_path):
    """
    Migration 10 adds the drift-assessment table and the chained lifecycle log. On
    a fresh database both are present, indexed per model, and the lifecycle chain
    verifies as empty -- the correct state on a default install, where no model has
    been trained and the ML path is off.
    """
    db = tmp_path / "ml_lifecycle_fresh.db"
    store = SQLiteEventStore(str(db))

    assert {"ml_drift_assessments", "ml_model_lifecycle"} <= _tables(db)
    assert {
        "id",
        "model_id",
        "comparison_dataset_id",
        "status",
        "method",
        "alpha",
        "reference_window_count",
        "comparison_window_count",
        "drifted_feature_count",
        "out_of_range_rate",
        "features_json",
        "reasons_json",
        "actor",
        "created_at",
    } <= _columns(db, "ml_drift_assessments")
    assert {
        "id",
        "model_id",
        "from_state",
        "to_state",
        "reason",
        "evidence_json",
        "activation_eligible",
        "actor",
        "created_at",
        "chain_seq",
        "chain_prev_hash",
        "chain_hash",
    } <= _columns(db, "ml_model_lifecycle")

    conn = sqlite3.connect(str(db))
    try:
        indexes = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    finally:
        conn.close()
    assert "idx_ml_drift_assessments_model" in indexes
    assert "idx_ml_model_lifecycle_model" in indexes
    assert "idx_ml_model_lifecycle_chain" in indexes
    assert store.verify_ml_lifecycle_chain()["ok"] is True


def test_ml_lifecycle_tables_added_to_an_existing_database(tmp_path):
    """
    Migration 10 over a version-9 database. Both tables are created empty (there is
    no history to reconstruct for a model trained before the log existed, and
    inventing one would be worse than an absent record), the evidence and triage
    chains already present are untouched, and reopening does not apply 10 twice.
    """
    db = tmp_path / "ml_lifecycle_upgrade.db"

    conn = sqlite3.connect(str(db))
    try:
        conn.isolation_level = None
        migrations._ensure_version_table(conn)
        migrations._apply_baseline(conn)
        migrations._apply_backpressure_telemetry(conn)
        migrations._apply_event_identity(conn)
        migrations._apply_kernel_loss_telemetry(conn)
        migrations._apply_hot_path_indexes(conn)
        migrations._apply_maintenance_log(conn)
        migrations._apply_collector_sources(conn)
        migrations._apply_evidence_chain(conn)
        migrations._apply_triage_annotations(conn)
        # A model registered before the lifecycle log existed: it keeps its
        # provenance and its inactive posture, and gains no history it never had.
        conn.execute(
            """
            INSERT INTO ml_models (
                id, version, algorithm, hyperparameters_json, artifact_path,
                artifact_checksum, schema_version, schema_hash,
                training_window_ids_json, runtime_json, evaluation_json,
                active, created_at
            ) VALUES ('legacy-model', 'v1', 'isolation_forest', '{}',
                      '/models/legacy.model.json', 'ab', 'canonical-window.v1', 'sh',
                      '[1, 2, 3]', '{}', '{}', 0, 100.0)
            """
        )
        for version in range(1, 10):
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, description, applied_at) "
                "VALUES (?, ?, 0.0)",
                (version, f"v{version}"),
            )
    finally:
        conn.close()

    store = SQLiteEventStore(str(db))

    assert store.schema_version == LATEST_VERSION == 10
    assert {"ml_drift_assessments", "ml_model_lifecycle"} <= _tables(db)
    assert store.verify_ml_lifecycle_chain() == {
        "ok": True,
        "checked": 0,
        "break_seq": None,
        "reason": None,
    }
    assert store.read_ml_drift_assessments() == []
    assert store.read_ml_lifecycle() == []
    # The pre-existing model is still there, and still inactive: a migration does
    # not activate anything.
    assert store.verify_triage_chain()["ok"] is True
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT active FROM ml_models WHERE id = 'legacy-model'").fetchone()[0] == 0
    finally:
        conn.close()

    # Reopening re-runs migrate(): version 10 must not apply twice.
    SQLiteEventStore(str(db))
    conn = sqlite3.connect(str(db))
    try:
        (rows,) = conn.execute(
            f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE} WHERE version = ?",
            (LATEST_VERSION,),
        ).fetchone()
    finally:
        conn.close()
    assert rows == 1, "migration 10 recorded itself more than once"


def test_ml_lifecycle_vocabulary_is_constrained_at_the_schema(tmp_path):
    """
    The lifecycle states, drift statuses, and the eligibility flag are pinned by
    CHECK constraints, so a direct writer bypassing the store's own validation
    still cannot record a state outside the declared path or an eligibility value
    that is neither true nor false.
    """
    db = tmp_path / "ml_lifecycle_checks.db"
    SQLiteEventStore(str(db)).close()

    conn = sqlite3.connect(str(db))
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ml_model_lifecycle (model_id, to_state, reason, evidence_json, created_at) "
                "VALUES ('m', 'promoted', 'why not', '{}', 100.0)"
            )
        # Not a boolean: the flag is read as a verdict, so a third value would make
        # "is this model eligible" unanswerable.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ml_model_lifecycle "
                "(model_id, to_state, reason, evidence_json, activation_eligible, created_at) "
                "VALUES ('m', 'eligible', 'gate passed', '{}', 2, 100.0)"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ml_drift_assessments ("
                "model_id, comparison_dataset_id, status, method, alpha, reference_window_count, "
                "comparison_window_count, drifted_feature_count, features_json, reasons_json, created_at) "
                "VALUES ('m', 'cmp', 'probably_fine', 'ks', 0.01, 12, 40, 0, '[]', '[]', 100.0)"
            )
        # A declared state and a declared status are accepted.
        conn.execute(
            "INSERT INTO ml_model_lifecycle (model_id, to_state, reason, evidence_json, created_at) "
            "VALUES ('m', 'trained', 'trained on 12 windows', '{}', 100.0)"
        )
        conn.execute(
            "INSERT INTO ml_drift_assessments ("
            "model_id, comparison_dataset_id, status, method, alpha, reference_window_count, "
            "comparison_window_count, drifted_feature_count, features_json, reasons_json, created_at) "
            "VALUES ('m', 'cmp', 'insufficient_data', 'ks', 0.01, 12, 5, 0, '[]', '[]', 100.0)"
        )
    finally:
        conn.close()


def test_host_index_exists_for_per_host_queries(tmp_path):
    """
    Filtering by host is the common analyst query once a file holds more than
    one host; without the index that becomes a full scan of the events table.
    """
    db = tmp_path / "host_index.db"
    SQLiteEventStore(str(db))

    conn = sqlite3.connect(str(db))
    try:
        indexes = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    finally:
        conn.close()

    assert "idx_events_host" in indexes


def test_current_version_reports_zero_for_a_new_database(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "empty.db"))
    try:
        migrations._ensure_version_table(conn)
        assert current_version(conn) == 0
    finally:
        conn.close()


def test_in_memory_store_still_migrates():
    """`:memory:` skips the WAL pragmas in _connect; migration must still run."""
    store = SQLiteEventStore(":memory:")

    assert store.schema_version == LATEST_VERSION
