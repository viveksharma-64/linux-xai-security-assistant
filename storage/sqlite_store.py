import json
import hashlib
import sqlite3
from typing import Any, Dict, Iterator, List, Optional

from pipeline.event_stream import CanonicalNormalizer, Event, EventStore


class SQLiteEventStore(EventStore):
    """
    SQLite-backed persistence for canonical events and Phase 2 analytics metadata.
    """

    def __init__(self, db_path: str = "phase2_events.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
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
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(events)").fetchall()
            }
            if "ppid" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN ppid INTEGER")
            if "executable" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN executable TEXT")
            if "event_hash" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN event_hash TEXT")
            if "parent_comm" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN parent_comm TEXT")
            if "ancestry_json" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN ancestry_json TEXT NOT NULL DEFAULT '[]'")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
            )
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
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(detection_findings)").fetchall()
            }
            if "provenance_hash" not in columns:
                conn.execute("ALTER TABLE detection_findings ADD COLUMN provenance_hash TEXT")
            if "detector_version" not in columns:
                conn.execute("ALTER TABLE detection_findings ADD COLUMN detector_version TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_findings_provenance ON detection_findings(provenance_hash) WHERE provenance_hash IS NOT NULL"
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_training_windows_dataset ON ml_training_windows(dataset_id, id)")
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
        )

    def _event_hash(self, event: Event) -> str:
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
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def write(self, event: Event) -> bool:
        if event is None:
            return

        try:
            timestamp = float(event.timestamp)
        except (TypeError, ValueError):
            raise ValueError("event timestamp must be numeric")

        if event.event_type is None or event.event_type.value is None:
            raise ValueError("event_type is required")
        event_hash = self._event_hash(event)

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_type, timestamp, timestamp_ns, pid, ppid, uid, gid,
                    comm, executable, parent_comm, ancestry_json, source, version,
                    payload_json, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_type.value,
                    timestamp,
                    event.timestamp_ns,
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
                    event_hash,
                ),
            )
            return cursor.rowcount == 1

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
        with self._connect() as conn:
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
        with self._connect() as conn:
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
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM ml_training_windows WHERE dataset_id = ? ORDER BY window_start, id", (dataset_id,)).fetchall()
        return self._decode_ml_training_windows(rows)

    def read_ml_training_windows_by_ids(self, window_ids: List[int]) -> List[Dict[str, Any]]:
        """Read immutable training windows for scorer diagnostics without changing them."""
        if not window_ids:
            return []
        placeholders = ", ".join("?" for _ in window_ids)
        with self._connect() as conn:
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
        with self._connect() as conn:
            if model["active"]:
                conn.execute("UPDATE ml_models SET active = 0 WHERE active = 1")
            conn.execute(
                "INSERT INTO ml_models (id, version, algorithm, hyperparameters_json, artifact_path, artifact_checksum, schema_version, schema_hash, training_window_ids_json, runtime_json, evaluation_json, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (model["id"], model["version"], model["algorithm"], json.dumps(model["hyperparameters"], sort_keys=True), model["artifact_path"], model["artifact_checksum"], model["schema_version"], model["schema_hash"], json.dumps(model["training_window_ids"], sort_keys=True), json.dumps(model["runtime"], sort_keys=True), json.dumps(model["evaluation"], sort_keys=True), int(bool(model["active"])), float(model["created_at"])),
            )
        return str(model["id"])

    def read_ml_model(self, model_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM ml_models WHERE id = ?", (model_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        for key in ("hyperparameters_json", "training_window_ids_json", "runtime_json", "evaluation_json"):
            record[key.removesuffix("_json")] = json.loads(record.pop(key))
        record["active"] = bool(record["active"])
        return record

    def write_feature_record(self, feature_data: Dict[str, Any]) -> None:
        with self._connect() as conn:
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
        with self._connect() as conn:
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

        with self._connect() as conn:
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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM anomaly_scores ORDER BY id ASC"
            ).fetchall()
            return [dict(row) for row in rows]

    def write_risk_record(self, risk_data: Dict[str, Any]) -> None:
        anomaly_score = float(risk_data["anomaly_score"])
        if not 0.0 <= anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be between 0 and 1")

        with self._connect() as conn:
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
        with self._connect() as conn:
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

        with self._connect() as conn:
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
        with self._connect() as conn:
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
        with self._connect() as conn:
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
        with self._connect() as conn:
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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT explanation_json FROM finding_explanations ORDER BY finding_id ASC"
            ).fetchall()
            return [json.loads(row["explanation_json"]) for row in rows]

    def read_explanation(self, finding_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT explanation_json FROM finding_explanations WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            return json.loads(row["explanation_json"]) if row else None

    def write_policy_decision(self, decision: Dict[str, Any]) -> int:
        with self._connect() as conn:
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
        with self._connect() as conn:
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

        with self._connect() as conn:
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
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM assistant_responses WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            return json.loads(row["response_json"]) if row else None

    def read_latest_ready_baseline(self, baseline_name: str = "default") -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
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

    def read_all(self) -> Iterator[Event]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp ASC, id ASC"
            ).fetchall()
            for row in rows:
                yield self._row_to_event(row)

    def read_event_records(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
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
        with self._connect() as conn:
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
            clauses.append(f"{key} = ?")
            values.append(value)

        if not clauses:
            yield from self.read_all()
            return

        sql = "SELECT * FROM events WHERE " + " AND ".join(clauses) + " ORDER BY timestamp ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, values).fetchall()
            for row in rows:
                yield self._row_to_event(row)

    def get_recent_events(self, limit: int = 100) -> List[Event]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_event(row) for row in rows]

    def count_events(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
            return int(row["c"])

    def latest_event_timestamp(self) -> Optional[float]:
        with self._connect() as conn:
            row = conn.execute("SELECT MAX(timestamp) AS latest FROM events").fetchone()
            return float(row["latest"]) if row["latest"] is not None else None

    def write_collector_health(self, health: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_runtime (
                    id, status, detail, error, started_at, stopped_at,
                    last_event_timestamp, processed_count, malformed_count,
                    dropped_event_count, duplicate_count, throughput, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status, detail=excluded.detail, error=excluded.error,
                    started_at=excluded.started_at, stopped_at=excluded.stopped_at,
                    last_event_timestamp=excluded.last_event_timestamp,
                    processed_count=excluded.processed_count,
                    malformed_count=excluded.malformed_count,
                    dropped_event_count=excluded.dropped_event_count,
                    duplicate_count=excluded.duplicate_count,
                    throughput=excluded.throughput, updated_at=excluded.updated_at
                """,
                (
                    health.get("status", "unknown"),
                    health.get("detail"),
                    health.get("error"),
                    health.get("started_at"),
                    health.get("stopped_at"),
                    health.get("last_event_timestamp"),
                    health.get("processed_count", 0),
                    health.get("malformed_count", 0),
                    health.get("dropped_event_count", 0),
                    health.get("duplicate_count", 0),
                    health.get("throughput", 0.0),
                    health.get("updated_at"),
                ),
            )

    def read_collector_health(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM collector_runtime WHERE id = 1").fetchone()
            return dict(row) if row else None

    def reset(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM anomaly_scores")
            conn.execute("DELETE FROM behavior_risks")
            conn.execute("DELETE FROM detection_findings")
            conn.execute("DELETE FROM finding_explanations")
            conn.execute("DELETE FROM policy_decisions")
            conn.execute("DELETE FROM assistant_responses")
            conn.execute("DELETE FROM behavior_baselines")
            conn.execute("DELETE FROM event_features")
            conn.execute("DELETE FROM events")
