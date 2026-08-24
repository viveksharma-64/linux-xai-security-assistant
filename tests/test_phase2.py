import json
from pathlib import Path

from telemetry.auditd.file_access_monitor import _filter_capture_records, parse_ausearch_text
from pipeline.event_stream import Event, EventType
from storage.sqlite_store import SQLiteEventStore
from baseline.behavioral_baseline import BehavioralBaseline


def _sample_event(event_type="process_exec", **extra):
    base = {
        "event_type": event_type,
        "timestamp": 1700000000.0,
        "pid": 100,
        "uid": 1000,
        "comm": "bash",
    }
    base.update(extra)
    return base


def test_sqlite_event_store_round_trip(tmp_path):
    db_path = tmp_path / "phase2.db"
    store = SQLiteEventStore(str(db_path))

    event = Event.from_raw_json(_sample_event())
    store.write(event)

    stored = list(store.read_all())
    assert len(stored) == 1
    assert stored[0].event_type == EventType.PROCESS_EXEC
    assert stored[0].uid == 1000
    assert stored[0].comm == "bash"


def test_tcp_connect_normalizes_payload_and_persists(tmp_path):
    event = Event.from_raw_json({
        "event_type": "tcp_connect",
        "timestamp": 1700000000.5,
        "timestamp_ns": 123456,
        "pid": 321,
        "uid": 1000,
        "comm": "curl",
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "source": "telemetry_bcc_network",
    })
    assert event.event_type == EventType.TCP_CONNECT
    assert event.payload == {"dest_ip": "93.184.216.34", "dest_port": 443}

    store = SQLiteEventStore(str(tmp_path / "tcp.db"))
    assert store.write(event) is True
    stored = list(store.read_all())[0]
    assert stored.event_type == EventType.TCP_CONNECT
    assert stored.payload["dest_ip"] == "93.184.216.34"
    assert stored.payload["dest_port"] == 443


def test_audit_parser_maps_open_syscall_and_path_to_canonical_fields():
    records = parse_ausearch_text(
        """----
type=SYSCALL msg=audit(1700000000.123:1): arch=x86_64 syscall=257 success=yes pid=123 uid=1000 comm=\"cat\"
type=PATH msg=audit(1700000000.123:1): item=0 name=\"/etc/passwd\"
----
"""
    )
    assert records[0]["event_type"] == "file_open"
    assert records[0]["filename"] == "/etc/passwd"
    assert records[0]["operation"] == "openat"
    normalized = Event.from_raw_json(records[0])
    assert normalized.executable == "/etc/passwd"
    assert normalized.payload["path"] == "/etc/passwd"


def test_audit_parser_maps_write_syscall_and_failure():
    records = parse_ausearch_text(
        """----
type=SYSCALL msg=audit(1700000000.123:2): arch=x86_64 syscall=1 success=no pid=123 uid=1000 comm=\"tee\"
type=PATH msg=audit(1700000000.123:2): item=0 name=\"/tmp/output\"
----
"""
    )
    assert records[0]["event_type"] == "file_write"
    assert records[0]["operation"] == "write"
    assert records[0]["success"] is False
    assert records[0]["payload"]["filename"] == "/tmp/output"


def test_audit_parser_handles_real_ausearch_context_and_quoted_paths():
    records = parse_ausearch_text(
        """----
type=SYSCALL msg=audit(1700000001.123:3): arch=x86_64 syscall=openat success=yes ppid=500 pid=501 uid=1000 gid=1000 comm=\"python3\" exe=\"/usr/bin/python3\"
type=PATH msg=audit(1700000001.123:3): item=0 name=\"/tmp/file with spaces\" nametype=NORMAL
----
"""
    )
    assert len(records) == 1
    assert records[0]["event_type"] == "file_open"
    assert records[0]["operation"] == "openat"
    assert records[0]["ppid"] == 500
    assert records[0]["executable"] == "/usr/bin/python3"
    assert records[0]["filename"] == "/tmp/file with spaces"
    normalized = Event.from_raw_json(records[0])
    assert normalized.ppid == 500
    assert normalized.executable == "/usr/bin/python3"


def test_audit_parser_skips_malformed_record_without_fabricating_context():
    records = parse_ausearch_text(
        """----
type=SYSCALL msg=audit(bad:4): syscall=openat success=yes pid=bad uid=bad comm=\"cat
----
"""
    )
    assert records == []


def test_audit_parser_deduplicates_identical_records():
    raw = """----
type=SYSCALL msg=audit(1700000002.123:5): arch=x86_64 syscall=write success=yes pid=501 uid=1000 comm=\"tee\"
type=PATH msg=audit(1700000002.123:5): item=0 name=\"/tmp/output\"
----
----
type=SYSCALL msg=audit(1700000002.123:5): arch=x86_64 syscall=write success=yes pid=501 uid=1000 comm=\"tee\"
type=PATH msg=audit(1700000002.123:5): item=0 name=\"/tmp/output\"
----
"""
    assert len(parse_ausearch_text(raw)) == 1


def test_audit_parser_handles_contiguous_raw_ausearch_events_without_separators():
    raw = """type=SYSCALL msg=audit(1700000003.100:6): arch=c000003e syscall=257 success=yes ppid=500 pid=501 uid=1000 gid=1000 comm=\"zsh\" exe=\"/usr/bin/zsh\" key=linux_xai_file_access
type=PATH msg=audit(1700000003.100:6): item=1 name=\"/tmp/sample.txt\"
type=SYSCALL msg=audit(1700000003.200:7): arch=c000003e syscall=257 success=yes ppid=500 pid=502 uid=1000 gid=1000 comm=\"cat\" exe=\"/usr/bin/cat\" key=linux_xai_file_access
type=PATH msg=audit(1700000003.200:7): item=0 name=\"/tmp/sample.txt\"
type=SYSCALL msg=audit(1700000003.300:8): arch=c000003e syscall=316 success=yes ppid=500 pid=503 uid=1000 gid=1000 comm=\"mv\" exe=\"/usr/bin/mv\" key=linux_xai_file_access
type=PATH msg=audit(1700000003.300:8): item=3 name=\"/tmp/renamed.txt\"
"""
    records = parse_ausearch_text(raw)
    assert [record["operation"] for record in records] == ["openat", "openat", "renameat2"]
    assert [record["event_type"] for record in records] == ["file_open", "file_open", "file_write"]
    assert [record["filename"] for record in records] == [
        "/tmp/sample.txt",
        "/tmp/sample.txt",
        "/tmp/renamed.txt",
    ]


def test_capture_filter_excludes_stale_and_auditctl_records():
    records = [
        {"timestamp": 99.9, "comm": "cat", "operation": "openat"},
        {"timestamp": 100.1, "comm": "auditctl", "operation": "sendto"},
        {"timestamp": 100.2, "comm": "cat", "operation": "openat"},
        {"timestamp": 100.3, "comm": "mv", "operation": "renameat2"},
        {"timestamp": 100.4, "comm": "cat", "operation": "sendto"},
        {"timestamp": 101.1, "comm": "cat", "operation": "openat"},
    ]
    filtered = _filter_capture_records(records, 100.0, 101.0)
    assert filtered == [records[2], records[3]]


def test_canonical_provenance_and_optional_process_context_round_trip(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "phase2.db"))
    event = Event.from_raw_json({
        **_sample_event(),
        "ppid": 42,
        "gid": 1000,
        "filename": "/usr/bin/bash",
        "source": "test_source",
        "version": "2.0",
    })
    store.write(event)
    stored = list(store.read_all())[0]
    assert stored.ppid == 42
    assert stored.gid == 1000
    assert stored.executable == "/usr/bin/bash"
    assert stored.source == "test_source"
    assert stored.version == "2.0"


def test_sqlite_store_skips_malformed_events(tmp_path):
    db_path = tmp_path / "phase2.db"
    store = SQLiteEventStore(str(db_path))

    malformed = {"event_type": "process_exec", "timestamp": "bad", "uid": 1000}
    assert store.write_raw(malformed) is False
    assert list(store.read_all()) == []


def test_baseline_rejects_insufficient_normal_data():
    baseline = BehavioralBaseline(minimum_samples=10)
    samples = [
        {"event_type": "process_exec", "timestamp": 1700000000 + i, "uid": 1000, "comm": "bash"}
        for i in range(3)
    ]

    result = baseline.learn(samples)
    assert result["status"] == "insufficient_normal_data"
    assert result["normal_count"] == 3
    assert result["normal_exec_count"] == 3


def test_baseline_builds_features_from_realistic_samples():
    baseline = BehavioralBaseline(minimum_samples=4)
    samples = [
        {"event_type": "process_exec", "timestamp": 1700000000 + i, "uid": 1000, "comm": "bash"}
        for i in range(4)
    ]
    samples += [
        {"event_type": "process_exec", "timestamp": 1700000000 + 100 + i, "uid": 1000, "comm": "python"}
        for i in range(2)
    ]

    result = baseline.learn(samples)
    assert result["status"] in {"ready", "learning"}
    assert "feature_summary" in result
    assert result["feature_summary"]["unique_commands"] >= 2


def test_features_are_deterministic_and_scores_are_explainable():
    baseline = BehavioralBaseline(minimum_samples=1)
    samples = [
        _sample_event(timestamp=1700000000.0, comm="bash"),
        _sample_event(timestamp=1700000001.0, comm="python"),
    ]

    first = baseline.feature_summary([baseline._normalize_event(item) for item in samples])
    second = baseline.feature_summary([baseline._normalize_event(item) for item in samples])
    assert first == second

    scored = baseline.score_events(samples, first)
    assert scored
    assert all(0.0 <= item["anomaly_score"] <= 1.0 for item in scored)
    assert "command_ratio=" in scored[0]["explanation"]
    assert "uid_deviation=" in scored[0]["explanation"]
    assert "burst_ratio=" in scored[0]["explanation"]
    assert "executable=" in scored[0]["explanation"]
    assert "ppid_frequency=" in scored[0]["explanation"]
    assert "weights=0.45,0.35,0.20" in scored[0]["explanation"]


def test_abnormal_burst_score_increases_with_peak_activity():
    baseline = BehavioralBaseline(minimum_samples=1)
    normal = [
        _sample_event(timestamp=1700000000.0 + index, comm="bash")
        for index in range(2)
    ]
    baseline_summary = baseline.feature_summary([baseline._normalize_event(item) for item in normal])
    low = baseline.score_events([_sample_event(timestamp=1700000100.0, comm="nc")], baseline_summary)[0]
    high = baseline.score_events(
        [_sample_event(timestamp=1700000100.0, comm="nc", pid=index) for index in range(10)],
        baseline_summary,
    )
    assert high[0]["anomaly_score"] > low["anomaly_score"]


def test_stored_anomaly_explanation_matches_scored_features(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "phase2.db"))
    baseline = BehavioralBaseline(minimum_samples=1)
    samples = [_sample_event(timestamp=1700000000.0, comm="bash")]
    summary = baseline.feature_summary([baseline._normalize_event(item) for item in samples])
    score = baseline.score_events(samples, summary)[0]

    store.write_anomaly_record(score)
    stored = store.read_anomaly_records()[0]
    assert stored["anomaly_score"] == score["anomaly_score"]
    assert stored["explanation"] == score["explanation"]


def test_sqlite_rejects_out_of_range_anomaly_scores(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "phase2.db"))
    try:
        store.write_anomaly_record({"anomaly_score": 1.1})
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-range anomaly score was stored")


def test_real_capture_is_not_treated_as_training_ready():
    live_path = Path("/home/virus/phase1_live_20260819_003757.jsonl")
    if not live_path.exists():
        return

    records = []
    with live_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))

    baseline = BehavioralBaseline(minimum_samples=500)
    result = baseline.learn(records)
    assert result["status"] in {"insufficient_normal_data", "learning"}
    assert result["normal_exec_count"] == 134
