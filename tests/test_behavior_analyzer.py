import json
from pathlib import Path

from baseline.behavior_analyzer import AnalysisMode, BehaviorAnalyzer
from storage.sqlite_store import SQLiteEventStore


def _event(timestamp, comm="bash", uid=1000, pid=100):
    return {
        "event_type": "process_exec",
        "timestamp": timestamp,
        "pid": pid,
        "uid": uid,
        "comm": comm,
    }


def test_aggregate_windows_are_configurable_and_deterministic(tmp_path):
    analyzer = BehaviorAnalyzer(SQLiteEventStore(str(tmp_path / "events.db")), window_seconds=10)
    events = [
        _event(100.0, comm="python", pid=2),
        _event(101.0, comm="bash", pid=1),
        _event(111.0, comm="python", pid=3),
    ]

    first = analyzer.aggregate_windows(events)
    second = analyzer.aggregate_windows(list(reversed(events)))

    assert first == second
    assert [window["total_execs"] for window in first] == [2, 1]
    assert first[0]["command_frequency"] == {"bash": 1, "python": 1}
    assert first[0]["burst_activity"]["peak_execs_per_second"] == 1


def test_learning_requires_verified_normal_data_and_promotes_once_ready(tmp_path):
    analyzer = BehaviorAnalyzer(
        SQLiteEventStore(str(tmp_path / "events.db")),
        minimum_normal_execs=4,
    )
    normal_events = [_event(1000 + index, comm="bash", pid=index) for index in range(3)]

    rejected = analyzer.learn_normal(normal_events)
    assert rejected["status"] == "normal_verification_required"
    assert rejected["mode"] == AnalysisMode.LEARNING.value

    learning = analyzer.learn_normal(normal_events, verified_normal=True)
    assert learning["status"] == "insufficient_normal_data"
    assert learning["normal_exec_count"] == 3

    ready = analyzer.learn_normal([_event(1003, comm="bash", pid=3)], verified_normal=True)
    assert ready["status"] == "baseline_ready"
    assert ready["mode"] == AnalysisMode.MONITORING.value

    after_ready = analyzer.learn_normal([_event(1004, comm="unexpected", pid=4)], verified_normal=True)
    assert after_ready["status"] == "baseline_ready"
    assert after_ready["normal_exec_count"] == 4


def test_monitoring_persists_structured_risk_and_does_not_learn(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    analyzer = BehaviorAnalyzer(store, minimum_normal_execs=4)
    normal_events = [_event(1000 + index, comm="bash", pid=index) for index in range(4)]
    analyzer.learn_normal(normal_events, verified_normal=True)

    result = analyzer.monitor([_event(1100, comm="nc", uid=1000, pid=99)])
    assert result["mode"] == AnalysisMode.MONITORING.value
    assert result["status"] == "monitoring"
    assert result["risks"]

    risk = result["risks"][0]
    assert risk["entity_type"] in {"command", "uid"}
    assert 0.0 <= risk["anomaly_score"] <= 1.0
    assert risk["risk_level"] in {"medium", "high"}
    assert risk["contributing_features"]["execution_frequency"] == 1
    assert "source=command_frequency=" in risk["explanation"]

    stored = store.read_risk_records()
    assert stored
    assert stored[0]["explanation"] == risk["explanation"]
    assert stored[0]["contributing_features"] == risk["contributing_features"]

    later = analyzer.monitor([_event(1200, comm="nc", uid=1000, pid=100)])
    assert later["status"] == "monitoring"
    assert len(analyzer._normal_events) == 4


def test_ready_baseline_can_be_reloaded_for_monitoring(tmp_path):
    db_path = tmp_path / "events.db"
    first_store = SQLiteEventStore(str(db_path))
    first_analyzer = BehaviorAnalyzer(first_store, minimum_normal_execs=4)
    first_analyzer.learn_normal(
        [_event(1000 + index, comm="bash", uid=1000, pid=index) for index in range(4)],
        verified_normal=True,
    )

    reloaded_analyzer = BehaviorAnalyzer(SQLiteEventStore(str(db_path)), minimum_normal_execs=4)
    result = reloaded_analyzer.monitor([_event(1100, comm="bash", uid=1000, pid=99)])
    assert result["status"] == "monitoring"
    assert result["risks"] == []


def test_monitoring_waits_for_ready_baseline(tmp_path):
    analyzer = BehaviorAnalyzer(
        SQLiteEventStore(str(tmp_path / "events.db")),
        minimum_normal_execs=500,
    )
    result = analyzer.monitor([_event(1000, comm="nc")])
    assert result == {
        "mode": AnalysisMode.LEARNING.value,
        "status": "baseline_not_ready",
        "risks": [],
    }


def test_real_capture_is_sanity_checked_but_not_promoted(tmp_path):
    capture_path = Path("/home/virus/phase1_live_20260819_003757.jsonl")
    if not capture_path.exists():
        return

    events = [json.loads(line) for line in capture_path.read_text().splitlines() if line.strip()]
    analyzer = BehaviorAnalyzer(
        SQLiteEventStore(str(tmp_path / "events.db")),
        minimum_normal_execs=500,
    )
    result = analyzer.learn_normal(events, verified_normal=True)
    assert result["status"] == "insufficient_normal_data"
    assert result["normal_exec_count"] == 134
    assert analyzer.monitor(events)["status"] == "baseline_not_ready"
