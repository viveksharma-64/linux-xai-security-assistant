import os
from pathlib import Path

import telemetry.bcc.process_context as process_context
from pipeline.event_stream import CanonicalNormalizer, Event, EventType
from storage.sqlite_store import SQLiteEventStore
from telemetry.bcc.process_context import read_process_context


def _raw(**extra):
    value = {
        "event_type": "process_exec",
        "timestamp": 1700000000.0,
        "pid": 100,
        "ppid": 90,
        "uid": 1000,
        "gid": 1000,
        "comm": "python3",
        "executable": "/usr/bin/python3",
        "parent_comm": "bash",
        "ancestry": [{"pid": 90, "comm": "bash", "ppid": 80}],
    }
    value.update(extra)
    return value


def test_process_context_reads_current_process_without_fabricating_parent_data():
    context = read_process_context(os.getpid())
    assert context["ppid"] == os.getppid()
    assert context["ancestry"]
    assert context["ancestry"][0]["pid"] == os.getppid()
    assert context["parent_comm"] is None or isinstance(context["parent_comm"], str)
    assert context["executable"] is None or context["executable"].startswith("/")


def test_unavailable_process_context_is_explicitly_empty():
    assert read_process_context(-1) == {
        "ppid": None,
        "executable": None,
        "parent_comm": None,
        "ancestry": [],
    }


def test_post_exec_context_uses_kernel_executable_and_stable_proc_parent(monkeypatch):
    identities = {
        100: {"comm": "python3", "uid": 1000, "gid": 1000, "starttime": "a"},
        90: {"comm": "bash", "uid": 1000, "gid": 1000, "starttime": "b"},
    }
    monkeypatch.setattr(process_context, "_read_identity", lambda pid: identities.get(pid))
    monkeypatch.setattr(process_context, "_read_ppid", lambda pid: 90 if pid == 100 else 1)

    context = process_context.read_process_context(
        100,
        expected_comm="python3",
        expected_uid=1000,
        expected_gid=1000,
        executable="/usr/bin/python3",
    )

    assert context["executable"] == "/usr/bin/python3"
    assert context["ppid"] == 90
    assert context["parent_comm"] == "bash"


def test_process_identity_mismatch_returns_empty_context(monkeypatch):
    monkeypatch.setattr(process_context, "_read_identity", lambda pid: {
        "comm": "other-process", "uid": 1000, "gid": 1000, "starttime": "new"
    })

    context = process_context.read_process_context(
        100,
        expected_comm="python3",
        expected_uid=1000,
        expected_gid=1000,
        executable="/usr/bin/python3",
    )

    assert context == {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}


def test_process_replacement_during_proc_lookup_returns_empty_context(monkeypatch):
    calls = {100: 0}

    def changing_identity(pid):
        if pid != 100:
            return None
        calls[100] += 1
        starttime = "old" if calls[100] == 1 else "new"
        return {"comm": "python3", "uid": 1000, "gid": 1000, "starttime": starttime}

    monkeypatch.setattr(process_context, "_read_identity", changing_identity)
    monkeypatch.setattr(process_context, "_read_ppid", lambda pid: 90)

    context = process_context.read_process_context(
        100,
        expected_comm="python3",
        expected_uid=1000,
        expected_gid=1000,
        executable="/usr/bin/python3",
    )

    assert context == {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}


def test_parent_disappearing_leaves_parent_context_unavailable(monkeypatch):
    identities = {
        100: {"comm": "python3", "uid": 1000, "gid": 1000, "starttime": "a"},
        90: None,
    }
    monkeypatch.setattr(process_context, "_read_identity", lambda pid: identities.get(pid))
    monkeypatch.setattr(process_context, "_read_ppid", lambda pid: 90)

    context = process_context.read_process_context(
        100,
        expected_comm="python3",
        expected_uid=1000,
        expected_gid=1000,
        executable="/usr/bin/python3",
    )

    assert context["ppid"] == 90
    assert context["parent_comm"] is None
    assert context["ancestry"] == []


def test_complete_process_context_normalizes_and_persists(tmp_path):
    event = CanonicalNormalizer().normalize(_raw())
    assert event.event_type == EventType.PROCESS_EXEC
    assert event.ppid == 90
    assert event.executable == "/usr/bin/python3"
    assert event.parent_comm == "bash"
    assert event.ancestry[0]["comm"] == "bash"

    store = SQLiteEventStore(str(tmp_path / "context.db"))
    assert store.write(event) is True
    stored = list(store.read_all())[0]
    assert stored.ppid == 90
    assert stored.parent_comm == "bash"
    assert stored.ancestry == [{"comm": "bash", "pid": 90, "ppid": 80}]
    record = store.read_event_records()[0]
    assert record["executable"] == "/usr/bin/python3"
    assert record["ancestry"][0]["pid"] == 90


def test_old_process_event_without_context_remains_compatible(tmp_path):
    event = CanonicalNormalizer().normalize({
        "event_type": "process_exec",
        "timestamp": 1700000000.0,
        "pid": 100,
        "uid": 1000,
        "gid": 1000,
        "comm": "bash",
    })
    assert event.ppid is None
    assert event.executable is None
    assert event.parent_comm is None
    assert event.ancestry == []

    store = SQLiteEventStore(str(tmp_path / "old.db"))
    store.write(event)
    assert list(store.read_all())[0].ancestry == []


def test_malformed_context_is_not_fabricated():
    event = CanonicalNormalizer().normalize(_raw(
        pid="not-a-pid",
        ppid="not-a-ppid",
        gid="not-a-gid",
        parent_comm=42,
        ancestry={"pid": 90},
    ))
    assert event.pid is None
    assert event.ppid is None
    assert event.gid is None
    assert event.parent_comm is None
    assert event.ancestry == []


def test_event_factory_accepts_context_fields_directly():
    event = Event.from_raw_json(_raw())
    assert event.executable == "/usr/bin/python3"
    assert event.parent_comm == "bash"
    assert event.ancestry[0]["pid"] == 90


def test_collector_uses_post_exec_tracepoint_kernel_filename():
    source = Path(__file__).parents[1] / "telemetry" / "bcc" / "telemetry_basic.py"
    text = source.read_text(encoding="utf-8")
    assert "TRACEPOINT_PROBE(sched, sched_process_exec)" in text
    assert "record + 8" in text
    assert "filename_loc & 0xFFFF" in text
    assert "sys_enter_execve" not in text
