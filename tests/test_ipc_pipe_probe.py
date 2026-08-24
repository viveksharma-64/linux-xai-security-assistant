from types import SimpleNamespace

from pipeline.event_stream import CanonicalNormalizer, EventType
from storage.sqlite_store import SQLiteEventStore
from telemetry.bcc.ipc_pipe_probe import BPF_PROGRAM, normalize_pipe_event


def _event(**values):
    fields = {
        "pid": 4321,
        "uid": 1000,
        "comm": b"python3\0",
        "read_fd": 3,
        "write_fd": 4,
        "read_fd_status": 0,
        "write_fd_status": 0,
        "result": 0,
        "timestamp_ns": 987654,
    }
    fields.update(values)
    return SimpleNamespace(**fields)


def test_pipe_kprobes_correlate_entry_and_exit_without_kernel_struct_access():
    assert "int trace_pipe_entry(struct pt_regs *ctx)" in BPF_PROGRAM
    assert "int trace_pipe_return(struct pt_regs *ctx)" in BPF_PROGRAM
    assert "PT_REGS_PARM1(ctx)" in BPF_PROGRAM
    assert "+ 0x70" in BPF_PROGRAM
    assert "bpf_probe_read_kernel" in BPF_PROGRAM
    assert "PT_REGS_RC(ctx)" in BPF_PROGRAM
    assert "bpf_probe_read_user" in BPF_PROGRAM
    assert "pipe_events.perf_submit(ctx" in BPF_PROGRAM
    assert "<net/sock.h>" not in BPF_PROGRAM


def test_successful_pipe_creation_normalizes_to_canonical_ipc_event():
    raw = normalize_pipe_event(_event(), timestamp=1700000000.5)
    event = CanonicalNormalizer().normalize(raw)

    assert event.event_type == EventType.IPC_EVENT
    assert event.pid == 4321 and event.uid == 1000 and event.comm == "python3"
    assert event.payload == {
        "action": "pipe_created", "kind": "anonymous_pipe", "endpoint": "fd:3->fd:4",
        "read_fd": 3, "write_fd": 4, "success": True, "errno": None,
    }


def test_failed_pipe_creation_retains_only_kernel_reported_failure_metadata():
    raw = normalize_pipe_event(_event(result=-24), timestamp=1.0)

    assert raw["success"] is False
    assert raw["errno"] == 24
    assert raw["endpoint"] is None
    assert raw["read_fd"] is None and raw["write_fd"] is None


def test_failed_userspace_fd_read_does_not_fabricate_zero_descriptors():
    raw = normalize_pipe_event(_event(read_fd=0, write_fd=0, read_fd_status=-14), timestamp=1.0)

    assert raw["success"] is True
    assert raw["read_fd"] is None and raw["write_fd"] is None
    assert raw["endpoint"] is None


def test_optional_comm_and_sqlite_persistence_are_supported(tmp_path):
    raw = normalize_pipe_event(_event(comm=None), timestamp=2.0)
    event = CanonicalNormalizer().normalize(raw)
    store = SQLiteEventStore(str(tmp_path / "ipc.db"))

    assert event.comm is None
    assert store.write(event) is True
    stored = list(store.read_all())[0]
    assert stored.event_type == EventType.IPC_EVENT
    assert stored.payload["endpoint"] == "fd:3->fd:4"


def test_malformed_or_unrelated_perf_payload_is_rejected():
    assert normalize_pipe_event(_event(pid=0), timestamp=1.0) is None
    invalid_fds = normalize_pipe_event(_event(read_fd=-1), timestamp=1.0)
    assert invalid_fds["read_fd"] is None and invalid_fds["write_fd"] is None
    assert invalid_fds["endpoint"] is None
    assert normalize_pipe_event(SimpleNamespace(pid=1), timestamp=1.0) is None
