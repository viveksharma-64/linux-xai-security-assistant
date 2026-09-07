#!/usr/bin/env python3
"""Read-only BCC telemetry for anonymous-pipe creation syscall results."""

import json
import sys
import time
from typing import Any, Optional

# Importable both as a package module and as a sibling file: the documented way
# to run this collector is `python3 telemetry/bcc/ipc_pipe_probe.py`, where the
# repository root is not on sys.path.
try:
    from telemetry.bcc.perf_loss import PerfBufferLossReporter
except ImportError:
    from perf_loss import PerfBufferLossReporter

try:
    from telemetry.bcc.bpf_runtime import load_bpf, require_bpf
except ImportError:
    from bpf_runtime import load_bpf, require_bpf

# None when bcc is unavailable; checked in main() rather than here so importing
# this module for normalize_pipe_event() does not kill the interpreter. See
# telemetry/bcc/bpf_runtime.py.
BPF = load_bpf()


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct pipe_args_t {
    u64 fildes;
};

struct pipe_event_t {
    u32 pid;
    u32 uid;
    s32 read_fd;
    s32 write_fd;
    s32 read_fd_status;
    s32 write_fd_status;
    s64 result;
    u64 timestamp_ns;
    char comm[16];
};

BPF_HASH(pipe_args, u64, struct pipe_args_t);
BPF_PERF_OUTPUT(pipe_events);

int trace_pipe_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct pipe_args_t state = {};
    // __x64_sys_pipe* receives a struct pt_regs * as its C ABI argument.
    // For the native x86_64 syscall ABI, the actual first argument (pipefd)
    // is regs->di at offset 0x70; see arch/x86/include/asm/syscall_wrapper.h.
    bpf_probe_read_kernel(&state.fildes, sizeof(state.fildes),
                          (void *)(PT_REGS_PARM1(ctx) + 0x70));
    pipe_args.update(&id, &state);
    return 0;
}

int trace_pipe_return(struct pt_regs *ctx) {
    s64 result = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    struct pipe_args_t *state = pipe_args.lookup(&id);
    if (state == 0) {
        return 0;
    }

    struct pipe_event_t event = {};
    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.result = result;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (result == 0) {
        event.read_fd_status = bpf_probe_read_user(&event.read_fd, sizeof(event.read_fd), (void *)state->fildes);
        event.write_fd_status = bpf_probe_read_user(&event.write_fd, sizeof(event.write_fd), (void *)(state->fildes + sizeof(event.read_fd)));
    }
    pipe_events.perf_submit(ctx, &event, sizeof(event));
    pipe_args.delete(&id);
    return 0;
}

"""


def _decode_comm(value: Any) -> Optional[str]:
    if isinstance(value, bytes):
        value = value.split(b"\0", 1)[0].decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    value = value.split("\0", 1)[0].strip()
    return value or None


def normalize_pipe_event(event: Any, timestamp: Optional[float] = None) -> Optional[dict]:
    """Convert one pipe syscall result into the canonical IPC raw contract."""
    try:
        pid = int(event.pid)
        uid = int(event.uid)
        result = int(event.result)
        timestamp_ns = int(event.timestamp_ns)
    except (AttributeError, TypeError, ValueError):
        return None
    if pid <= 0 or uid < 0 or timestamp_ns < 0:
        return None

    raw = {
        "event_type": "ipc_event",
        "timestamp": time.time() if timestamp is None else float(timestamp),
        "timestamp_ns": timestamp_ns,
        "pid": pid,
        "uid": uid,
        "comm": _decode_comm(getattr(event, "comm", None)),
        "action": "pipe_created",
        "kind": "anonymous_pipe",
        "success": result == 0,
        "errno": -result if result < 0 else None,
        "source": "telemetry_bcc_pipe_syscalls",
        "version": "1.0",
    }
    if result == 0:
        try:
            read_fd_status = int(event.read_fd_status)
            write_fd_status = int(event.write_fd_status)
            read_fd = int(event.read_fd)
            write_fd = int(event.write_fd)
        except (AttributeError, TypeError, ValueError):
            return None
        if read_fd_status == 0 and write_fd_status == 0 and read_fd >= 0 and write_fd >= 0:
            raw.update({
                "read_fd": read_fd,
                "write_fd": write_fd,
                "endpoint": f"fd:{read_fd}->fd:{write_fd}",
            })
        else:
            raw.update({"read_fd": None, "write_fd": None, "endpoint": None})
    else:
        raw.update({"read_fd": None, "write_fd": None, "endpoint": None})
    return raw


def handle_pipe_event(cpu, data, size):
    event = b["pipe_events"].event(data)
    normalized = normalize_pipe_event(event)
    if normalized is not None:
        print(json.dumps(normalized), flush=True)


# Module level, and shared by every per-CPU registration bcc makes, so the count
# it reports is process-wide rather than one total per CPU.
loss_reporter = PerfBufferLossReporter(
    buffer_name="pipe_events",
    source="telemetry_bcc_pipe_syscalls",
)


def main() -> int:
    global b
    require_bpf(BPF)
    print(json.dumps({
        "event_type": "telemetry_startup",
        "message": "pipe/pipe2 syscall kprobe attached.",
        "timestamp": time.time(),
    }), file=sys.stderr)
    try:
        b = BPF(text=BPF_PROGRAM)
        for syscall in ("__x64_sys_pipe", "__x64_sys_pipe2"):
            b.attach_kprobe(event=syscall, fn_name="trace_pipe_entry")
            b.attach_kretprobe(event=syscall, fn_name="trace_pipe_return")
        # lost_cb is what makes a kernel ring-buffer overrun visible. Without it
        # the samples the kernel discards leave a hole in this stream that no
        # counter anywhere records. See telemetry/bcc/perf_loss.py.
        b["pipe_events"].open_perf_buffer(handle_pipe_event, lost_cb=loss_reporter)
    except Exception as error:
        print(json.dumps({
            "event_type": "telemetry_warning",
            "message": f"Failed to load pipe syscall kprobe: {error}",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 1
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        # Flushed before the shutdown notice so a loss burst inside the last
        # reporting window is still reported rather than lost with the process.
        loss_reporter.flush()
        print(json.dumps({
            "event_type": "telemetry_shutdown",
            "message": "stopped by user",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
