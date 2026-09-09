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
    from telemetry.bcc.ringbuf_loss import RingBufferLossReporter
except ImportError:
    from ringbuf_loss import RingBufferLossReporter

try:
    from telemetry.bcc.bpf_runtime import (
        EVENT_BUFFER_RINGBUF,
        RINGBUF_POLL_TIMEOUT_MS,
        load_bpf,
        request_keyboard_interrupt_on_sigterm,
        require_bpf,
        select_event_buffer,
    )
except ImportError:
    from bpf_runtime import (
        EVENT_BUFFER_RINGBUF,
        RINGBUF_POLL_TIMEOUT_MS,
        load_bpf,
        request_keyboard_interrupt_on_sigterm,
        require_bpf,
        select_event_buffer,
    )

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
#ifdef USE_RINGBUF
BPF_RINGBUF_OUTPUT(pipe_events, 8);
// One-element counter for reservations the kernel refused when the ring was
// full. The perf build never references it, so it is not compiled in that mode.
BPF_ARRAY(pipe_events_dropped, u64, 1);
#else
BPF_PERF_OUTPUT(pipe_events);
#endif

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
#ifdef USE_RINGBUF
    struct pipe_event_t *out = pipe_events.ringbuf_reserve(sizeof(*out));
    if (!out) {
        u32 slot = 0;
        u64 *dropped = pipe_events_dropped.lookup(&slot);
        if (dropped) { __sync_fetch_and_add(dropped, 1); }
        // Still drop the per-call state: a refused reservation must not leak a
        // pipe_args entry that trace_pipe_return would otherwise never reap.
        pipe_args.delete(&id);
        return 0;
    }
    *out = event;
    pipe_events.ringbuf_submit(out, 0);
#else
    pipe_events.perf_submit(ctx, &event, sizeof(event));
#endif
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
    request_keyboard_interrupt_on_sigterm()
    try:
        mechanism = select_event_buffer(BPF)
    except ValueError as error:
        print(json.dumps({
            "event_type": "telemetry_error",
            "message": f"{error}",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 1
    # Durable and on stdout so it is ingested: this is the one signal that names
    # which transport -- and therefore which loss-accounting path -- is in force.
    # The loss record itself is frozen and does not carry the mechanism.
    print(json.dumps({
        "event_type": "telemetry_warning",
        "message": f"event buffer transport selected: {mechanism}",
        "buffer_transport": mechanism,
        "reason": "startup_transport_selection",
        "timestamp": time.time(),
        "source": "telemetry_bcc_pipe_syscalls",
        "version": "1.0",
    }), flush=True)
    print(json.dumps({
        "event_type": "telemetry_startup",
        "message": "pipe/pipe2 syscall kprobe attached.",
        "timestamp": time.time(),
    }), file=sys.stderr)
    ring_loss = RingBufferLossReporter(loss_reporter, map_name="pipe_events_dropped")
    try:
        if mechanism == EVENT_BUFFER_RINGBUF:
            b = BPF(text=BPF_PROGRAM, cflags=["-DUSE_RINGBUF"])
        else:
            b = BPF(text=BPF_PROGRAM)
        for syscall in ("__x64_sys_pipe", "__x64_sys_pipe2"):
            b.attach_kprobe(event=syscall, fn_name="trace_pipe_entry")
            b.attach_kretprobe(event=syscall, fn_name="trace_pipe_return")
        if mechanism == EVENT_BUFFER_RINGBUF:
            # open_ring_buffer has no lost_cb; discards are counted in the BPF
            # program and read from pipe_events_dropped by ring_loss.poll below.
            b["pipe_events"].open_ring_buffer(handle_pipe_event)
        else:
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
            if mechanism == EVENT_BUFFER_RINGBUF:
                b.ring_buffer_poll(timeout=RINGBUF_POLL_TIMEOUT_MS)
                ring_loss.poll(b)
            else:
                b.perf_buffer_poll()
    except KeyboardInterrupt:
        # A final counter read captures anything dropped in the last window, then
        # flush before the shutdown notice so that loss is reported rather than
        # lost with the process. SIGTERM reaches here via the handler above.
        if mechanism == EVENT_BUFFER_RINGBUF:
            ring_loss.poll(b)
        loss_reporter.flush()
        print(json.dumps({
            "event_type": "telemetry_shutdown",
            "message": "stopped by user",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
