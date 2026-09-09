#!/usr/bin/env python3
"""
telemetry_basic.py - Minimal eBPF post-exec tracepoint collector

Captures process execution using sched:sched_process_exec. The executable
identity is copied from the post-exec kernel tracepoint; procfs is used only
for optional parent and ancestry context.

Run: sudo python3 telemetry/bcc/telemetry_basic.py
Ctrl+C to stop
"""

import json
import sys
import time

try:
    from telemetry.bcc.process_context import read_process_context
except ImportError:
    from process_context import read_process_context

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

try:
    import psutil
except ImportError:
    psutil = None

# None when bcc is unavailable; checked in main() rather than at import so that
# importing this module for its helpers does not kill the interpreter, and so the
# BPF program is compiled only once the transport (and its cflags) is chosen. See
# telemetry/bcc/bpf_runtime.py.
BPF = load_bpf()

# Post-exec tracepoint: filename is available after the new image is installed.
BPF_CODE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
#ifdef USE_RINGBUF
BPF_RINGBUF_OUTPUT(exec_events, 8);
// One-element counter for reservations the kernel refused when the ring was
// full. The perf build never references it, so it is not compiled in that mode.
BPF_ARRAY(exec_events_dropped, u64, 1);
#else
BPF_PERF_OUTPUT(exec_events);
#endif

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event ev = {};
    u32 filename_loc = 0;
    char *record = (char *)args;
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev.gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    // Kernel format: __data_loc filename at offset 8; low 16 bits are the data offset.
    bpf_probe_read_kernel(&filename_loc, sizeof(filename_loc), record + 8);
    bpf_probe_read_kernel_str(&ev.filename, sizeof(ev.filename), record + (filename_loc & 0xFFFF));
#ifdef USE_RINGBUF
    struct exec_event *out = exec_events.ringbuf_reserve(sizeof(*out));
    if (!out) {
        u32 slot = 0;
        u64 *dropped = exec_events_dropped.lookup(&slot);
        if (dropped) { __sync_fetch_and_add(dropped, 1); }
        return 0;
    }
    *out = ev;
    exec_events.ringbuf_submit(out, 0);
#else
    exec_events.perf_submit(args, &ev, sizeof(ev));
#endif
    return 0;
}
"""


def handle_exec_event(cpu, data, size):
    ev = b["exec_events"].event(data)
    filename = ev.filename.decode("utf-8", errors="replace").strip() or None
    context = read_process_context(
        ev.pid,
        expected_comm=ev.comm.decode("utf-8", errors="replace").strip() or None,
        expected_uid=ev.uid,
        expected_gid=ev.gid,
        executable=filename,
    )
    event = {
        "event_type": "process_exec",
        "timestamp": time.time(),
        "pid": ev.pid,
        "uid": ev.uid,
        "gid": ev.gid,
        "comm": ev.comm.decode("utf-8", errors="replace").strip(),
        **context,
        "source": "telemetry_bcc",
        "version": "1.0",
    }
    print(json.dumps(event), flush=True)


# Shared by every per-CPU registration bcc makes, so the count it reports is
# process-wide rather than one total per CPU. lost_cb (perf) and the polled drop
# counter (ring buffer) both feed this one reporter, so the telemetry_loss wire
# record is identical whichever transport is active. See telemetry/bcc/perf_loss.py.
loss_reporter = PerfBufferLossReporter(buffer_name="exec_events", source="telemetry_bcc")


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
        "source": "telemetry_bcc",
        "version": "1.0",
    }), flush=True)
    ring_loss = RingBufferLossReporter(loss_reporter, map_name="exec_events_dropped")
    try:
        if mechanism == EVENT_BUFFER_RINGBUF:
            b = BPF(text=BPF_CODE, cflags=["-DUSE_RINGBUF"])
        else:
            b = BPF(text=BPF_CODE)
        print(json.dumps({
            "event_type": "telemetry_startup",
            "message": "Post-exec probe attached. Capturing process execution events.",
            "timestamp": time.time()
        }), file=sys.stderr)
    except Exception as e:
        print(json.dumps({
            "event_type": "telemetry_error",
            "message": f"Failed to load eBPF: {e}",
            "timestamp": time.time()
        }), file=sys.stderr)
        return 1

    if mechanism == EVENT_BUFFER_RINGBUF:
        # open_ring_buffer has no lost_cb; discards are counted in the BPF program
        # and read from exec_events_dropped by ring_loss.poll below.
        b["exec_events"].open_ring_buffer(handle_exec_event)
    else:
        b["exec_events"].open_perf_buffer(handle_exec_event, lost_cb=loss_reporter)

    health_count = 0
    try:
        while True:
            if mechanism == EVENT_BUFFER_RINGBUF:
                b.ring_buffer_poll(timeout=RINGBUF_POLL_TIMEOUT_MS)
                ring_loss.poll(b)
            else:
                b.perf_buffer_poll()
            health_count += 1
            if health_count >= 100 and psutil:
                try:
                    mem = psutil.virtual_memory()
                    print(json.dumps({
                        "event_type": "system_health",
                        "timestamp": time.time(),
                        "mem_percent": mem.percent,
                        "mem_available_mb": mem.available // (1024*1024),
                    }), flush=True)
                    health_count = 0
                # Health reporting is best-effort and must never take the collector
                # down: psutil.Error, OSError on a closed/broken stdout, and encoding
                # failures are all swallowed here. Narrowed from a bare `except:` so
                # a Ctrl+C landing inside this block still reaches the
                # KeyboardInterrupt handler below, which flushes the loss reporter.
                except Exception:
                    pass
    except KeyboardInterrupt:
        # A final counter read captures anything dropped in the last window, then
        # flush before the shutdown notice so that loss is reported rather than
        # lost with the process. SIGTERM reaches here via the handler above.
        if mechanism == EVENT_BUFFER_RINGBUF:
            ring_loss.poll(b)
        loss_reporter.flush()
        print(json.dumps({"event_type": "telemetry_shutdown", "timestamp": time.time()}), file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
