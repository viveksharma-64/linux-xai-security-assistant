#!/usr/bin/env python3
"""Network-only BCC collector using sock:inet_sock_set_state."""

import json
import socket
import sys
import time
from typing import Any, Optional

# Importable both as a package module and as a sibling file: the documented way
# to run this collector is `python3 telemetry/bcc/network_state_probe.py`, where
# the repository root is not on sys.path.
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
# this module for its address/state formatting helpers does not kill the
# interpreter. See telemetry/bcc/bpf_runtime.py.
BPF = load_bpf()

AF_INET = 2
IPPROTO_TCP = 6
TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2

struct state_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    u8 daddr[4];
    u16 dport;
    u64 timestamp_ns;
};
#ifdef USE_RINGBUF
BPF_RINGBUF_OUTPUT(state_events, 8);
// One-element counter for reservations the kernel refused when the ring was
// full. The perf build never references it, so it is not compiled in that mode.
BPF_ARRAY(state_events_dropped, u64, 1);
#else
BPF_PERF_OUTPUT(state_events);
#endif

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->family != AF_INET || args->protocol != IPPROTO_TCP) {
        return 0;
    }
    if (args->oldstate != TCP_SYN_SENT || args->newstate != TCP_ESTABLISHED) {
        return 0;
    }

    struct state_event_t event = {};
    // Capture identity in the tracepoint's current task context.  Reading the
    // common trace header or /proc later can report a stale or unrelated task.
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // daddr is a four-byte tracepoint field, not a kernel pointer.  Copy each
    // byte directly from the tracepoint context to preserve IPv4 byte order.
    event.daddr[0] = args->daddr[0];
    event.daddr[1] = args->daddr[1];
    event.daddr[2] = args->daddr[2];
    event.daddr[3] = args->daddr[3];
    // The tracepoint exports sport/dport in host order.  Do not apply ntohs:
    // that turns a requested local port such as 18080 into 41030.
    event.dport = args->dport;
    event.timestamp_ns = bpf_ktime_get_ns();
#ifdef USE_RINGBUF
    struct state_event_t *out = state_events.ringbuf_reserve(sizeof(*out));
    if (!out) {
        u32 slot = 0;
        u64 *dropped = state_events_dropped.lookup(&slot);
        if (dropped) { __sync_fetch_and_add(dropped, 1); }
        return 0;
    }
    *out = event;
    state_events.ringbuf_submit(out, 0);
#else
    state_events.perf_submit(args, &event, sizeof(event));
#endif
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


def _decode_ipv4(value: Any) -> Optional[str]:
    try:
        packed = bytes(value)
    except (TypeError, ValueError):
        return None
    if len(packed) != 4:
        return None
    try:
        return socket.inet_ntoa(packed)
    except OSError:
        return None


def normalize_state_event(event: Any, timestamp: Optional[float] = None) -> Optional[dict]:
    """Convert one tracepoint payload into the existing tcp_connect contract."""
    try:
        pid = int(event.pid)
        uid = int(event.uid)
        port = int(event.dport)
        timestamp_ns = int(event.timestamp_ns)
    except (AttributeError, TypeError, ValueError):
        return None
    destination_ip = _decode_ipv4(getattr(event, "daddr", None))
    if pid <= 0 or uid < 0 or not 1 <= port <= 65535 or destination_ip is None:
        return None
    return {
        "event_type": "tcp_connect",
        "timestamp": time.time() if timestamp is None else float(timestamp),
        "timestamp_ns": timestamp_ns,
        "pid": pid,
        "uid": uid,
        "comm": _decode_comm(getattr(event, "comm", None)),
        "dest_ip": destination_ip,
        "dest_port": port,
        "source": "telemetry_bcc_network_state",
        "version": "1.0",
    }


def handle_state_event(cpu, data, size):
    event = b["state_events"].event(data)
    normalized = normalize_state_event(event)
    if normalized is not None:
        print(json.dumps(normalized), flush=True)


# Module level, and shared by every per-CPU registration bcc makes, so the count
# it reports is process-wide rather than one total per CPU.
loss_reporter = PerfBufferLossReporter(
    buffer_name="state_events",
    source="telemetry_bcc_network_state",
)


def main():
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
        "source": "telemetry_bcc_network_state",
        "version": "1.0",
    }), flush=True)
    print(json.dumps({
        "event_type": "telemetry_startup",
        "message": "TCP state tracepoint probe attached.",
        "timestamp": time.time(),
    }), file=sys.stderr)
    ring_loss = RingBufferLossReporter(loss_reporter, map_name="state_events_dropped")
    try:
        if mechanism == EVENT_BUFFER_RINGBUF:
            b = BPF(text=BPF_PROGRAM, cflags=["-DUSE_RINGBUF"])
            # open_ring_buffer has no lost_cb; discards are counted in the BPF
            # program and read from state_events_dropped by ring_loss.poll below.
            b["state_events"].open_ring_buffer(handle_state_event)
        else:
            b = BPF(text=BPF_PROGRAM)
            # lost_cb is what makes a kernel ring-buffer overrun visible. Without it
            # the samples the kernel discards leave a hole in this stream that no
            # counter anywhere records. See telemetry/bcc/perf_loss.py.
            b["state_events"].open_perf_buffer(handle_state_event, lost_cb=loss_reporter)
    except Exception as error:
        print(json.dumps({
            "event_type": "telemetry_error",
            "message": f"Failed to load TCP state probe: {error}",
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
