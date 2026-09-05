#!/usr/bin/env python3
"""
telemetry_collector.py - Full-featured telemetry PoC

DEPRECATED / LEGACY: superseded by the per-domain collectors
(telemetry/bcc/telemetry_basic.py, network_state_probe.py, ipc_pipe_probe.py).
Retained as a historical proof of concept only. It is not wired to the
ingestion pipeline, is not covered by the regression suite, and is not
perf-buffer-loss reported. Do not use it for live telemetry and do not build
on it.

Extended version of process_exec_probe.py with:
- Process execution events
- TCP connection events  
- System health metrics (CPU, memory, disk)
- Minimal, kernel-compatible eBPF probes

Run (requires root):
    sudo python3 telemetry/bcc/telemetry_collector.py

Ctrl+C to stop.
"""

import ctypes as ct
import json
import socket
import struct
import sys
import time

try:
    from bcc import BPF
except ImportError:
    sys.stderr.write(
        "ERROR: could not import bcc. Install with:\n"
        "    sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc\n"
    )
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

# ---------------------------------------------------------------------------
# eBPF PROGRAM — Proven, minimal, kernel 7.0+ compatible
# ---------------------------------------------------------------------------
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16
#define ARGSIZE 128

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
    u64 timestamp_ns;
};
BPF_PERF_OUTPUT(exec_events);

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u64 timestamp_ns;
};
BPF_PERF_OUTPUT(connect_events);

// Map to stash socket between entry and return
BPF_HASH(currsock, u32, struct sock *);

// --- PROCESS EXECUTION TRACEPOINT ---
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    void *filename_ptr = (void *)args->__data_loc_filename + (args->__data_loc_filename >> 16);
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), filename_ptr);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// --- TCP CONNECT: ENTRY (KPROBE) ---
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

// --- TCP CONNECT: RETURN (KRETPROBE) ---
int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }
    if (ret \!= 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock *skp = *skpp;
    u32 daddr = 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    struct connect_event_t event = {};
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.daddr = daddr;
    event.dport = ntohs(dport);

    connect_events.perf_submit(ctx, &event, sizeof(event));
    currsock.delete(&pid);
    return 0;
}
"""


def handle_exec_event(cpu, data, size):
    """Process execution event."""
    event = b["exec_events"].event(data)
    out = {
        "event_type": "process_exec",
        "timestamp": time.time(),
        "timestamp_ns": event.timestamp_ns,
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode("utf-8", "replace"),
        "filename": event.filename.decode("utf-8", "replace"),
    }
    print(json.dumps(out), flush=True)


def handle_connect_event(cpu, data, size):
    """TCP connection event."""
    event = b["connect_events"].event(data)
    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
    out = {
        "event_type": "tcp_connect",
        "timestamp": time.time(),
        "timestamp_ns": event.timestamp_ns,
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode("utf-8", "replace"),
        "dest_ip": daddr,
        "dest_port": event.dport,
    }
    print(json.dumps(out), flush=True)


def collect_system_health():
    """Collect CPU, memory, disk metrics."""
    if not psutil:
        return None
    try:
        return {
            "event_type": "system_health",
            "timestamp": time.time(),
            "cpu_percent": psutil.cpu_percent(interval=0.05),
            "mem_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "mem_available_mb": psutil.virtual_memory().available // (1024 * 1024),
        }
    except Exception:
        return None


def main():
    """Main entry point."""
    global b

    print(
        json.dumps(
            {
                "event_type": "telemetry_startup",
                "message": "loading eBPF programs...",
                "timestamp": time.time(),
            }
        ),
        file=sys.stderr,
    )

    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        print(
            json.dumps(
                {
                    "event_type": "telemetry_error",
                    "message": f"BPF load failed: {str(e)}",
                    "timestamp": time.time(),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    # Attach probes
    try:
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
        print(
            json.dumps(
                {
                    "event_type": "telemetry_info",
                    "message": "tcp probes attached",
                    "timestamp": time.time(),
                }
            ),
            file=sys.stderr,
        )
    except Exception as e:
        print(
            json.dumps(
                {
                    "event_type": "telemetry_warning",
                    "message": f"tcp probes failed: {e}",
                    "timestamp": time.time(),
                }
            ),
            file=sys.stderr,
        )

    # Open perf buffers
    b["exec_events"].open_perf_buffer(handle_exec_event)
    b["connect_events"].open_perf_buffer(handle_connect_event)

    print(
        json.dumps(
            {
                "event_type": "telemetry_startup",
                "message": "probes attached, polling events. Ctrl+C to stop.",
                "timestamp": time.time(),
            }
        ),
        file=sys.stderr,
    )

    # Poll loop
    health_counter = 0
    try:
        while True:
            b.perf_buffer_poll()
            health_counter += 1
            if health_counter >= 50:  # ~5 second interval
                health = collect_system_health()
                if health:
                    print(json.dumps(health), flush=True)
                health_counter = 0

    except KeyboardInterrupt:
        print(
            json.dumps(
                {
                    "event_type": "telemetry_shutdown",
                    "message": "stopped by user",
                    "timestamp": time.time(),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
