#!/usr/bin/env python3
"""
process_exec_probe.py

DEPRECATED / LEGACY: the original proof of concept, superseded by
telemetry/bcc/telemetry_basic.py. Retained for historical reference only. It is
not wired to the ingestion pipeline, is not covered by the regression suite,
and is not perf-buffer-loss reported. Do not use it for live telemetry and do
not build on it.

The original telemetry PoC. NOT the final pipeline — this proves that we can
capture structured, kernel-level events (process execution + outbound
TCP connect attempts) using BCC on this specific host, and prints them
as JSON lines to stdout.

The "print to stdout" step was later replaced by a real event collector
that normalizes and forwards these into the pipeline.

Run (must be root — BCC needs CAP_BPF/CAP_SYS_ADMIN to attach probes):
    sudo python3 telemetry/bcc/process_exec_probe.py

Stop with Ctrl+C.

Requires: bpfcc-tools, python3-bpfcc (see scripts/verify_environment.sh)
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


# ---------------------------------------------------------------------------
# eBPF program (C), compiled and loaded into the kernel by BCC at runtime.
# Two probes:
#   1. tracepoint on sched_process_exec -> process execution events
#   2. kprobe/kretprobe on tcp_v4_connect -> outbound IPv4 connect attempts
# ---------------------------------------------------------------------------
BPF_PROGRAM = r"""
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16
#define ARGSIZE 128

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};
BPF_PERF_OUTPUT(exec_events);

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
};
BPF_PERF_OUTPUT(connect_events);

// Map to stash the sock* between kprobe entry and kretprobe return
BPF_HASH(currsock, u32, struct sock *);

// --- process exec ---
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // args->filename is a pointer into the tracepoint's data; copy safely
    void *filename_ptr = (void *)args->__data_loc_filename + (args->__data_loc_filename >> 16);
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), filename_ptr);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// --- tcp connect: entry, stash sock pointer keyed by pid ---
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

// --- tcp connect: return, emit event if entry was recorded and call succeeded ---
int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0; // missed entry
    }
    if (ret != 0) {
        currsock.delete(&pid);
        return 0; // failed connect, skip
    }

    struct sock *skp = *skpp;
    u32 daddr = 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    struct connect_event_t event = {};
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.daddr = daddr;
    event.dport = ntohs(dport);

    connect_events.perf_submit(ctx, &event, sizeof(event));
    currsock.delete(&pid);
    return 0;
}
"""


def handle_exec_event(cpu, data, size):
    event = b["exec_events"].event(data)
    out = {
        "event_type": "process_exec",
        "timestamp": time.time(),
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode("utf-8", "replace"),
        "filename": event.filename.decode("utf-8", "replace"),
    }
    print(json.dumps(out), flush=True)


def handle_connect_event(cpu, data, size):
    event = b["connect_events"].event(data)
    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
    out = {
        "event_type": "tcp_connect",
        "timestamp": time.time(),
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode("utf-8", "replace"),
        "dest_ip": daddr,
        "dest_port": event.dport,
    }
    print(json.dumps(out), flush=True)


def main():
    global b
    print(
        json.dumps(
            {"event_type": "probe_startup", "message": "loading BPF program..."}
        ),
        file=sys.stderr,
    )
    b = BPF(text=BPF_PROGRAM)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

    b["exec_events"].open_perf_buffer(handle_exec_event)
    b["connect_events"].open_perf_buffer(handle_connect_event)

    print(
        json.dumps(
            {
                "event_type": "probe_startup",
                "message": "probes attached, polling for events. Ctrl+C to stop.",
            }
        ),
        file=sys.stderr,
    )

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print(
                json.dumps({"event_type": "probe_shutdown"}),
                file=sys.stderr,
            )
            sys.exit(0)


if __name__ == "__main__":
    main()
