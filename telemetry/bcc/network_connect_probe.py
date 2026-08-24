#!/usr/bin/env python3
"""Network-only BCC collector for successful IPv4 TCP connections."""

import json
import socket
import struct
import sys
import time

try:
    from bcc import BPF
except ImportError:
    sys.stderr.write("ERROR: bcc not installed\n")
    raise SystemExit(1)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u64 timestamp_ns;
};
BPF_PERF_OUTPUT(connect_events);
BPF_HASH(currsock, u32, struct sock *);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }
    if (ret != 0) {
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


def handle_connect_event(cpu, data, size):
    event = b["connect_events"].event(data)
    print(json.dumps({
        "event_type": "tcp_connect",
        "timestamp": time.time(),
        "timestamp_ns": event.timestamp_ns,
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode("utf-8", "replace").strip(),
        "dest_ip": socket.inet_ntoa(struct.pack("I", event.daddr)),
        "dest_port": event.dport,
        "source": "telemetry_bcc_network",
        "version": "1.0",
    }), flush=True)


def main():
    global b
    print(json.dumps({
        "event_type": "telemetry_startup",
        "message": "TCP IPv4 connect probe attached.",
        "timestamp": time.time(),
    }), file=sys.stderr)
    try:
        b = BPF(text=BPF_PROGRAM)
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
        b["connect_events"].open_perf_buffer(handle_connect_event)
    except Exception as error:
        print(json.dumps({
            "event_type": "telemetry_error",
            "message": f"Failed to load TCP probe: {error}",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 1

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(json.dumps({
            "event_type": "telemetry_shutdown",
            "message": "stopped by user",
            "timestamp": time.time(),
        }), file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
