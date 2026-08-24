#\!/usr/bin/env python3
"""
telemetry_simple.py - Ultra-simplified Phase 1 PoC

Uses only basic tracepoints, no complex kernel struct includes.
Captures: process execution, system calls, basic context.

Run: sudo python3 telemetry/bcc/telemetry_simple.py
Ctrl+C to stop
"""

import json
import sys
import time

try:
    from bcc import BPF
except ImportError:
    sys.stderr.write("ERROR: bcc not installed\n")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

# Minimal eBPF - only tracepoints, no complex includes
BPF_CODE = r"""
#include <uapi/linux/ptrace.h>

#define TASK_COMM_LEN 16
#define ARG_LEN 128

struct sched_event {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[ARG_LEN];
};
BPF_PERF_OUTPUT(sched_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct sched_event ev = {};
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev.gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    
    void *name_ptr = (void *)args->__data_loc_filename + (args->__data_loc_filename >> 16);
    bpf_probe_read_kernel_str(&ev.filename, sizeof(ev.filename), name_ptr);
    
    sched_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

b = BPF(text=BPF_CODE)

def handle_sched_event(cpu, data, size):
    ev = b["sched_events"].event(data)
    print(json.dumps({
        "event_type": "process_exec",
        "timestamp": time.time(),
        "pid": ev.pid,
        "uid": ev.uid,
        "gid": ev.gid,
        "comm": ev.comm.decode("utf-8", "replace"),
        "filename": ev.filename.decode("utf-8", "replace"),
    }), flush=True)

b["sched_events"].open_perf_buffer(handle_sched_event)

print(json.dumps({
    "event_type": "telemetry_startup",
    "message": "Simple probe ready. Ctrl+C to stop.",
    "timestamp": time.time()
}), file=sys.stderr)

health_count = 0
try:
    while True:
        b.perf_buffer_poll()
        health_count += 1
        if health_count >= 50 and psutil:
            try:
                print(json.dumps({
                    "event_type": "system_health",
                    "timestamp": time.time(),
                    "cpu_percent": psutil.cpu_percent(interval=0.01),
                    "mem_percent": psutil.virtual_memory().percent,
                }), flush=True)
                health_count = 0
            except:
                pass
except KeyboardInterrupt:
    print(json.dumps({"event_type": "telemetry_shutdown", "timestamp": time.time()}), file=sys.stderr)
    sys.exit(0)
