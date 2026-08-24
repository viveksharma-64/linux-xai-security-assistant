#\!/usr/bin/env python3
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
    from bcc import BPF
except ImportError:
    sys.stderr.write("ERROR: bcc not installed\n")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

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
BPF_PERF_OUTPUT(exec_events);

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
    exec_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

try:
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
    sys.exit(1)

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

b["exec_events"].open_perf_buffer(handle_exec_event)

health_count = 0
try:
    while True:
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
            except:
                pass
except KeyboardInterrupt:
    print(json.dumps({"event_type": "telemetry_shutdown", "timestamp": time.time()}), file=sys.stderr)
    sys.exit(0)
