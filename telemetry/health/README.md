# Health telemetry

`system_health_probe.py` is the dedicated collector for this event type. It
samples CPU, memory, and disk from `/proc` via read-only `psutil` and emits
JSONL on stdout, normalized through the canonical Event pipeline like every
other collector.

It needs **no capabilities** — no `CAP_BPF`, no `CAP_SYS_ADMIN`, no root — which
makes it the one supervised source that still reports on a kernel where BCC
cannot attach.

```bash
python3 telemetry/health/system_health_probe.py --interval 30
```

`deploy/systemd/linux-xai-ingest.service` supervises it as the `system_health`
source. `detection/system_failure.py` consumes what it emits.

## Why it is separate from `../bcc/`

The memory sampling in `../bcc/telemetry_basic.py` lives inside a `process_exec`
poll loop, and the two collectors that sampled health standalone
(`telemetry_collector.py`, `telemetry_simple.py`) are both marked
DEPRECATED/LEGACY and explicitly not for live telemetry. Supervising
`telemetry_basic.py` for its health samples would have run a second `process_exec`
collector alongside `process_exec_probe.py` and double-counted every exec into
the behaviour baseline. None of the three sampled disk at all, so the detector's
disk-exhaustion rules had no possible input.

One process, one event type, no overlap with the security collectors.

## Signal coverage

Implemented:
- CPU utilization (overall, as the mean over each sample interval)
- Memory usage and available memory
- Disk space for a configurable mount point (`--disk-path`, default `/`)

Not implemented (would come from `/proc`, `psutil`, or systemd/D-Bus; no eBPF
needed):
- Per-core CPU and load average
- Swap pressure
- Disk I/O throughput and latency
- Inode exhaustion
- File descriptor / socket exhaustion

Service crash-loops are covered, but by `../journald/service_monitor.py` via
`service_state` events rather than here.

Any future addition must remain read-only, publish an unreadable metric as
`null` rather than as a healthy zero, and use the existing canonical
Event → bounded ingestion → SQLite pipeline.
