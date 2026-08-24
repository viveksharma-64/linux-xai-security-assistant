# Health telemetry

`system_health` telemetry is implemented by the existing BCC process collector
using read-only `psutil` metrics and is normalized through the canonical Event
pipeline. This directory remains the boundary for future dedicated health
collectors, distinct from security-event telemetry in `../bcc/`.

> **Current project status:** All planned security telemetry families are LIVE VERIFIED. The planned signals below are future health-depth enhancements, not unverified security-telemetry claims. See [AGENTS.md](../../AGENTS.md).

Planned signals (no eBPF needed — these come from `/proc`, `psutil`, or
systemd/D-Bus):
- CPU utilization (overall + per-core, load average)
- Memory usage + swap pressure
- Disk I/O throughput and latency
- Disk space / inode exhaustion
- Process/service crash-loops (systemd unit failures)
- File descriptor / socket exhaustion

The additional signals are not yet implemented as dedicated collectors. Any
future implementation must remain read-only and use the existing canonical
Event → bounded ingestion → SQLite pipeline.
