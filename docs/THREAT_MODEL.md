# Threat Model — Linux XAI Security Assistant

Scope: the read-only telemetry, storage, and API components hardened in Phase B —
the eBPF collectors, the supervised ingestion service, the SQLite evidence store,
and the authenticated API/dashboard. It does not cover the ML/detection model
internals (data-poisoning of the learned baseline is tracked separately) or the
host's own kernel hardening.

This document follows the shape of a lightweight STRIDE pass: what we are
protecting, who might attack it, the trust boundaries they would cross, and the
controls that are actually implemented in this tree today. Where a risk is
accepted rather than mitigated, it says so.

## Assets

| Asset | Why it matters |
|-------|----------------|
| The evidence database (`events.db`) | Holds command lines, file paths, usernames, and network tuples — the record an investigation runs on. Its integrity and confidentiality are the product. |
| API tokens (`/etc/linux-xai-security/tokens`) | Bearer credentials for the whole evidence feed and metrics. |
| Collector → store event stream | Loss or forgery here means the record has silent gaps or planted entries. |
| Availability of ingestion | A dead collector that no one notices is an undetected blind spot during an incident. |

## Trust boundaries

1. **Kernel → collector.** eBPF programs read kernel structures; the collector process is userspace.
2. **Collector → ingestion service.** Separate processes; events cross as JSONL over a pipe.
3. **Ingestion service → database.** A file on disk, shared with the API process.
4. **API → operator/network.** The only component that faces a human or the network.
5. **Operator config (`/etc`) → all processes.** Configuration is an input that changes security behaviour.

## Adversaries

- **Local unprivileged user** on the monitored host — the primary concern. Wants to read the audit trail (what has been observed about them) or blind it.
- **Network client** reachable to the API port.
- **A compromised or crashing collector** — not malicious per se, but its failure must not cost evidence.
- Out of scope: an attacker who already has root/kernel control. Once the TCB is owned, the monitor running on the same host cannot be trusted to report on it; this is an accepted, documented limit, and the reason the design keeps the evidence store read-only and points toward off-host shipping as future work.

## Threats and controls

### Information disclosure — reading the evidence trail
- **Database confidentiality.** The store is created and *enforced* at mode `0600`; opening a database with looser permissions is refused (`db_enforce_mode`), and readiness reports the instance not-ready if the file becomes group/other-readable. Quarantined batches are written with the same `0600`, so the fallback path cannot become a way around the database's mode.
- **Token confidentiality.** Tokens are preferably supplied via a `0600` file rather than an environment variable (an env var is visible in `systemctl show` and `/proc/<pid>/environ`); the API refuses to start if the token file is group/world-readable.
- **Metrics as reconnaissance.** `/metrics` discloses event volumes and collector names, so it is behind the same auth gate as `/api/*` (including `/api/health/ready`, which queries the store). Only the static, DB-free liveness and health-summary endpoints (`/api/health/live`, `/api/health`) are open, and they disclose nothing but "the process is up".

### Tampering — forging or altering the record
- **Read-only by construction.** The API process runs with no capabilities and performs no `INSERT`s; the systemd unit gives it a strict sandbox (`ProtectSystem=strict`, no `AF_*` beyond what it serves on, `MemoryDenyWriteExecute=yes`). There is no API path that writes an event.
- **Least privilege for collectors.** Collectors get only `CAP_BPF`/`CAP_PERFMON` (with `CAP_SYS_ADMIN` as the kernel-dependent fallback) via *ambient* capabilities from the ingestion unit — not root, and `NoNewPrivileges=yes` blocks setuid escalation.

### Spoofing — unauthenticated access
- Authentication is **on by default and fails closed**: with auth required but no token configured, the API returns `503`, never an open evidence feed. Tokens are compared with `secrets.compare_digest` over *every* configured token (no short-circuit on first match), so response timing does not reveal which token matched or how many exist. Tokens shorter than 16 chars are refused so a placeholder cannot be the control.

### Denial of service / evidence loss
- **Bounded queue with accounting.** Ingestion uses a bounded queue with backpressure; drops are counted and surfaced, and kernel perf-ring loss is reported separately from backpressure drops (different cause, different fix).
- **Supervision.** A crashed collector is restarted with exponential backoff; a genuinely broken one is marked *degraded* and the service exits non-zero so the process manager re-runs the set rather than limping silently. Verified by `scripts/soak_chaos.py`: 20 injected `SIGKILL`s, 20 recoveries, zero lost events.
- **Write-failure quarantine.** A batch a failed DB write would lose is written to disk (self-describing, `0600`, size-capped) for replay, so a transient disk error does not discard events.
- **Self-bounding storage.** Retention prunes by age and by a byte cap and VACUUMs on a timer, so the monitor cannot fill the disk it runs on. A full disk raises a critical alert before it becomes total.

### Repudiation / observability
- Alert transitions (not every interval) are logged at a severity that maps to the log level, so a journald paging rule keyed on level works. Liveness stays true through a collector outage precisely so the one component that can still *report* the outage is not the one restarted away.

### Configuration as an attack surface
- Config **fails closed**: an unknown key or an unparseable value is a startup error, not a silent fallback to a default that might, e.g., disable auth or keep events forever. File modes must be quoted so YAML cannot reinterpret `0600` as a different number.

## Residual risks (accepted)

- **Root/kernel compromise of the monitored host** — out of scope, as above.
- **No transport encryption in-process.** The API binds loopback; TLS is expected to be terminated by a reverse proxy. Binding off-loopback is gated behind an explicit `ALLOW_NON_LOOPBACK_API=1`.
- **On-host storage only.** Evidence lives on the host it describes; an attacker with sufficient local privilege and time could delete history within the retention window. Off-host/append-only shipping is future work.
- **Advisory linting/typing in CI.** `ruff`/`mypy` run but do not gate merges yet (they could not be baselined on the offline build host); the test suite is the gate. Tracked to become required.
