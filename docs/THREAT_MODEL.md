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
- **Metrics as reconnaissance.** `/metrics` discloses event volumes and collector names, so it is behind the same auth gate as `/api/*` (including `/api/health/ready`, which queries the store). The gate is **default-deny**: the middleware refuses every path that is not explicitly opened, rather than gating a list of known-sensitive prefixes. That distinction is load-bearing — it was previously a prefix allowlist, which left FastAPI's own `/openapi.json`, `/docs`, `/redoc`, and `/docs/oauth2-redirect` unauthenticated. The schema names every route, parameter, and response field of the evidence feed, so it was the reconnaissance document this control exists to withhold; it is now gated and reachable only with a token. The open set is exactly four things, and `tests/test_api_auth.py` asserts set equality over the live route table so a route opened later fails the build:
  - `/api/health/live` and `/api/health` — static, DB-free, disclosing nothing but "the process is up", and reachable by a process manager before a credential exists.
  - `/` — a redirect to the dashboard, carrying no telemetry, so an operator landing on the host reaches the page where they enter their token instead of a 401 with nowhere to go.
  - `/dashboard/*` — markup and JavaScript with no telemetry in them; the data they render comes from the gated `/api/*`.

### Tampering — forging or altering the record
- **Read-only by construction.** The API process runs with no capabilities and performs no `INSERT`s; the systemd unit gives it a strict sandbox (`ProtectSystem=strict`, no `AF_*` beyond what it serves on, `MemoryDenyWriteExecute=yes`). There is no API path that writes an event.
- **Least privilege for collectors.** Collectors get capabilities via *ambient* capabilities from the ingestion unit — not root — and `NoNewPrivileges=yes` blocks setuid escalation. The shipped set is deliberately broader than "least privilege" literally implies, so it attaches out of the box across kernels: `CAP_BPF` and `CAP_PERFMON` (sufficient alone on kernels ≥ 5.8), plus `CAP_SYS_ADMIN` as the kernel-dependent fallback older kernels and some BCC operations still require, plus `CAP_SYS_PTRACE` for process introspection and `CAP_SYS_RESOURCE` for the locked-memory limit BPF maps are charged against. The last two are the widest part of the grant and the first candidates to drop. Trimming the set to what the target kernel actually accepts is the single highest-value hardening step for a deployment and is documented as such in `deploy/README.md`; until an operator does it, treat the grant as `CAP_SYS_ADMIN`-equivalent rather than as a minimal one.

### Spoofing — unauthenticated access
- Authentication is **on by default and fails closed**: with auth required but no token configured, the API returns `503`, never an open evidence feed. Tokens are compared with `secrets.compare_digest` over *every* configured token (no short-circuit on first match), so response timing does not reveal which token matched or how many exist. Tokens shorter than 16 chars are refused so a placeholder cannot be the control.

### Denial of service / evidence loss
- **Bounded queue with accounting.** Ingestion uses a bounded queue with backpressure; drops are counted and surfaced, and kernel perf-ring loss is reported separately from backpressure drops (different cause, different fix).
- **Supervision.** A crashed collector is restarted with exponential backoff; a genuinely broken one is marked *degraded* and the service exits non-zero so the process manager re-runs the set rather than limping silently. Verified by `scripts/soak_chaos.py`: 20 injected `SIGKILL`s, 20 recoveries, zero lost events.
- **Write-failure quarantine.** A batch a failed DB write would lose is written to disk (self-describing, `0600`, size-capped) for replay, so a transient disk error does not discard events.
- **Self-bounding storage.** Retention prunes by age and by a byte cap and VACUUMs on a timer, so the monitor cannot fill the disk it runs on. A full disk raises a critical alert before it becomes total.
- **API request-rate DoS: not implemented in-process; delegated to the reverse proxy, with per-request cost bounded here.** There is **no rate limiting, connection cap, or concurrency limit in this codebase** — no middleware, no `429` path. Request rate is the reverse proxy's job, the same component that terminates TLS (`deploy/README.md`); the API binds `127.0.0.1` by default and the packaged entry point refuses a non-loopback bind without authentication, so in the shipped posture there is no path from an untrusted network to the app that does not cross that proxy. What is handled in-process is the other half of the problem — *amplification*, the work one request can buy — and it is handled three ways. Default-deny auth means an unauthenticated flood reaches only the four things in the open set above, and every one of them costs a fixed amount regardless of how long the host has been running: `/` is a redirect, `/api/health` is a literal, `/api/health/live` is built from a fresh empty snapshot, and `/dashboard/*` is 48 KB of markup, CSS, and JavaScript served off disk. **None of the four opens a database connection.** Every other path — including `/metrics` and `/api/health/ready`, the two that do query the store — is refused in middleware before a route function runs, a body is parsed, or a query is issued. Every route over a table that grows on its own is paged (`le=500`, and `MAX_TRIAGE_EXPORT_LIMIT` on the export), so no single request can ask for a response whose size is a function of uptime. And the three remaining whole-table reads — `read_latest_triage_state()`, `read_triage_annotations(finding_id=…)`, `read_ml_models()` — are over tables that grow at analyst or retrain rate, not telemetry rate.
- **The expensive route is `/api/integrity`, and its cost is accepted.** It re-folds all four hash chains from genesis on every call, which `docs/SCALE_RESULTS.md` measures as strictly linear at ~56 µs/row (findings), ~34 (policy), ~23 (triage): about **1.1 s of single-threaded work per request at 10,000 findings**, and growing without bound, because retention deliberately exempts the chains. Paging cannot help — a partial verification is not a verification. So an *authenticated* client can amplify a single request into seconds of CPU and I/O, and nothing in-process stops it. That is accepted rather than mitigated: the route is behind default-deny auth, a token-holder is already trusted to read the whole evidence record, and the honest fix is caching a verified prefix (which does not exist yet) rather than a rate limiter bolted on in front of it. An operator exposing this API to anything wider than a trusted reader set should rate-limit `/api/integrity` specifically at the proxy.

### Repudiation / observability
- Alert transitions (not every interval) are logged at a severity that maps to the log level, so a journald paging rule keyed on level works. Liveness stays true through a collector outage precisely so the one component that can still *report* the outage is not the one restarted away.

### Configuration as an attack surface
- Config **fails closed**: an unknown key or an unparseable value is a startup error, not a silent fallback to a default that might, e.g., disable auth or keep events forever. File modes must be quoted so YAML cannot reinterpret `0600` as a different number.

## Residual risks (accepted)

- **Root/kernel compromise of the monitored host** — out of scope, as above.
- **No transport encryption in-process.** The API binds loopback; TLS is expected to be terminated by a reverse proxy. The packaged entry point (`api/__main__.py`, which the systemd unit runs) refuses a non-loopback bind unless `ALLOW_NON_LOOPBACK_API=1` is set, and refuses a non-loopback bind without authentication regardless. Both are startup checks in that entry point rather than properties of the ASGI app, so an operator who runs `uvicorn api.app:app --host 0.0.0.0` by hand bypasses them — the guard is against accident, not against a determined operator.
- **No in-process request rate limiting.** Covered above under denial of service: rate is the reverse proxy's responsibility, amplification is bounded in-process by default-deny auth and paged reads, and `/api/integrity`'s unbounded linear cost is an accepted residual for an authenticated caller. A deployment that puts this API in front of a wider audience than a trusted reader set needs a proxy-side limit, and `/api/integrity` is the route to limit first.
- **On-host storage only.** Evidence lives on the host it describes; an attacker with sufficient local privilege and time could delete history within the retention window. Off-host/append-only shipping is future work.
- **Partial type coverage in CI.** `ruff` and `mypy` are now required merge gates (they were advisory until the pre-existing tree had been baselined to zero findings). `mypy` is invoked on the Phase B modules listed in the workflow rather than the whole tree, and is configured leniently (`ignore_missing_imports`, `warn_unused_ignores = false`), so type errors outside what those modules reach are not caught. The reach is wider than the list — mypy follows imports, so `storage/sqlite_store.py` and the `ml/` modules it imports are checked too — but it is still reach-based rather than deliberate, which means a module no listed file imports has no type coverage at all. Widening the scope explicitly is tracked.
