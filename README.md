# Linux XAI Security Assistant

> Explainable, read-only Linux security telemetry and detection for Kali Linux.
> Built for the C-DAC Hackathon.

Linux XAI Security Assistant observes host activity, normalizes it into one
canonical event model, persists evidence in SQLite, and produces transparent
security findings. It helps analysts understand *what was observed*, *why it
was flagged*, and *what evidence supports that conclusion*.

## What the problem asks for

The project brief:

> Design an AI-powered monitoring system that learns normal system behavior to
> detect security threats and system failures in real time. The solution should
> explain why anomalies are detected and automatically recommend or perform
> corrective actions.

Each clause maps to code, and the honest gaps are marked rather than hidden:

| Requirement clause | Where it lives | Status |
|---|---|---|
| Learn normal system behavior | `baseline/` behavioral baseline (ML present but inactive) | Implemented |
| Detect security threats in real time | `detection/` fusion over streaming collectors (6 of 7 sources stream) | Implemented |
| Detect system failures in real time | `detection/system_failure.py` windowed scoring of `system_health`/`service_state` | **Implemented** (detection only) |
| Explain why anomalies are detected | `explainability/` evidence + advisory `assistant/` | Implemented |
| Recommend or perform corrective actions | `assistant/` advises and `policy/` emits fail-closed dry-run decisions | **Recommend only** — performing actions is deliberately not built |

The remaining gap is a documented position, not an oversight. Performing
corrective actions is intentionally out of scope: it would conflict with the
safety principles below — observation-only collectors, an advisory assistant,
and fail-closed dry-run policy. System-failure detection holds the same line: it
surfaces findings for a human operator and performs no restart, kill, freeze, or
throttle. [AGENTS.md](AGENTS.md) carries the full clause-by-clause traceability.

## Submission snapshot

| Area | Current state |
|---|---|
| Telemetry | All planned families are **LIVE VERIFIED** on Kali Linux 2026.3 / kernel `7.1.5+kali` |
| Detection | Deterministic baseline, rules, context, and fusion are implemented |
| System-failure detection | Windowed, hysteresis-gated scoring of resource-exhaustion and service-failure telemetry; **detection only** — findings for an operator, no active response |
| Explainability | Persisted evidence reconstruction and analyst-facing explanations are implemented |
| Assistant | Optional, provider-neutral, evidence-grounded narration; never a decision-maker |
| Policy | Fail-closed, dry-run, advisory-only; no remediation executor exists |
| ML | Implemented and tested, but the current Isolation Forest is **inactive** and not approved for activation |
| Dashboard | Read-only, **authenticated** FastAPI API and browser dashboard over persisted SQLite data |
| Operational readiness (Phase B) | Supervised multi-collector ingestion, authenticated API, self-bounding retention, metrics/alerts, and systemd deployment; the test suite gates CI |
| Detection credibility (Phase C) | Published precision/recall on a seeded corpus, versioned MITRE-mapped rules with per-rule tests, and a tamper-evident append-only evidence hash-chain |

### LIVE VERIFIED telemetry

- Process execution and post-exec context — BCC/eBPF.
- File access — controlled live validation.
- Network activity — `sock:inet_sock_set_state`; controlled client PID `32379`
  was captured connecting as `python3` to `127.0.0.1:18080`.
- Authentication/session — structured journald PAM records; controlled sudo
  session captured PID `37934`, UID `1000`, including open/close events.
- System/service lifecycle — structured journald/systemd lifecycle records;
  `systemd-timedated.service` was captured starting successfully.
- IPC / pipes / streams — BCC `pipe`/`pipe2` kprobe; controlled PID `40231`
  captured `read_fd=3`, `write_fd=4`, endpoint `fd:3->fd:4`.

## Architecture

```text
Linux telemetry collectors
        ↓ JSONL
Canonical Event normalization
        ↓
Bounded ingestion → SQLite persistence
        ↓
Baseline / deterministic rules / optional ML fusion
        ↓
Evidence and explainability → advisory assistant → fail-closed policy
        ↓
Read-only FastAPI API and dashboard
```

The canonical `Event` contract in `pipeline/event_stream.py` is the central
boundary. Collectors do not write directly to SQLite, and downstream modules
do not depend on a collector-specific event model.

## Safety principles

- Collectors are observation-only.
- The assistant is advisory only; it cannot execute commands or change scores.
- Policy is deterministic and fail-closed. Default approval-gated outcomes are
  dry-run decisions.
- The API is read-only, authenticated on by default, and fails closed: with
  authentication required but no token configured it returns `503` rather than
  serve the evidence feed unauthenticated. It binds loopback unless
  `ALLOW_NON_LOOPBACK_API=1` is set explicitly.
- No automatic termination, freezing, blocking, firewall changes, or account
  changes are implemented.
- ML failure falls back to deterministic detection; it cannot break the
  existing detection path.

## Operational readiness (Phase B)

Beyond the collectors and detection, the system is built to run unattended as
two systemd services — a supervised ingestion daemon and the read-only API:

- **Supervised multi-collector ingestion** (`pipeline/service.py`,
  `pipeline/supervisor.py`) — runs the collectors together, restarts a crashed
  one with exponential backoff, marks a genuinely broken one *degraded* rather
  than limping silently, and reports perf-ring loss separately from backpressure
  drops.
- **No silent evidence loss** — a bounded queue counts drops, and a batch a
  failed DB write would otherwise lose is quarantined to disk at `0600` for
  replay (`pipeline/quarantine.py`). A collector-kill soak
  (`scripts/soak_chaos.py`) demonstrates 20 kills → 20 auto-recoveries → zero
  lost events.
- **Authenticated API** (`api/auth.py`) — bearer token, on by default and
  fail-closed, constant-time comparison over every configured token, loopback by
  default. Only liveness and a static health summary are open.
- **Self-bounding storage** (`storage/retention.py`) — age and byte-cap pruning
  plus a periodic `VACUUM`, in-process, so the monitor cannot fill its own disk.
  The evidence database is created and enforced at mode `0600`.
- **Observability** (`observability/`) — a Prometheus-style `/metrics` endpoint,
  disk/queue/collector-silence alerts logged on transition, and layered
  `defaults < config-file < environment` configuration that fails closed on an
  unknown key or unparseable value.
- **CI** (`.github/workflows/ci.yml`) — the test suite is the hard merge gate.

Deployment, the threat model, and measured throughput/latency plus the soak
result are documented in [deploy/README.md](deploy/README.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and
[docs/PHASE_B_RESULTS.md](docs/PHASE_B_RESULTS.md).

## Detection credibility (Phase C)

Detection quality is held to the same standard the ML gate already sets —
measured, versioned, and tamper-evident rather than asserted:

- **Published precision/recall** — the deterministic detector is measured
  against a committed, seeded, labeled corpus of synthesized canonical `Event`s
  (`simulation/corpus.py`, read-only simulation — nothing is executed on the
  host). `docs/DETECTION_EFFICACY.md` is generated from that run and verified in
  sync: precision 0.7143, recall 1.0000, F1 0.8333, ~11.5 projected false
  positives/day, over 55 windows.
- **Versioned, MITRE-mapped rules** — the four rules are externalized to
  `detection/rules_catalog.yaml`; nothing about a rule is hardcoded. Each carries
  a `version`, an ATT&CK tactic/technique, and a written mapping rationale, and
  is independently tested.
- **Fusion weights justified, not asserted** — the measured separation gap
  (0.5079 between the highest benign and the lowest attack score) justifies
  keeping the `0.50/0.35/0.15` weights and `0.80/0.60/0.35` bands unchanged.
- **Correlation & suppression** — related findings receive a deterministic
  `correlation_id`; suppression is an explicit disposition
  (`suppressed`/`suppression_reason`), never a silent drop and never a score
  input.
- **Tamper-evident evidence** — `detection_findings` and `policy_decisions` are
  an append-only hash chain (migration 8);
  `verify_findings_chain()`/`verify_policy_chain()` detect any mutation,
  reordering, or deletion.
- **Verified-normal corpus program** — a documented, operator-attested path to
  the ≥ 60-window ML gate (`docs/NORMAL_CORPUS_PROGRAM.md`), reusing the fixed
  gate unchanged rather than moving it.

The full roll-up, chain/migration verifications, and reproduction commands are
in [docs/PHASE_C_RESULTS.md](docs/PHASE_C_RESULTS.md) and the generated
[docs/DETECTION_EFFICACY.md](docs/DETECTION_EFFICACY.md).

## System-failure detection

The system-failure requirement is met on the same read-only terms as the rest of
the pipeline: failures are **detected and surfaced, never acted on**.
`detection/system_failure.py` scores the `system_health` and `service_state`
telemetry the collectors already emit and writes findings through the existing
`detection_findings` store — no new schema, no new migration.

- **What it flags** — memory exhaustion (a high band and a lower medium band), an
  available-memory floor, sustained CPU saturation, and a near-full disk, plus
  service failures, with repeated failures of one unit inside a lookback labelled
  a crash loop rather than a string of unrelated failures.
- **Fixed windows with hysteresis** — scoring runs over epoch-aligned 300s
  windows. A condition must breach for `failure_consecutive_windows` windows
  before a finding is emitted, and fall below a distinct lower clear threshold for
  `failure_clear_windows` windows before it resolves; the dead-band between the
  two stops a value hovering at the line from flapping. The hysteresis is
  window-idempotent, so the many ingestion batches that make up one window advance
  the counters exactly once.
- **Missing telemetry is unknown, never healthy** — a null CPU, disk, or memory
  reading is scored as neither a failure nor healthy, and a window with no health
  or service events produces no finding.
- **Detection-only by construction** — failure findings carry
  `mode="system_failure"` with the failure magnitude in `risk_score` and zero
  behaviour/rule/context scores. They are persisted for the operator but are
  deliberately **not** routed through the assistant or policy: policy is the
  response-proposal stage, and that is the boundary this feature does not cross.
  No ATT&CK technique is asserted — the category is availability, and the
  T1489/T1499 relationship is recorded only as an interpretation note.

All thresholds and the window/hysteresis counts are configurable (`failure_*` in
[deploy/config.example.yaml](deploy/config.example.yaml), `SECURITY_FAILURE_*` in
the environment) and validated fail-closed on load.

## Quick start: run the project

The application has two runtime pieces: a privileged collector/ingestion
process and a separate read-only dashboard/API process. This is intentional:
kernel probes require privileges, while the dashboard does not.

### 1. Prerequisites

Target platform: Kali Linux (rolling), x86_64. Install the system telemetry
dependencies once:

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc libbpfcc-dev \
  python3-psutil python3-fastapi python3-uvicorn python3-yaml auditd audispd-plugins
```

Check the environment:

```bash
cd ~/linux-xai-security-assistant
bash scripts/verify_environment.sh
```

Optional ML/test environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` covers the Python API, policy, ML, and test dependencies.
The BCC binding is deliberately installed through Kali packages, not pip: it
must match the installed `libbcc` and running kernel. Run privileged BCC
collectors with the system `python3` after installing `python3-bpfcc`.

### 2. Start live ingestion

In terminal 1, start the verified BCC process collector and bounded SQLite
ingestion. This writes to a local demo database named `security_demo.db`.

```bash
cd ~/linux-xai-security-assistant
sudo env PYTHONPATH=. python3 -m pipeline.live_ingestion \
  --db "$PWD/security_demo.db" -- \
  python3 telemetry/bcc/telemetry_basic.py
```

Generate harmless activity in a second terminal, for example:

```bash
ls /tmp
whoami
python3 -c 'print("Linux XAI Security Assistant demo")'
```

Press `Ctrl+C` in terminal 1 when you have collected enough events. The
ingestion service records collector health, processed/malformed/dropped counts,
and persists canonical events in SQLite.

> The command above is the single-collector demo path — the simplest way to see
> one family end to end. A supervised multi-collector service now exists
> (`pipeline/service.py`, driven by `pipeline/supervisor.py`): it runs the
> collectors together, restarts a crashed one with exponential backoff, marks a
> genuinely broken one *degraded*, and quarantines any batch a failed DB write
> would otherwise lose. See [deploy/README.md](deploy/README.md) for running it
> under systemd.

### 3. Start the read-only dashboard

The API authenticates by default and fails closed: with authentication required
but no token configured it answers `503` rather than serve the evidence feed
unauthenticated. For the local demo, mint a token and pass it in. In terminal 2:

```bash
cd ~/linux-xai-security-assistant
export SECURITY_API_TOKENS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "Dashboard token: $SECURITY_API_TOKENS"
SECURITY_DB_PATH="$PWD/security_demo.db" PYTHONPATH=. python3 -m api
```

Open <http://127.0.0.1:8000/dashboard/>. The dashboard stores no telemetry of
its own, so on first load it prompts for the token (kept in `sessionStorage`) —
paste the value printed above. Only liveness (`/api/health/live`) and the static
health summary (`/api/health`) are served without a token.

For a throwaway, loopback-only look you can instead set
`SECURITY_API_REQUIRE_AUTH=false`; the API logs a warning and the dashboard
stops prompting. Never do this for anything reachable off loopback.

The dashboard reports two different things:

- **Telemetry verified** means the collector family has passed controlled live
  validation on the target Kali environment.
- **Collector stopped** or **Data stale** means the selected SQLite database is
  not receiving events right now. It does not revoke the collector's verified
  capability.

### 4. Inspect the API

Two endpoints are open (no token) — a liveness probe and a static health
summary that disclose only that the process is up:

```text
GET /api/health/live
GET /api/health
```

Everything else requires the token, sent as `Authorization: Bearer <token>` or
`X-API-Key: <token>`:

```bash
curl -fsS -H "Authorization: Bearer $SECURITY_API_TOKENS" \
  http://127.0.0.1:8000/api/status
```

```text
GET /api/health/ready        # 200 ready / 503 not-ready (DB present, mode 0600, telemetry fresh)
GET /metrics                 # Prometheus-style counters and coverage windows
GET /api/status
GET /api/telemetry/status
GET /api/alerts
GET /api/sources
GET /api/maintenance
GET /api/events?limit=100
GET /api/detections
GET /api/detections/{id}
GET /api/explanations/{id}
GET /api/assistant/{id}
GET /api/policies
GET /api/policy-decisions
```

## Running individual verified collectors

Live BCC probes must be run from an interactive privileged Kali terminal.
Each collector emits JSONL that can be sent through the same canonical
normalizer and SQLite ingestion boundary.

| Telemetry | Collector | Mode |
|---|---|---|
| Process execution / health | `telemetry/bcc/telemetry_basic.py` | streaming (kernel) |
| Post-exec context | `telemetry/bcc/process_context.py` | streaming (kernel) |
| Network | `telemetry/bcc/network_state_probe.py` | streaming (kernel) |
| File access | `telemetry/auditd/file_access_monitor.py` | one-shot query |
| Authentication/session | `telemetry/journald/auth_session_monitor.py` | streaming (journal cursor) |
| Service lifecycle | `telemetry/journald/service_monitor.py` | streaming (journal cursor) |
| IPC pipe creation | `telemetry/bcc/ipc_pipe_probe.py` | streaming (kernel) |

For example, use a collector with the ingestion service:

```bash
sudo env PYTHONPATH=. python3 -m pipeline.live_ingestion \
  --db "$PWD/security_demo.db" -- \
  python3 telemetry/bcc/network_state_probe.py
```

Do not reintroduce `ntohs()` in the network collector: this Kali tracepoint
exports `dport` in host byte order. Do not revert the IPC probe's x86_64 ABI
fix: the `pipefd` user pointer comes from `regs->di` in the syscall wrapper.

The remaining files in `telemetry/bcc/` — `telemetry_simple.py`,
`telemetry_collector.py`, `process_exec_probe.py`, and
`network_connect_probe.py` — are superseded proofs of concept, marked
`DEPRECATED / LEGACY` in their module docstrings. They are kept for historical
reference only: they are not wired to ingestion, not covered by the regression
suite, and not perf-buffer-loss reported. Use the collectors in the table above.

### Streaming journald collectors

Both journald collectors follow the journal continuously and persist a journal
cursor, so a restart resumes where the previous run stopped instead of
re-reading a fixed window or silently skipping the gap.

```bash
sudo env PYTHONPATH=. python3 -m pipeline.live_ingestion \
  --db "$PWD/security_demo.db" -- \
  python3 telemetry/journald/auth_session_monitor.py
```

| Flag / variable | Default | Purpose |
|---|---|---|
| `--follow` / `--no-follow` | `--follow` | Stream continuously, or read one window and exit. |
| `--since` | `10 minutes ago` | Start window when no usable cursor exists. |
| `--cursor-file` | `state/journald-<name>.cursor` | Where the resume position is stored. |
| `--checkpoint-interval` | `2.0` seconds | Coalescing window for cursor writes. |
| `SECURITY_STATE_DIR` | `<repo>/state` | Base directory for cursor files. |

Operational properties that matter when reading the output:

- **At-least-once, biased to re-read.** The cursor is persisted only after the
  event it covers has been written and flushed, so a crash re-reads a small
  overlap rather than dropping events. The re-read is safe because the store
  inserts on a content hash that excludes the per-run fields (`boot_id`,
  `agent_id`, monotonic time), so a replayed record collapses onto its existing
  row instead of duplicating it.
- **The cursor advances over records the collector ignores**, so a quiet period
  cannot turn a restart into hours of re-reading.
- **A cursor that cannot be resumed from is reported, never silently replaced.**
  If the stored position no longer exists in the journal — rotation, vacuum, or a
  rebuilt journal — the collector emits a `telemetry_warning` event carrying
  `stale_cursor`, `reason`, and `recovery="since_window"`, then falls back to
  `--since`. That warning is a stored row, so the gap is visible in the API and
  dashboard rather than only in a log.
- **Clean shutdown is checkpointed.** `SIGTERM`/`SIGINT` handlers stop the stream
  and force a final cursor write, well inside the supervisor's five-second grace
  period before `SIGKILL`.
- `state/` is git-ignored; cursor files are local runtime state, not artifacts.
- `read_journal()` remains in both modules for scripted one-shot use. It is not
  the supervised path and cannot resume; `tests/test_journal_stream.py` pins that
  it derives the same events as the streaming path so the two cannot drift.

## ML status and activation gate

The ML subsystem uses the deterministic `canonical-window.v1` schema with
explicit verified-normal provenance, reproducible Isolation Forest training,
artifact checksums, schema checks, feature-range diagnostics, and held-out
evaluation.

The current experiment, `iforest-6ef9e765-8bc8-4bfc-b8d5-e1ebd18730e7`, is
**inactive**. Its historical evaluation produced 2 false positives from 5
normal holdouts (40% FPR), which fails the fixed 5% requirement.

A future model may be considered for activation only after independent,
operator-reviewed normal holdouts satisfy all of the following:

- observed FPR ≤ 5%;
- one-sided 95% FPR upper bound ≤ 5%; and
- at least 60 independent holdout windows.

No threshold changes, activation, or baseline contamination are allowed merely
to make a model pass.

## Tests

Run the whole suite from the repository root. `pyproject.toml` sets
`pythonpath = ["."]`, so no `PYTHONPATH` prefix is needed:

```bash
pytest -q
```

To run a focused subset:

```bash
pytest -q tests/test_journal_stream.py tests/test_ml_integration.py
```

Measured on Python 3.14.6 with pytest 9.1.1:

- Full suite: **507 passed, 4 skipped** (~22s)
- The 4 skips are `tests/test_ml_integration.py`, which requires scikit-learn
- Streaming journald: 92 passed, including two integration tests that exercise
  the real `journalctl` cursor semantics on systemd 261
- Phase B added coverage for the supervised service, quarantine, retention,
  layered config, metrics, alerts, and API authentication (`tests/test_service.py`,
  `test_supervisor.py`, `test_quarantine.py`, `test_retention.py`,
  `test_config.py`, `test_metrics.py`, `test_alerts.py`, `test_api_auth.py`)
- Phase C added coverage for the efficacy harness and contamination guard,
  per-rule matching, rule-catalog integrity, the append-only evidence hash-chain
  (continuity, tamper detection, dedup-adds-no-link, suppressed-still-chained),
  and migration-8 additive/idempotent schema (`tests/test_efficacy.py`,
  `test_rules.py`, `test_rule_catalog.py`, `test_evidence_chain.py`,
  `test_schema_migrations.py`)
- System-failure detection added coverage for empty/unknown/partial telemetry,
  hysteresis breach and reset, window idempotency across batches, the flap
  dead-band, memory bands and the available-memory floor, CPU and disk breaches,
  single/collapsed/crash-loop service failures, the persisted detection-only
  finding shape, config validation, and pipeline integration
  (`tests/test_system_failure.py`)

Re-measure before restating those numbers. Tests are never weakened, skipped, or
removed to make a run look clean.

## Project layout

| Directory | Responsibility |
|---|---|
| `telemetry/` | BCC, journald, auditd, and health collectors |
| `pipeline/` | Canonical Event model, normalization, bounded ingestion, and the supervised multi-collector service with write-failure quarantine |
| `storage/` | SQLite persistence (mode `0600` enforced), ML provenance, and age/byte-cap retention |
| `baseline/` | Explicit verified-normal behavioral baseline |
| `detection/` | Deterministic rules, evidence fusion, and detection-only system-failure scoring |
| `ml/` | Canonical window schema, training, scoring, evaluation |
| `explainability/` | Evidence reconstruction and bounded explanations |
| `assistant/` | Optional provider-neutral advisory narration |
| `policy/` | Deterministic fail-closed dry-run policy |
| `observability/` | Layered config, Prometheus-style metrics, and disk/queue/silence alerting |
| `api/`, `dashboard/` | Read-only, authenticated analyst API and interface |
| `deploy/` | systemd units, example config, and the deployment guide |
| `scripts/` | Environment check, ingestion benchmark, and collector-kill soak harness |
| `tests/` | Focused unit and integration regression tests |
| `requirements.txt` | Python dependencies for API, policy, ML, and tests |

## Data handling

Raw telemetry databases, normal-data captures, Python environments, cache
files, and model binaries are excluded through `.gitignore`. They may contain
host-sensitive data and must not be treated as verified-normal training data
without explicit provenance and operator approval.

## Further reading

- [AGENTS.md](AGENTS.md) — authoritative handoff, exact validation evidence,
  architectural constraints, and current ML safety gate.
- [deploy/README.md](deploy/README.md) — deploying the two systemd services,
  capability tuning, and verification.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — STRIDE-shaped threat model for
  the telemetry, storage, and API surface hardened in Phase B.
- [docs/PHASE_B_RESULTS.md](docs/PHASE_B_RESULTS.md) — measured ingestion
  throughput/latency and the collector-kill (no-data-loss) soak result.
- [docs/PHASE_C_RESULTS.md](docs/PHASE_C_RESULTS.md) — published detection
  efficacy, versioned MITRE-mapped rules, the tamper-evident evidence chain, and
  the verified-normal corpus path.
- [docs/DETECTION_EFFICACY.md](docs/DETECTION_EFFICACY.md) — generated
  precision/recall/FP-per-day and the seeded corpus manifest.
- [docs/NORMAL_CORPUS_PROGRAM.md](docs/NORMAL_CORPUS_PROGRAM.md) — the
  verified-normal capture/review program and the (unchanged) ML activation gate.
- `docs/PHASE*_RESULTS.md` — historical phase evidence. Their older telemetry
  limitations are clearly marked as superseded; AGENTS.md is authoritative.
- `docs/phase1_sample_events.jsonl` — synthetic fixture only, never live
  telemetry or normal-training data.

## License

Released under the [MIT License](LICENSE).
