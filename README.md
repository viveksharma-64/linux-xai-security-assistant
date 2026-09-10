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
| ML | Implemented and tested, with a governed artifact/drift/lifecycle layer; the current Isolation Forest is **inactive** and not approved for activation |
| Dashboard | Read-only, **authenticated** FastAPI API and browser dashboard over persisted SQLite data |
| Operational readiness (Phase B) | Supervised multi-collector ingestion, authenticated API, self-bounding retention, metrics/alerts, and systemd deployment; the test suite gates CI |
| Detection credibility (Phase C) | Published precision/recall on a seeded corpus, versioned MITRE-mapped rules with per-rule tests, and a tamper-evident append-only evidence hash-chain |
| Analyst experience (Phase D) | Append-only, hash-chained triage (acknowledge/annotate/disposition/suppress) that never mutates the evidence record; authenticated default-deny writes; integrity alarm; faithful export; and operational efficacy from dispositions, decoupled from the ML gate |
| ML lifecycle (Phase E, track 1) | Code-free `iforest-native.v1` model artifact (no pickle), a stdlib KS/Holm drift check that refuses rather than guesses, and an append-only hash-chained model lifecycle log — with the activation gate untouched |

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

## Analyst experience (Phase D)

Phase D adds an analyst workflow — acknowledge, annotate, disposition, suppress —
on top of the immutable record without ever mutating it. The apparent conflict
with immutability is resolved by keeping triage in a **separate, append-only
annotation layer** that never touches a finding row or the finding/policy hash
chains.

- **Append-only triage layer** — triage writes land in `triage_annotations`
  (migration 9), itself an append-only hash chain
  (`verify_triage_chain()`). A correction is a new append event, never an edit;
  the latest annotation per finding wins for effective state. The immutable
  `detection_findings` rows and their chain are left byte-for-byte unchanged, so
  the READ-ONLY (evidence) guarantee survives. The console distinguishes
  *evidence: immutable and tamper-evident* from *triage: append-only
  annotations*.
- **Suppress is presentation-only** — `suppress`/`unsuppress` set an effective
  alerting state; they **never** delete a finding, hide it from a read, or drop
  it from the export. A suppressed finding stays in the record, is returned by
  the API, and is exported **included and marked** (`triage.effective_suppressed`).
- **Authenticated, default-deny writes** — the five triage actions are `POST`
  under `/api/triage/{id}/...` and require a token (401 without one). No triage
  route is destructive: there is no `PUT`/`DELETE`/`PATCH`. `actor` is a
  self-reported claim, labelled as such — the token proves the writer is
  authorized, not who they are.
- **Faithful export** — `GET /api/triage/export` emits a complete JSON document
  (`schema: linux-xai-security/triage-export/v1`) with every finding, its
  evidence, its full append-only annotation history, and the verdicts of the three
  hash chains that cover the exported record (findings, policy, triage). The
  ML-lifecycle chain is deliberately not folded in: it says nothing about the
  integrity of these findings, and adding it would silently change a released
  export schema. Suppressed findings are included and marked, never omitted.
- **Integrity alarm** — `GET /api/integrity` returns the `verify_chain` verdict
  for the findings, policy, triage, and ML-lifecycle chains. The console raises an
  unmissable banner **only** when a chain fails to verify, and stays silent when
  all four are intact, so it never cries wolf.
- **Operational efficacy, decoupled from the gate** — `GET
  /api/efficacy/operational` (`detection/operational_efficacy.py`) reports what
  analyst dispositions can honestly support: counts and **precision** over
  *reviewed fired findings only*, plus a labelled reviewed-false-positive rate.
  It deliberately does **not** recompute population FPR or recall (dispositions
  cover only fired findings — there are no observed true negatives) and never
  imports the seeded corpus harness or the ML acceptance gate. Dispositions feed
  operational reporting; they cannot move a gate threshold.

The console is also hardened and made more usable: server-side
filter/sort/pagination on `/api/detections` (page metadata in `X-Total-Count`
headers, response body still a JSON array), safe DOM construction throughout (no
`innerHTML`), a last-updated indicator with a stale/disconnected badge that never
wipes an open investigation, keyboard navigation of the findings table, and an
ARIA live region that announces new findings and integrity alarms without
stealing focus.

## ML lifecycle: artifacts, drift, and the log (Phase E, track 1)

A model needs a governed life, not just a file on disk. Track 1 adds three pieces
and activates nothing — the gate is unchanged and the ML subsystem is still
inactive. Full detail in [docs/ML_LIFECYCLE.md](docs/ML_LIFECYCLE.md).

- **A model artifact that cannot carry code.** `iforest-native.v1` is two files:
  `<model_id>.model.json` (the descriptor — schema identity, threshold and its
  provenance, forest scalars) and `<model_id>.arrays.npz` (the numbers). One root
  of trust, one hop: `ml_models.artifact_checksum` pins the descriptor's bytes and
  the descriptor pins the arrays, so no schema change was needed. The order is
  **verify, then parse** — checksum before `json.loads`, array checksum before
  `np.load(..., allow_pickle=False)`. The previous format loaded through
  `pickle.loads`, where that checksum was the *only* thing between a swapped
  artifact and arbitrary code execution.
- **Scoring no longer needs scikit-learn.** `ml/iforest.py` reimplements Isolation
  Forest scoring in numpy, bitwise-identical to sklearn (including its float32
  routing cast), so `is_anomaly = raw <= threshold` cannot change meaning between
  a training host and a scoring host. Training still needs sklearn; the estimator
  is reduced to arrays once, where sklearn exists. Identical arrays also produce
  byte-identical files, so the checksum doubles as a reproducibility check —
  something `pickle` never offered.
- **A drift check that refuses rather than guesses.** `ml/drift.py` asks one
  narrow question — is each feature's distribution in a newer verified-normal
  dataset distinguishable from the training distribution? — with a per-feature
  exact two-sample Kolmogorov–Smirnov test and Holm–Bonferroni correction across
  all 34 features (stdlib only; no scipy). Distinguishability is a **FACT**;
  whether to retrain is a labelled **INTERPRETATION**. Too little data, a schema
  mismatch, unverified windows, or a comparison set that reuses the model's own
  training windows all yield `insufficient_data` **with reasons**, never a
  reassuring "no drift" — and `scripts/ml_drift_check.py` exits non-zero so a
  scheduled run cannot log "checked" and move on.
- **An append-only log of how a model got where it is.** `ml/lifecycle.py` records
  `trained → evaluated → (eligible | ineligible) → active → (drifted | retired)`,
  hash-chained in the same one fold as the evidence chains. The log **records; it
  does not decide**: no append can activate a model, `activation_eligible` comes
  only from a fresh call to the acceptance gate, and drift can append exactly two
  states — `drift_assessed` and `retraining_required`. Drift raises the question; a
  human answers it by training a new model and putting it through the same gate.

Run a drift check (read-only unless you pass `--record`):

```bash
python3 scripts/ml_drift_check.py --db events.db --model-id iforest-... \
    --comparison-db corpus/normal.db --comparison-dataset verified-normal-...
```

**Seeing the recorded state (Phase E, track 5).** `GET /api/models` and `GET
/api/models/{id}` render what the lifecycle log already holds — a model's
provenance, its transition history, the activation-gate verdict, and its latest
drift summary — so an analyst can see *whether the model behind a score is fit for
this host*, not just *why a finding scored*. The surface is strictly read-only and
additive: it re-computes no gate (`activation_eligible` is surfaced verbatim from
the recorded rows), writes no row, and adds no migration. It exposes
`artifact_checksum` but withholds `artifact_path`, so the read surface never leaks
host filesystem layout. On a default install the list is `[]` — the honest answer,
since detection runs deterministically until a model passes the gate — and the
console's "ML models" panel says exactly that.

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
GET /api/detections                 # filter/sort/paginate; page metadata in X-Total-Count
GET /api/detections/{id}
GET /api/explanations/{id}
GET /api/assistant/{id}
GET /api/policies
GET /api/policy-decisions
GET /api/integrity                   # verify_chain verdicts: findings, policy, triage, ml_lifecycle
GET /api/efficacy/operational        # precision/counts from dispositions (not the ML gate)
GET /api/models                      # model provenance + recorded lifecycle state (never artifact_path)
GET /api/models/{id}                 # provenance, transition history, gate verdict, latest drift, chain
GET /api/triage/{id}                 # append-only history + effective state
GET /api/triage/export               # faithful record; suppressed findings included and marked
```

The only non-`GET` routes are the append-only triage writes, each `POST` only
and token-gated (default-deny). None is destructive — there is no
`PUT`/`DELETE`/`PATCH`, and none mutates a finding row or a hash chain:

```text
POST /api/triage/{id}/acknowledge    {note?, actor?}
POST /api/triage/{id}/annotate       {note, actor?}
POST /api/triage/{id}/disposition    {disposition: true-positive|false-positive|benign, note?, actor?}
POST /api/triage/{id}/suppress       {reason, actor?}    # presentation only; never drops the finding
POST /api/triage/{id}/unsuppress     {reason, actor?}
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
authenticated code-free artifacts, schema checks, feature-range diagnostics,
held-out evaluation, drift assessment, and an append-only lifecycle log.

The current experiment, `iforest-6ef9e765-8bc8-4bfc-b8d5-e1ebd18730e7`, is
**inactive**. Its historical evaluation produced 2 false positives from 5
normal holdouts (40% FPR), which fails the fixed 5% requirement. Its artifact is
a pre-Phase-E pickle and is no longer loadable; since it was never active and is
not activation-eligible, nothing in service was affected.

A future model may be considered for activation only after independent,
operator-reviewed normal holdouts satisfy all of the following:

- observed FPR ≤ 5%;
- one-sided 95% FPR upper bound ≤ 5%; and
- at least 60 independent holdout windows.

No threshold changes, activation, or baseline contamination are allowed merely
to make a model pass. Drift assessment and the lifecycle log feed this gate's
paperwork; they are never a way around it.

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

- Full suite: **648 passed, 5 skipped** (~25s)
- The 5 skips are all scikit-learn-gated: `tests/test_ml_integration.py` (4) and
  the sklearn-parity test in `tests/test_ml_artifact.py` (1). That file reports
  **56 passed** under an interpreter that has scikit-learn installed
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
- Phase D added coverage for the append-only triage layer (chained writes,
  corrections as new events, suppress/unsuppress effective state, suppress never
  dropping a finding from a read or export, auth-required writes, and the finding
  row plus finding/policy chains unchanged after triage), operational efficacy
  from dispositions with a static guarantee it never imports the corpus harness
  or ML gate, the new `/api/integrity` and `/api/efficacy/operational` routes,
  detections pagination/filter/sort with `X-Total-Count`, the three new labelled
  explanation factors, and migration 9 (`tests/test_triage.py`,
  `test_operational_efficacy.py`, `test_api_app.py`, `test_explainer.py`,
  `test_schema_migrations.py`, `test_evidence_chain.py`)
- Phase E track 1 added coverage for the native artifact (checksum-before-parse in
  both hops, refusal of a traversing array filename, `0600` on both files,
  reproducible bytes, and a source-level ban on code-executing deserializers and
  on `allow_pickle=True` anywhere in `ml/` — plus a hand-built toy artifact that
  exercises the loader and the scoring math with **no** scikit-learn), the drift
  check (KS statistics and Holm thresholds against independently verified
  literals, every named `insufficient_data` refusal, and that a drift result
  cannot mutate a model or threshold), the lifecycle log (chain tamper detection,
  the recomputed drift binding, the store-level refusal of an ungated `active`
  row, and the gate's constants pinned as literals), the fourth chain in
  `/api/integrity`, and migration 10 (`tests/test_ml_artifact.py`,
  `test_ml_drift.py`, `test_ml_lifecycle.py`, `test_api_app.py`,
  `test_schema_migrations.py`)

Re-measure before restating those numbers. Tests are never weakened, skipped, or
removed to make a run look clean.

## Project layout

| Directory | Responsibility |
|---|---|
| `telemetry/` | BCC, journald, auditd, and health collectors |
| `pipeline/` | Canonical Event model, normalization, bounded ingestion, and the supervised multi-collector service with write-failure quarantine |
| `storage/` | SQLite persistence (mode `0600` enforced), ML provenance, and age/byte-cap retention |
| `baseline/` | Explicit verified-normal behavioral baseline |
| `detection/` | Deterministic rules, evidence fusion, detection-only system-failure scoring, and operational efficacy from analyst dispositions (decoupled from the ML gate) |
| `ml/` | Canonical window schema, training, code-free model artifacts, scoring, evaluation, drift assessment, and the model lifecycle log |
| `explainability/` | Evidence reconstruction and bounded explanations |
| `assistant/` | Optional provider-neutral advisory narration |
| `policy/` | Deterministic fail-closed dry-run policy |
| `observability/` | Layered config, Prometheus-style metrics, and disk/queue/silence alerting |
| `api/`, `dashboard/` | Authenticated analyst API and interface: read-only over the immutable evidence record, with append-only, default-deny triage writes |
| `deploy/` | systemd units, example config, and the deployment guide |
| `scripts/` | Environment check, ingestion benchmark, and collector-kill soak harness |
| `tests/` | Focused unit and integration regression tests |
| `requirements.txt` | Python dependencies for API, policy, ML, and tests |

## Data handling

Raw telemetry databases, normal-data captures, Python environments, cache
files, and model artifacts are excluded through `.gitignore`. They may contain
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
- [docs/ML_LIFECYCLE.md](docs/ML_LIFECYCLE.md) — the code-free model artifact
  format, the drift check and its refusals, the append-only lifecycle log, and the
  trust boundaries around them.
- [docs/ML_ATTRIBUTION.md](docs/ML_ATTRIBUTION.md) — the opt-in, advisory
  per-feature decomposition of the Isolation Forest's isolation-path length,
  exact and reconciling but model-faithful rather than causal.
- `docs/PHASE*_RESULTS.md` — historical phase evidence. Their older telemetry
  limitations are clearly marked as superseded; AGENTS.md is authoritative.
- `docs/phase1_sample_events.jsonl` — synthetic fixture only, never live
  telemetry or normal-training data.

## License

Released under the [MIT License](LICENSE).
