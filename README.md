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
| Detect system failures in real time | `system_health` events are collected but not yet scored | **Not implemented** |
| Explain why anomalies are detected | `explainability/` evidence + advisory `assistant/` | Implemented |
| Recommend or perform corrective actions | `assistant/` advises and `policy/` emits fail-closed dry-run decisions | **Recommend only** — performing actions is deliberately not built |

The two gaps are documented positions, not oversights. Performing corrective
actions in particular is intentionally out of scope: it would conflict with the
safety principles below — observation-only collectors, an advisory assistant,
and fail-closed dry-run policy. [AGENTS.md](AGENTS.md) carries the full
clause-by-clause traceability.

## Submission snapshot

| Area | Current state |
|---|---|
| Telemetry | All planned families are **LIVE VERIFIED** on Kali Linux 2026.3 / kernel `7.1.5+kali` |
| Detection | Deterministic baseline, rules, context, and fusion are implemented |
| Explainability | Persisted evidence reconstruction and analyst-facing explanations are implemented |
| Assistant | Optional, provider-neutral, evidence-grounded narration; never a decision-maker |
| Policy | Fail-closed, dry-run, advisory-only; no remediation executor exists |
| ML | Implemented and tested, but the current Isolation Forest is **inactive** and not approved for activation |
| Dashboard | Read-only FastAPI API and browser dashboard over persisted SQLite data |

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
- The API is read-only and defaults to loopback binding.
- No automatic termination, freezing, blocking, firewall changes, or account
  changes are implemented.
- ML failure falls back to deterministic detection; it cannot break the
  existing detection path.

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

> The command above is the primary end-to-end demo path for process execution
> and system health. Other telemetry collectors are independently LIVE
> VERIFIED; they intentionally remain separate privileged tools until a
> multi-collector supervisor is added.

### 3. Start the read-only dashboard

In terminal 2:

```bash
cd ~/linux-xai-security-assistant
SECURITY_DB_PATH="$PWD/security_demo.db" PYTHONPATH=. python3 -m api
```

Open <http://127.0.0.1:8000/dashboard/>.

The dashboard reports two different things:

- **Telemetry verified** means the collector family has passed controlled live
  validation on the target Kali environment.
- **Collector stopped** or **Data stale** means the selected SQLite database is
  not receiving events right now. It does not revoke the collector's verified
  capability.

### 4. Inspect the API

Useful read-only endpoints:

```text
GET /api/health
GET /api/status
GET /api/telemetry/status
GET /api/events?limit=100
GET /api/detections
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

- Full suite: **304 passed, 4 skipped** (~16s)
- The 4 skips are `tests/test_ml_integration.py`, which requires scikit-learn
- Streaming journald: 92 passed, including two integration tests that exercise
  the real `journalctl` cursor semantics on systemd 261

Re-measure before restating those numbers. Tests are never weakened, skipped, or
removed to make a run look clean.

## Project layout

| Directory | Responsibility |
|---|---|
| `telemetry/` | BCC, journald, auditd, and health collectors |
| `pipeline/` | Canonical Event model, normalization, bounded ingestion |
| `storage/` | SQLite persistence and ML provenance records |
| `baseline/` | Explicit verified-normal behavioral baseline |
| `detection/` | Deterministic rules and evidence fusion |
| `ml/` | Canonical window schema, training, scoring, evaluation |
| `explainability/` | Evidence reconstruction and bounded explanations |
| `assistant/` | Optional provider-neutral advisory narration |
| `policy/` | Deterministic fail-closed dry-run policy |
| `api/`, `dashboard/` | Read-only analyst API and interface |
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
- `docs/PHASE*_RESULTS.md` — historical phase evidence. Their older telemetry
  limitations are clearly marked as superseded; AGENTS.md is authoritative.
- `docs/phase1_sample_events.jsonl` — synthetic fixture only, never live
  telemetry or normal-training data.

## License

Released under the [MIT License](LICENSE).
