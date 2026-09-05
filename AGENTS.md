# Linux XAI Security Assistant — Authoritative Handoff

**Project**: AI-Powered Explainable Linux Security Assistant for kernel-level intrusion and behavioral threat detection  
**Environment**: Kali Linux 2026.3, kernel `7.1.5+kali`, x86_64  
**Current state**: Telemetry implementation and controlled live validation are complete. ML infrastructure is implemented, tested, and intentionally inactive pending independent normal-data acceptance.  
**Last consolidated update**: 2026-09-05

## Problem statement and requirement traceability

The authoritative problem statement (supplied with the project brief) is recorded
here verbatim so each clause is traceable to code and its status is unambiguous:

> Design an AI-powered monitoring system that **learns normal system behavior** to
> detect **security threats** and **system failures** **in real time**. The solution
> should **explain why anomalies are detected** and automatically **recommend or
> perform corrective actions**.

The statement decomposes into five requirement clauses. Each is mapped to the code
that satisfies it, or marked as a known gap. These statuses are load-bearing: do
not describe a gap as satisfied, and do not close a gap by weakening the safety
boundaries above.

| # | Requirement clause | Where it lives | Status |
|---|---|---|---|
| R1 | Learns normal system behavior | `baseline/behavior_analyzer.py` and the baseline engine; per-`EventType` windowed baselines. ML (`ml/`) is implemented but intentionally inactive. | **Satisfied** (deterministic baseline). |
| R2 | Detects security threats in real time | `detection/detector.py` deterministic fusion over streaming telemetry; explained findings persisted via `storage/sqlite_store.py`. Real-time now covers the kernel collectors (exec, network, IPC) and both streaming journald collectors (auth, service). | **Satisfied**, with one narrowed gap — see Gap B. |
| R3 | Detects system failures in real time | `system_health` events are collected (`telemetry/bcc/telemetry_basic.py`) and stored, but **no baseline or detector scores them**: there is no failure-detection path at the detection layer. | **Gap A — not implemented.** |
| R4 | Explains why anomalies are detected | `explainability/explainer.py` builds evidence and rationale for each finding; `assistant/service.py` renders an advisory, human-readable explanation. | **Satisfied.** |
| R5 | Recommends or performs corrective actions | *Recommend:* `assistant/service.py` (advisory) and `policy/engine.py` (deterministic, fail-closed, approval-gated **dry-run** decisions). *Perform:* not built — `response/` is empty and no executor exists. | **Partial (Gap C):** recommend yes; perform deliberately absent. |

Gap notes:

- **Gap A (system-failure detection).** The telemetry exists; the detection side does
  not. Closing it means adding a baseline/detector path for `system_health`, not
  relabelling existing security-threat findings as failures.
- **Gap B (real-time coverage).** Six of the seven telemetry families stream in real
  time. File access (`telemetry/auditd/file_access_monitor.py`) remains a one-shot
  query and is not yet a live source. This is the only remaining non-real-time family.
- **Gap C (perform corrective actions).** "Perform" is intentionally unimplemented
  because it collides with the non-negotiable boundaries: collectors are
  observation-only, the assistant is advisory, and policy is fail-closed/dry-run. Any
  future executor must stay approval-gated and must not become an automatic
  destructive action. The empty `response/` directory is the placeholder for that
  future, deliberately gated work — its emptiness is a design decision, not an
  oversight.

## Architecture and non-negotiable boundaries

Preserve this architecture and its existing interfaces:

```text
collector → JSONL → canonical normalization → bounded ingestion → SQLite
→ detection/fusion → evidence/explainability → advisory assistant
→ fail-closed policy → read-only API/dashboard
```

- `pipeline/event_stream.py` owns the canonical `Event` contract and `EventType` values. Do not introduce a competing event model or parallel pipeline.
- `pipeline/live_ingestion.py` is the bounded-ingestion boundary; `storage/sqlite_store.py` is the persistence boundary.
- Collectors are observation-only. The assistant is advisory only; policy is fail-closed/dry-run. Do not add automatic termination, freezing, blocking, firewall changes, or other destructive system actions.
- Test verification and live verification are distinct. A low anomaly score is not verified-normal data.

## Telemetry status

All planned telemetry families are **LIVE VERIFIED**. No telemetry category remains unverified.

| Family | Status | Source and controlled evidence |
|---|---|---|
| Process execution | **LIVE VERIFIED** | BCC process collectors; real kernel events captured. |
| Post-exec process context | **LIVE VERIFIED** | `sched:sched_process_exec`; executable and parent context captured. |
| File access | **LIVE VERIFIED** | Existing file-access collector and controlled validation. |
| Network activity | **LIVE VERIFIED** | `sock:inet_sock_set_state`: client PID `32379`, UID `1000`, `comm=python3`, destination `127.0.0.1:18080`. |
| Authentication/session | **LIVE VERIFIED** | Structured journald PAM source `journald_pam`: controlled sudo session, PID `37934`, UID `1000`, `session_opened` and `session_closed`. |
| System/service lifecycle | **LIVE VERIFIED** | Structured journald/systemd lifecycle records; e.g. `systemd-timedated.service` `started` with success. |
| IPC | **LIVE VERIFIED** | BCC `pipe`/`pipe2` kprobe: PID `40231`, UID `1000`, `comm=python3`, `read_fd=3`, `write_fd=4`, endpoint `fd:3->fd:4`, success `true`. |

### Collector and event details

- Network: `telemetry/bcc/network_state_probe.py` emits `tcp_connect` from `sock:inet_sock_set_state`, filtered to IPv4 TCP `SYN_SENT → ESTABLISHED`. The tracepoint exports `dport` in host order on this kernel. Do **not** reintroduce `ntohs()`—it previously byte-swapped `18080` to `41030`. Do not revert to the older `tcp_v4_connect`/`struct sock` approach.
- Authentication: `telemetry/journald/auth_session_monitor.py` emits `auth_session` from real structured PAM/session journald records.
- System/service: `telemetry/journald/service_monitor.py` emits `service_state` only for explicit systemd lifecycle records. `unit` is the affected unit parsed from that fixed lifecycle message; `_SYSTEMD_UNIT` is retained as `reporter_unit`.
- Both journald collectors stream through the shared loop in `telemetry/journald/journal_stream.py` and persist a journal cursor to `state/journald-<name>.cursor` (override with `--cursor-file` or `SECURITY_STATE_DIR`). `--follow` is the default; `--since` (default `10 minutes ago`) applies only when no usable cursor exists. Keep the resumption logic shared — do not give either collector a private copy of it; `tests/test_journal_stream.py` asserts both delegate to `add_stream_arguments`/`run_collector`.
- Cursor handling invariants, all pinned by `tests/test_journal_stream.py`. These were validated by a one-off 56-mutation campaign (a point-in-time measurement, tooling not retained): 55 caught; the single survivor, `bufsize=1` → `bufsize=-1`, is behaviourally equivalent because `BufferedReader.readline` still returns lines as they arrive. If you weaken one of these invariants, the named test should fail — if it does not, the test is the thing that is broken.
  - The cursor is written only **after** the event it covers has been written and flushed. Never reorder this: a cursor ahead of an unflushed event turns a crash into silent event loss.
  - A stored cursor is validated with a `--cursor` pre-flight probe, not `--after-cursor`. On systemd 261 a well-formed cursor whose index is past the end of the journal makes `--after-cursor --follow` exit 0 with no output and no stderr — a silent blackout. `--cursor ... --lines=1` separates "position exists" (`CURSOR_RESUMABLE`) from "does not exist" (`CURSOR_UNRESOLVABLE`) from "unreadable" (`CURSOR_UNREADABLE`). Do not replace the probe with `--after-cursor`.
  - An unusable cursor is **reported**, never silently substituted: the collector emits a `telemetry_warning` event with `stale_cursor`, `reason`, and `recovery="since_window"`, increments `discarded_cursor_count`, then falls back to `--since`. `telemetry_warning` is a real `EventType`, so the gap becomes a durable row visible through the API.
  - The cursor advances over records the collector does not emit, so a quiet period cannot make a restart re-read hours of journal.
  - `SIGTERM`/`SIGINT` stop the stream and force a final checkpoint; measured clean shutdown is 0.062s, inside `live_ingestion`'s five-second grace period before `SIGKILL`. Buffered records are abandoned rather than drained, which is safe precisely because the cursor was not advanced over them.
  - `read_journal()` is retained in both modules for scripted one-shot use only. `tests/test_journal_stream.py` pins that it derives the same events as the streaming path, so it cannot drift; if you change normalization, that equivalence test must stay green.
- IPC: `telemetry/bcc/ipc_pipe_probe.py` emits `ipc_event` for anonymous `pipe`/`pipe2` creation. On x86_64, `__x64_sys_pipe*` receives a `struct pt_regs *` wrapper argument; the real `pipefd` argument is `regs->di` at offset `0x70`. Do **not** revert to the incorrect direct-wrapper-pointer read that produced false `fd:0->fd:0` events. If either userspace FD read fails, emit `null` FD/endpoint values rather than fabricate descriptors. System-wide background shell/service pipe events are expected and are not controlled-validation evidence.
- Deprecated collectors: `telemetry/bcc/telemetry_simple.py`, `telemetry_collector.py`, `process_exec_probe.py`, and `network_connect_probe.py` are superseded proofs of concept, marked `DEPRECATED / LEGACY` in their module docstrings. They are retained for historical reference only — not wired to ingestion, not covered by the regression suite, and not perf-buffer-loss reported. Do not use them for live telemetry, do not build on them, and do not add them to `CANONICAL_COLLECTORS` in `tests/test_perf_loss.py`. The current collectors are `telemetry_basic.py`, `network_state_probe.py`, and `ipc_pipe_probe.py`.
- Perf-buffer loss reporting is pinned per canonical collector by `tests/test_perf_loss.py`, including that no collector uses a bare `except:` or catches `BaseException`: such a handler swallows the Ctrl+C that triggers the shutdown `loss_reporter.flush()`, so a pending loss count would die with the process.

IPC canonical persistence validation succeeded using the controlled evidence: `processed_count=1`, `malformed_count=0`, `dropped_event_count=0`, persisted event type `ipc_event` with endpoint `fd:3->fd:4`.

## Validation and test status

- IPC focused tests: `pytest -q tests/test_ipc_pipe_probe.py` — **6 passed**.
- Authentication focused tests: **4 passed**.
- Earlier network focused tests: **27 passed**.
- Streaming journald tests: `pytest -q tests/test_journal_stream.py` — **92 passed**, no skips (the two `journalctl`-guarded integration tests do run here and agree with the fake).
- Full suite, measured on Python 3.14.6 / pytest 9.1.1: **304 passed, 4 skipped in ~16s**. The only skips are `tests/test_ml_integration.py` (scikit-learn absent). Re-measure before restating this number; report the actual output, and do not hide, weaken, or remove tests to claim a clean run.
- `PYTHONPATH=.` is no longer required: `[tool.pytest.ini_options] pythonpath = ["."]` in `pyproject.toml` makes bare `pytest` work. Verified with `env -u PYTHONPATH python3 -m pytest -q`.
- Live BCC validation requires an interactive privileged Kali terminal. The agent sandbox may lack usable sudo credentials even where a user terminal can attach probes.

## Reference repository and future ML rules

`https://github.com/likitha-shankar/Linux-Security-Agent` is an ML-concepts reference only, not a replacement architecture. Before implementing ML, inspect this project’s existing detection interfaces and the reference repository’s ML-related files.

Useful concepts to evaluate and adapt behind canonical Event windows:

- Isolation Forest and One-Class SVM
- DBSCAN experimentation
- feature engineering and temporal/behavioral features
- model persistence and evaluation metrics
- connection-pattern analysis
- MITRE/IOC concepts

Rules:

- Do **not** replace canonical `Event` with the reference `SyscallEvent` or its in-memory event history.
- Do **not** copy destructive response, termination, or freeze behavior.
- Do **not** copy unsafe incremental training, feature vectors, or datasets blindly.
- Do not copy code unless licensing/permission is verified; no license may be assumed for the reference repository.
- Reimplement/adapt compatible concepts around canonical events, preserving explicit feature schemas, schema/version provenance, reproducible training, verified-normal training boundaries, held-out evaluation, model metadata, contamination protection, and traceable evidence into the existing `DetectionEngine`.

## ML status and activation gate

- `ml/feature_schema.py` owns the deterministic `canonical-window.v1` feature schema.
- `ml/training.py`, `ml/scoring.py`, and `ml/evaluation.py` provide explicit verified-normal dataset capture, reproducible Isolation Forest training, artifact checksums, schema checks, feature-range diagnostics, held-out evaluation, and activation assessment.
- Training now rejects fewer than 10 verified-normal windows and fewer than 3 distinct feature vectors. The Isolation Forest decision boundary is recorded as an experimental model boundary, not independent threshold calibration.
- A model can only be considered for activation after separate reviewed-normal holdouts meet all of: observed FPR <= 5%, one-sided 95% FPR upper bound <= 5%, and at least 60 independent holdout windows. The assessment never changes a model, threshold, or activation state.
- The current verified-normal dataset is `verified-normal-5e74298f-78c6-443e-9f32-f410f2413b2f`: 18 operator-reviewed current-format five-minute Kali windows (1,474 events). Source database hashes, collector health, event-ID namespaces, and approval metadata are immutable window provenance. Training windows 04 and 13 were excluded for integrity reasons. Holdouts remain separate.
- The current experiment `iforest-6ef9e765-8bc8-4bfc-b8d5-e1ebd18730e7` is an inactive Isolation Forest (`random_state=42`, `contamination=0.05`, 200 estimators) with checksum and canonical-window schema provenance.
- Historical evaluation of that experiment against the then-available five normal holdouts produced 2 false positives / 5 windows (40% FPR). It is not activation-eligible. The original holdout #1 is no longer available, so do not claim a new five-window FPR from the four preserved holdouts.
- ML scoring is optional and diagnostic. `DetectionEngine` catches any ML load/score failure and retains the deterministic behavior/rule/context fusion path. When ML is supplied successfully, its feature-deviation evidence is additive and `FindingExplainer` exposes it as statistical—not causal—evidence.

## Next task

After submission, collect more explicitly reviewed current-format normal windows covering high-volume/high-diversity activity, then collect independent normal holdouts. Retrain only as a new inactive experiment and require the activation gate above; never alter the current inactive models or relax the 5% FPR criterion merely to activate one.

## Documentation rule

This is the consolidated telemetry handoff. Do not update `AGENTS.md` after every small future change; update it at a major architectural decision, major milestone, or durable handoff state change.
