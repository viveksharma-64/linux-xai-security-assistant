# Linux XAI Security Assistant — Authoritative Handoff

**Project**: AI-Powered Explainable Linux Security Assistant for kernel-level intrusion and behavioral threat detection  
**Environment**: Kali Linux 2026.3, kernel `7.0.12+kali`, x86_64  
**Current state**: Telemetry implementation and controlled live validation are complete. ML infrastructure is implemented, tested, and intentionally inactive pending independent normal-data acceptance.  
**Last consolidated update**: 2026-08-24

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
- IPC: `telemetry/bcc/ipc_pipe_probe.py` emits `ipc_event` for anonymous `pipe`/`pipe2` creation. On x86_64, `__x64_sys_pipe*` receives a `struct pt_regs *` wrapper argument; the real `pipefd` argument is `regs->di` at offset `0x70`. Do **not** revert to the incorrect direct-wrapper-pointer read that produced false `fd:0->fd:0` events. If either userspace FD read fails, emit `null` FD/endpoint values rather than fabricate descriptors. System-wide background shell/service pipe events are expected and are not controlled-validation evidence.

IPC canonical persistence validation succeeded using the controlled evidence: `processed_count=1`, `malformed_count=0`, `dropped_event_count=0`, persisted event type `ipc_event` with endpoint `fd:3->fd:4`.

## Validation and test status

- IPC focused tests: `PYTHONPATH=. pytest -q tests/test_ipc_pipe_probe.py` — **6 passed**.
- Authentication focused tests: **4 passed**.
- Earlier network focused tests: **27 passed**.
- Earlier combined telemetry tests and Python compilation checks passed as established during their respective collector work.
- Do not claim the entire repository suite is fully passing: existing environment/runtime timeout issues remain around some TestClient/live-ingestion tests. Do not hide, weaken, or remove tests to claim a clean full suite.
- This repository currently needs `PYTHONPATH=.` because it has no package/test-path configuration.
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
