# Linux XAI Security Assistant — Authoritative Handoff

**Project**: AI-Powered Explainable Linux Security Assistant for kernel-level intrusion and behavioral threat detection  
**Environment**: Kali Linux 2026.3, kernel `7.1.5+kali`, x86_64  
**Current state**: Telemetry implementation and controlled live validation are complete. Phase B operational readiness is complete: supervised multi-collector ingestion, an authenticated read-only API, self-bounding retention, observability, and systemd deployment, with the test suite as the CI gate. Phase C detection credibility is complete: published precision/recall against a seeded corpus, versioned MITRE-mapped rules with per-rule tests, a tamper-evident evidence hash-chain, and a documented verified-normal corpus program on a credible path to the (unchanged) ML gate. ML infrastructure is implemented, tested, and intentionally inactive pending independent normal-data acceptance. System-failure detection (R3) is now implemented on strictly detection-only terms: `detection/system_failure.py` scores `system_health`/`service_state` over fixed windows and surfaces failures as findings, taking no active response. Phase D analyst experience is complete: an append-only, hash-chained triage layer (acknowledge/annotate/disposition/suppress) that never mutates the immutable evidence record, authenticated default-deny writes, a faithful export, an integrity alarm, operational efficacy from dispositions decoupled from the ML gate, and a hardened, more accessible console.  
**Last consolidated update**: 2026-09-08

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
| R3 | Detects system failures in real time | `detection/system_failure.py` scores `system_health`/`service_state` over fixed 300s windows with hysteresis and persists failure findings via `storage/sqlite_store.py` (`mode="system_failure"`, no schema change). Detection surfaces failures for an operator; taking an active response is R5, not this clause. | **Satisfied** (detection only). |
| R4 | Explains why anomalies are detected | `explainability/explainer.py` builds evidence and rationale for each finding; `assistant/service.py` renders an advisory, human-readable explanation. | **Satisfied.** |
| R5 | Recommends or performs corrective actions | *Recommend:* `assistant/service.py` (advisory) and `policy/engine.py` (deterministic, fail-closed, approval-gated **dry-run** decisions). *Perform:* not built — `response/` is empty and no executor exists. | **Partial (Gap C):** recommend yes; perform deliberately absent. |

Gap notes:

- **Gap A (system-failure detection) — closed.** `detection/system_failure.py`
  now scores the `system_health`/`service_state` telemetry over fixed 300s windows
  and persists failure findings; it does **not** relabel existing security-threat
  findings as failures. It stays strictly detection-only — findings surface for an
  operator and are not routed through the assistant or policy — so closing it did
  not weaken any boundary below. See "System-failure detection (R3)" below.
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

## Operational readiness (Phase B)

Phase B makes the system run unattended as two systemd services (see `deploy/`): a
supervised ingestion daemon and the read-only API. The components and their
load-bearing invariants:

- **Supervised ingestion.** `pipeline/service.py` runs the collectors; `pipeline/supervisor.py` restarts a crashed collector with exponential backoff, resets the ladder after a healthy run, and marks a collector *degraded* (service exits non-zero) on a genuine crash loop rather than limping silently. Backoff/health timings are config-driven (`restart_*`, `crash_loop_*`). Proven by `scripts/soak_chaos.py`: 20 `SIGKILL`s → 20 recoveries → zero lost events.
- **Write-failure quarantine.** `pipeline/quarantine.py` writes any batch a failed DB write would drop to disk — self-describing, `0600` (`FILE_MODE = 0o600`), size-capped — for replay. The no-loss property therefore extends past the store boundary, not just across collector kills.
- **Authenticated API.** `api/auth.py`. On by default and fail-closed: auth required with no token configured returns `503`, never an open evidence feed. Tokens are compared with `secrets.compare_digest` over a SHA-256 digest of *every* configured token (no short-circuit, so timing does not leak which matched or how many exist); tokens under 16 chars (`MIN_TOKEN_LENGTH`) are refused. Only `/api/health` and `/api/health/live` are unauthenticated (`unprotected_paths()`); `/api/health/ready` and `/metrics` are gated because readiness and metrics are reconnaissance. Do not move readiness or metrics into the open set.
- **Store hardening.** The evidence DB is created and enforced at mode `0600` (`file_mode`/`enforce_mode`); opening a looser-mode database is refused and readiness reports not-ready. `storage/sqlite_store.py` opens connections `check_same_thread=False` **only** so `close()` can reclaim a worker-thread handle at shutdown — each connection is still used by a single thread. Do not "restore" `check_same_thread=True`; it reintroduces the unclosed-connection leak.
- **Self-bounding storage.** `storage/retention.py` prunes by age and by a byte cap and `VACUUM`s on a timer, all **in-process** on the ingest daemon (there is deliberately no `.timer` unit). `retention_max_age_days: 0` keeps events indefinitely (byte cap only).
- **Observability.** `observability/metrics.py` serves a Prometheus-style `/metrics`; `observability/alerts.py` logs disk/queue/collector-silence alerts on *transition* (not every interval) at a level a journald paging rule can key on.
- **Layered config.** `observability/config.py`: defaults < config file < environment, fail-closed on an unknown key or unparseable value. File modes must be quoted in YAML so `0600` is not reinterpreted as decimal. Env var per field is `SECURITY_<NAME>` (e.g. `SECURITY_API_REQUIRE_AUTH`, `SECURITY_API_TOKENS`, `SECURITY_API_TOKEN_FILE`).
- **CI.** `.github/workflows/ci.yml`. pytest is the hard gate; `ruff`/`mypy` run but are advisory (they could not be baselined on the offline build host). Do not describe them as gating until they are.

Rationale and measured numbers live in `docs/THREAT_MODEL.md` (STRIDE for this surface) and `docs/PHASE_B_RESULTS.md` (throughput/latency and the soak result); deployment and capability tuning live in `deploy/README.md`.

## Detection credibility (Phase C)

Phase C holds detection quality to the standard the ML gate already sets:
measured, versioned, tamper-evident. Components and their load-bearing invariants:

- **Published efficacy.** `simulation/corpus.py` (seeded, labeled canonical `Event`s — read-only simulation, nothing executed on the host) + `simulation/efficacy.py` measure the deterministic detector; `scripts/run_efficacy.py` regenerates `docs/DETECTION_EFFICACY.md` and `--check` gates it in sync. Headline: Precision 0.7143, Recall 1.0000, F1 0.8333, FP/day 11.52 over 55 windows. The throwaway behaviour baseline is promoted only via `BehaviorAnalyzer.learn_normal(..., verified_normal=True)` — **never** the `ml/training.py` verified-normal path; `tests/test_efficacy.py` is the contamination guard.
- **Externalized rules.** The four rules live in `detection/rules_catalog.yaml` (catalog schema v1) — score, gates, thresholds, allowlists, per-rule `version`, and MITRE mapping with a written rationale. Nothing about a rule is hardcoded; `detection/rules.py:load_catalog()` fails closed on an inconsistent catalog. Bump a rule's `version` whenever its semantics/score/tunables change; changing a `score` is a calibration change — re-run `run_efficacy.py`. Pinned by `tests/test_rules.py` (per-rule) and `tests/test_rule_catalog.py` (integrity).
- **Fusion weights unchanged, now justified.** `0.50/0.35/0.15` and the `0.80/0.60/0.35` bands are **retained**, justified by the measured separation (clean benign peaks at 0.0000, lowest attack 0.5079). The weight/threshold lockstep across `detection/detector.py`, `explainability/explainer.py` (both formula branches + strings), and `tests/test_detection_engine.py` is unchanged — a band/weight change still touches all three in one commit and regenerates the efficacy doc.
- **Correlation & suppression.** `DetectionEngine.detect()` assigns a deterministic `correlation_id` (contiguous-run grouping per entity) and applies operator suppression specs. Suppression is a **disposition, never a silent drop and never a score input**: a suppressed finding is still persisted, explained, and chained; only `suppressed`/`suppression_reason` are set. This keeps the explainer's `1 - Π(1-score)` reconciliation intact.
- **Tamper-evident evidence.** `storage/evidence_chain.py` defines one fold (`chain_hash = SHA256(chain_prev_hash || serialized_core)`) used by both the runtime writer and the migration-8 backfill. `detection_findings` and `policy_decisions` are append-only chains extended only on a genuine INSERT (a dedup hit adds no link) under `BEGIN IMMEDIATE`. `verify_findings_chain()`/`verify_policy_chain()` re-fold from disk and detect a mutation, reorder, gap, or deletion. Migration **8** adds these columns additively via `_add_column_if_absent`; versions 1–7 are untouched, `LATEST_VERSION=8`.
- **Verified-normal corpus program.** `docs/NORMAL_CORPUS_PROGRAM.md` + `scripts/collect_normal_window.py` + `scripts/corpus_status.py` reuse the existing ML training/eval and add **no new ML path**. The tool cannot self-approve (requires `--i-verified-normal` + operator + reason; `ml/training.py` re-checks `verified_normal=True`) and reads sources read-only. The gate (`ml/evaluation.py`: FPR ≤ 5%, 95% Wilson upper ≤ 5%, ≥ 60 independent holdout windows) is **reused, never edited** — the corpus grows to meet the bar.

Rationale and the full measured roll-up live in `docs/PHASE_C_RESULTS.md`; the generated efficacy numbers in `docs/DETECTION_EFFICACY.md`.

## System-failure detection (R3)

System-failure detection closes Gap A on the same read-only terms as the rest of
the pipeline. `detection/system_failure.py` scores the telemetry the collectors
already emit and persists findings through the existing store. Load-bearing
invariants — do not weaken these:

- **Detection-only, by construction.** Failures surface as findings; nothing is terminated, restarted, killed, frozen, blocked, or throttled, and no groundwork for that is laid. This is the non-negotiable scope of the feature. Findings carry `mode="system_failure"`, put the failure magnitude in `risk_score`, and set behaviour/rule/context scores to `0.0`. They are persisted and readable but are **not** routed through the explainer, assistant, or policy — policy is the response-proposal stage, and that boundary is exactly what this feature must not cross. Do not add an active-response path here.
- **No schema change.** Findings reuse `detection_findings` via `store.write_detection_finding(...)`; there is no new column and no new migration. A single `system_failure` evidence signal carries the condition, detail, and threshold context.
- **Fixed 300s windows, epoch-aligned.** `_window_start_for(ts)` matches `baseline/behavior_analyzer.py` (`int(ts // 300) * 300`). `score_batch` buckets a batch's `system_health`/`service_state` events by window and scores windows in ascending order.
- **Window-idempotent hysteresis with a dead-band.** A condition must breach for `failure_consecutive_windows` windows before emitting and clear below a *distinct lower* threshold (`breach × failure_clear_ratio`, inverted for a floor like available memory) for `failure_clear_windows` windows before resolving. The counter advances at most once per distinct, strictly-increasing `window_start`, so the many ~50-event ingestion batches inside one 300s window cannot over-count — "N windows" is wall-clock time, not batch count.
- **Missing telemetry is unknown.** A null cpu/disk/memory field is scored as neither failure nor healthy (that dimension is simply not observed for the window); a window with no health/service events yields no finding.
- **Stable-identity provenance dedup.** `_provenance_hash` folds only the stable identity (detector version, window bounds, entity, condition, severity), not the fluctuating observed values, so re-scoring the same window+condition dedups to one row through the store's existing provenance-hash path.
- **No ATT&CK assertion.** Category is availability; T1489/T1499 are interpretation-only notes, not asserted technique mappings.
- **Config-driven and fail-closed.** All thresholds and the window/hysteresis counts are `failure_*` settings (`SECURITY_FAILURE_*` env), documented in `deploy/config.example.yaml` and validated on load (percentages ≤ 100, medium band below high, `failure_clear_ratio` in `(0, 1]`, positive window counts).
- **Wired ahead of the no-risk early return.** `DatabaseAnalysisPipeline.process` runs `failure_scorer.score_batch(events)` before the behaviour-risk early return, so a health/service-only batch still produces failure findings. Pinned by `tests/test_system_failure.py`, including two pipeline integration tests.

## Analyst experience (Phase D)

Phase D adds an analyst workflow — acknowledge, annotate, disposition, suppress — on top of the immutable record. The apparent conflict with immutability is resolved by keeping triage in a **separate, append-only annotation layer** that never touches a finding row or the finding/policy chains. Load-bearing invariants — do not weaken these:

- **Evidence stays immutable; triage is a new chain.** A triage action never mutates a `detection_findings` row, `finding.suppressed`, or the finding/policy hash chains. Corrections are new append events, not edits — the latest annotation per finding wins for effective state. The READ-ONLY (evidence) badge refers to evidence immutability and survives; the UI distinguishes *evidence: immutable/tamper-evident* from *triage: append-only annotations*.
- **New migration, never an edit.** Migration **9** (`_apply_triage_annotations`) creates `triage_annotations` **with** chain columns from the start (brand-new table ⇒ no backfill), with CHECK constraints on `action`/`disposition` and a partial-unique chain index. `LATEST_VERSION=9`; migrations 1–8 are untouched. Never edit or renumber a released migration.
- **Triage chain reuses the one fold.** `storage/evidence_chain.py` adds `TRIAGE_CHAIN_COLUMNS = (finding_id, action, disposition, note, actor, created_at)`; `write_triage_annotation` extends the chain under `BEGIN IMMEDIATE` on a genuine INSERT exactly like `write_policy_decision`, and `verify_triage_chain()` re-folds from disk to detect mutation/reorder/gap/deletion. The DB file stays mode `0600`.
- **Suppress is presentation-only, never a drop.** `suppress`/`unsuppress` set an effective alerting state; they never delete a finding, hide it from a read, or omit it from the export. `effective_suppressed = config suppressed OR latest analyst suppress`; the immutable `suppressed` column is shown truthfully alongside. A suppressed finding remains in `/api/detections`, `/api/detections/{id}`, and the export (**included and marked**).
- **Writes are authenticated, append-only, default-deny.** The five actions are `POST` under `/api/triage/{id}/...` and 401 without a token. There is no `PUT`/`DELETE`/`PATCH` — nothing destructive or editing. `actor` is a self-reported claim (auth has no principal), labelled honestly. Evidence reads stay GET/read-only. The one strengthened test is `test_dashboard_is_served_without_mutation_routes`: it now pins that the *only* non-GET routes are `POST`-only triage writes under `/api/triage/`, each default-deny.
- **Dispositions feed operational efficacy, never the gate.** `detection/operational_efficacy.py` computes counts + **precision** = tp/reviewed over *reviewed fired findings only*, plus a labelled reviewed-FP rate = (fp+benign)/reviewed. It returns `population_false_positive_rate=None` and `recall=None` on purpose — dispositions cover only fired findings, so there are no observed true negatives. It must **not** import `simulation.efficacy`, `simulation.corpus`, `scripts.run_efficacy`, or `ml.evaluation` (pinned by an AST test); a disposition cannot move a gate threshold. Surfaced read-only at `/api/efficacy/operational`.
- **Explanations gained three labelled factors, additively.** `explainability/explainer.py` appends a counterfactual (INTERPRETATION, rule thresholds from `rules_catalog.yaml`), a cross-finding narrative (INTERPRETATION, siblings by `correlation_id`), and baseline provenance (FACT + an INTERPRETATION sufficiency judgment). These append to `contributing_factors` only — `_calculation`/score reconstruction is untouched, and the FACT/INTERPRETATION contract is preserved.
- **Integrity alarm, honest by default.** `/api/integrity` returns the `verify_chain` verdict for findings/policy/triage; the dashboard raises an unmissable banner only when a chain fails and stays silent when all three verify.
- **Console hardening.** Server-side filter/sort/pagination on `/api/detections` (page metadata in `X-Total-Count`/`X-Limit`/`X-Offset` headers; body stays a JSON array), safe DOM construction (no `innerHTML`/`escapeHtml`), a last-updated + stale/disconnected badge that never wipes an open investigation, keyboard nav of the findings table, and an ARIA live region that never steals focus or fights the 10s refresh.

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
- Phase B operational-readiness tests cover the supervised service, supervisor, quarantine, retention, layered config, metrics, alerts, and API authentication (`tests/test_service.py`, `test_supervisor.py`, `test_quarantine.py`, `test_retention.py`, `test_config.py`, `test_metrics.py`, `test_alerts.py`, `test_api_auth.py`).
- Phase C detection-credibility tests cover the efficacy harness + contamination guard, per-rule matching, catalog integrity, the evidence hash-chain (continuity, tamper, dedup-no-link, suppressed-chained, backfill==runtime), and migration-8 additive/idempotent schema (`tests/test_efficacy.py`, `test_rules.py`, `test_rule_catalog.py`, `test_evidence_chain.py`, `test_schema_migrations.py`).
- Phase D analyst-experience tests cover the append-only triage layer (chained writes, corrections as new events, suppress/unsuppress effective state, suppress never dropping a finding from a read or export, auth-required writes, and finding row + finding/policy chains unchanged after triage), operational efficacy from dispositions with a static AST guarantee it never imports the corpus harness or ML gate, the new `/api/integrity` and `/api/efficacy/operational` routes, detections pagination/filter/sort + `X-Total-Count` (invalid params → 422), the three labelled explanation factors, the triage chain in `test_evidence_chain.py`, and migration 9 (`tests/test_triage.py`, `test_operational_efficacy.py`, `test_api_app.py`, `test_explainer.py`, `test_evidence_chain.py`, `test_schema_migrations.py`).
- System-failure detection tests cover empty/unknown/partial telemetry, hysteresis breach + reset, window idempotency across batches, the flap dead-band and breach directionality, memory bands + the available-memory floor, CPU and disk breaches, single/result-failure/collapsed/crash-loop service failures, the persisted detection-only finding shape (`mode`, zero scores, single signal), config validation, and two pipeline integration tests (`tests/test_system_failure.py`).
- Full suite, measured on Python 3.14.6 / pytest 9.1.1: **544 passed, 4 skipped in ~24s**. The only skips are `tests/test_ml_integration.py` (scikit-learn absent). Re-measure before restating this number; report the actual output, and do not hide, weaken, or remove tests to claim a clean run.
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
