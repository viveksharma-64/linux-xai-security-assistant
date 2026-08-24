# Linux XAI Security Assistant

AI-powered, explainable Linux security assistant for kernel-level intrusion
and behavioral threat/failure detection. Built for the C-DAC Hackathon.

## Status

**Project hardening checkpoint: all telemetry families are live verified; ML infrastructure is implemented but no model is approved for activation.**

Target environment for this build: **Kali Linux (rolling), running in VirtualBox.**

## Architecture (target)

```
Linux Kernel
   |
   v
Collectors  -->  JSONL  -->  Canonical Event normalization  -->  Bounded ingestion
   -->  SQLite  -->  Detection/fusion  -->  Evidence/explainability
   -->  Advisory AI assistant  -->  Fail-closed policy
   -->  FastAPI read-only API  -->  Dashboard
```

Key design constraints:
- The full detection -> explainability -> scoring -> response pipeline
  MUST work with **no LLM/API access at all**. The LLM is an optional
  narrator bolted on top of structured evidence — never the decision-maker.
- `bpftrace` is used ONLY for ad-hoc debugging/verification of kernel
  probes. The actual application telemetry layer is BCC + Python.
- All automated remediation is policy-gated. The LLM never executes
  commands directly.

## Folder layout

| Folder | Responsibility |
|---|---|
| `telemetry/bpftrace/` | One-off `.bt` scripts to verify kernel probes fire (debug only, not shipped) |
| `telemetry/bcc/` | BCC + Python collectors — the real telemetry layer |
| `telemetry/health/` | System health signals (CPU/mem/swap/disk/service) — scaffolded Phase 1, implemented Phase 2+ |
| `pipeline/` | Event collector, normalizer, feature extractor (Phase 2) |
| `baseline/` | Host-level behavioral baseline, later per-process/user (Phase 3) |
| `detection/` | ML models, rule engine, fusion, risk scoring (Phase 4) |
| `explainability/` | Feature-contribution / evidence generation (Phase 5) |
| `assistant/` | Abstract LLM client interface + narrator (Phase 6, optional) |
| `policy/` | policy.yaml + policy engine (Phase 7) |
| `response/` | Reserved future response boundary; no executor is implemented |
| `storage/` | SQLite schema + data access (Phase 2+) |
| `api/` | FastAPI read-only API |
| `dashboard/` | Static read-only security dashboard |
| `simulation/` | Reserved for controlled demo scenarios |
| `scripts/` | Environment setup/verification scripts |
| `docs/` | Phase notes, verification logs |

## Verified reality

- Real BCC/eBPF `syscalls:sys_enter_execve` process telemetry is verified on Kali kernel `7.0.12+kali-amd64`.
- The verified capture contains 136 total lines: 134 `process_exec`, 1 `telemetry_startup`, and 1 `system_health`.
- Real BCC/eBPF `sched:sched_process_exec` post-exec telemetry is also verified: 115 real `process_exec` events included consistent kernel-captured executable paths plus optional parent context.
- The real capture is validation evidence only and is not sufficient to promote a normal baseline.
- **LIVE VERIFIED**: process execution, post-exec process context, file access, network activity, authentication/session, system/service lifecycle, and IPC.
- Network uses `sock:inet_sock_set_state`; controlled validation captured PID `32379`, UID `1000`, `python3`, connecting to `127.0.0.1:18080`.
- Authentication/session uses structured `journald_pam` records; controlled sudo PAM session evidence captured PID `37934`, UID `1000`, and `session_opened`/`session_closed`.
- System/service lifecycle uses structured journald/systemd records; `systemd-timedated.service` was captured starting successfully.
- IPC uses the BCC `pipe`/`pipe2` kprobe. Controlled validation captured PID `40231`, UID `1000`, `python3`, read FD `3`, write FD `4`, and endpoint `fd:3->fd:4`; canonical ingestion persisted one `ipc_event` with no malformed or dropped events.
- No telemetry category remains unverified.
- **ML IMPLEMENTED, MODEL NOT APPROVED**: `canonical-window.v1` has explicit verified-normal provenance, reproducible inactive Isolation Forest training, checksum/schema validation, training-range diagnostics, held-out evaluation, and additive explainability/detection integration. ML failure falls back to deterministic detection.
- The current 18-window verified-normal experiment (`iforest-6ef9e765-8bc8-4bfc-b8d5-e1ebd18730e7`) remains inactive. Its historical five-window normal evaluation had 2 false positives (40% FPR), so it fails the fixed 5% acceptance criterion. The original holdout #1 is unavailable; do not claim a new five-window FPR from the preserved four holdouts.
- Future activation requires independent reviewed-normal holdouts with observed FPR and one-sided 95% FPR upper bound at or below 5%, with at least 60 holdout windows. The decision boundary is not independently calibrated until that evidence exists.
- See `AGENTS.md` for the authoritative handoff, validation evidence, architectural constraints, and the next ML task.
- `docs/phase1_sample_events.jsonl` is synthetic fixture data only.
- The AI assistant is advisory; policy decisions are deterministic; no remediation or command execution exists.

## Run the read-only dashboard

```bash
SECURITY_DB_PATH=/path/to/phase2_events.db python3 -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/dashboard/`.

## Historical Phase 1 setup

1. Copy this project to your Kali VM.
2. Run `scripts/verify_environment.sh` and record its output — do not
   proceed until this passes (or you understand why a step is skipped).
3. Read `docs/PHASE1_README.md` for exact objectives and how to run the
   bpftrace verification scripts and the BCC PoC.
4. Keep the output as environment evidence. Only capabilities explicitly marked verified should be presented as live functionality.
