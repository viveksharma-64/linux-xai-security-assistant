# Phase 1 — Linux Telemetry PoC

> **Historical guide:** This document records the original Phase 1 process/TCP proof-of-concept workflow. It is not the current telemetry status or full-project runbook. All planned telemetry families are now **LIVE VERIFIED**; see [AGENTS.md](../AGENTS.md) and [README.md](../README.md) for the submission state.

## Objective

Using **BCC (not bpftrace)** in Python, attach to process-execution and
TCP-connect kernel events, and print each event as a structured JSON
line in real time, on your actual Kali VM kernel. `bpftrace` is used
beforehand only as an optional sanity check that the underlying
tracepoints/kprobes exist and fire — it is not part of the shipped app.

## Explicit non-goals for Phase 1

No SQLite, no FastAPI, no ML, no LLM interface, no policy engine yet.
Those start Phase 2 onward.

## Steps

### 1. Copy the project to your Kali VM

Copy the whole `linux-xai-security-assistant/` folder onto your Kali VM
(shared folder, scp, or however you move files into VirtualBox).

### 2. Install prerequisites

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc libbpfcc-dev \
    linux-headers-$(uname -r) auditd audispd-plugins

# bpftrace is optional/best-effort on Kali — see note below
sudo apt install -y bpftrace || echo "bpftrace unavailable on this snapshot — not required, continuing"
```

### 3. Run environment verification

```bash
cd linux-xai-security-assistant
bash scripts/verify_environment.sh | tee docs/phase1_verification_output.txt
```

Read the PASS/WARN/FAIL summary at the end. Do not proceed past any
`[FAIL]` line without resolving it — send me the output if anything
fails and we'll debug it together before touching the BCC PoC.

### 4. (Optional) Sanity-check kernel probes with bpftrace

Only if bpftrace installed successfully in step 2:

```bash
sudo bpftrace telemetry/bpftrace/verify_probes.bt
```

In another terminal, run something like `ls /tmp` and `curl https://example.com`
to trigger events, and confirm lines print. Ctrl+C to stop.

### 5. Run the real Phase 1 PoC (BCC)

```bash
sudo python3 telemetry/bcc/process_exec_probe.py
```

In another terminal, generate some activity:

```bash
ls /tmp
curl -s https://example.com > /dev/null
whoami
```

You should see JSON lines like:

```json
{"event_type": "process_exec", "timestamp": 1755400000.12, "pid": 4821, "uid": 1000, "comm": "ls", "filename": "/usr/bin/ls"}
{"event_type": "tcp_connect", "timestamp": 1755400001.44, "pid": 4830, "uid": 1000, "comm": "curl", "dest_ip": "93.184.216.34", "dest_port": 443}
```

Ctrl+C to stop the probe.

## What to send back before Phase 2

1. Full output of `scripts/verify_environment.sh`.
2. A short sample (10-20 lines) of real JSON output from
   `process_exec_probe.py` running on your VM.
3. Any errors encountered, verbatim.

## Known Kali-specific risk (already accounted for)

Kali-rolling has, at times, dropped the `bpftrace` package from its repo
entirely. This does **not** block Phase 1 — `bpftrace` is optional
debug tooling only. If step 2's bpftrace install fails, skip straight to
step 5; BCC is the layer that matters and is confirmed available in
Kali's main repo (`bpfcc-tools`, `python3-bpfcc`).
