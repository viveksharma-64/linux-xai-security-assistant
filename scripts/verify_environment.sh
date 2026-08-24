#!/usr/bin/env bash
#
# verify_environment.sh
#
# Verifies (does NOT assume) that this Kali Linux host can support the
# BCC-based telemetry layer for Phase 1. Every check prints a clear
# PASS/WARN/FAIL line. Run this BEFORE any telemetry code, and keep the
# output — it goes into docs/phase1_verification.md.
#
# Usage: bash scripts/verify_environment.sh

set -u
PASS=0
WARN=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
warn() { echo "[WARN] $1"; WARN=$((WARN+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=================================================="
echo " Linux XAI Security Assistant — Environment Check"
echo "=================================================="
echo

echo "--- OS release ---"
if [ -f /etc/os-release ]; then
    cat /etc/os-release
    if grep -qi "kali" /etc/os-release; then
        pass "Running on Kali Linux, as expected."
    else
        warn "OS does not identify as Kali — double-check this is the intended VM."
    fi
else
    fail "/etc/os-release not found — cannot identify OS."
fi
echo

echo "--- Kernel version ---"
KVER=$(uname -r)
echo "uname -r => $KVER"
pass "Kernel version recorded: $KVER"
echo

echo "--- BTF support (needed for CO-RE style BCC programs) ---"
if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "BTF present at /sys/kernel/btf/vmlinux"
else
    warn "BTF NOT found. BCC programs may still work using kernel headers, but CO-RE-style probes will not. Will need to fall back to header-based compilation."
fi
echo

echo "--- bpftool feature probe (bpf_syscall / btf) ---"
if command -v bpftool >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        bpftool feature probe 2>/dev/null | grep -E "bpf_syscall|btf" || warn "bpftool ran but no matching bpf_syscall/btf lines found."
    else
        echo "(re-run as root for full bpftool feature probe output)"
        sudo bpftool feature probe 2>/dev/null | grep -E "bpf_syscall|btf" || warn "bpftool ran but no matching bpf_syscall/btf lines found."
    fi
else
    warn "bpftool not installed. Install with: sudo apt install linux-tools-common linux-tools-\$(uname -r) (or bpftool directly if packaged for your kernel)."
fi
echo

echo "--- Kernel headers ---"
if [ -d "/usr/src/linux-headers-$KVER" ] || [ -d "/lib/modules/$KVER/build" ]; then
    pass "Kernel headers appear present for $KVER."
else
    warn "Kernel headers NOT found for $KVER. Try: sudo apt install linux-headers-\$(uname -r). Note: on Kali's custom kernel this package may not exist under that exact name — check 'apt-cache search linux-headers' if the direct install fails."
fi
echo

echo "--- BCC (bpfcc-tools / python3-bpfcc) ---"
if dpkg -l | grep -q bpfcc-tools 2>/dev/null; then
    pass "bpfcc-tools package is installed."
else
    warn "bpfcc-tools not installed yet. Install with: sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc libbpfcc-dev"
fi

BCC_IMPORT_ERR=$(mktemp "${TMPDIR:-/tmp}/linux-xai-bcc-import.XXXXXX" 2>/dev/null || true)
if [ -n "$BCC_IMPORT_ERR" ] && python3 -c "import bcc; print('BCC python module OK:', bcc.__file__)" 2>"$BCC_IMPORT_ERR"; then
    pass "python3 'import bcc' succeeded."
else
    if [ -z "$BCC_IMPORT_ERR" ]; then
        warn "BCC import could not be checked because no writable temporary path was available."
    else
        fail "python3 'import bcc' failed. Error was:"
        cat "$BCC_IMPORT_ERR"
        echo "Likely fix: sudo apt install -y python3-bpfcc"
        rm -f "$BCC_IMPORT_ERR"
    fi
fi
echo

echo "--- bpftrace (debug/verification tool only — NOT part of the shipped app) ---"
if command -v bpftrace >/dev/null 2>&1; then
    bpftrace --version
    if [ "$(id -u)" -eq 0 ]; then
        bpftrace -e 'BEGIN { printf("eBPF OK via bpftrace\n"); exit(); }' 2>&1
    else
        sudo bpftrace -e 'BEGIN { printf("eBPF OK via bpftrace\n"); exit(); }' 2>&1
    fi
    pass "bpftrace available and executed a probe."
else
    warn "bpftrace not installed or not found. This is a KNOWN issue on some Kali-rolling snapshots (the package has been intermittently pulled from the repo). This is NOT a blocker — the application telemetry layer uses BCC, not bpftrace. bpftrace is only used here for quick manual verification. If you want it anyway, try: sudo apt update && sudo apt install -y bpftrace"
fi
echo

echo "--- auditd (fallback telemetry source) ---"
if command -v auditctl >/dev/null 2>&1; then
    pass "auditd tools present."
else
    warn "auditd not installed. Install with: sudo apt install -y auditd audispd-plugins"
fi
echo

echo "--- Privilege check ---"
if [ "$(id -u)" -eq 0 ]; then
    pass "Running as root — BCC probes will be able to attach."
else
    warn "Not running as root. BCC probe attachment (CAP_BPF/CAP_SYS_ADMIN) will need sudo when we run the actual PoC."
fi
echo

echo "=================================================="
echo " Summary: $PASS passed, $WARN warnings, $FAIL failed"
echo "=================================================="
if [ "$FAIL" -gt 0 ]; then
    echo "One or more checks FAILED. Resolve these before running the BCC PoC."
    exit 1
else
    echo "No hard failures. Review warnings, then proceed to telemetry/bcc/process_exec_probe.py"
    exit 0
fi
