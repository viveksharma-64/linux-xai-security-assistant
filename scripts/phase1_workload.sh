#!/bin/bash
#
# phase1_workload.sh
#
# Generates realistic system activity to test Phase 1 telemetry collection.
# Covers: process execution, TCP connections, file operations, authentication, services.
#
# Usage:
#   bash scripts/phase1_workload.sh
#

set -e

echo "[*] Phase 1 Test Workload — Generating realistic system activity..."
echo

# Temporary directory for test files (use home dir to avoid sandbox restrictions)
TESTDIR="$HOME/.phase1_test_$$"
mkdir -p "$TESTDIR"
trap "rm -rf $TESTDIR" EXIT

# ============================================================================
# 1. PROCESS EXECUTION EVENTS
# ============================================================================
echo "[1/7] Process Execution Events..."
ls /usr/bin > "$TESTDIR/listing.txt"
find /tmp -name "*.tmp" -type f 2>/dev/null | head -10 > "$TESTDIR/find_results.txt" || true
grep -r "root" /etc/passwd > "$TESTDIR/grep_results.txt" 2>/dev/null || true
whoami > "$TESTDIR/whoami.txt"
id >> "$TESTDIR/whoami.txt"
ps aux | head -5 >> "$TESTDIR/ps_output.txt"
sleep 1

# ============================================================================
# 2. FILE OPERATIONS (open/write)
# ============================================================================
echo "[2/7] File Operations..."
touch "$TESTDIR/file1.txt"
touch "$TESTDIR/file2.txt"
echo "Test data line 1" > "$TESTDIR/file1.txt"
echo "Test data line 2" >> "$TESTDIR/file1.txt"
echo "Test data line 3" >> "$TESTDIR/file1.txt"
cat "$TESTDIR/file1.txt" > "$TESTDIR/file2.txt"
echo "Appended data" >> "$TESTDIR/file2.txt"
dd if=/dev/zero of="$TESTDIR/largefile.bin" bs=1M count=1 2>/dev/null
sleep 1

# ============================================================================
# 3. TCP/NETWORK CONNECTIONS
# ============================================================================
echo "[3/7] Network Activity (TCP connections)..."
# Try to connect to example.com:443
timeout 5 curl -s -o /dev/null https://example.com 2>/dev/null || echo "  (curl completed or timed out)"
timeout 5 curl -s -o /dev/null https://www.google.com 2>/dev/null || echo "  (curl completed or timed out)"

# DNS lookups (also go via TCP/UDP)
timeout 5 nslookup example.com 8.8.8.8 2>/dev/null | head -5 || true
sleep 1

# ============================================================================
# 4. USER/AUTHENTICATION EVENTS
# ============================================================================
echo "[4/7] Authentication & User Events..."
# These generate auditd records
whoami
id
groups
# Try to check sudo (doesn't require privilege)
sudo -l 2>/dev/null || echo "  (sudo -l skipped)"
sleep 1

# ============================================================================
# 5. SYSTEM INFORMATION QUERIES
# ============================================================================
echo "[5/7] System Information..."
uname -a
hostnamectl status 2>/dev/null || echo "  (hostnamectl skipped)"
df -h /
free -h
sleep 1

# ============================================================================
# 6. SERVICE & PROCESS ENUMERATION
# ============================================================================
echo "[6/7] Service/Process Queries..."
systemctl status --no-pager ssh 2>/dev/null | head -10 || true
journalctl -n 5 --no-pager 2>/dev/null || true
pgrep -a python | head -3 || true
sleep 1

# ============================================================================
# 7. PIPE & STREAM DATA
# ============================================================================
echo "[7/7] Pipes & Stream Operations..."
echo "Stream data test" | cat > "$TESTDIR/stream.txt"
cat "$TESTDIR/stream.txt" | wc -l
seq 1 100 | tail -10 > "$TESTDIR/seq_output.txt"
sleep 1

echo
echo "[✓] Workload complete. Test files in: $TESTDIR"
echo "[✓] Check telemetry output for captured events."
