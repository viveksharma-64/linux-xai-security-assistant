#!/usr/bin/env python3
"""
Minimal file-access telemetry for Phase 1.

Priority:
1. auditd (preferred if the environment is root-capable and auditd is usable)
2. inotifywait fallback for a controlled, real Linux filesystem watch in a
   root-capable shell when auditd is not available

This module intentionally does not generate synthetic events.
It emits real file events only from the Linux system it is running on.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import shlex
from pathlib import Path


CANONICAL_EVENT_TYPES = {"file_open", "file_write"}
SYSCALL_NAMES = {
    1: "write", 2: "open", 20: "writev", 76: "truncate", 82: "rename",
    85: "creat", 87: "unlink", 257: "openat", 263: "unlinkat",
    264: "renameat", 316: "renameat2", 437: "openat2",
}
OPEN_OPERATIONS = {"open", "openat", "openat2", "creat"}
FILE_OPERATIONS = set(SYSCALL_NAMES.values())


def print_json(obj):
    print(json.dumps(obj, separators=(",", ":"), sort_keys=True), flush=True)


def is_root() -> bool:
    return os.geteuid() == 0


def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


def auditd_status() -> tuple[bool, str]:
    if not is_root():
        return False, "auditd requires root; the current process is not root"
    for binary in ("auditd", "auditctl", "ausearch"):
        if not cmd_exists(binary):
            return False, f"missing required auditd binary: {binary}"
    return True, "auditd available"


def install_auditd_rules(watch_path: str = "/tmp", rule_key: str = "linux_xai_file_access") -> None:
    if not is_root():
        raise PermissionError("auditd rules require root")
    path = Path(watch_path)
    if not path.is_absolute() or not path.exists() or not path.is_dir():
        raise ValueError("watch_path must be an existing absolute directory")

    # Add only scoped rules. Existing audit rules must remain untouched.
    rule_specs = [
        ["auditctl", "-a", "always,exit", "-F", "arch=b64", "-F", f"dir={path}", "-S", "open,openat,openat2,creat,truncate,write,writev,rename,renameat,renameat2,unlink,unlinkat", "-F", "auid>=1000", "-F", "auid!=4294967295", "-k", rule_key],
        ["auditctl", "-a", "always,exit", "-F", "arch=b32", "-F", f"dir={path}", "-S", "open,openat,creat,truncate,write,writev,rename,renameat,unlink,unlinkat", "-F", "auid>=1000", "-F", "auid!=4294967295", "-k", rule_key],
    ]

    for cmd in rule_specs:
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError(f"unable to install additive audit rule: {error}") from error


def parse_ausearch_text(raw: str):
    """Parse minimal auditd text output into canonical event dictionaries."""
    records = []
    current = {}
    ts_re = re.compile(r"msg=audit\((?P<ts>[^:]+):\d+\)\:")

    def flush_current():
        if not current:
            return
        ts_val = current.get("timestamp")
        if not ts_val:
            return
        operation = current.get("operation", "file_access")
        event = {
            "event_type": "file_open" if operation in OPEN_OPERATIONS else "file_write",
            "timestamp": float(ts_val),
            "pid": current.get("pid"),
            "ppid": current.get("ppid"),
            "uid": current.get("uid"),
            "gid": current.get("gid"),
            "comm": current.get("comm"),
            "executable": current.get("executable"),
            "filename": current.get("path"),
            "path": current.get("path"),
            "operation": operation,
            "success": current.get("success") in ("yes", "true", "True", True),
            "source": "auditd",
            "version": "1.0",
            "payload": {
                "filename": current.get("path"),
                "path": current.get("path"),
                "operation": operation,
                "success": current.get("success") in ("yes", "true", "True", True),
            },
        }
        records.append(event)

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("----"):
            flush_current()
            current = {}
            continue
        if line.startswith("type=SYSCALL") and current.get("timestamp") is not None:
            flush_current()
            current = {}
        m = ts_re.search(line)
        if m:
            try:
                current["timestamp"] = float(m.group("ts"))
            except ValueError:
                current = {}
                continue

        if line.startswith("type=SYSCALL"):
            try:
                kvs = shlex.split(line)
            except ValueError:
                continue
            for pair in kvs:
                if "=" not in pair:
                    continue
                key, val = pair.split("=", 1)
                val = val.strip('"')
                if key in {"pid", "ppid", "uid", "gid"}:
                    try:
                        current[key] = int(val)
                    except ValueError:
                        current.pop(key, None)
                elif key == "comm":
                    current["comm"] = val
                elif key == "exe":
                    current["executable"] = val
                elif key == "success":
                    current["success"] = val
                elif key == "syscall":
                    try:
                        current["operation"] = SYSCALL_NAMES.get(int(val), val.lower())
                    except ValueError:
                        current["operation"] = val.lower()
        elif line.startswith("type=PATH"):
            try:
                kvs = shlex.split(line)
            except ValueError:
                continue
            for pair in kvs:
                if "=" not in pair:
                    continue
                key, val = pair.split("=", 1)
                if key == "name":
                    current["path"] = val.strip('"')
        elif line.startswith("type=EXECVE"):
            for pair in line.split():
                if "=" not in pair:
                    continue
                key, val = pair.split("=", 1)
                if key == "comm":
                    current["comm"] = val.strip('"')

    flush_current()
    unique_records = []
    seen = set()
    for record in records:
        signature = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if signature in seen:
            continue
        seen.add(signature)
        unique_records.append(record)
    return unique_records


def _filter_capture_records(records: list[dict], start_time: float, end_time: float) -> list[dict]:
    """Keep only file syscalls from this invocation's precise capture window."""
    return [
        record for record in records
        if start_time <= float(record.get("timestamp", 0.0)) <= end_time
        and record.get("comm") != "auditctl"
        and record.get("operation") in FILE_OPERATIONS
    ]


def run_auditd_capture(duration_seconds: int = 30, watch_path: str = "/tmp") -> list[dict]:
    if not is_root():
        raise PermissionError("auditd file monitoring requires root")
    ok, reason = auditd_status()
    if not ok:
        raise RuntimeError(reason)

    install_auditd_rules(watch_path=watch_path)
    records = []
    start_time = time.time()

    try:
        # ausearch is a point-in-time query, not a live stream. Wait while the
        # additive rule observes the controlled workload, then query the window.
        time.sleep(duration_seconds)
        end_time = time.time()
        # Keep epoch timestamps so parse_ausearch_text can associate records
        # reliably; human-readable date conversion is lossy for this parser.
        cmd = ["ausearch", "-k", "linux_xai_file_access", "-ts", "recent", "--format", "raw"]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=10)
        stdout = result.stdout
        if stdout:
            records.extend(_filter_capture_records(parse_ausearch_text(stdout), start_time, end_time))
        if result.returncode not in (0, 1):
            raise RuntimeError(f"ausearch failed with status {result.returncode}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("ausearch timed out while reading audit records") from error

    return records


def run_inotify_fallback(watch_path: str = "/tmp", duration_seconds: int = 30) -> list[dict]:
    if not cmd_exists("inotifywait"):
        raise RuntimeError("Neither auditd nor inotifywait is available on this system")

    path = Path(watch_path)
    if not path.exists():
        raise FileNotFoundError(f"Watch path does not exist: {watch_path}")

    cmd = [
        "inotifywait",
        "-m",
        "-e",
        "close_write,create,modify,attrib,delete,delete_self,moved_to,moved_from",
        "--format",
        "%T %w%f %e",
        str(path),
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    records = []
    try:
        deadline = time.time() + duration_seconds
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            ts = float(parts[0])
            path_text = parts[1]
            op = parts[2]
            event_type = "file_write" if op.lower() in {"close_write", "modify", "create", "moved_to"} else "file_open"
            records.append({
                "event_type": event_type,
                "timestamp": ts,
                "pid": None,
                "uid": None,
                "comm": None,
                "operation": op,
                "path": path_text,
                "success": True,
                "source": "inotifywait",
                "version": "1.0",
                "payload": {
                    "path": path_text,
                    "operation": op,
                    "success": True,
                },
            })
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    return records


def main():
    if len(sys.argv) > 1:
        watch_path = sys.argv[1]
    else:
        watch_path = "/tmp"

    print_json({
        "event_type": "telemetry_startup",
        "message": "file access telemetry starting",
        "timestamp": time.time(),
        "source": "auditd_file_monitor",
    })

    try:
        ok, reason = auditd_status()
        if ok:
            events = run_auditd_capture(duration_seconds=15, watch_path=watch_path)
        else:
            print_json({
                "event_type": "telemetry_warning",
                "message": f"auditd not usable here: {reason}; falling back to inotifywait if available",
                "timestamp": time.time(),
            },)
            try:
                events = run_inotify_fallback(watch_path=watch_path, duration_seconds=15)
            except Exception as e:
                print_json({
                    "event_type": "telemetry_warning",
                    "message": f"file telemetry unavailable: {e}",
                    "timestamp": time.time(),
                })
                return 1
        for event in events:
            print_json(event)
        print_json({
            "event_type": "telemetry_shutdown",
            "message": "file access telemetry finished",
            "timestamp": time.time(),
        })
        return 0
    except Exception as exc:
        print_json({
            "event_type": "telemetry_warning",
            "message": f"file telemetry failed: {exc}",
            "timestamp": time.time(),
        })
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
