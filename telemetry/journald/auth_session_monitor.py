#!/usr/bin/env python3
"""Read-only authentication/session telemetry from structured journald records."""

import argparse
import json
import re
import subprocess
import sys
import time
from typing import Any, Iterable, Iterator, Optional


_PAM_SESSION = re.compile(
    r"pam_[^(]+\((?P<service>[^:()]+):session\): session "
    r"(?P<action>opened|closed) for user (?P<account>[^\s(]+)",
    re.IGNORECASE,
)
_PAM_FAILURE = re.compile(r"pam_[^(]+\((?P<service>[^:()]+):auth\): authentication failure", re.IGNORECASE)


def _integer(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def normalize_journal_record(record: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a recognized PAM record to canonical raw JSON without inventing fields."""
    message = record.get("MESSAGE")
    if not isinstance(message, str):
        return None
    session = _PAM_SESSION.search(message)
    failure = _PAM_FAILURE.search(message)
    if session:
        action = f"session_{session.group('action').lower()}"
        result = "success"
        service = session.group("service")
        account = session.group("account")
    elif failure:
        action = "authentication"
        result = "failure"
        service = failure.group("service")
        account = None
    else:
        return None

    timestamp_us = _integer(record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP"))
    if timestamp_us is None or timestamp_us <= 0:
        return None
    return {
        "event_type": "auth_session",
        "timestamp": timestamp_us / 1_000_000,
        "pid": _integer(record.get("_PID") or record.get("SYSLOG_PID")),
        "uid": _integer(record.get("_UID")),
        "comm": record.get("SYSLOG_IDENTIFIER") or record.get("_COMM"),
        "action": action,
        "result": result,
        "service": service,
        "account": account,
        "message": message,
        "source": "journald_pam",
        "version": "1.0",
    }


def parse_journal_json(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for line in lines:
        try:
            record = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        event = normalize_journal_record(record)
        if event is not None:
            yield event


def read_journal(since: str) -> Iterator[dict[str, Any]]:
    command = ["journalctl", "--no-pager", "--output=json", "--since", since]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"journalctl exited with status {result.returncode}")
    yield from parse_journal_json(result.stdout.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only PAM/session telemetry from journald.")
    parser.add_argument("--since", default="10 minutes ago", help="journald --since expression")
    args = parser.parse_args()
    print(json.dumps({"event_type": "telemetry_startup", "message": "journald authentication query starting", "timestamp": time.time()}), flush=True)
    try:
        for event in read_journal(args.since):
            print(json.dumps(event, sort_keys=True), flush=True)
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(json.dumps({"event_type": "telemetry_warning", "message": f"journald authentication query failed: {error}", "timestamp": time.time()}), flush=True)
        return 1
    print(json.dumps({"event_type": "telemetry_shutdown", "message": "journald authentication query finished", "timestamp": time.time()}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
