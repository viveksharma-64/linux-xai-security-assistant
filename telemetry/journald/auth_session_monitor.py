#!/usr/bin/env python3
"""Read-only authentication/session telemetry from structured journald records."""

import argparse
import json
import re
import subprocess
from typing import Any, Iterable, Iterator, Optional

# Importable both as a package module and as a sibling file: this collector is
# run as `python3 telemetry/journald/auth_session_monitor.py`, where the
# repository root is not on sys.path.
try:
    from telemetry.journald.journal_stream import add_stream_arguments, run_collector
except ImportError:
    from journal_stream import add_stream_arguments, run_collector

COLLECTOR_NAME = "auth"


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
    """
    One-shot query over a fixed window.

    Retained for scripted and ad-hoc use, not for live collection: it buffers the
    whole result and cannot resume. The supervised path is `run_collector`, which
    streams and persists a cursor. `tests/test_journal_stream.py` pins that both
    paths derive the same events from the same journalctl output, so this cannot
    drift away from the live behaviour it mirrors.
    """
    command = ["journalctl", "--no-pager", "--output=json", "--since", since]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"journalctl exited with status {result.returncode}")
    yield from parse_journal_json(result.stdout.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only PAM/session telemetry from journald.")
    add_stream_arguments(parser)
    args = parser.parse_args()
    return run_collector(COLLECTOR_NAME, normalize_journal_record, args)


if __name__ == "__main__":
    raise SystemExit(main())
