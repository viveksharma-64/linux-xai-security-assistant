#!/usr/bin/env python3
"""Read-only systemd service lifecycle telemetry from structured journald records."""

import argparse
import json
import re
import subprocess
import time
from typing import Any, Iterable, Iterator, Optional

from telemetry.journald.auth_session_monitor import _integer

_UNIT_NAME = re.compile(r"\b(?P<unit>[^\s]+\.(?:service|target|scope|timer|socket|path))\b")


def _lifecycle(message: str) -> Optional[tuple[str, str, str]]:
    """Classify only explicit systemd-manager lifecycle statements."""
    unit_match = _UNIT_NAME.search(message)
    if unit_match is None:
        return None
    unit = unit_match.group("unit")
    if message.startswith("Started "):
        return unit, "started", "success"
    if message.startswith("Stopped "):
        return unit, "stopped", "success"
    if message.startswith("Failed to start ") or " entered failed state." in message:
        return unit, "failed", "failure"
    return None


def normalize_journal_record(record: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map an explicit systemd unit lifecycle record without inferring state."""
    reporter_unit = record.get("_SYSTEMD_UNIT")
    message = record.get("MESSAGE")
    identifier = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM")
    if not isinstance(reporter_unit, str) or not reporter_unit or not isinstance(message, str) or identifier != "systemd":
        return None
    lifecycle = _lifecycle(message)
    timestamp_us = _integer(record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP"))
    if lifecycle is None or timestamp_us is None or timestamp_us <= 0:
        return None
    unit, action, result = lifecycle
    return {
        "event_type": "service_state",
        "timestamp": timestamp_us / 1_000_000,
        "pid": _integer(record.get("_PID") or record.get("SYSLOG_PID")),
        "uid": _integer(record.get("_UID")),
        "comm": identifier,
        "unit": unit,
        "reporter_unit": reporter_unit,
        "action": action,
        "result": result,
        "message": message,
        "source": "journald_systemd",
        "version": "1.0",
    }


def parse_journal_json(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for line in lines:
        try:
            record = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(record, dict):
            event = normalize_journal_record(record)
            if event is not None:
                yield event


def read_journal(since: str) -> Iterator[dict[str, Any]]:
    result = subprocess.run(
        ["journalctl", "--no-pager", "--output=json", "--since", since],
        capture_output=True, text=True, check=False, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"journalctl exited with status {result.returncode}")
    yield from parse_journal_json(result.stdout.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only systemd service lifecycle query from journald.")
    parser.add_argument("--since", default="10 minutes ago", help="journald --since expression")
    args = parser.parse_args()
    print(json.dumps({"event_type": "telemetry_startup", "message": "journald service query starting", "timestamp": time.time()}), flush=True)
    try:
        for event in read_journal(args.since):
            print(json.dumps(event, sort_keys=True), flush=True)
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(json.dumps({"event_type": "telemetry_warning", "message": f"journald service query failed: {error}", "timestamp": time.time()}), flush=True)
        return 1
    print(json.dumps({"event_type": "telemetry_shutdown", "message": "journald service query finished", "timestamp": time.time()}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
