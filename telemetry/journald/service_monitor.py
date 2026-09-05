#!/usr/bin/env python3
"""Read-only systemd service lifecycle telemetry from structured journald records."""

import argparse
import json
import re
import subprocess
from typing import Any, Iterable, Iterator, Optional

# Importable both as a package module and as a sibling file: this collector is
# run as `python3 telemetry/journald/service_monitor.py`, where the repository
# root is not on sys.path.
try:
    from telemetry.journald.auth_session_monitor import _integer
    from telemetry.journald.journal_stream import add_stream_arguments, run_collector
except ImportError:
    from auth_session_monitor import _integer
    from journal_stream import add_stream_arguments, run_collector

COLLECTOR_NAME = "service"

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
    """
    One-shot query over a fixed window.

    Retained for scripted and ad-hoc use, not for live collection: it buffers the
    whole result and cannot resume. The supervised path is `run_collector`, which
    streams and persists a cursor. `tests/test_journal_stream.py` pins that both
    paths derive the same events from the same journalctl output, so this cannot
    drift away from the live behaviour it mirrors.
    """
    result = subprocess.run(
        ["journalctl", "--no-pager", "--output=json", "--since", since],
        capture_output=True, text=True, check=False, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"journalctl exited with status {result.returncode}")
    yield from parse_journal_json(result.stdout.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only systemd service lifecycle telemetry from journald.")
    add_stream_arguments(parser)
    args = parser.parse_args()
    return run_collector(COLLECTOR_NAME, normalize_journal_record, args)


if __name__ == "__main__":
    raise SystemExit(main())
