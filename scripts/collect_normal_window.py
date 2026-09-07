#!/usr/bin/env python3
"""
Promote one reviewed five-minute window of live telemetry into a candidate
verified-normal dataset.

This is the operator-facing step of the verified-normal corpus program
(docs/NORMAL_CORPUS_PROGRAM.md). It reads events from a *source capture* store
(a normal SQLiteEventStore that a collector filled on a live host) and appends
them, as one window, to a *candidate dataset* store via the existing
``ml/training.py`` verified-normal API:

    create_verified_normal_dataset(...)   # one immutable dataset header
    add_verified_normal_window(...)        # one immutable feature window

It deliberately adds NO new ML path. Two boundaries are load-bearing:

* **It cannot self-approve.** ``verified_normal`` is an operator attestation of
  human review, not something a script may assert on its own behalf. This tool
  refuses to write unless the operator passes ``--i-verified-normal`` together
  with ``--operator`` and ``--reason``; ``ml/training.py`` independently rejects
  any window whose verification is not ``verified_normal=True``. The flag is the
  human saying "I reviewed this window and it is benign" -- the script only
  records that attestation, it never manufactures it.
* **It never mutates the source capture.** The source is opened read-only
  (``mode=ro``), so an operator's raw capture is untouched -- and older-schema
  captures (missing later columns) are read tolerantly rather than migrated.

Everything the tool writes goes to the candidate dataset store, which inherits
the store's ``0600`` file mode. Whether a window counts toward the ML gate's
holdout budget is recorded as the dataset's ``role`` (``holdout`` | ``training``)
and read back by ``scripts/corpus_status.py``.

    # inspect a capture without writing anything (no attestation needed):
    python3 scripts/collect_normal_window.py --source capture.db --dry-run

    # create a new holdout dataset and add this window to it (operator attests):
    python3 scripts/collect_normal_window.py \\
        --source capture.db --dataset-db corpus/normal.db \\
        --dataset-name "kali-desktop-holdout" --role holdout \\
        --operator alice --reason "idle desktop, reviewed logs" \\
        --i-verified-normal

    # add another window to an existing dataset:
    python3 scripts/collect_normal_window.py \\
        --source capture2.db --dataset-db corpus/normal.db \\
        --dataset-id verified-normal-... --role holdout \\
        --operator alice --reason "..." --i-verified-normal
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Runnable as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_schema import SCHEMA_VERSION, extract_features, schema_hash  # noqa: E402
from ml.training import (  # noqa: E402
    add_verified_normal_window,
    create_verified_normal_dataset,
)
from pipeline.event_stream import Event, EventType  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402

_ROLES = ("holdout", "training")


def _row_to_event(row: sqlite3.Row) -> Event:
    """
    Rebuild a canonical ``Event`` from a persisted ``events`` row, tolerantly.

    This mirrors ``SQLiteEventStore._row_to_event`` but reads every optional
    column defensively (``name in row.keys()``) so it also accepts captures made
    by an older store version that predates a later column (e.g. ``host_id`` /
    ``timestamp_monotonic``). We cannot reuse the store's own reader for that:
    it must open the source read-write to migrate before it can index those
    columns, and this tool must never write to the operator's raw capture.
    """
    keys = set(row.keys())

    def value(name: str, default: Any = None) -> Any:
        return row[name] if name in keys else default

    payload_json = value("payload_json")
    ancestry_json = value("ancestry_json")
    return Event(
        event_type=EventType(value("event_type") or "process_exec"),
        timestamp=float(value("timestamp") or 0.0),
        timestamp_ns=value("timestamp_ns"),
        timestamp_monotonic=value("timestamp_monotonic"),
        pid=value("pid"),
        ppid=value("ppid"),
        uid=value("uid"),
        gid=value("gid"),
        comm=value("comm"),
        executable=value("executable"),
        parent_comm=value("parent_comm"),
        ancestry=json.loads(ancestry_json) if ancestry_json else [],
        payload=json.loads(payload_json) if payload_json else {},
        source=value("source") or "telemetry_bcc",
        version=value("version") or "1.0",
        host_id=value("host_id"),
        boot_id=value("boot_id"),
        agent_id=value("agent_id"),
    )


def read_source_window(
    source_path: str,
    window_start: Optional[float],
    window_end: Optional[float],
) -> Tuple[List[int], List[Event]]:
    """
    Read (event_ids, events) from a source capture, read-only, in id order.

    ``window_start``/``window_end`` are optional inclusive/exclusive timestamp
    bounds ``[start, end)``; when omitted the whole capture is one window. The
    returned ``event_ids`` are the source store's row ids -- provenance pointers
    recorded alongside the window's features, one-to-one with ``events``.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"source capture not found: {source_path}")

    clauses: List[str] = []
    params: List[Any] = []
    if window_start is not None:
        clauses.append("timestamp >= ?")
        params.append(float(window_start))
    if window_end is not None:
        clauses.append("timestamp < ?")
        params.append(float(window_end))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

    uri = f"file:{os.path.abspath(source_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM events{where} ORDER BY timestamp ASC, id ASC",
            params,
        ).fetchall()
    finally:
        conn.close()

    event_ids = [int(row["id"]) for row in rows]
    events = [_row_to_event(row) for row in rows]
    return event_ids, events


def _feature_summary(events: List[Event]) -> Dict[str, Any]:
    """A small, human-checkable digest of the window the operator is attesting."""
    features = extract_features(events)
    timestamps = [float(event.timestamp) for event in events]
    return {
        "event_count": len(events),
        "window_start": min(timestamps) if timestamps else None,
        "window_end": max(timestamps) if timestamps else None,
        "observed_span_seconds": (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0,
        "unique_event_types": int(features["unique_event_types"]),
        "unique_commands": int(features["unique_commands"]),
        "privileged_event_count": int(features["privileged_event_count"]),
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema_hash(),
    }


def _build_verification(args: argparse.Namespace, source_path: str) -> Dict[str, Any]:
    """The operator attestation recorded immutably with the dataset and window."""
    return {
        "verified_normal": True,  # only reached after the --i-verified-normal gate
        "operator": args.operator,
        "reason": args.reason,
        "reviewed_at": time.time(),
        "source_capture": os.path.basename(source_path),
        "role": args.role,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Promote one reviewed normal window into a candidate verified-normal dataset.",
    )
    parser.add_argument("--source", required=True, help="source capture SQLite DB (opened read-only)")
    parser.add_argument("--dataset-db", help="candidate dataset store to write into (required unless --dry-run)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dataset-id", help="append to this existing verified-normal dataset")
    group.add_argument("--dataset-name", help="create a new verified-normal dataset with this name")
    parser.add_argument("--role", choices=_ROLES, help="does this dataset feed training or the holdout gate")
    parser.add_argument("--window-start", type=float, default=None, help="inclusive start timestamp (default: whole capture)")
    parser.add_argument("--window-end", type=float, default=None, help="exclusive end timestamp (default: whole capture)")
    parser.add_argument("--operator", help="name/id of the human attesting this window is normal")
    parser.add_argument("--reason", help="why this window is benign (recorded in the attestation)")
    parser.add_argument(
        "--i-verified-normal",
        action="store_true",
        help="explicit operator attestation of human review; required to write (cannot be self-approved)",
    )
    parser.add_argument("--dry-run", action="store_true", help="read and summarize the window; write nothing")
    parser.add_argument("--json", action="store_true", help="emit the result summary as JSON")
    args = parser.parse_args(argv)

    # Read the window first -- read-only, never mutating the operator's capture.
    try:
        event_ids, events = read_source_window(args.source, args.window_start, args.window_end)
    except (FileNotFoundError, sqlite3.Error) as error:
        print(f"error reading source capture: {error}", file=sys.stderr)
        return 1

    if not events:
        print(
            "no events in the selected window; nothing to promote "
            "(check --window-start/--window-end against the capture)",
            file=sys.stderr,
        )
        return 1

    summary = _feature_summary(events)

    if args.dry_run:
        summary["dry_run"] = True
        summary["would_write"] = False
        _emit(summary, args.json, header="DRY RUN -- no dataset written")
        return 0

    # ---- writing path: everything below requires an explicit operator attestation
    missing = [
        flag
        for flag, present in (
            ("--dataset-db", bool(args.dataset_db)),
            ("--role", bool(args.role)),
            ("--operator", bool(args.operator)),
            ("--reason", bool(args.reason)),
        )
        if not present
    ]
    if missing:
        print(f"writing requires: {', '.join(missing)} (or use --dry-run to inspect)", file=sys.stderr)
        return 2
    if not (args.dataset_id or args.dataset_name):
        print("writing requires exactly one of --dataset-id or --dataset-name", file=sys.stderr)
        return 2
    if not args.i_verified_normal:
        print(
            "refusing to write without --i-verified-normal: verified_normal is an "
            "operator attestation of human review and cannot be self-approved by this tool",
            file=sys.stderr,
        )
        return 3

    verification = _build_verification(args, args.source)
    environment = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "role": args.role,
        "source_capture": os.path.basename(args.source),
    }

    store = SQLiteEventStore(args.dataset_db)
    try:
        if args.dataset_name:
            dataset_id = create_verified_normal_dataset(
                store, args.dataset_name, verification, environment=environment
            )
            created_dataset = True
        else:
            dataset_id = args.dataset_id
            created_dataset = False

        window_id = add_verified_normal_window(
            store,
            dataset_id,
            events,
            event_ids,
            verification,
            collector_context={
                "role": args.role,
                "source_capture": os.path.basename(args.source),
                "sources": sorted({event.source for event in events}),
                "versions": sorted({event.version for event in events}),
            },
        )
    except Exception as error:  # store/training raise ValueError subclasses on bad input
        print(f"error writing verified-normal window: {error}", file=sys.stderr)
        store.close()
        return 1
    store.close()

    summary.update(
        {
            "dry_run": False,
            "would_write": True,
            "dataset_db": args.dataset_db,
            "dataset_id": dataset_id,
            "created_dataset": created_dataset,
            "window_id": window_id,
            "role": args.role,
            "operator": args.operator,
        }
    )
    _emit(summary, args.json, header="wrote verified-normal window")
    return 0


def _emit(summary: Dict[str, Any], as_json: bool, header: str) -> None:
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    print(header)
    for key in (
        "dataset_id",
        "window_id",
        "role",
        "operator",
        "event_count",
        "observed_span_seconds",
        "unique_event_types",
        "unique_commands",
        "privileged_event_count",
        "window_start",
        "window_end",
    ):
        if key in summary:
            print(f"  {key}: {summary[key]}")


if __name__ == "__main__":
    raise SystemExit(main())
