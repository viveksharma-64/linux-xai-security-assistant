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

It deliberately adds NO new ML path. Three boundaries are load-bearing:

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
* **One login session contributes one holdout window.** The gate's Wilson bound
  counts each holdout window as an independent trial, so a ``--role holdout``
  window must be exactly one ``(boot_id, session_id)`` pair and must not be a
  pair the target dataset already holds (exit status 4 otherwise). That rules out
  re-promoting a capture and rules out slicing one session into two windows with
  ``--window-start``/``--window-end``. The pair, plus the capture's logind
  manifest, is stored in the window's immutable ``collector_context`` so the
  claim stays auditable after logind has forgotten the session. Training windows
  are not restricted this way: independence is a holdout property.

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
from typing import Any

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
        session_id=value("session_id"),
    )


def read_source_window(
    source_path: str,
    window_start: float | None,
    window_end: float | None,
) -> tuple[list[int], list[Event]]:
    """
    Read (event_ids, events) from a source capture, read-only, in id order.

    ``window_start``/``window_end`` are optional inclusive/exclusive timestamp
    bounds ``[start, end)``; when omitted the whole capture is one window. The
    returned ``event_ids`` are the source store's row ids -- provenance pointers
    recorded alongside the window's features, one-to-one with ``events``.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"source capture not found: {source_path}")

    clauses: list[str] = []
    params: list[Any] = []
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


def _session_provenance(source_path: str, events: list[Event]) -> dict[str, Any]:
    """
    Describe which boot and login session this window's events came from.

    The identity is the *pair*: logind numbers sessions from 1 again after every
    reboot, so ``session_id`` alone collides across boots while ``boot_id`` alone
    collapses every session of one uptime into a single window. Computed the same
    way ``scripts/verify_capture_boot.py`` computes it, from the rows rather than
    the filename, so the two tools cannot disagree about what a capture claims.

    ``identity`` is set only when the window is unambiguously one session.
    Unattributed rows are counted rather than treated as a defect: the always-on
    ingest service has no login session of its own, so daemon activity inside the
    window legitimately carries NULLs, and captures stay host-wide on purpose --
    filtering a window down to one session's processes would shift its feature
    distribution away from training and runtime scoring.

    The ``.manifest.json`` sidecar written by ``scripts/capture_normal_window.sh``
    is folded in when present. It matters because logind discards its session
    records at reboot: the login wall-clock in there is the only lasting evidence
    that two same-boot sessions did not overlap, and without it a window reviewed
    a week later cannot be audited at all.
    """
    pairs: dict[tuple[str, str], int] = {}
    without_boot_id = 0
    without_session_id = 0
    for event in events:
        if event.boot_id is None:
            without_boot_id += 1
        if event.session_id is None:
            without_session_id += 1
        if event.boot_id is not None and event.session_id is not None:
            key = (str(event.boot_id), str(event.session_id))
            pairs[key] = pairs.get(key, 0) + 1

    identities = [
        {"boot_id": boot_id, "session_id": session_id, "events": count}
        for (boot_id, session_id), count in sorted(pairs.items())
    ]
    provenance: dict[str, Any] = {
        "identities": identities,
        "identity": identities[0] if len(identities) == 1 else None,
        "rows_without_boot_id": without_boot_id,
        "rows_without_session_id": without_session_id,
        "capture_manifest": _read_capture_manifest(source_path),
    }
    if provenance["identity"] is not None:
        # Drop the row count from the identity itself: it is the key two windows
        # are compared on, and a count would make the same session look like two.
        provenance["identity"] = {
            "boot_id": identities[0]["boot_id"],
            "session_id": identities[0]["session_id"],
        }
    return provenance


def _read_capture_manifest(source_path: str) -> dict[str, Any] | None:
    """Load the capture's ``.manifest.json`` sidecar, or None if there is none.

    Missing is normal, not an error: captures taken before this sidecar existed,
    or by hand, simply have no logind snapshot to record. Unreadable is also not
    fatal here -- this tool's job is to record what provenance exists, and
    refusing to promote over a damaged sidecar would be a gate this change was
    not asked to add. ``scripts/verify_capture_boot.py`` is where independence is
    adjudicated.
    """
    manifest_path = f"{source_path}.manifest.json"
    if not os.path.exists(manifest_path):
        return None
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, ValueError) as error:
        return {"error": f"unreadable manifest at {manifest_path}: {error}"}
    return loaded if isinstance(loaded, dict) else {"error": "manifest is not an object"}


def _promoted_session_identities(
    store: SQLiteEventStore,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Map (boot_id, session_id) -> the first window in this store that holds it.

    Deliberately corpus-wide rather than dataset-scoped: the thing that must not
    happen twice is the *promotion of a session*, and a dataset-scoped read cannot
    see a second dataset in the same file. Checking only the dataset being
    appended to left a hole wide enough to drive the whole program through --
    create a second dataset and the same capture promotes again, with no
    refusal and nothing in the stored provenance to mark the two windows as one
    session.

    Read back out of the immutable ``collector_context`` this tool writes, which
    is covered by each window's ``immutable_hash``, so a session cannot be hidden
    by editing the row. Windows written before session provenance existed have no
    identity to report and are simply absent -- they were promoted under the
    old one-per-boot rule and are not re-adjudicated here.
    """
    promoted: dict[tuple[str, str], dict[str, Any]] = {}
    for window in store.read_ml_training_windows():
        context = window.get("collector_context") or {}
        identity = (context.get("session_provenance") or {}).get("identity")
        if not isinstance(identity, dict):
            continue
        boot_id, session_id = identity.get("boot_id"), identity.get("session_id")
        if boot_id is None or session_id is None:
            continue
        promoted.setdefault(
            (str(boot_id), str(session_id)),
            {
                "window_id": int(window["id"]),
                "dataset_id": str(window["dataset_id"]),
                "role": context.get("role"),
            },
        )
    return promoted


def _feature_summary(events: list[Event]) -> dict[str, Any]:
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


def _build_verification(
    args: argparse.Namespace, source_path: str, provenance: dict[str, Any]
) -> dict[str, Any]:
    """The operator attestation recorded immutably with the dataset and window.

    The session identity rides along with the attestation, not only in the
    window's collector context, because this is the record of *what a human said
    they reviewed*. "alice reviewed boot X session 3" is auditable a year later;
    "alice reviewed a window" is not.
    """
    return {
        "verified_normal": True,  # only reached after the --i-verified-normal gate
        "operator": args.operator,
        "reason": args.reason,
        "reviewed_at": time.time(),
        "source_capture": os.path.basename(source_path),
        "role": args.role,
        "session_identity": provenance["identity"],
    }


def main(argv: list[str] | None = None) -> int:
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
    provenance = _session_provenance(args.source, events)
    summary["session_identity"] = provenance["identity"]
    summary["session_count"] = len(provenance["identities"])
    summary["rows_without_session_id"] = provenance["rows_without_session_id"]

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

    # ---- holdout windows must each be one distinct login session
    #
    # The gate's Wilson bound treats the 60 holdout windows as independent trials,
    # so two windows from one login session would not just be redundant, they
    # would overstate the evidence. scripts/verify_capture_boot.py already refuses
    # such a capture, but it inspects captures and can be skipped; this is the
    # door the corpus is actually written through, and it is the only place that
    # can see what has already been promoted.
    if args.role == "holdout" and provenance["identity"] is None:
        detail = (
            f"{len(provenance['identities'])} distinct login sessions"
            if provenance["identities"]
            else "no attributable login session "
            f"({provenance['rows_without_session_id']} rows with a NULL session_id)"
        )
        print(
            f"refusing to promote a holdout window with {detail}: a holdout window "
            "must be exactly one (boot_id, session_id) pair, because the activation "
            "gate counts it as one independent trial. Verify the capture first:\n"
            f"  python3 scripts/verify_capture_boot.py {args.source} --against DIR",
            file=sys.stderr,
        )
        return 4

    # ---- a login session is promoted once, into one dataset
    #
    # Two rules, and the asymmetry between them is deliberate. *Across* datasets a
    # session may appear once whatever the role, including on the --dataset-name
    # path: the same session in two datasets is one piece of evidence counted
    # twice, and if either dataset feeds training then the other is no longer held
    # out from it -- an overlap ml_train_and_evaluate.py cannot catch, because it
    # compares window content byte-for-byte and two differently-bounded windows
    # over one session do not match. *Within* one dataset only holdout is strict --
    # one session, one window -- because training windows are not counted as
    # independent trials and more data from a session already in the set is just
    # more data.
    if provenance["identity"] is not None:
        check = SQLiteEventStore(args.dataset_db)
        try:
            promoted = _promoted_session_identities(check)
        finally:
            check.close()
        key = (provenance["identity"]["boot_id"], provenance["identity"]["session_id"])
        prior = promoted.get(key)
        # args.dataset_id is None on the creation path, so every prior hit there is
        # in another dataset by construction -- which is the case that used to pass.
        elsewhere = prior is not None and prior["dataset_id"] != args.dataset_id
        if prior is not None and (elsewhere or args.role == "holdout"):
            consequence = (
                "A session belongs to one dataset. Promoting it again here would "
                "count the same evidence twice and, if the two datasets split "
                "training from holdout, would stop the holdout being held out from "
                "training."
                if elsewhere
                else "One session contributes one window -- re-promoting a capture, "
                "or slicing it into two windows with --window-start/--window-end, "
                "would inflate the holdout count without adding independent evidence."
            )
            print(
                f"refusing to promote: boot {key[0]} session {key[1]} is already "
                f"window {prior['window_id']} in dataset {prior['dataset_id']} "
                f"(role {prior['role'] or 'unrecorded'}). {consequence}",
                file=sys.stderr,
            )
            return 4

    verification = _build_verification(args, args.source, provenance)
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
                # The whole independence argument, stored with the window rather
                # than left on the host: logind discards its session records at
                # reboot, so this is the only thing that can answer "were these
                # two windows really different sessions?" a month from now. It is
                # covered by the window's immutable_hash, which is why the
                # duplicate check above can trust what it reads back.
                "session_provenance": provenance,
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


def _emit(summary: dict[str, Any], as_json: bool, header: str) -> None:
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    print(header)
    for key in (
        "dataset_id",
        "window_id",
        "role",
        "operator",
        "session_identity",
        "session_count",
        "rows_without_session_id",
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
