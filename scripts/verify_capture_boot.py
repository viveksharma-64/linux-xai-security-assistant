#!/usr/bin/env python3
"""Verify that a capture came from one login session this corpus has not used.

The activation gate in ``ml/evaluation.py`` wants 60 *independent* verified-normal
holdout windows, and ``docs/NORMAL_CORPUS_PROGRAM.md`` is explicit that
independence "is a judgement recorded by the collection program, not a property
this program's counter can prove". ``scripts/corpus_status.py`` counts windows; it
cannot tell 60 sessions from 60 slices of one afternoon.

This script turns that judgement into a check for the one part of it that *is*
mechanically decidable. Every event row carries the boot and the login session the
agent observed it under (``pipeline/identity`` -> ``pipeline/event_stream`` ->
``storage/sqlite_store``), so "this capture is one session" and "this session is
new to the corpus" are both plain queries. The August 2026 corpus failed exactly
this test after the fact -- 25 captures, strictly monotonic PIDs, one 2h17m uptime
-- and it failed it only because someone went looking. Running this before
promoting makes that cheap.

The identity is the *pair*. logind numbers sessions from 1 again after every
reboot, so session 2 of today's boot and session 2 of yesterday's are different
sessions that share an id; ``session_id`` alone would collide across boots and
``boot_id`` alone would collapse every session of one uptime into one window. A
capture is therefore promotable when its rows agree on one ``boot_id`` *and* one
``session_id``, and no capture in ``--against`` already claims that pair.

Several captures from one boot are expected and allowed -- that is the point of
keying on sessions, and it is what makes 60 windows cost 6-9 boots instead of 60.
It is also a weaker independence claim than 60 distinct boots would be, for the
reasons set out in ``docs/NORMAL_CORPUS_PROGRAM.md``; this script enforces
distinctness, not strength.

What it does NOT do, by design:

* It never writes. Captures open ``mode=ro``, and nothing here opens the corpus
  database at all.
* It never promotes. Promotion is ``scripts/collect_normal_window.py``, which
  refuses without ``--i-verified-normal`` because ``verified_normal`` is an
  operator attestation of human review. A passing verdict here is a
  precondition for that review, not a substitute for it.
* It says nothing about whether the window is *normal*. A single-session, unused
  capture full of attacker behaviour passes every check in this file. Looking at
  the events is still the operator's job.
* It says nothing about whether two sessions overlapped in time. The login
  instant that settles that lives in the capture's ``.manifest.json`` sidecar
  (``scripts/capture_normal_window.sh``), which is operator-reviewed; a session
  id is evidence of distinctness, not of separation.

Usage:
    python3 scripts/verify_capture_boot.py CAPTURE.db [CAPTURE.db ...] \\
        [--against /var/lib/linux-xai-captures/promoted] [--json]

Exit status is 0 only when every capture is non-empty, agrees on a single
(boot_id, session_id) pair, and carries a pair no other capture in ``--against``
already used.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys
from datetime import UTC, datetime

# Verdicts. Only OK is promotable; the rest are refusals with distinct causes,
# because "this session is already in the corpus" and "this capture has no session
# id" call for different operator responses. Note what is *absent*: a capture
# whose boot is already represented is not a refusal, because many sessions per
# boot is the design. Only the pair has to be new.
OK = "ok"
EMPTY = "empty"
MULTI_BOOT = "multi_boot"
NO_BOOT_ID = "no_boot_id"
NO_SESSION_ID = "no_session_id"
MULTI_SESSION = "multi_session"
DUPLICATE_SESSION = "duplicate_session"
UNREADABLE = "unreadable"


def _connect_readonly(path: str) -> sqlite3.Connection:
    """Open a capture read-only.

    ``mode=ro`` rather than ``mode=ro&immutable=1``: a capture whose collector was
    killed can have rows that exist only in an unreplayed WAL, and ``immutable=1``
    would silently hide them and report a healthy-looking empty database. That is
    precisely how ``training-13.db`` in the August corpus looked -- 4 KiB of main
    database, 1.9 MB of WAL -- and the useful answer there is "this capture is
    damaged", not "this capture has no events".
    """
    uri = f"file:{os.path.abspath(path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _event_columns(conn: sqlite3.Connection) -> set[str]:
    """Which identity columns this capture's schema actually has.

    Old captures are missing them for different reasons and the distinction is
    worth keeping: ``boot_id`` arrived in migration 3 and ``session_id`` in
    migration 11, so a capture from in between has a boot but no session, and
    saying so points the operator at the real answer (re-capture) rather than at
    a corrupt-database hunt.
    """
    return {str(row["name"]) for row in conn.execute("PRAGMA table_info(events)")}


def inspect_capture(path: str) -> dict:
    """Read one capture and describe its session provenance. Never writes."""
    result: dict = {
        "path": path,
        "events": 0,
        "boot_ids": [],
        "session_ids": [],
        # Every (boot_id, session_id) pair present, with row counts. Carried
        # separately from the verdict because `--against` needs the pairs a
        # capture claims even when that capture is itself not promotable.
        "identities": [],
        "identity": None,
        "rows_without_boot_id": 0,
        "rows_without_session_id": 0,
        "first_event": None,
        "last_event": None,
        "span_seconds": None,
        "verdict": UNREADABLE,
        "reason": "",
    }

    try:
        conn = _connect_readonly(path)
    except sqlite3.Error as exc:
        result["reason"] = f"cannot open: {exc}"
        return result

    try:
        try:
            total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
            result["events"] = int(total["n"])
        except sqlite3.Error as exc:
            # No events table, or a WAL this process cannot read. Both mean the
            # capture is not usable, and the message distinguishes them.
            result["reason"] = f"cannot read events: {exc}"
            return result

        bounds = conn.execute(
            "SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM events"
        ).fetchone()
        if bounds["lo"] is not None and bounds["hi"] is not None:
            lo, hi = float(bounds["lo"]), float(bounds["hi"])
            result["first_event"] = _iso(lo)
            result["last_event"] = _iso(hi)
            result["span_seconds"] = round(hi - lo, 1)

        if result["events"] == 0:
            result["verdict"] = EMPTY
            result["reason"] = "no events; nothing to promote"
            return result

        columns = _event_columns(conn)
        if "boot_id" not in columns:
            result["verdict"] = NO_BOOT_ID
            result["reason"] = (
                "capture predates the boot_id column (migration 3); independence "
                "cannot be verified from the data"
            )
            return result
        if "session_id" not in columns:
            result["verdict"] = NO_SESSION_ID
            result["reason"] = (
                "capture predates the session_id column (migration 11); the login "
                "session cannot be verified from the data, so this capture can only "
                "be promoted if its boot is otherwise unrepresented -- re-capturing "
                "is cheaper than arguing"
            )
            return result

        rows = conn.execute(
            "SELECT boot_id, session_id, COUNT(*) AS n FROM events "
            "GROUP BY boot_id, session_id ORDER BY n DESC"
        ).fetchall()
        for row in rows:
            count = int(row["n"])
            boot_id = row["boot_id"]
            session_id = row["session_id"]
            if boot_id is None:
                result["rows_without_boot_id"] += count
            if session_id is None:
                result["rows_without_session_id"] += count
            if boot_id is not None and session_id is not None:
                result["identities"].append(
                    {
                        "boot_id": str(boot_id),
                        "session_id": str(session_id),
                        "events": count,
                    }
                )
        result["boot_ids"] = sorted(
            {str(row["boot_id"]) for row in rows if row["boot_id"] is not None}
        )
        result["session_ids"] = sorted(
            {str(row["session_id"]) for row in rows if row["session_id"] is not None}
        )
    finally:
        conn.close()

    # Boot before session: a capture spanning two boots is a merged or tampered
    # file rather than a session-attribution problem, and saying "two boots" is
    # more useful than "two sessions" when both are true.
    if not result["boot_ids"]:
        result["verdict"] = NO_BOOT_ID
        result["reason"] = (
            f"all {result['rows_without_boot_id']} rows have a NULL boot_id; "
            "independence cannot be verified from the data"
        )
    elif len(result["boot_ids"]) > 1:
        result["verdict"] = MULTI_BOOT
        result["reason"] = (
            f"{len(result['boot_ids'])} distinct boot ids in one capture; a capture "
            "cannot outlive a reboot, so this file was merged or renamed and cannot "
            "be promoted as one independent window"
        )
    elif not result["session_ids"]:
        result["verdict"] = NO_SESSION_ID
        result["reason"] = (
            f"all {result['rows_without_session_id']} rows have a NULL session_id; "
            "the agent could not attribute them to a login session, so this window "
            "cannot be shown independent of any other window from the same boot"
        )
    elif len(result["session_ids"]) > 1:
        result["verdict"] = MULTI_SESSION
        result["reason"] = (
            f"{len(result['session_ids'])} distinct login sessions in one capture "
            f"({', '.join(result['session_ids'])}); this is more than one session "
            "and cannot be promoted as one independent window"
        )
    else:
        result["verdict"] = OK
        result["identity"] = {
            "boot_id": result["boot_ids"][0],
            "session_id": result["session_ids"][0],
        }
        unattributed = []
        if result["rows_without_boot_id"]:
            unattributed.append(f"{result['rows_without_boot_id']} with a NULL boot_id")
        if result["rows_without_session_id"]:
            unattributed.append(
                f"{result['rows_without_session_id']} with a NULL session_id"
            )
        if unattributed:
            # Expected rather than alarming: the always-on ingest service belongs
            # to no login session and stamps nothing, so daemon activity inside
            # the window is unattributed by design. Captures stay host-wide on
            # purpose -- filtering the window down to one session's processes
            # would shift its feature distribution away from training and
            # runtime, which is a worse problem than these NULLs.
            result["reason"] = (
                f"{' and '.join(unattributed)}; the attributed rows are one session"
            )
    return result


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat(timespec="seconds")


def collect_known_sessions(
    directory: str, exclude: set[str]
) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Map (boot_id, session_id) -> capture path for captures in ``directory``.

    Read from the databases rather than parsed out of filenames: a renamed or
    hand-copied capture would defeat a name-based check, and the pair in the rows
    is the claim that actually matters.

    Every pair a capture claims is recorded, not just the one that would make it
    promotable. A capture that is itself unpromotable -- two sessions in one file,
    say -- has still consumed those sessions, and a later single-session capture
    of one of them would not be a new window.
    """
    known: dict[tuple[str, str], str] = {}
    problems: list[str] = []
    for path in sorted(glob.glob(os.path.join(directory, "*.db"))):
        if os.path.abspath(path) in exclude:
            continue
        found = inspect_capture(path)
        if found["verdict"] == UNREADABLE:
            # Reported rather than ignored: an unreadable capture in promoted/ is
            # a hole in the --against set, so a duplicate could slip through and
            # the operator needs to know the check was incomplete.
            problems.append(f"{path}: {found['reason']}")
            continue
        for identity in found["identities"]:
            known.setdefault((identity["boot_id"], identity["session_id"]), path)
    return known, problems


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a capture is one login session the corpus has not already "
            "used (read-only)."
        ),
    )
    parser.add_argument("captures", nargs="+", help="capture database(s) to verify")
    parser.add_argument(
        "--against",
        action="append",
        default=[],
        metavar="DIR",
        help="directory of captures already used; repeatable. Their "
        "(boot_id, session_id) pairs are read and any reuse is reported as a "
        "duplicate. A boot appearing more than once is fine; a session is not.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def _emit_text(report: dict) -> None:
    for problem in report["against_problems"]:
        print(f"WARN  unreadable in --against: {problem}")
    for capture in report["captures"]:
        verdict = capture["verdict"]
        label = "PASS" if verdict == OK else "FAIL"
        print(f"{label}  {capture['path']}")
        print(f"      verdict      {verdict}")
        print(f"      events       {capture['events']}")
        if capture["span_seconds"] is not None:
            print(
                f"      window       {capture['first_event']} .. {capture['last_event']}"
                f"  ({capture['span_seconds']}s)"
            )
        if capture["boot_ids"]:
            print(f"      boot_id      {', '.join(capture['boot_ids'])}")
        if capture["session_ids"]:
            print(f"      session_id   {', '.join(capture['session_ids'])}")
        if capture["rows_without_boot_id"]:
            print(f"      null boot_id {capture['rows_without_boot_id']} rows")
        if capture["rows_without_session_id"]:
            print(f"      null session {capture['rows_without_session_id']} rows")
        if capture["reason"]:
            print(f"      reason       {capture['reason']}")
    print(
        f"\n{report['passed']}/{report['checked']} capture(s) verified as an unused "
        "single login session."
    )
    if report["passed"]:
        print(
            "Independence verified; normality is not. Review the events and the "
            "capture's\n.manifest.json sidecar, then promote with\n"
            "  python3 scripts/collect_normal_window.py --source CAPTURE.db ... --i-verified-normal"
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    targets = [os.path.abspath(path) for path in args.captures]
    known: dict[tuple[str, str], str] = {}
    problems: list[str] = []
    for directory in args.against:
        found, found_problems = collect_known_sessions(directory, exclude=set(targets))
        problems.extend(found_problems)
        for identity, path in found.items():
            known.setdefault(identity, path)

    captures = []
    # Pairs seen among the captures on this command line, so verifying two
    # captures of one session in a single run is caught too.
    seen: dict[tuple[str, str], str] = {}
    for path in args.captures:
        capture = inspect_capture(path)
        if capture["verdict"] == OK:
            identity = (capture["identity"]["boot_id"], capture["identity"]["session_id"])
            prior = known.get(identity) or seen.get(identity)
            if prior:
                capture["verdict"] = DUPLICATE_SESSION
                capture["reason"] = (
                    f"boot {identity[0]} session {identity[1]} is already "
                    f"represented by {prior}"
                )
            else:
                seen[identity] = os.path.abspath(path)
        captures.append(capture)

    report = {
        "checked": len(captures),
        "passed": sum(1 for capture in captures if capture["verdict"] == OK),
        "known_sessions": len(known),
        "against_problems": problems,
        "captures": captures,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _emit_text(report)

    return 0 if report["passed"] == report["checked"] else 1


if __name__ == "__main__":
    sys.exit(main())
