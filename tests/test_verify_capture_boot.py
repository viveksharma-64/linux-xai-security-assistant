"""
Tests for the capture session-provenance verifier.

The verifier exists because `scripts/corpus_status.py` counts holdout windows but
cannot tell 60 independent sessions from 60 slices of one afternoon, and the
August 2026 corpus was exactly the latter. So the verdicts *are* the contract: a
capture that spans two login sessions, or reuses a `(boot_id, session_id)` pair
the corpus already holds, must be refused by name rather than merely scored
lower. `main(argv)` is called directly so the exit codes are under test too.

A reused *boot* is deliberately not a refusal any more -- several sessions per
boot is the whole point of the pair being the identity -- so that distinction has
a test of its own.
"""

import importlib.util
import json
import sqlite3
from pathlib import Path

from pipeline.event_stream import Event, EventType
from storage.sqlite_store import SQLiteEventStore

# scripts/ is not importable by name (no __init__.py, and `pyproject.toml` ships
# only the real packages), so load it by path -- the convention
# `tests/test_ml_workflow_cli.py` uses.
_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "verify_capture_boot.py"
_spec = importlib.util.spec_from_file_location("verify_capture_boot", _MODULE_PATH)
assert _spec and _spec.loader
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

BOOT_A = "11111111-1111-4111-8111-111111111111"
BOOT_B = "22222222-2222-4222-8222-222222222222"


def _capture(path, identities, *, count=3, start=1_000.0):
    """Write a capture with ``count`` events per (boot_id, session_id) pair.

    pid varies so `_event_hash` sees distinct events: both identity fields are
    excluded from the dedup key on purpose, so events differing only in boot_id
    or session_id would otherwise collapse into one row.
    """
    store = SQLiteEventStore(str(path))
    pid = 100
    for boot_id, session_id in identities:
        for _ in range(count):
            store.write(
                Event(
                    event_type=EventType.PROCESS_EXEC,
                    timestamp=start + pid,
                    pid=pid,
                    comm="python3",
                    boot_id=boot_id,
                    session_id=session_id,
                )
            )
            pid += 1
    return store


def test_single_session_capture_passes(tmp_path):
    path = tmp_path / "normal-a-s2.db"
    _capture(path, [(BOOT_A, "2")])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.OK
    assert result["boot_ids"] == [BOOT_A]
    assert result["session_ids"] == ["2"]
    assert result["identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    assert result["events"] == 3
    assert result["span_seconds"] == 2.0
    assert verifier.main([str(path)]) == 0


def test_two_boots_in_one_capture_is_refused(tmp_path):
    """A capture cannot outlive a reboot, so two boots means a merged file."""
    path = tmp_path / "fused.db"
    _capture(path, [(BOOT_A, "2"), (BOOT_B, "2")])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.MULTI_BOOT
    assert sorted(result["boot_ids"]) == sorted([BOOT_A, BOOT_B])
    assert "distinct boot ids" in result["reason"]
    assert verifier.main([str(path)]) == 1


def test_two_sessions_in_one_capture_is_refused(tmp_path):
    """
    The new refusal. One capture covering two logins would be counted by the
    gate as one window while really containing two -- or, promoted twice with
    different window bounds, as two windows that share a session.
    """
    path = tmp_path / "two-sessions.db"
    _capture(path, [(BOOT_A, "2"), (BOOT_A, "3")])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.MULTI_SESSION
    assert result["boot_ids"] == [BOOT_A]
    assert result["session_ids"] == ["2", "3"]
    assert "2 distinct login sessions" in result["reason"]
    assert result["identity"] is None
    assert verifier.main([str(path)]) == 1


def test_null_boot_id_cannot_be_verified(tmp_path):
    """Pre-migration captures are refused rather than assumed independent."""
    path = tmp_path / "legacy-null.db"
    _capture(path, [(None, None)])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.NO_BOOT_ID
    assert result["boot_ids"] == []
    assert result["rows_without_boot_id"] == 3
    assert verifier.main([str(path)]) == 1


def test_null_session_id_cannot_be_verified(tmp_path):
    """
    A capture whose rows carry a boot but no session cannot be shown independent
    of any other window from that boot, which is exactly what the gate counts on.
    """
    path = tmp_path / "no-session.db"
    _capture(path, [(BOOT_A, None)])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.NO_SESSION_ID
    assert result["boot_ids"] == [BOOT_A]
    assert result["session_ids"] == []
    assert result["rows_without_session_id"] == 3
    assert verifier.main([str(path)]) == 1


def test_unattributed_daemon_rows_do_not_fail_an_otherwise_single_session(tmp_path):
    """
    Captures stay host-wide on purpose, and the always-on ingest service belongs
    to no login session, so NULL session_ids alongside one attributed session are
    expected. Filtering the window down to one session's processes would shift its
    feature distribution away from training -- a worse problem than these NULLs --
    so this passes, and says so.
    """
    path = tmp_path / "mixed.db"
    _capture(path, [(BOOT_A, "2"), (BOOT_A, None)])

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.OK
    assert result["identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    assert result["rows_without_session_id"] == 3
    assert "3 with a NULL session_id" in result["reason"]
    assert verifier.main([str(path)]) == 0


def test_missing_boot_id_column_cannot_be_verified(tmp_path):
    """A capture written before migration 3 has no boot_id column at all."""
    path = tmp_path / "pre-migration.db"
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp REAL)")
        conn.executemany("INSERT INTO events (timestamp) VALUES (?)", [(1.0,), (2.0,)])
        conn.commit()
    finally:
        conn.close()

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.NO_BOOT_ID
    assert "migration 3" in result["reason"]


def test_missing_session_id_column_cannot_be_verified(tmp_path):
    """
    Every capture taken before migration 11 is in this state, including the four
    survivors of the August 2026 corpus: the boot is verifiable, the session is
    not, so the capture is refused rather than credited with an independence it
    cannot demonstrate.
    """
    path = tmp_path / "pre-session.db"
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp REAL, boot_id TEXT)"
        )
        conn.executemany(
            "INSERT INTO events (timestamp, boot_id) VALUES (?, ?)",
            [(1.0, BOOT_A), (2.0, BOOT_A)],
        )
        conn.commit()
    finally:
        conn.close()

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.NO_SESSION_ID
    assert "migration 11" in result["reason"]
    assert verifier.main([str(path)]) == 1


def test_empty_capture_is_refused(tmp_path):
    path = tmp_path / "empty.db"
    SQLiteEventStore(str(path))

    result = verifier.inspect_capture(str(path))

    assert result["verdict"] == verifier.EMPTY
    assert result["events"] == 0


def test_unreadable_capture_reports_rather_than_raises(tmp_path):
    result = verifier.inspect_capture(str(tmp_path / "absent.db"))

    assert result["verdict"] == verifier.UNREADABLE
    assert result["reason"]


def test_reused_session_is_a_duplicate(tmp_path):
    """The whole point: a second capture of an already-promoted session is refused."""
    promoted = tmp_path / "promoted"
    promoted.mkdir()
    _capture(promoted / "normal-a-s2.db", [(BOOT_A, "2")])

    candidate = tmp_path / "pending" / "normal-a-s2-again.db"
    candidate.parent.mkdir()
    _capture(candidate, [(BOOT_A, "2")], start=9_000.0)

    assert verifier.main([str(candidate), "--against", str(promoted)]) == 1

    fresh = tmp_path / "pending" / "normal-b-s2.db"
    _capture(fresh, [(BOOT_B, "2")])
    assert verifier.main([str(fresh), "--against", str(promoted)]) == 0


def test_a_second_session_from_the_same_boot_is_not_a_duplicate(tmp_path):
    """
    The behaviour change that makes the program finishable: session 3 of a boot
    whose session 2 is already promoted is a distinct login, so it passes. The
    session id alone cannot carry this -- logind renumbers from 1 after a reboot
    -- which is why the key is the pair.
    """
    promoted = tmp_path / "promoted"
    promoted.mkdir()
    _capture(promoted / "normal-a-s2.db", [(BOOT_A, "2")])

    later = tmp_path / "pending" / "normal-a-s3.db"
    later.parent.mkdir()
    _capture(later, [(BOOT_A, "3")], start=9_000.0)

    assert verifier.main([str(later), "--against", str(promoted)]) == 0

    # And the same session id from a *different* boot is likewise fine.
    other_boot = tmp_path / "pending" / "normal-b-s2.db"
    _capture(other_boot, [(BOOT_B, "2")], start=20_000.0)
    assert verifier.main([str(other_boot), "--against", str(promoted)]) == 0


def test_an_unpromotable_capture_still_consumes_its_sessions(tmp_path):
    """
    A two-session capture cannot be promoted, but those logins have been
    observed: a later single-session capture of one of them would be a second
    window over the same session, so the pairs are recorded from every capture in
    --against, not only the promotable ones.
    """
    promoted = tmp_path / "promoted"
    promoted.mkdir()
    _capture(promoted / "normal-a-fused.db", [(BOOT_A, "2"), (BOOT_A, "3")])

    candidate = tmp_path / "pending" / "normal-a-s3.db"
    candidate.parent.mkdir()
    _capture(candidate, [(BOOT_A, "3")], start=9_000.0)

    assert verifier.main([str(candidate), "--against", str(promoted)]) == 1

    unconsumed = tmp_path / "pending" / "normal-a-s4.db"
    _capture(unconsumed, [(BOOT_A, "4")], start=20_000.0)
    assert verifier.main([str(unconsumed), "--against", str(promoted)]) == 0


def test_duplicate_within_one_invocation_is_caught(tmp_path):
    """Two captures of one session handed over together must not both pass."""
    first = tmp_path / "one.db"
    second = tmp_path / "two.db"
    _capture(first, [(BOOT_A, "2")])
    _capture(second, [(BOOT_A, "2")], start=9_000.0)

    assert verifier.main([str(first), str(second)]) == 1

    # Two *different* sessions in one invocation are both fine, which is the
    # normal case when a boot's pending captures are reviewed as a batch.
    third = tmp_path / "three.db"
    _capture(third, [(BOOT_A, "3")], start=20_000.0)
    assert verifier.main([str(first), str(third)]) == 0


def test_capture_under_verification_is_not_its_own_duplicate(tmp_path):
    """Verifying a capture that already sits in the --against directory is fine."""
    promoted = tmp_path / "promoted"
    promoted.mkdir()
    path = promoted / "normal-a-s2.db"
    _capture(path, [(BOOT_A, "2")])

    assert verifier.main([str(path), "--against", str(promoted)]) == 0


def test_json_output_is_machine_readable(tmp_path, capsys):
    path = tmp_path / "normal-a-s2.db"
    _capture(path, [(BOOT_A, "2")])

    assert verifier.main([str(path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["checked"] == 1
    assert report["passed"] == 1
    assert report["captures"][0]["boot_ids"] == [BOOT_A]
    assert report["captures"][0]["identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    # Per-pair event counts, so a reviewer can see how much of the capture the
    # attributed session actually accounts for.
    assert report["captures"][0]["identities"] == [
        {"boot_id": BOOT_A, "session_id": "2", "events": 3}
    ]


def test_verification_never_writes_to_the_capture(tmp_path):
    """`mode=ro` is the mechanism; this pins the guarantee."""
    path = tmp_path / "normal-a-s2.db"
    _capture(path, [(BOOT_A, "2")])
    before = path.read_bytes()

    assert verifier.main([str(path)]) == 0

    assert path.read_bytes() == before
