"""
Tests for the append-only hash chain over the evidence tables.

Two layers are covered:

* the pure fold in `storage/evidence_chain.py` (serialization determinism,
  verification of a hand-built chain), independent of any database;
* the store integration in `storage/sqlite_store.py` (findings and policy
  decisions are chained on write, dedup hits add no link, suppressed findings
  are still chained, tampering/deletion/reordering is detected on verify, and
  the migration-8 backfill produces byte-identical hashes to the runtime writer).
"""

import sqlite3

from storage import migrations
from storage.evidence_chain import (
    FINDING_CHAIN_COLUMNS,
    GENESIS_PREV_HASH,
    next_link,
    serialize_core,
    verify_chain,
)
from storage.sqlite_store import SQLiteEventStore


def _finding(entity_key, score=0.7, provenance="ph", **overrides):
    finding = {
        "source_risk_id": 1,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": "command",
        "entity_key": entity_key,
        "risk_score": score,
        "severity": "HIGH",
        "behavior_score": score,
        "rule_score": score,
        "context_score": score,
        "evidence": [{"signal": "behavior_anomaly", "score": score}],
        "explanation": f"finding for {entity_key}",
        "mode": "detection",
        "provenance_hash": provenance,
        "detector_version": "detector.v1",
    }
    finding.update(overrides)
    return finding


def _decision(policy_id="p", **overrides):
    decision = {
        "finding_id": 1,
        "policy_id": policy_id,
        "decision": "advisory_only",
        "reason": "dry-run, approval required",
        "risk_score": 0.7,
        "severity": "HIGH",
        "required_approval": True,
        "proposed_action": "notify_operator",
        "limitations": {"dry_run": True},
        "timestamp": 1000.0,
        "dry_run": True,
        "advisory_rejection": None,
    }
    decision.update(overrides)
    return decision


# --------------------------------------------------------------- pure fold


def test_serialize_core_ignores_mapping_order_and_excludes_id():
    row = {name: name for name in FINDING_CHAIN_COLUMNS}
    row["id"] = 999  # not a chained column
    forward = serialize_core(FINDING_CHAIN_COLUMNS, row)
    reversed_row = dict(reversed(list(row.items())))
    assert serialize_core(FINDING_CHAIN_COLUMNS, reversed_row) == forward
    assert "999" not in forward  # the surrogate id is never part of the hash


def test_verify_chain_detects_a_mutation_on_hand_built_rows():
    columns = ("a", "b")
    rows = []
    prev_seq = None
    prev_hash = None
    for i in range(3):
        data = {"a": i, "b": f"v{i}"}
        link = next_link(prev_seq, prev_hash, columns, data)
        data.update(link)
        rows.append(data)
        prev_seq, prev_hash = link["chain_seq"], link["chain_hash"]

    assert verify_chain(columns, rows)["ok"] is True
    assert rows[0]["chain_prev_hash"] == GENESIS_PREV_HASH

    rows[1]["a"] = 999  # tamper with a covered column
    verdict = verify_chain(columns, rows)
    assert verdict["ok"] is False
    assert verdict["break_seq"] == 1


def test_empty_chain_verifies_ok():
    assert verify_chain(FINDING_CHAIN_COLUMNS, []) == {
        "ok": True,
        "checked": 0,
        "break_seq": None,
        "reason": None,
    }


# ----------------------------------------------------------- store: findings


def test_empty_store_chains_verify_ok(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    assert store.verify_findings_chain()["ok"] is True
    assert store.verify_findings_chain()["checked"] == 0
    assert store.verify_policy_chain()["ok"] is True


def test_findings_chain_is_contiguous_and_verifies(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    for i in range(3):
        store.write_detection_finding(_finding(f"cmd{i}", provenance=f"ph{i}"))

    verdict = store.verify_findings_chain()
    assert verdict["ok"] is True
    assert verdict["checked"] == 3

    findings = store.read_detection_findings()
    assert [f["chain_seq"] for f in findings] == [0, 1, 2]
    assert findings[0]["chain_prev_hash"] == GENESIS_PREV_HASH
    # Each link points at its predecessor's hash.
    assert findings[1]["chain_prev_hash"] == findings[0]["chain_hash"]
    assert findings[2]["chain_prev_hash"] == findings[1]["chain_hash"]


def test_dedup_hit_adds_no_link(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    first = store.write_detection_finding(_finding("dup", provenance="samehash"))
    second = store.write_detection_finding(_finding("dup", provenance="samehash"))

    assert first == second
    assert len(store.read_detection_findings()) == 1
    # A duplicate must not extend the chain: the finding is already a link.
    assert store.verify_findings_chain()["checked"] == 1


def test_suppressed_findings_are_persisted_and_chained(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    store.write_detection_finding(_finding("normal", provenance="p0"))
    sid = store.write_detection_finding(
        _finding("noisy", provenance="p1", suppressed=True, suppression_reason="known scanner")
    )

    suppressed = store.read_detection_finding(sid)
    assert suppressed["suppressed"] is True
    assert suppressed["suppression_reason"] == "known scanner"
    # Suppression is a disposition, never a silent drop: the row is still in the
    # chain, and its scores are untouched by the disposition.
    assert suppressed["chain_seq"] == 1
    assert suppressed["risk_score"] == 0.7
    verdict = store.verify_findings_chain()
    assert verdict["ok"] is True
    assert verdict["checked"] == 2


def test_mutating_a_finding_row_breaks_verification(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    for i in range(3):
        store.write_detection_finding(_finding(f"cmd{i}", provenance=f"ph{i}"))
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE detection_findings SET risk_score = 0.123 WHERE chain_seq = 1")
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_findings_chain()
    assert verdict["ok"] is False
    assert verdict["break_seq"] == 1
    assert "hash mismatch" in verdict["reason"]


def test_deleting_a_finding_row_is_detected(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    for i in range(3):
        store.write_detection_finding(_finding(f"cmd{i}", provenance=f"ph{i}"))
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute("DELETE FROM detection_findings WHERE chain_seq = 1")
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_findings_chain()
    assert verdict["ok"] is False
    # Surviving rows carry chain_seq 0 and 2; position 1 now holds seq 2.
    assert "non-contiguous" in verdict["reason"]


def test_mutating_prev_hash_breaks_linkage(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    for i in range(3):
        store.write_detection_finding(_finding(f"cmd{i}", provenance=f"ph{i}"))
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "UPDATE detection_findings SET chain_prev_hash = ? WHERE chain_seq = 2",
            ("f" * 64,),
        )
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_findings_chain()
    assert verdict["ok"] is False
    assert verdict["break_seq"] == 2
    assert "linkage" in verdict["reason"]


# ------------------------------------------------------ store: policy chain


def test_policy_decisions_are_chained(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    for i in range(3):
        store.write_policy_decision(_decision(policy_id=f"p{i}"))

    verdict = store.verify_policy_chain()
    assert verdict["ok"] is True
    assert verdict["checked"] == 3

    decisions = store.read_policy_decisions()
    assert [d["chain_seq"] for d in decisions] == [0, 1, 2]
    assert decisions[0]["chain_prev_hash"] == GENESIS_PREV_HASH


def test_mutating_a_policy_row_breaks_verification(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    for i in range(2):
        store.write_policy_decision(_decision(policy_id=f"p{i}"))
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE policy_decisions SET decision = 'tampered' WHERE chain_seq = 0")
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_policy_chain()
    assert verdict["ok"] is False
    assert verdict["break_seq"] == 0


# ------------------------------------------- backfill == runtime equivalence


def test_backfill_matches_runtime_finding_hashes(tmp_path):
    """
    The migration-8 backfill and the runtime writer must produce identical
    hashes for identical stored rows, or a database migrated in the field would
    fail its own verification. Both read the values back from the stored row and
    fold them through the single `next_link`; this pins that they agree.
    """
    runtime_db = str(tmp_path / "runtime.db")
    runtime = SQLiteEventStore(runtime_db)
    samples = [
        _finding("a", provenance="pa", created_at=5),  # int -> REAL affinity round-trip
        _finding("b", provenance="pb", correlation_id="grp-1", created_at=6.5),
        _finding("c", provenance="pc", suppressed=True, suppression_reason="noise"),
    ]
    for finding in samples:
        runtime.write_detection_finding(finding)
    runtime.close()

    rconn = sqlite3.connect(runtime_db)
    rconn.row_factory = sqlite3.Row
    try:
        runtime_rows = [
            dict(row)
            for row in rconn.execute("SELECT * FROM detection_findings ORDER BY id ASC")
        ]
    finally:
        rconn.close()
    runtime_hashes = [row["chain_hash"] for row in runtime_rows]

    # Fresh v8 database; insert the identical stored rows with NULL chain columns,
    # then fold them via the migration backfill and compare.
    backfill_db = str(tmp_path / "backfill.db")
    SQLiteEventStore(backfill_db).close()
    non_chain = [
        column
        for column in runtime_rows[0].keys()
        if column not in ("id", "chain_seq", "chain_prev_hash", "chain_hash")
    ]
    bconn = sqlite3.connect(backfill_db)
    try:
        cols = ", ".join(non_chain)
        placeholders = ", ".join("?" for _ in non_chain)
        for row in runtime_rows:
            bconn.execute(
                f"INSERT INTO detection_findings ({cols}) VALUES ({placeholders})",
                tuple(row[column] for column in non_chain),
            )
        migrations._backfill_chain(bconn, "detection_findings", FINDING_CHAIN_COLUMNS)
        bconn.commit()
        backfill_hashes = [
            row[0]
            for row in bconn.execute("SELECT chain_hash FROM detection_findings ORDER BY id ASC")
        ]
    finally:
        bconn.close()

    assert backfill_hashes == runtime_hashes
    assert all(backfill_hashes)
    # The backfilled chain verifies through the store's own reader as well.
    assert SQLiteEventStore(backfill_db).verify_findings_chain()["ok"] is True


# ------------------------------------------------------ store: triage chain
#
# The triage annotation layer (migration 9) is append-only and hash-chained on
# the same rules as the evidence tables, but it is deliberately separate: writing
# triage must never touch a finding row or the finding/policy chains. These pin
# that the triage trail is itself tamper-evident, that a correction is a new link
# rather than an edit, and -- crucially -- that annotating a finding leaves the
# evidence chain byte-for-byte unchanged.


def test_empty_triage_chain_verifies_ok(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    verdict = store.verify_triage_chain()
    assert verdict == {"ok": True, "checked": 0, "break_seq": None, "reason": None}


def test_triage_annotations_are_chained_and_contiguous(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    fid = store.write_detection_finding(_finding("nc", provenance="p0"))
    store.write_triage_annotation(fid, "acknowledge", actor="analyst-a")
    store.write_triage_annotation(fid, "annotate", note="looks like a real reverse shell")
    store.write_triage_annotation(fid, "disposition", disposition="true-positive")

    verdict = store.verify_triage_chain()
    assert verdict["ok"] is True
    assert verdict["checked"] == 3

    annotations = store.read_triage_annotations(finding_id=fid)
    assert [a["chain_seq"] for a in annotations] == [0, 1, 2]
    assert annotations[0]["chain_prev_hash"] == GENESIS_PREV_HASH
    assert annotations[1]["chain_prev_hash"] == annotations[0]["chain_hash"]
    assert annotations[2]["chain_prev_hash"] == annotations[1]["chain_hash"]


def test_triage_correction_is_a_new_link_not_an_edit(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    fid = store.write_detection_finding(_finding("nc", provenance="p0"))
    # An analyst dispositions true-positive, then reconsiders and corrects to
    # false-positive. The correction is a *second* row, not an overwrite: the
    # first disposition remains in the immutable history, and latest wins.
    store.write_triage_annotation(fid, "disposition", disposition="true-positive")
    store.write_triage_annotation(fid, "disposition", disposition="false-positive")

    history = store.read_triage_annotations(finding_id=fid)
    assert [a["disposition"] for a in history] == ["true-positive", "false-positive"]
    assert store.verify_triage_chain()["checked"] == 2  # two links, not one edited link
    assert store.read_latest_triage_state()[fid]["disposition"] == "false-positive"


def test_triage_writes_leave_the_evidence_chain_untouched(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    fid = store.write_detection_finding(_finding("nc", provenance="p0"))
    before = store.read_detection_finding(fid)["chain_hash"]

    store.write_triage_annotation(fid, "suppress", note="known internal scanner")
    store.write_triage_annotation(fid, "disposition", disposition="benign")

    after = store.read_detection_finding(fid)
    # The finding row and its chain link are identical; triage lives elsewhere.
    assert after["chain_hash"] == before
    assert after["suppressed"] is False  # config column never flipped by triage
    assert store.verify_findings_chain()["ok"] is True


def test_mutating_a_triage_row_breaks_verification(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    fid = store.write_detection_finding(_finding("nc", provenance="p0"))
    store.write_triage_annotation(fid, "annotate", note="original note")
    store.write_triage_annotation(fid, "disposition", disposition="true-positive")
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE triage_annotations SET note = 'rewritten' WHERE chain_seq = 0")
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_triage_chain()
    assert verdict["ok"] is False
    assert verdict["break_seq"] == 0
    assert "hash mismatch" in verdict["reason"]


def test_deleting_a_triage_row_is_detected(tmp_path):
    db = str(tmp_path / "e.db")
    store = SQLiteEventStore(db)
    fid = store.write_detection_finding(_finding("nc", provenance="p0"))
    for _ in range(3):
        store.write_triage_annotation(fid, "annotate", note="n")
    store.close()

    conn = sqlite3.connect(db)
    try:
        conn.execute("DELETE FROM triage_annotations WHERE chain_seq = 1")
        conn.commit()
    finally:
        conn.close()

    verdict = SQLiteEventStore(db).verify_triage_chain()
    assert verdict["ok"] is False
    assert "non-contiguous" in verdict["reason"]
