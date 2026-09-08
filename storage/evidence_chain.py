"""
Append-only hash chain over the evidence tables.

Why a chain and not just per-row hashes
----------------------------------------
`detection_findings` already carries a `provenance_hash`: a self-hash of a
finding's own content, which makes duplicate suppression idempotent and lets a
reader detect that *one* row was altered. What it cannot detect is anything
about the *sequence* of rows -- a deleted finding, a reordered pair, or a whole
run of evidence quietly excised leaves every surviving `provenance_hash` intact.
For a table that is the audit record behind security decisions, "each row is
internally consistent" is a weaker promise than "no row has been added, removed,
or reordered since it was written".

A hash chain closes that gap. Each row records the hash of the row before it, so
the newest `chain_hash` commits to the entire history: change, drop, or reorder
any earlier row and every later hash fails to reconstruct. This is the same
tamper-evidence property a Merkle log gives, kept deliberately linear because the
tables are append-only and read back in full for verification, not proved by
inclusion witness.

One source of truth for the fold
---------------------------------
The runtime writer (`storage/sqlite_store.py`) and the migration backfill
(`storage/migrations.py`) must produce byte-identical hashes for the same row,
or a database migrated in the field would fail its own verification. Both call
`next_link` here over the same `serialize_core`, and both feed it values read
back from the stored row -- never a pre-insert Python value that might round-trip
through SQLite's type affinity differently (an `int` written to a `REAL` column
returns as `float`). This module is pure and store-independent so neither side
can drift from the other.

Column order is frozen
----------------------
`FINDING_CHAIN_COLUMNS` and `POLICY_CHAIN_COLUMNS` fix the serialization order.
They must never be reordered or have members removed: doing so changes every
hash and invalidates every chain already written to a database in the field.
A genuinely new evidence column may be appended (behind a new migration), which
extends the covered content for rows written after it without touching earlier
links, because earlier rows are never re-serialized.
"""

import hashlib
import json
from typing import Any, Dict, Mapping, Sequence

# The prev-hash recorded by the first link in a chain. A fixed, all-zero digest
# rather than NULL so the genesis row is hashed by the same rule as every other
# row -- verification never needs a special case for "the first one".
GENESIS_PREV_HASH = "0" * 64

# Persisted columns of detection_findings covered by the chain, in fixed order,
# excluding the surrogate `id` and the `chain_*` columns themselves. Uses the
# stored column names (e.g. `evidence_json`, not the decoded `evidence`) so the
# runtime writer, the backfill, and verification all serialize the same bytes.
FINDING_CHAIN_COLUMNS: Sequence[str] = (
    "source_risk_id",
    "window_start",
    "window_end",
    "entity_type",
    "entity_key",
    "risk_score",
    "severity",
    "behavior_score",
    "rule_score",
    "context_score",
    "evidence_json",
    "explanation",
    "mode",
    "provenance_hash",
    "detector_version",
    "correlation_id",
    "suppressed",
    "suppression_reason",
    "created_at",
)

# Persisted columns of policy_decisions covered by the chain, same rules.
POLICY_CHAIN_COLUMNS: Sequence[str] = (
    "finding_id",
    "policy_id",
    "decision",
    "reason",
    "risk_score",
    "severity",
    "required_approval",
    "proposed_action",
    "limitations_json",
    "timestamp",
    "dry_run",
    "advisory_rejection",
)

# Persisted columns of triage_annotations covered by the chain, same rules. The
# analyst annotation layer is append-only and separate from the evidence itself:
# a finding is never edited to record triage, so the finding chain above is left
# untouched. Recording who/what/when in its own chain makes the triage trail as
# tamper-evident as the evidence it annotates -- a deleted or altered disposition
# is as detectable as a deleted finding. `actor` is a self-reported claim (the
# token proves the writer is authorized, not who they are); it is chained anyway
# so the claim, once written, cannot be silently rewritten.
TRIAGE_CHAIN_COLUMNS: Sequence[str] = (
    "finding_id",
    "action",
    "disposition",
    "note",
    "actor",
    "created_at",
)


def serialize_core(columns: Sequence[str], row: Mapping[str, Any]) -> str:
    """
    Canonically serialize the chained columns of one row.

    A JSON array of `[name, value]` pairs in fixed column order: the names are
    carried in the payload so the serialization is self-describing and a later
    appended column cannot silently shift the meaning of an existing position.
    `ensure_ascii=True` and the compact separators match the hashing convention
    used elsewhere in the store (`_event_hash`, the detector's provenance hash),
    so the bytes are stable across machines and Python builds.

    `row` is a mapping (a `dict(sqlite3.Row)` in every caller); values are the
    stored column values, already JSON-serializable primitives.
    """
    return json.dumps(
        [[name, row.get(name)] for name in columns],
        separators=(",", ":"),
        ensure_ascii=True,
    )


def link_hash(seq: int, prev_hash: str, serialized: str) -> str:
    """
    Hash one link from its sequence number, predecessor hash, and serialized core.

    `seq` is bound into the digest so that a row cannot be moved to a different
    position in the chain without changing its hash, even if its content and
    predecessor were somehow preserved. Newline delimiters keep the three fields
    unambiguous (a hash is fixed-length hex and the seq is digits, so neither can
    absorb the delimiter).
    """
    return hashlib.sha256(f"{seq}\n{prev_hash}\n{serialized}".encode("utf-8")).hexdigest()


def next_link(
    prev_seq: Any,
    prev_hash: Any,
    columns: Sequence[str],
    row: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Compute the chain fields for the row that follows `(prev_seq, prev_hash)`.

    Pass `prev_seq=None, prev_hash=None` for the first row in a table; it becomes
    seq 0 linked to `GENESIS_PREV_HASH`. Returns the three `chain_*` values to
    persist. This is the single fold both the runtime writer and the migration
    backfill call, so they cannot diverge.
    """
    seq = 0 if prev_seq is None else int(prev_seq) + 1
    prev = prev_hash if prev_hash else GENESIS_PREV_HASH
    serialized = serialize_core(columns, row)
    return {
        "chain_seq": seq,
        "chain_prev_hash": prev,
        "chain_hash": link_hash(seq, prev, serialized),
    }


def verify_chain(columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Recompute a whole chain from stored columns and report the first break.

    `rows` must be the complete chain for one table, ordered by `chain_seq`
    ascending. Walks from genesis, checking three things at each link:

    * contiguity -- `chain_seq` equals its position, so a deleted row (which
      leaves a gap) or a duplicated seq is caught;
    * linkage -- the stored `chain_prev_hash` equals the previous link's hash, so
      a reordering is caught;
    * integrity -- the recomputed `chain_hash` equals the stored one, so any
      mutation of a covered column is caught.

    Returns `{ok, checked, break_seq, reason}`. An empty table verifies as ok
    (an empty append-only log is valid). This never mutates anything; it is the
    read-side counterpart to the append-only writer.
    """
    prev_hash = GENESIS_PREV_HASH
    checked = 0
    for index, row in enumerate(rows):
        seq = row.get("chain_seq")
        if seq != index:
            return {
                "ok": False,
                "checked": checked,
                "break_seq": seq,
                "reason": f"non-contiguous chain_seq at position {index}: found {seq!r}",
            }
        stored_prev = row.get("chain_prev_hash")
        if stored_prev != prev_hash:
            return {
                "ok": False,
                "checked": checked,
                "break_seq": seq,
                "reason": f"broken prev-hash linkage at seq {seq}",
            }
        expected = link_hash(seq, prev_hash, serialize_core(columns, row))
        if row.get("chain_hash") != expected:
            return {
                "ok": False,
                "checked": checked,
                "break_seq": seq,
                "reason": f"hash mismatch at seq {seq} (row mutated, reordered, or removed)",
            }
        prev_hash = expected
        checked += 1
    return {"ok": True, "checked": checked, "break_seq": None, "reason": None}
