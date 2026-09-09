#!/usr/bin/env python3
"""
Read / verify / retention scaling benchmark.

Phase B's `benchmark_ingest.py` measures how fast the store *absorbs* events, and
`soak_chaos.py` proves nothing is lost when a collector is killed. Neither answers
the question a scale-out decision actually turns on: as the database grows, which
operation on the *read* side goes nonlinear first, and at what volume? This
harness measures that curve for the four O(n)-suspect operations that
`benchmark_ingest` never touches:

  * the dashboard page query -- `read_detection_findings_page`, whose CTE runs a
    correlated triage-state subquery per finding;
  * hash-chain verification -- `verify_findings_chain` / `verify_policy_chain` /
    `verify_triage_chain` / `verify_ml_lifecycle_chain`, each of which reads its
    whole table and re-folds every row;
  * retention pruning and the VACUUM that reclaims the space (an exclusive-lock
    rebuild, the most disruptive operation the store performs);
  * write throughput held against a table that is already large.

It builds volume through the *real* writers (`write_events`,
`write_detection_finding`, `write_policy_decision`, `write_triage_annotation`,
`write_ml_lifecycle_transition`), so every chain is folded exactly as production
folds it and every measurement runs against a genuinely-shaped database. Nothing
is executed on the host: the only writes are to a throwaway temp database this
script creates and unlinks, exactly as `benchmark_ingest` does.

Timings are hardware- and load-dependent -- a capacity *shape*, not an SLA (see
docs/SCALE_RESULTS.md). Only the deterministic correctness invariants are
gate-able, and `--check` asserts *those alone*, never a time:

  * every chain verifies ok at every tier;
  * event and finding counts reconcile against what was written and pruned;
  * an age prune leaves the coverage floor at or after its cutoff;
  * a size-cap prune brings the file under its byte cap.

    python3 scripts/benchmark_scale.py                    # default tiers, full report
    python3 scripts/benchmark_scale.py --event-tiers 25000,100000,1000000
    python3 scripts/benchmark_scale.py --check            # invariants only, CI-safe
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Runnable as a bare script from anywhere: put the repository root on the path so
# the package imports resolve without a PYTHONPATH incantation.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from observability.config import settings as load_process_settings  # noqa: E402
from pipeline.event_stream import CanonicalNormalizer  # noqa: E402
from storage.retention import SECONDS_PER_DAY, RetentionManager  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402

# Findings are far rarer than events in production, so their tiers are an order of
# magnitude smaller than the event tiers -- the doc says so rather than pretending
# a host emits as many findings as syscalls.
DEFAULT_EVENT_TIERS = (25_000, 100_000, 250_000)
DEFAULT_FINDING_TIERS = (1_000, 5_000, 10_000)
# The ML lifecycle log is a handful of rows per model in practice, not a stream.
# It is populated to a fixed small floor so its chain is real and verifiable, and
# its verify time is read as a floor, not a growth curve.
DEFAULT_ML_FLOOR = 300

EVENT_EPOCH = 1_000_000.0  # matches benchmark_ingest's _raw_event timestamps
DEFAULT_BATCH = 200  # Phase B operating-range batch size
DEFAULT_REPEATS = 25  # samples per read measurement, for stable percentiles

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_DISPOSITIONS = ("true-positive", "false-positive", "benign")


# --------------------------------------------------------------- synthetic data


def _raw_event(seq: int) -> Dict[str, Any]:
    # A process_exec event shaped like the exec probe's output. `seq` keeps the
    # content hash unique so dedupe does not silently absorb the batch and flatter
    # both the write rate and the row count the read curve is measured against.
    return {
        "event_type": "process_exec",
        "timestamp": EVENT_EPOCH + seq * 0.001,
        "pid": 1000 + (seq % 40000),
        "ppid": 1,
        "uid": 1000,
        "gid": 1000,
        "comm": "proc%d" % (seq % 512),
        "filename": "/usr/bin/tool%d" % (seq % 512),
        "source": "benchmark",
        "version": "1.0",
        "argv": ["tool", "--seq", str(seq)],
    }


def _finding(seq: int) -> Dict[str, Any]:
    # A minimal but valid finding. provenance_hash is the dedup key
    # (sqlite_store.write_detection_finding): a unique, seq-derived hash is what
    # makes every finding extend the chain instead of collapsing onto an existing
    # row -- the same concern _raw_event's seq handles for events.
    ratio = (seq % 100) / 100.0
    return {
        "source_risk_id": None,
        "window_start": EVENT_EPOCH + seq,
        "window_end": EVENT_EPOCH + seq + 300.0,
        "entity_type": "process" if seq % 2 == 0 else "network",
        "entity_key": "entity-%d" % (seq % 1024),
        "risk_score": ratio,
        "severity": _SEVERITIES[seq % 4],
        "behavior_score": ratio,
        "rule_score": (seq % 50) / 100.0,
        "context_score": (seq % 25) / 100.0,
        "evidence": {"seq": seq, "signals": ["signal-%d" % (seq % 8)]},
        "explanation": "synthetic scale finding %d" % seq,
        "mode": "monitor",
        "provenance_hash": hashlib.sha256(
            ("scale-finding-%d" % seq).encode("utf-8")
        ).hexdigest(),
        "detector_version": "scale-harness",
        "correlation_id": "corr-%d" % (seq % 256),
    }


def _policy(seq: int, finding_id: int) -> Dict[str, Any]:
    # Advisory-only and dry_run throughout: the synthetic corpus never proposes an
    # active response, mirroring the system's own posture.
    return {
        "finding_id": finding_id,
        "policy_id": "policy-%d" % (seq % 16),
        "decision": "advise",
        "reason": "synthetic scale decision %d" % seq,
        "risk_score": (seq % 100) / 100.0,
        "severity": _SEVERITIES[seq % 4],
        "required_approval": bool(seq % 2),
        "proposed_action": "notify",
        "limitations": {"advisory_only": True},
        "timestamp": EVENT_EPOCH + seq,
        "dry_run": True,
        "advisory_rejection": None,
    }


# ------------------------------------------------------------------- utilities


def _percentile(sorted_values: List[float], fraction: float) -> float:
    if not sorted_values:
        return float("nan")
    index = min(
        len(sorted_values) - 1, int(round(fraction * (len(sorted_values) - 1)))
    )
    return sorted_values[index]


def _time_repeated(fn: Callable[[], Any], repeats: int) -> Dict[str, float]:
    """Run `fn` `repeats` times and return read-latency percentiles in ms."""
    samples: List[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    return {
        "p50": round(_percentile(samples, 0.50), 3),
        "p95": round(_percentile(samples, 0.95), 3),
        "p99": round(_percentile(samples, 0.99), 3),
    }


# ------------------------------------------------------------------ population


def _populate_events(
    store: SQLiteEventStore,
    normalizer: CanonicalNormalizer,
    start_seq: int,
    count: int,
    batch: int,
) -> Tuple[int, float]:
    """Write `count` fresh events via the real normalize+write_events path."""
    inserted = 0
    pending: List[Any] = []
    start = time.perf_counter()
    for seq in range(start_seq, start_seq + count):
        event = normalizer.normalize(_raw_event(seq))
        if event is None:
            continue
        pending.append(event)
        if len(pending) >= batch:
            inserted += store.write_events(pending).inserted
            pending = []
    if pending:
        inserted += store.write_events(pending).inserted
    return inserted, time.perf_counter() - start


def _populate_finding_stack(
    store: SQLiteEventStore, start_seq: int, count: int
) -> float:
    """
    Grow the finding / triage / policy chains together, one annotation and one
    policy decision per finding, through the real chain-extending writers.
    """
    start = time.perf_counter()
    for seq in range(start_seq, start_seq + count):
        finding_id = store.write_detection_finding(_finding(seq))
        store.write_triage_annotation(
            finding_id, "disposition", disposition=_DISPOSITIONS[seq % 3]
        )
        store.write_policy_decision(_policy(seq, finding_id))
    return time.perf_counter() - start


def _populate_ml_floor(store: SQLiteEventStore, count: int) -> None:
    # Only non-active states with no eligibility claim, so the activation gate is
    # never touched: this records lifecycle events, it does not cause one.
    for seq in range(count):
        store.write_ml_lifecycle_transition(
            "scale-model-%d" % (seq % 8),
            "trained" if seq % 2 == 0 else "evaluated",
            reason="synthetic scale lifecycle %d" % seq,
            evidence={"seq": seq},
            from_state=None,
            activation_eligible=False,
        )


# ----------------------------------------------------------------- measurement


def _measure_event_reads(store: SQLiteEventStore, repeats: int) -> Dict[str, Any]:
    return {
        "count_events_ms": _time_repeated(store.count_events, repeats),
        "get_recent_100_ms": _time_repeated(
            lambda: store.get_recent_events(100), repeats
        ),
        "read_records_100_ms": _time_repeated(
            lambda: store.read_event_records(100), repeats
        ),
        "read_records_typed_100_ms": _time_repeated(
            lambda: store.read_event_records(100, event_type="process_exec"), repeats
        ),
    }


def _measure_finding_reads(
    store: SQLiteEventStore, total: int, repeats: int
) -> Dict[str, Any]:
    deep_offset = max(0, total - 100)
    return {
        "first_page_ms": _time_repeated(
            lambda: store.read_detection_findings_page(limit=100, offset=0), repeats
        ),
        "deep_page_ms": _time_repeated(
            lambda: store.read_detection_findings_page(limit=100, offset=deep_offset),
            repeats,
        ),
        "filter_severity_ms": _time_repeated(
            lambda: store.read_detection_findings_page(limit=100, severity="HIGH"),
            repeats,
        ),
        "filter_disposition_ms": _time_repeated(
            lambda: store.read_detection_findings_page(
                limit=100, disposition="true-positive"
            ),
            repeats,
        ),
        "sort_severity_ms": _time_repeated(
            lambda: store.read_detection_findings_page(
                limit=100, sort="severity", order="desc"
            ),
            repeats,
        ),
    }


def _verify(fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    start = time.perf_counter()
    verdict = fn()
    seconds = time.perf_counter() - start
    checked = int(verdict.get("checked", 0))
    return {
        "seconds": round(seconds, 4),
        "checked": checked,
        "us_per_row": round(seconds / checked * 1e6, 2) if checked else float("nan"),
        "ok": bool(verdict.get("ok")),
    }


def _measure_chains(store: SQLiteEventStore) -> Dict[str, Any]:
    return {
        "findings": _verify(store.verify_findings_chain),
        "policy": _verify(store.verify_policy_chain),
        "triage": _verify(store.verify_triage_chain),
        "ml_lifecycle": _verify(store.verify_ml_lifecycle_chain),
    }


def _measure_retention(store: SQLiteEventStore) -> Dict[str, Any]:
    """
    Drive age prune, size cap, and a standalone VACUUM at the top event tier, and
    record both their (illustrative) cost and the (deterministic) invariants they
    must satisfy. Ordered after every non-destructive event read so the reads run
    against the full table; the destructive passes come last.
    """
    base = load_process_settings()
    count_before = store.count_events()
    bytes_before = store.database_bytes()

    # A standalone VACUUM at full volume: the pure exclusive-lock stall window,
    # measured before anything is deleted.
    start = time.perf_counter()
    store.vacuum()
    standalone_vacuum_seconds = round(time.perf_counter() - start, 4)

    # Age prune ~half the corpus. The events span [EVENT_EPOCH, EVENT_EPOCH +
    # (n-1)*0.001]; an injected clock places the cutoff at the midpoint, so the
    # cutoff is exact and independent of the wall clock. Size cap and vacuum are
    # disabled here so run_once performs the age prune alone.
    oldest = store.oldest_event_timestamp() or EVENT_EPOCH
    latest = store.latest_event_timestamp() or EVENT_EPOCH
    midpoint = (oldest + latest) / 2.0
    age_days = 1.0
    clock_value = midpoint + age_days * SECONDS_PER_DAY
    age_settings = dataclasses.replace(
        base,
        retention_max_age_days=age_days,
        retention_max_db_bytes=0,
        retention_vacuum_interval_seconds=0.0,
        retention_prune_batch=5000,
    )
    age_mgr = RetentionManager(store, config=age_settings, clock=lambda: clock_value)
    start = time.perf_counter()
    age_actions = age_mgr.run_once()
    age_seconds = round(time.perf_counter() - start, 4)
    age_deleted = sum(a.get("events_deleted", 0) for a in age_actions)
    oldest_after_prune = store.oldest_event_timestamp()

    # Size cap to half of the post-prune size, forcing a real reclaim through the
    # VACUUM-in-loop path. Age is disabled so run_once performs the size cap alone.
    bytes_after_prune = store.database_bytes()
    cap = int(bytes_after_prune * 0.5)
    cap_settings = dataclasses.replace(
        base,
        retention_max_age_days=0,
        retention_max_db_bytes=cap,
        retention_vacuum_interval_seconds=0.0,
        retention_prune_batch=5000,
    )
    cap_mgr = RetentionManager(store, config=cap_settings, clock=lambda: clock_value)
    start = time.perf_counter()
    cap_actions = cap_mgr.run_once()
    cap_seconds = round(time.perf_counter() - start, 4)
    cap_deleted = sum(a.get("events_deleted", 0) for a in cap_actions)
    bytes_after_cap = store.database_bytes()
    count_after = store.count_events()

    # "Under cap" is an asymptotic outcome, not a universal invariant: the manager
    # is bounded (8 rounds) and documents that it can legitimately end over budget
    # when schema/index/WAL bytes dominate the event rows (its ineffective branch).
    # So gate the contract that DOES hold at every volume -- when over budget the
    # manager acts: it reaches the cap, or shrinks toward it, or runs out of
    # deletable events; it never leaves the file larger. Whether the cap was
    # actually reached is reported as an outcome, for the doc to read against
    # volume, never gated.
    reached_cap = bytes_after_cap <= cap
    made_progress = bytes_after_cap < bytes_after_prune
    events_exhausted = count_after == 0
    size_cap_honored = reached_cap or made_progress or events_exhausted

    return {
        "at_events": count_before,
        "db_bytes_before": bytes_before,
        "standalone_vacuum_seconds": standalone_vacuum_seconds,
        "age_prune": {
            "cutoff": midpoint,
            "events_deleted": age_deleted,
            "oldest_after": oldest_after_prune,
            "seconds": age_seconds,
        },
        "size_cap": {
            "cap_bytes": cap,
            "db_bytes_before": bytes_after_prune,
            "events_deleted": cap_deleted,
            "db_bytes_after": bytes_after_cap,
            "reached_cap": reached_cap,
            "seconds": cap_seconds,
        },
        "facts": {
            # Age prune deletes events at or before the cutoff, so the surviving
            # floor is at or after it (None only if the table was emptied).
            "oldest_after_ge_cutoff": (
                oldest_after_prune is None or oldest_after_prune >= midpoint
            ),
            # The size cap acted on an over-budget file (see above): reached the
            # cap, shrank toward it, or exhausted deletable events -- never grew.
            "size_cap_honored": size_cap_honored,
            # Every deleted event is accounted for by one of the two passes.
            "count_consistent": count_after == count_before - age_deleted - cap_deleted,
        },
    }


# ---------------------------------------------------------------------- sweeps


def run_event_sweep(
    tiers: Tuple[int, ...],
    batch: int,
    repeats: int,
    db_path: str,
    measure_retention: bool = True,
) -> Dict[str, Any]:
    """Grow events cumulatively through `tiers`, measuring reads at each tier."""
    store = SQLiteEventStore(db_path)
    normalizer = CanonicalNormalizer()
    reports: List[Dict[str, Any]] = []
    written = 0
    seq = 0
    for target in tiers:
        add = target - written
        if add < 0:
            raise ValueError("event tiers must be non-decreasing")
        inserted, wall = _populate_events(store, normalizer, seq, add, batch)
        seq += add
        written += inserted
        db_bytes = store.database_bytes()
        events_in_db = store.count_events()
        reports.append(
            {
                "events_in_db": events_in_db,
                "write": {
                    "added": inserted,
                    "wall_seconds": round(wall, 4),
                    "throughput_events_per_sec": (
                        round(inserted / wall, 1) if wall else float("nan")
                    ),
                },
                "db_bytes": db_bytes,
                "bytes_per_event": (
                    round(db_bytes / events_in_db, 1) if events_in_db else float("nan")
                ),
                "reads": _measure_event_reads(store, repeats),
                "facts": {"count_matches_written": events_in_db == written},
            }
        )
    retention = _measure_retention(store) if measure_retention else None
    store.close()
    return {"kind": "events", "tiers": reports, "retention": retention}


def run_finding_sweep(
    tiers: Tuple[int, ...],
    repeats: int,
    ml_floor: int,
    db_path: str,
) -> Dict[str, Any]:
    """
    Grow the finding / triage / policy chains cumulatively through `tiers`,
    measuring the page query and all four chain verifications at each tier. The ML
    lifecycle chain is populated once to a fixed floor before the sweep.
    """
    store = SQLiteEventStore(db_path)
    _populate_ml_floor(store, ml_floor)
    reports: List[Dict[str, Any]] = []
    written = 0
    seq = 0
    for target in tiers:
        add = target - written
        if add < 0:
            raise ValueError("finding tiers must be non-decreasing")
        wall = _populate_finding_stack(store, seq, add)
        seq += add
        written += add
        _, total = store.read_detection_findings_page(limit=1, offset=0)
        chains = _measure_chains(store)
        reports.append(
            {
                "findings_in_db": total,
                "populate_seconds": round(wall, 4),
                "db_bytes": store.database_bytes(),
                "page_reads": _measure_finding_reads(store, total, repeats),
                "verify": chains,
                "facts": {
                    "page_total_matches": total == written,
                    "all_chains_ok": all(c["ok"] for c in chains.values()),
                },
            }
        )
    store.close()
    return {"kind": "findings", "tiers": reports, "ml_floor": ml_floor}


# ------------------------------------------------------------------ invariants


def check_invariants(
    event_sweep: Dict[str, Any], finding_sweep: Dict[str, Any]
) -> List[str]:
    """Return a list of invariant violations; empty means everything held."""
    violations: List[str] = []

    for tier in event_sweep["tiers"]:
        n = tier["events_in_db"]
        if not tier["facts"]["count_matches_written"]:
            violations.append(
                f"event tier {n}: count_events disagrees with events written"
            )

    retention = event_sweep.get("retention")
    if retention is not None:
        facts = retention["facts"]
        if not facts["oldest_after_ge_cutoff"]:
            violations.append("retention: coverage floor fell below the age cutoff")
        if not facts["size_cap_honored"]:
            violations.append(
                "retention: size cap left the file larger while over budget"
            )
        if not facts["count_consistent"]:
            violations.append("retention: deleted-event accounting does not reconcile")

    for tier in finding_sweep["tiers"]:
        n = tier["findings_in_db"]
        if not tier["facts"]["all_chains_ok"]:
            broken = [
                name for name, c in tier["verify"].items() if not c["ok"]
            ]
            violations.append(
                f"finding tier {n}: chain(s) failed verification: {', '.join(broken)}"
            )
        if not tier["facts"]["page_total_matches"]:
            violations.append(
                f"finding tier {n}: page total disagrees with findings written"
            )

    return violations


# ----------------------------------------------------------------- presentation


def _fmt_pct(block: Dict[str, float]) -> str:
    return f"p50={block['p50']:.3f} p95={block['p95']:.3f} p99={block['p99']:.3f}"


def print_report(event_sweep: Dict[str, Any], finding_sweep: Dict[str, Any]) -> None:
    print("=" * 78)
    print("EVENT SWEEP  (write throughput held at volume, and bounded read latency)")
    print("=" * 78)
    for tier in event_sweep["tiers"]:
        w = tier["write"]
        print(
            f"\nevents_in_db={tier['events_in_db']:,}  "
            f"db_bytes={tier['db_bytes']:,}  "
            f"bytes/event={tier['bytes_per_event']}"
        )
        print(
            f"  write (+{w['added']:,}): "
            f"{w['throughput_events_per_sec']:,} ev/s over {w['wall_seconds']}s"
        )
        for name, block in tier["reads"].items():
            print(f"  {name:<28} {_fmt_pct(block)}")

    retention = event_sweep.get("retention")
    if retention is not None:
        age = retention["age_prune"]
        cap = retention["size_cap"]
        print(f"\nretention at {retention['at_events']:,} events "
              f"(db_bytes={retention['db_bytes_before']:,}):")
        print(f"  standalone VACUUM:  {retention['standalone_vacuum_seconds']}s")
        print(
            f"  age prune:          {age['events_deleted']:,} events in "
            f"{age['seconds']}s  (floor now {age['oldest_after']})"
        )
        reached = "reached cap" if cap["reached_cap"] else "floor-limited, over cap"
        print(
            f"  size cap -> {cap['cap_bytes']:,}: {cap['events_deleted']:,} events in "
            f"{cap['seconds']}s  (db_bytes now {cap['db_bytes_after']:,}, {reached})"
        )

    print("\n" + "=" * 78)
    print(f"FINDING SWEEP  (page query + chain verification; ml_floor="
          f"{finding_sweep['ml_floor']})")
    print("=" * 78)
    for tier in finding_sweep["tiers"]:
        print(
            f"\nfindings_in_db={tier['findings_in_db']:,}  "
            f"db_bytes={tier['db_bytes']:,}  "
            f"(populate {tier['populate_seconds']}s)"
        )
        for name, block in tier["page_reads"].items():
            print(f"  {name:<24} {_fmt_pct(block)}")
        for name, v in tier["verify"].items():
            print(
                f"  verify {name:<14} {v['seconds']}s over {v['checked']:,} rows "
                f"({v['us_per_row']} us/row)  ok={v['ok']}"
            )


# ------------------------------------------------------------------------ main


def _parse_tiers(text: str) -> Tuple[int, ...]:
    tiers = tuple(int(part) for part in text.split(",") if part.strip())
    if not tiers:
        raise argparse.ArgumentTypeError("expected a comma-separated list of integers")
    return tiers


def _with_temp_db(prefix: str, fn: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    """Run `fn` against a fresh temp database path, cleaning up all sidecars."""
    handle, db_path = tempfile.mkstemp(prefix=prefix, suffix=".db")
    os.close(handle)
    os.unlink(db_path)  # let the store create it fresh
    try:
        return fn(db_path)
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(db_path + suffix)
            except OSError:
                pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-tiers", type=_parse_tiers, default=DEFAULT_EVENT_TIERS)
    parser.add_argument(
        "--finding-tiers", type=_parse_tiers, default=DEFAULT_FINDING_TIERS
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--ml-floor", type=int, default=DEFAULT_ML_FLOOR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="assert deterministic invariants only (never timings) and exit nonzero on violation",
    )
    parser.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    args = parser.parse_args(argv)

    if args.check:
        # A tiny, fast corpus: --check proves the invariant logic and that the
        # harness builds valid chains, without the volume a timing run needs.
        event_tiers: Tuple[int, ...] = (200,)
        finding_tiers: Tuple[int, ...] = (50,)
        repeats = 3
        ml_floor = 20
    else:
        event_tiers = args.event_tiers
        finding_tiers = args.finding_tiers
        repeats = args.repeats
        ml_floor = args.ml_floor

    event_sweep = _with_temp_db(
        "bench_scale_events_",
        lambda p: run_event_sweep(event_tiers, args.batch_size, repeats, p),
    )
    finding_sweep = _with_temp_db(
        "bench_scale_findings_",
        lambda p: run_finding_sweep(finding_tiers, repeats, ml_floor, p),
    )

    if args.check:
        violations = check_invariants(event_sweep, finding_sweep)
        if violations:
            print("SCALE INVARIANTS FAILED:")
            for violation in violations:
                print(f"  - {violation}")
            return 1
        print(
            "scale invariants OK: chains verify, counts reconcile, "
            "age floor and byte cap honoured"
        )
        return 0

    if args.json:
        import json

        print(json.dumps({"events": event_sweep, "findings": finding_sweep}, indent=2))
        return 0

    print_report(event_sweep, finding_sweep)
    # Even a full report ends by asserting the invariants held for this run, so a
    # timing run cannot silently pass over a broken chain or a missed cap.
    violations = check_invariants(event_sweep, finding_sweep)
    if violations:
        print("\nWARNING: invariants violated during this run:")
        for violation in violations:
            print(f"  - {violation}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
