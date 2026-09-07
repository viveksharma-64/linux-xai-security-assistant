#!/usr/bin/env python3
"""
Report progress of the verified-normal corpus toward the ML activation gate.

Reads a candidate dataset store (the one ``scripts/collect_normal_window.py``
writes) and prints, per dataset and in total, how many verified-normal windows
exist and how many of those are holdout windows -- then runs the *fixed* gate
acceptance function ``ml/evaluation.py:normal_fpr_acceptance`` to show how far
the holdout budget is from the ≥60-window requirement.

It changes nothing. The database is opened read-only (``mode=ro``), so this
tool cannot write, migrate, or otherwise mutate the corpus -- running it a
hundred times leaves the store byte-for-byte identical.

Two honesty boundaries are stated in the output, not hidden:

* **Independence is asserted by the collection program, not proven here.** The
  gate counts *independent* holdout windows (distinct boots/sessions,
  non-overlapping time -- see docs/NORMAL_CORPUS_PROGRAM.md). This counter can
  see how many holdout windows exist; it cannot prove they are independent.
* **This is a best-case count readiness, not a measured FPR.** The real gate
  needs a trained candidate model scoring the holdouts to produce a
  false-positive count. That scoring is out of scope here (and unavailable while
  scikit-learn is absent), so the tool passes ``false_positives=0`` -- the most
  favourable case -- purely to answer "is the *count* sufficient yet, and what
  is the Wilson ceiling at best?" A real acceptance run replaces the zero with
  the model's measured false positives. The bar itself is never moved.

    python3 scripts/corpus_status.py --dataset-db corpus/normal.db
    python3 scripts/corpus_status.py --dataset-db corpus/normal.db --json
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List, Optional

# Runnable as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.evaluation import (  # noqa: E402
    MAX_NORMAL_FPR,
    MIN_NORMAL_HOLDOUT_WINDOWS,
    normal_fpr_acceptance,
)

_HOLDOUT_ROLE = "holdout"


def _role_of(dataset: sqlite3.Row) -> str:
    """The dataset's role (holdout|training|unspecified), read from its metadata."""
    for column in ("environment_json", "verification_json"):
        try:
            meta = json.loads(dataset[column]) if dataset[column] else {}
        except (ValueError, TypeError):
            meta = {}
        role = meta.get("role")
        if role:
            return str(role)
    return "unspecified"


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def collect_status(dataset_db: str) -> Dict[str, Any]:
    """
    Read per-dataset verified-normal window counts, read-only.

    Returns a structured report: one entry per dataset, the holdout/training/total
    verified-normal window counts, and the fixed-gate assessment against the
    holdout count (best case, false_positives=0).
    """
    if not os.path.exists(dataset_db):
        raise FileNotFoundError(f"dataset store not found: {dataset_db}")

    uri = f"file:{os.path.abspath(dataset_db)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        if not (_table_exists(conn, "ml_datasets") and _table_exists(conn, "ml_training_windows")):
            # A raw capture or an empty store: no verified-normal corpus yet.
            datasets: List[sqlite3.Row] = []
            window_counts: Dict[str, int] = {}
        else:
            datasets = conn.execute(
                "SELECT id, name, environment_json, verification_json, created_at "
                "FROM ml_datasets ORDER BY created_at, id"
            ).fetchall()
            window_counts = {
                str(row["dataset_id"]): int(row["n"])
                for row in conn.execute(
                    "SELECT dataset_id, COUNT(*) AS n FROM ml_training_windows "
                    "WHERE verified_normal = 1 GROUP BY dataset_id"
                ).fetchall()
            }
    finally:
        conn.close()

    dataset_reports: List[Dict[str, Any]] = []
    holdout_windows = 0
    training_windows = 0
    other_windows = 0
    for dataset in datasets:
        role = _role_of(dataset)
        count = window_counts.get(str(dataset["id"]), 0)
        if role == _HOLDOUT_ROLE:
            holdout_windows += count
        elif role == "training":
            training_windows += count
        else:
            other_windows += count
        dataset_reports.append(
            {
                "id": dataset["id"],
                "name": dataset["name"],
                "role": role,
                "verified_normal_windows": count,
                "created_at": dataset["created_at"],
            }
        )

    total_windows = holdout_windows + training_windows + other_windows

    # Fixed gate, best-case count readiness (false_positives=0). This never
    # moves the bar; it only reports whether the holdout *count* suffices and the
    # best-possible Wilson ceiling at that count.
    gate = normal_fpr_acceptance(false_positives=0, normal_windows=holdout_windows)
    windows_still_needed = max(0, MIN_NORMAL_HOLDOUT_WINDOWS - holdout_windows)

    return {
        "dataset_db": dataset_db,
        "datasets": dataset_reports,
        "dataset_count": len(dataset_reports),
        "verified_normal_windows_total": total_windows,
        "holdout_windows": holdout_windows,
        "training_windows": training_windows,
        "unspecified_role_windows": other_windows,
        "minimum_normal_holdout_windows": MIN_NORMAL_HOLDOUT_WINDOWS,
        "windows_still_needed": windows_still_needed,
        "max_normal_fpr": MAX_NORMAL_FPR,
        "gate_best_case": gate,
    }


def _print_human(status: Dict[str, Any]) -> None:
    print(f"verified-normal corpus status: {status['dataset_db']}")
    print("")
    if status["datasets"]:
        print(f"{'role':<12} {'windows':>8}  dataset")
        print(f"{'-' * 12} {'-' * 8}  {'-' * 40}")
        for dataset in status["datasets"]:
            print(
                f"{dataset['role']:<12} {dataset['verified_normal_windows']:>8}  "
                f"{dataset['name']} ({dataset['id']})"
            )
        print("")
    else:
        print("  (no verified-normal datasets in this store yet)")
        print("")

    print(f"holdout windows:            {status['holdout_windows']}")
    print(f"training windows:           {status['training_windows']}")
    if status["unspecified_role_windows"]:
        print(f"unspecified-role windows:   {status['unspecified_role_windows']}")
    print(f"total verified-normal:      {status['verified_normal_windows_total']}")
    print("")

    gate = status["gate_best_case"]
    needed = status["windows_still_needed"]
    upper = gate["normal_fpr_upper_95"]
    upper_str = "n/a" if upper is None else f"{upper:.4f}"
    print(
        f"ML gate: requires >= {status['minimum_normal_holdout_windows']} independent "
        f"holdout windows at observed FPR <= {status['max_normal_fpr']:.0%} "
        f"(one-sided 95% Wilson upper <= {status['max_normal_fpr']:.0%})."
    )
    print(f"  holdout windows so far:   {status['holdout_windows']}")
    print(f"  still needed for count:   {needed}")
    print(f"  best-case Wilson upper:   {upper_str}  (at false_positives=0)")
    print(f"  count sufficient:         {'yes' if needed == 0 else 'no'}")
    print(f"  best-case eligible:       {gate['activation_eligible']}")
    if gate["reasons"]:
        for reason in gate["reasons"]:
            print(f"    - {reason}")
    print("")
    print(
        "NOTE: best case only. Independence is asserted by the collection program\n"
        "(docs/NORMAL_CORPUS_PROGRAM.md), not proven here; and a real acceptance run\n"
        "replaces false_positives=0 with a trained candidate model's measured false\n"
        "positives on these holdouts. This tool never changes the model, the gate,\n"
        "or the corpus."
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report verified-normal corpus progress toward the fixed ML activation gate (read-only).",
    )
    parser.add_argument("--dataset-db", required=True, help="candidate dataset store (opened read-only)")
    parser.add_argument("--json", action="store_true", help="emit the status report as JSON")
    args = parser.parse_args(argv)

    try:
        status = collect_status(args.dataset_db)
    except (FileNotFoundError, sqlite3.Error) as error:
        print(f"error reading dataset store: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        _print_human(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
