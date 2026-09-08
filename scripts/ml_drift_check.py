#!/usr/bin/env python3
"""
Assess whether a trained model's feature distributions still describe the host.

This is the operator-facing entry point for ``ml/drift.py``. It compares the
verified-normal windows a model was trained on against a *newer* verified-normal
dataset and reports, per feature, whether the distributions are distinguishable
(two-sample Kolmogorov-Smirnov with a Holm-Bonferroni correction across the
feature family). Drift is a statement about the data, not about the host's
security posture: a legitimate workload change produces exactly the same signal.

Three boundaries are load-bearing:

* **It cannot activate, deactivate, or re-threshold anything.** The assessment is
  advisory. A ``drift_detected`` result appends a ``retraining_required`` entry to
  the model lifecycle log and stops there; a human decides whether to retrain, and
  a retrained model still has to pass the activation gate in ``ml/evaluation.py``.
* **It writes nothing unless asked.** Without ``--record`` this prints the
  assessment and exits. With ``--record`` it appends to the two append-only tables
  (``ml_drift_assessments`` and the hash-chained ``ml_model_lifecycle``) and
  touches nothing else -- no threshold, no artifact, no ``active`` flag.
* **It never mutates the comparison corpus.** The comparison database is opened
  read-only (``mode=ro``), so an operator's verified-normal corpus is untouched.

It refuses rather than reassures. Too few windows on either side -- or sample
sizes too small for any Holm-corrected result to be attainable at all -- is
reported as ``insufficient_data`` with the reasons named, never as "no drift".

    # what models and datasets are here?
    python3 scripts/ml_drift_check.py --db models.db --list-models
    python3 scripts/ml_drift_check.py --comparison-db corpus/normal.db --list-datasets

    # assess, print only:
    python3 scripts/ml_drift_check.py --db models.db --model-id iforest-... \\
        --comparison-db corpus/normal.db --comparison-dataset verified-normal-...

    # assess and append to the lifecycle log:
    python3 scripts/ml_drift_check.py --db models.db --model-id iforest-... \\
        --comparison-db corpus/normal.db --comparison-dataset verified-normal-... \\
        --record --operator alice
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List

# Runnable as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.drift import DEFAULT_ALPHA, assess_drift, drift_summary  # noqa: E402
from ml.lifecycle import record_drift_assessment  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402


def _read_only(path: str) -> sqlite3.Connection:
    """Open a database read-only, so an inspection cannot alter it."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"database not found: {path}")
    connection = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


class ReadOnlyWindowSource:
    """
    Read verified-normal windows from a corpus database without opening it writable.

    Duck-types the one method ``ml/drift.py:assess_drift`` calls on a comparison
    store. It exists because ``SQLiteEventStore`` opens read-write and would
    migrate the file it is pointed at -- and an operator's verified-normal corpus
    must not be modified, or even schema-touched, by a monitoring check. Same
    posture ``scripts/collect_normal_window.py`` takes with a source capture.

    The decode mirrors ``SQLiteEventStore._decode_ml_training_windows`` so the
    window dicts have the same shape either way.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def read_ml_training_windows(self, dataset_id: str) -> List[Dict[str, Any]]:
        connection = _read_only(self.db_path)
        try:
            rows = connection.execute(
                "SELECT * FROM ml_training_windows WHERE dataset_id = ? ORDER BY window_start, id",
                (dataset_id,),
            ).fetchall()
        finally:
            connection.close()
        windows = []
        for row in rows:
            window = dict(row)
            for key in ("event_ids_json", "features_json", "collector_context_json", "verification_json"):
                window[key.removesuffix("_json")] = json.loads(window.pop(key))
            window["verified_normal"] = bool(window["verified_normal"])
            windows.append(window)
        return windows


def _list_models(path: str) -> List[Dict[str, Any]]:
    connection = _read_only(path)
    try:
        rows = connection.execute(
            "SELECT id, version, active, schema_version, created_at, "
            "json_array_length(training_window_ids_json) AS training_windows "
            "FROM ml_models ORDER BY created_at"
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _list_datasets(path: str) -> List[Dict[str, Any]]:
    connection = _read_only(path)
    try:
        rows = connection.execute(
            "SELECT d.id, d.name, d.schema_version, d.created_at, "
            "(SELECT COUNT(*) FROM ml_training_windows w WHERE w.dataset_id = d.id) AS windows "
            "FROM ml_datasets d ORDER BY d.created_at"
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _print_assessment(assessment: Dict[str, Any]) -> None:
    summary = drift_summary(assessment)
    print(f"model:      {summary['model_id']}")
    print(f"comparison: {summary['comparison_dataset_id']}")
    print(f"status:     {summary['status']}")
    print(f"method:     {summary['method']} (alpha={summary['alpha']})")
    print(
        f"windows:    {summary['reference_window_count']} reference vs "
        f"{summary['comparison_window_count']} comparison"
    )
    if summary["reasons"]:
        print("reasons:")
        for reason in summary["reasons"]:
            print(f"  - {reason}")
    if summary["out_of_range_rate"] is not None:
        print(f"out-of-training-range values: {summary['out_of_range_rate']:.2%}")
    if summary["drifted_features"]:
        print(f"drifted features ({summary['drifted_feature_count']}):")
        for item in assessment["features"]:
            if item["drifted"]:
                print(
                    f"  - {item['feature']}: D={item['statistic']:.3f} "
                    f"p={item['p_value']:.3g} (Holm threshold {item['holm_threshold']:.3g}, "
                    f"{item['p_value_method']}); training range "
                    f"[{item['reference_min']:.4g}, {item['reference_max']:.4g}], "
                    f"mean {item['reference_mean']:.4g} -> {item['comparison_mean']:.4g}"
                )
    # The labelled split is the point, so it is printed rather than summarized:
    # the statistics are facts and what they imply for the model is not.
    print("assessment:")
    for factor in assessment["factors"]:
        print(f"  [{factor['label']}] {factor['statement']}")
        for limitation in factor["evidence"].get("limitations", []):
            print(f"      - {limitation}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="database holding the model and its training windows")
    parser.add_argument("--model-id", help="model to assess")
    parser.add_argument("--comparison-db", help="database holding the newer verified-normal dataset")
    parser.add_argument("--comparison-dataset", help="dataset id to compare against")
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA, help="family-wise error rate")
    parser.add_argument("--record", action="store_true", help="append the assessment to the lifecycle log")
    parser.add_argument("--operator", help="operator recording the assessment (self-reported, chained)")
    parser.add_argument("--list-models", action="store_true", help="list models in --db and exit")
    parser.add_argument("--list-datasets", action="store_true", help="list datasets in --comparison-db and exit")
    parser.add_argument("--json", action="store_true", help="print the full assessment as JSON")
    args = parser.parse_args(argv)

    if args.list_models:
        if not args.db:
            parser.error("--list-models requires --db")
        print(json.dumps(_list_models(args.db), indent=2, sort_keys=True))
        return 0
    if args.list_datasets:
        source = args.comparison_db or args.db
        if not source:
            parser.error("--list-datasets requires --comparison-db or --db")
        print(json.dumps(_list_datasets(source), indent=2, sort_keys=True))
        return 0

    for required in ("db", "model_id", "comparison_dataset"):
        if not getattr(args, required):
            parser.error(f"--{required.replace('_', '-')} is required")
    if args.record and not args.operator:
        parser.error("--record requires --operator: the lifecycle log records who assessed the model")

    store = SQLiteEventStore(args.db)
    comparison_store = ReadOnlyWindowSource(args.comparison_db) if args.comparison_db else None
    assessment = assess_drift(
        store,
        args.model_id,
        args.comparison_dataset,
        comparison_store=comparison_store,
        alpha=args.alpha,
    )

    if args.json:
        print(json.dumps(assessment, indent=2, sort_keys=True))
    else:
        _print_assessment(assessment)

    if args.record:
        written = record_drift_assessment(store, assessment, actor=args.operator)
        states = ", ".join(row["to_state"] for row in written["lifecycle"])
        print(f"\nrecorded assessment {written['assessment']['id']}; lifecycle appended: {states}")
        chain = store.verify_ml_lifecycle_chain()
        print(f"lifecycle chain: {'ok' if chain['ok'] else chain['reason']} ({chain['checked']} links)")
        if not chain["ok"]:
            return 1
    else:
        print("\n(nothing written: pass --record --operator NAME to append this to the lifecycle log)")

    # A refusal is not a pass. Exit non-zero so a scheduled run surfaces it rather
    # than logging "checked" and moving on.
    return 2 if assessment["status"] == "insufficient_data" else 0


if __name__ == "__main__":
    sys.exit(main())
