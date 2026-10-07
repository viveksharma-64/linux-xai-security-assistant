#!/usr/bin/env python3
"""
Train a model, measure it on a holdout corpus, and record what the activation gate said.

This is the operator-facing entry point for the one sequence that can make a model
eligible: ``ml/training.py`` trains it, ``ml/evaluation.py`` measures it against
verified-normal windows it has never seen, and ``ml/lifecycle.py`` appends the
gate's verdict to the hash-chained log. Those three had no caller outside the test
suite before this script, so the workflow the documentation described was one an
operator had to assemble by hand -- and a documented workflow with no entry point
is a workflow nobody follows correctly twice.

Four boundaries are load-bearing:

* **It cannot activate anything.** ``eligible`` is as far as this sequence goes.
  Activation is a second, separate invocation (``--activate --model-id ...``), and
  combining it with a training run is refused outright -- so no single command can
  take raw data to an active model, and whoever activates has had to read the
  verdict first.
* **It writes nothing unless asked.** Without ``--record`` it runs every
  up-front refusal, reports what the run would attempt and whether it could
  possibly clear the gate, and exits having trained nothing. Training writes an
  artifact and an ``ml_models`` row, so a dry run that trained would not be a dry
  run.
* **It never mutates the holdout corpus.** ``--holdout-db`` is opened read-only
  (``mode=ro``) -- the posture ``scripts/ml_drift_check.py`` takes with a
  comparison corpus and ``scripts/collect_normal_window.py`` with a source
  capture. An evaluation must not be able to edit the evidence it cites.
* **It refuses to self-approve.** The verdict comes from
  ``ml/evaluation.py:normal_fpr_acceptance``, called inside
  ``ml/lifecycle.py:record_activation_gate`` over counts this script measured.
  There is no flag here that asserts eligibility and none that relaxes the gate's
  thresholds; the gate's answer is printed verbatim, including its reasons.

It refuses rather than reassures, and refuses *before* training, so a run that
could never have cleared the gate does not leave an artifact behind.

Expect a refusal on a corpus that was not deliberately built for this. The gate
requires 60 independent verified-normal holdout windows
(``ml/evaluation.py:MIN_NORMAL_HOLDOUT_WINDOWS``); a collection program that has
promoted four of them will be told so, with the count named. That is the gate
working, not the tool failing.

``--contamination`` is the main lever on the verdict, and worth understanding
before reaching for it. Contamination *is* the Isolation Forest decision
threshold, so a forest fitted to treat 5% of its training data as outlying flags
roughly 5% of normal windows -- while the gate allows 5% only as a 95% upper
bound, which at 60 windows means zero. Lowering it raises the bar for calling a
window anomalous; lowering it *while growing the training set* eventually buys
eligibility with a model too permissive to flag anything, which is the one
failure a false-positive budget cannot see.

    # what is here?
    python3 scripts/ml_train_and_evaluate.py --db models.db --list-models
    python3 scripts/ml_train_and_evaluate.py --holdout-db corpus/normal.db --list-datasets

    # check whether a run could clear the gate, writing nothing:
    python3 scripts/ml_train_and_evaluate.py --db models.db \\
        --training-dataset verified-normal-... --holdout-db corpus/normal.db \\
        --holdout-dataset verified-normal-... --artifact-dir models/

    # train, measure, and record the verdict (three chained lifecycle rows):
    python3 scripts/ml_train_and_evaluate.py --db models.db \\
        --training-dataset verified-normal-... --holdout-db corpus/normal.db \\
        --holdout-dataset verified-normal-... --artifact-dir models/ \\
        --contamination 0.01 --record --operator alice

    # only if that printed `eligible`, and only as its own invocation:
    python3 scripts/ml_train_and_evaluate.py --db models.db --activate \\
        --model-id iforest-... --operator alice

Exit status: 0 nothing refused the run, 2 the gate or a precondition refused it,
1 the run could not be completed (bad arguments, missing data, training error).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from inspect import signature
from typing import Any, NoReturn

# Runnable as a bare script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Imported rather than restated: "the same window" has to mean one thing in this
# codebase, and `ml/drift.py` already decided what -- content, not row id. A second
# definition here would be a second thing to keep in step.
from ml.drift import _window_fingerprint  # noqa: E402
from ml.evaluation import (  # noqa: E402
    MIN_NORMAL_HOLDOUT_WINDOWS,
    MLEvaluationError,
    evaluate_threshold_from_windows,
    normal_fpr_acceptance,
)
from ml.feature_schema import SCHEMA_VERSION, schema_hash  # noqa: E402
from ml.lifecycle import (  # noqa: E402
    current_state,
    record_activation,
    record_activation_gate,
    record_evaluated,
    record_trained,
)
from ml.scoring import MLScorer, MLScoringError  # noqa: E402
from ml.training import MLTrainingError, train_isolation_forest  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402

# The attestation a dataset must carry to be measured against. Same literal
# `scripts/corpus_status.py` reports on and `scripts/collect_normal_window.py`
# writes; see `_role_of` below for why it is restated rather than imported.
HOLDOUT_ROLE = "holdout"

# Read off the trainer rather than restated here, so the help text cannot claim a
# default `train_isolation_forest` does not actually use.
DEFAULT_CONTAMINATION = signature(train_isolation_forest).parameters["contamination"].default


class _Parser(argparse.ArgumentParser):
    """
    An argument parser whose usage errors exit 1 rather than argparse's default 2.

    Exit 2 is reserved here for "the gate refused", which is a *result*. A
    scheduled run tells the two apart on the exit status alone, so a mistyped
    flag must not be able to look like a measured refusal.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        raise SystemExit(f"{self.prog}: error: {message}")


def _read_only(path: str) -> sqlite3.Connection:
    """Open a database read-only, so an inspection cannot alter it."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"database not found: {path}")
    connection = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _role_of(environment: dict[str, Any], verification: dict[str, Any]) -> str:
    """
    The dataset's role (holdout|training|unspecified), read from its metadata.

    `scripts/collect_normal_window.py` writes `role` into both metadata dicts at
    collection time, so both are tried, environment first -- the same order and
    the same default `scripts/corpus_status.py:_role_of` uses. Restated rather
    than imported because `scripts/` is not an importable package; the two
    readers and the one writer are cross-referenced here so a change to the
    convention has a thread to follow.
    """
    for meta in (environment, verification):
        role = meta.get("role") if isinstance(meta, dict) else None
        if role:
            return str(role)
    return "unspecified"


class ReadOnlyCorpus:
    """
    Read a holdout dataset and its windows without opening the corpus writable.

    `SQLiteEventStore` opens read-write and migrates the file it is pointed at,
    which is not an acceptable thing to do to the corpus an activation decision
    cites. `read_ml_training_windows` keeps the store's name and return shape --
    the decode mirrors `SQLiteEventStore._decode_ml_training_windows` -- so it
    duck-types for the one method the evaluation path needs, exactly as
    `scripts/ml_drift_check.py:ReadOnlyWindowSource` does for the drift path.

    Pointed at the same database as `--db` when no separate `--holdout-db` is
    given, which is why it is constructed after the store: `mode=ro` cannot
    create the file, and on a fresh install the store is what creates it.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def read_ml_dataset(self, dataset_id: str) -> dict[str, Any] | None:
        connection = _read_only(self.db_path)
        try:
            row = connection.execute("SELECT * FROM ml_datasets WHERE id = ?", (dataset_id,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        dataset = dict(row)
        for key in ("environment_json", "verification_json"):
            dataset[key.removesuffix("_json")] = json.loads(dataset.pop(key))
        return dataset

    def read_ml_training_windows(self, dataset_id: str) -> list[dict[str, Any]]:
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


def _list_models(path: str) -> list[dict[str, Any]]:
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


def _list_datasets(path: str) -> list[dict[str, Any]]:
    """Datasets with their role, which is what tells an operator which is a holdout."""
    connection = _read_only(path)
    try:
        rows = connection.execute(
            "SELECT d.id, d.name, d.schema_version, d.schema_hash, d.created_at, "
            "d.environment_json, d.verification_json, "
            "(SELECT COUNT(*) FROM ml_training_windows w WHERE w.dataset_id = d.id) AS windows "
            "FROM ml_datasets d ORDER BY d.created_at"
        ).fetchall()
    finally:
        connection.close()
    listed = []
    for row in rows:
        dataset = dict(row)
        environment = json.loads(dataset.pop("environment_json") or "{}")
        verification = json.loads(dataset.pop("verification_json") or "{}")
        dataset["role"] = _role_of(environment, verification)
        listed.append(dataset)
    return listed


def _preflight(
    store: SQLiteEventStore,
    corpus: ReadOnlyCorpus,
    training_dataset: str,
    holdout_dataset: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Every refusal that can be made before an artifact exists, made before one does.

    The ordering is the point. Training writes an `.npz` artifact and an
    `ml_models` row, so a check deferred until afterwards leaves an operator
    holding a model that was never eligible -- and an unusable model sitting in
    an artifact directory is exactly the thing someone activates by mistake
    later. None of these refusals needs the model, so none of them waits for it:

    * The holdout cannot be the training set. Measuring a model on the data it
      was fitted on does not estimate a false-positive rate on normal behaviour;
      it estimates nothing, and it estimates it optimistically.
    * The holdout cannot re-serve training windows, even under fresh row ids in
      a different database. Identity is content, from
      `ml/drift.py:_window_fingerprint`.
    * The holdout must be attested as a holdout. `role` is written at collection
      time, which is the only moment the claim is honest -- a dataset relabelled
      `holdout` after a model has already seen it is not one, and nothing later
      can tell the difference.
    * The holdout must have been built under this runtime's feature schema, or
      its stored feature values are not the quantities this model's forest was
      fitted on. `ml/evaluation.py` re-checks this per window against the model
      itself; checking the dataset here is what makes the refusal arrive before
      the artifact rather than after it.

    Refusals are returned, not raised, so a dry run prints all of them at once
    instead of one per invocation. Returns the report and the holdout windows,
    which the measurement then reads rather than fetching a second time.
    """
    refusals: list[str] = []
    training_windows = store.read_ml_training_windows(training_dataset)
    if not training_windows:
        refusals.append(f"training dataset {training_dataset!r} has no windows in --db")

    dataset = corpus.read_ml_dataset(holdout_dataset)
    holdout_windows = corpus.read_ml_training_windows(holdout_dataset)
    role = "unknown"
    schema_ok = False
    if dataset is None:
        refusals.append(f"holdout dataset {holdout_dataset!r} does not exist in the holdout database")
    else:
        role = _role_of(dataset["environment"], dataset["verification"])
        if role != HOLDOUT_ROLE:
            refusals.append(
                f"holdout dataset {holdout_dataset!r} has role {role!r}, not {HOLDOUT_ROLE!r}: "
                "a dataset is only holdout evidence if it was collected as one"
            )
        schema_ok = dataset["schema_hash"] == schema_hash() and dataset["schema_version"] == SCHEMA_VERSION
        if not schema_ok:
            refusals.append(
                f"holdout dataset {holdout_dataset!r} was built under feature schema "
                f"{dataset['schema_version']}/{dataset['schema_hash'][:12]}, not this runtime's "
                f"{SCHEMA_VERSION}/{schema_hash()[:12]}"
            )

    if training_dataset == holdout_dataset:
        refusals.append(
            "the training and holdout datasets are the same dataset: a model measured on "
            "its own training data has not been measured"
        )
    # Gated on `schema_ok` because the fingerprint reads all 34 named features: a
    # dataset from another schema has already been refused above, and comparing
    # its vectors would raise rather than add a second reason.
    elif schema_ok and training_windows and holdout_windows:
        training_fingerprints = {_window_fingerprint(window) for window in training_windows}
        reused = [
            window["id"] for window in holdout_windows
            if _window_fingerprint(window) in training_fingerprints
        ]
        if reused:
            refusals.append(
                f"{len(reused)} holdout window(s) are byte-identical to training windows "
                f"(ids {reused[:10]}{'...' if len(reused) > 10 else ''}): the holdout must be data "
                "the model has never seen"
            )

    report = {
        "training_dataset": training_dataset,
        "training_window_count": len(training_windows),
        "holdout_dataset": holdout_dataset,
        "holdout_database": corpus.db_path,
        "holdout_role": role,
        "holdout_window_count": len(holdout_windows),
        "holdout_window_ids": [window["id"] for window in holdout_windows],
        "unverified_holdout_window_count": sum(
            1 for window in holdout_windows if not window["verified_normal"]
        ),
        # The verdict the gate would return if the model fired on none of them: an
        # upper bound on this run's prospects, computable without training. It is
        # how the dry run answers "can this corpus support an activation attempt
        # at all" without writing an artifact to find out.
        "best_case_acceptance": normal_fpr_acceptance(0, len(holdout_windows)),
        "refusals": refusals,
    }
    return report, holdout_windows


def _print_preflight(report: dict[str, Any]) -> None:
    print(f"training dataset: {report['training_dataset']} ({report['training_window_count']} windows)")
    print(
        f"holdout dataset:  {report['holdout_dataset']} "
        f"({report['holdout_window_count']} windows, role {report['holdout_role']})"
    )
    print(f"holdout database: {report['holdout_database']} (read-only)")
    if report["unverified_holdout_window_count"]:
        print(f"unverified holdout windows: {report['unverified_holdout_window_count']}")
    if report["refusals"]:
        print("refusing before training:")
        for refusal in report["refusals"]:
            print(f"  - {refusal}")
        return
    best = report["best_case_acceptance"]
    if best["activation_eligible"]:
        print(
            f"gate floor:       {report['holdout_window_count']} holdout windows meets the "
            f"{MIN_NORMAL_HOLDOUT_WINDOWS}-window minimum; the verdict now depends on the "
            "measured false-positive rate"
        )
    else:
        print("gate cannot be cleared by this holdout even with zero false positives:")
        for reason in best["reasons"]:
            print(f"  - {reason}")


def _activate(store: SQLiteEventStore, model_id: str, *, operator: str) -> int:
    """
    Activate a model on the counts its own `eligible` row recorded.

    The counts are read out of the chained lifecycle row rather than taken from
    the command line, so activation cites the measurement that was actually made.
    `storage/sqlite_store.py:activate_ml_model` re-runs the gate over whatever it
    is handed and additionally requires the model's latest state to *be*
    `eligible` -- but it cannot tell whether the numbers it was handed are the
    numbers that were measured, and a count an operator types is a count nobody
    measured. Reading them back closes that gap without weakening either check.
    """
    latest = current_state(store, model_id)
    if latest is None:
        print(f"refusing to activate: {model_id} has no lifecycle history", file=sys.stderr)
        return 1
    if latest["to_state"] != "eligible":
        print(
            f"refusing to activate: the latest lifecycle state of {model_id} is "
            f"{latest['to_state']!r}, not 'eligible'",
            file=sys.stderr,
        )
        return 2
    evidence = latest["evidence"]
    row = record_activation(
        store,
        model_id,
        false_positive_count=evidence["false_positive_count"],
        normal_window_count=evidence["normal_window_count"],
        actor=operator,
    )
    print(
        f"activated {model_id} on its recorded measurement "
        f"({evidence['false_positive_count']} false positives in "
        f"{evidence['normal_window_count']} verified-normal holdout windows)"
    )
    print(f"lifecycle appended: {row['to_state']} (chain_seq {row['chain_seq']})")
    chain = store.verify_ml_lifecycle_chain()
    print(f"lifecycle chain: {'ok' if chain['ok'] else chain['reason']} ({chain['checked']} links)")
    return 0 if chain["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="database holding the models, training windows, and lifecycle log")
    parser.add_argument("--training-dataset", help="verified-normal dataset to train on")
    parser.add_argument("--holdout-db", help="database holding the holdout dataset (opened read-only)")
    parser.add_argument("--holdout-dataset", help="verified-normal holdout dataset to measure against")
    parser.add_argument("--artifact-dir", default="models", help="directory to write the model artifact into")
    parser.add_argument(
        "--contamination", type=float, default=DEFAULT_CONTAMINATION,
        help=(
            "fraction of the training data the forest is allowed to treat as outlying "
            f"(default {DEFAULT_CONTAMINATION}). This sets the decision threshold, so it is "
            "the main lever on the false-positive rate the gate then measures: a model fitted "
            "at 0.05 should be expected to flag about 5%% of normal windows, which the gate's "
            "budget of 5%% at a 95%% upper bound will not clear. Lower it to raise the bar for "
            "calling a window anomalous, but note that a very low value on a large training "
            "set buys eligibility with a model too permissive to flag anything."
        ),
    )
    parser.add_argument("--record", action="store_true", help="train, measure, and append the verdict to the lifecycle log")
    parser.add_argument("--activate", action="store_true", help="activate an already-eligible model (separate invocation)")
    parser.add_argument("--model-id", help="model to act on, with --activate")
    parser.add_argument("--operator", help="operator responsible for the run (self-reported, chained)")
    parser.add_argument("--list-models", action="store_true", help="list models in --db and exit")
    parser.add_argument("--list-datasets", action="store_true", help="list datasets in --holdout-db or --db and exit")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)

    if args.list_models:
        if not args.db:
            parser.error("--list-models requires --db")
        print(json.dumps(_list_models(args.db), indent=2, sort_keys=True))
        return 0
    if args.list_datasets:
        source = args.holdout_db or args.db
        if not source:
            parser.error("--list-datasets requires --holdout-db or --db")
        print(json.dumps(_list_datasets(source), indent=2, sort_keys=True))
        return 0

    if args.activate:
        # The separation is enforced here, not merely documented: one invocation
        # cannot both produce a model and activate it, so the verdict is always
        # read by a human between the two.
        if args.training_dataset or args.holdout_dataset:
            parser.error(
                "--activate cannot be combined with a training run: activation "
                "is a separate invocation by design, so that no single command takes raw data "
                "to an active model. Record the verdict first, read it, then activate."
            )
        for required in ("db", "model_id", "operator"):
            if not getattr(args, required):
                parser.error(f"--{required.replace('_', '-')} is required with --activate")
        return _activate(SQLiteEventStore(args.db), args.model_id, operator=args.operator)

    for required in ("db", "training_dataset", "holdout_dataset"):
        if not getattr(args, required):
            parser.error(f"--{required.replace('_', '-')} is required")
    if args.record and not args.operator:
        parser.error("--record requires --operator: the lifecycle log records who trained and measured the model")
    if not 0.0 < args.contamination <= 0.5:
        parser.error(f"--contamination must be greater than 0 and at most 0.5, not {args.contamination}")

    store = SQLiteEventStore(args.db)
    corpus = ReadOnlyCorpus(args.holdout_db or args.db)
    try:
        report, holdout_windows = _preflight(store, corpus, args.training_dataset, args.holdout_dataset)
    except (FileNotFoundError, sqlite3.Error) as error:
        print(f"error reading the holdout corpus: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_preflight(report)

    if report["refusals"]:
        return 2
    if not args.record:
        print(
            "\n(nothing written: pass --record --operator NAME to train, measure, and record "
            "the gate's verdict)"
        )
        # The best case is all a dry run can report on, so it is what the exit
        # status reports: 2 means this holdout cannot clear the gate however the
        # model turns out, which is worth surfacing before anyone trains.
        return 0 if report["best_case_acceptance"]["activation_eligible"] else 2

    try:
        metadata = train_isolation_forest(
            store, args.training_dataset, args.artifact_dir, contamination=args.contamination
        )
    except MLTrainingError as error:
        print(f"training refused: {error}", file=sys.stderr)
        return 1
    trained = record_trained(store, metadata, actor=args.operator)
    try:
        # `allow_inactive=True` is the one legitimate use of that flag outside
        # `ml/evaluation.py`'s own callers, and this is why it exists: the model
        # has to be scored while inactive, because scoring it against the holdout
        # is how it becomes eligible. Nothing on the detection path passes it.
        scorer = MLScorer(store, metadata["id"], allow_inactive=True)
        evaluation = evaluate_threshold_from_windows(scorer, holdout_windows)
    except (MLScoringError, MLEvaluationError) as error:
        print(f"evaluation refused: {error}", file=sys.stderr)
        print(f"model {metadata['id']} remains trained and inactive", file=sys.stderr)
        return 1
    evaluated = record_evaluated(store, metadata["id"], evaluation, actor=args.operator)
    # The ids, not just the count: the gate row then commits to *which* windows
    # were measured, so a later reader can reproduce the measurement instead of
    # taking a bare number on trust. `evaluate_threshold_from_windows` has already
    # refused any repeat, so the set and the list are the same length.
    window_ids = evaluation["normal_window_ids"]
    gate = record_activation_gate(
        store,
        metadata["id"],
        false_positive_count=evaluation["normal_false_positive_count"],
        normal_window_count=len(set(window_ids)),
        holdout_window_ids=window_ids,
        actor=args.operator,
    )
    acceptance = gate["evidence"]["acceptance"]

    if args.json:
        print(json.dumps(
            {"model": metadata["id"], "evaluation": evaluation, "verdict": gate},
            indent=2, sort_keys=True, default=str,
        ))
    else:
        rate = evaluation["normal_false_positive_rate"]
        print(f"\nmodel:            {metadata['id']}")
        print(f"artifact:         {metadata['artifact_path']} ({metadata['artifact_format']})")
        print(
            f"false positives:  {evaluation['normal_false_positive_count']} of "
            f"{evaluation['normal_window_count']} verified-normal holdout windows"
            + (f" ({rate:.2%})" if rate is not None else "")
        )
        bound = acceptance["normal_fpr_upper_95"]
        if bound is not None:
            print(f"one-sided 95% upper bound: {bound:.2%} (budget {acceptance['max_normal_fpr']:.2%})")
        print(f"verdict:          {gate['to_state']}")
        if acceptance["reasons"]:
            print("reasons:")
            for reason in acceptance["reasons"]:
                print(f"  - {reason}")

    states = " -> ".join(row["to_state"] for row in (trained, evaluated, gate))
    print(f"lifecycle appended: {states}")
    chain = store.verify_ml_lifecycle_chain()
    print(f"lifecycle chain: {'ok' if chain['ok'] else chain['reason']} ({chain['checked']} links)")
    if not chain["ok"]:
        return 1
    if acceptance["activation_eligible"]:
        print(
            "\nthe model is eligible and still inactive. To activate it, as a separate "
            f"invocation:\n  python3 {os.path.relpath(__file__)} --db {args.db} "
            f"--activate --model-id {metadata['id']} --operator NAME"
        )
        return 0
    # A refusal is not a pass. Exit non-zero so a scheduled run surfaces it rather
    # than logging "evaluated" and moving on.
    return 2


if __name__ == "__main__":
    sys.exit(main())
