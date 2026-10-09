"""
Tests for the train -> evaluate -> gate workflow CLI.

`main(argv)` is called directly rather than through a subprocess: the exit codes
are the contract being tested (0 ran, 2 refused, 1 could not run), and a
subprocess would hide the tracebacks that explain a failure. The one thing a
subprocess would add -- proof the file is executable as a script -- is covered by
loading it the way an operator invokes it, by path.
"""

import importlib.util
import json
import math
import sqlite3
from pathlib import Path

import pytest

from ml.artifact import load_artifact
from ml.evaluation import MIN_NORMAL_HOLDOUT_WINDOWS, evaluate_threshold_from_windows
from ml.feature_schema import extract_features
from ml.lifecycle import record_activation_gate, record_evaluated, record_trained
from ml.scoring import MLScorer
from ml.training import (
    SKLEARN_AVAILABLE,
    add_verified_normal_window,
    create_verified_normal_dataset,
    train_isolation_forest,
)
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore

# The harness lives under scripts/, which is not importable by name (no
# __init__.py, and `pyproject.toml` ships only the real packages), so it is loaded
# from its path -- the convention `tests/test_benchmark_scale.py` established.
_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ml_train_and_evaluate.py"
_spec = importlib.util.spec_from_file_location("ml_train_and_evaluate", _MODULE_PATH)
assert _spec and _spec.loader
workflow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(workflow)

_VERIFICATION = {"verified_normal": True, "operator": "test", "method": "controlled normal workload"}


def _event(timestamp, event_type="process_exec", **values):
    raw = {"event_type": event_type, "timestamp": timestamp, "pid": 10, "uid": 1000, "comm": "python3", **values}
    return Event.from_raw_json(raw)


def _window(index, *, spread=None):
    """
    A small window of ordinary-looking activity, distinct from every other index.

    The shape -- how many execs, how far apart, how many distinct binaries -- cycles
    over a fixed range rather than growing with the index, so training and holdout
    windows are drawn from one distribution. A holdout the model finds alien would
    make its false-positive rate meaningless. Only `window_start` grows with the
    index, which is what keeps every window a distinct row:
    `add_verified_normal_window` derives the window bounds from the timestamps and
    `_window_fingerprint` hashes them, while none of the 34 features read absolute
    time.

    `spread` is open so a holdout can sit *between* the training grid's values
    instead of on them -- interior points the model has genuinely never seen, but
    which are not out-of-range in any feature. That is the distinction the
    activation gate is trying to measure.
    """
    count = 2 + index % 7
    spread = 1.0 + (index % 5) * 0.25 if spread is None else spread
    executables = 1 + index % 3
    base = 1000.0 + index * 10_000.0
    events = [
        _event(base + offset * spread, executable=f"/usr/bin/app{offset % executables}",
               comm=f"app{offset % executables}", pid=100 + offset)
        for offset in range(count)
    ]
    events.append(_event(
        base + count * spread + 1.0, "tcp_connect",
        dest_ip=f"10.0.0.{1 + index % 4}", dest_port=18080 + index % 6, pid=100 + count,
    ))
    return events


def _outlier_window(index):
    """
    A verified-normal window far outside the training distribution.

    Present so one test can observe a *measured* false positive rather than a
    supplied one. Forty execs of forty distinct binaries under forty distinct
    uids, against training windows of two to eight, puts every count and
    diversity feature far outside the fitted range -- which is precisely what an
    Isolation Forest isolates. A verified-normal window the model flags anyway is
    exactly what a false positive is.
    """
    base = 50_000_000.0 + index * 1000.0
    return [
        _event(base + offset, executable=f"/usr/bin/tool{offset}", pid=9000 + offset, uid=2000 + offset,
               comm=f"tool{offset}")
        for offset in range(40)
    ]


def _fill(store, dataset_id, windows, *, id_base=0):
    for index, events in enumerate(windows):
        add_verified_normal_window(
            store, dataset_id, events,
            [id_base + index * 100 + offset for offset in range(len(events))],
            _VERIFICATION,
        )


def _training_store(tmp_path, *, count=35):
    """
    A store holding a training dataset dense enough to define a normal range.

    Thirty-five windows, not the ten `train_isolation_forest` demands as a floor:
    the shape cycle closes over 35 indices, so the model sees the whole grid. Fit
    on a sparser sample it rejects ordinary windows it simply never saw, which is
    a real property of the model rather than a bug, but it is not what the tests
    about the gate's plumbing are trying to observe.
    """
    if not SKLEARN_AVAILABLE:
        pytest.skip("scikit-learn is not installed in the active Python environment")
    store = SQLiteEventStore(str(tmp_path / "ml.db"))
    dataset_id = create_verified_normal_dataset(store, "train", _VERIFICATION, {"role": "training"})
    _fill(store, dataset_id, [_window(index) for index in range(count)])
    return store, dataset_id


def _holdout_db(tmp_path, windows, *, role="holdout", name="holdout.db"):
    """
    A separate database holding one attested holdout dataset.

    Separate on purpose: the CLI opens it `mode=ro`, and pointing the two at one
    file would let a bug in that posture pass unnoticed.
    """
    path = tmp_path / name
    store = SQLiteEventStore(str(path))
    dataset_id = create_verified_normal_dataset(store, "holdout", _VERIFICATION, {"role": role})
    _fill(store, dataset_id, windows, id_base=500_000)
    store.close()
    return str(path), dataset_id


def _normal_holdout(count=MIN_NORMAL_HOLDOUT_WINDOWS):
    """
    Verified-normal windows the model has never seen but should not flag.

    Start times are offset past the training indices so no holdout window is a
    reused training window -- `test_refuses_when_holdout_reuses_training_windows`
    is what proves the overlap check notices when one is. The event spacing is
    taken off the training grid rather than from it, landing between the values
    the model was fitted on: unseen, but inside the normal range in every feature.
    """
    return [
        _window(1000 + index, spread=1.0 + ((index * 7) % 41) / 40.0)
        for index in range(count)
    ]


def _lifecycle_states(store, model_id=None):
    return [row["to_state"] for row in store.read_ml_lifecycle(model_id)]


def test_dry_run_writes_nothing(tmp_path):
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout())
    artifacts = tmp_path / "models"

    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(artifacts),
    ])

    # Sixty clean holdout windows could clear the gate, so nothing refused the run.
    assert code == 0
    # Training writes an artifact *and* an `ml_models` row, so "wrote nothing"
    # has to mean it never trained -- not that it trained and discarded the result.
    assert not artifacts.exists()
    assert workflow._list_models(str(tmp_path / "ml.db")) == []
    assert store.read_ml_lifecycle() == []


def test_records_the_full_trained_evaluated_gated_sequence(tmp_path):
    """
    The whole workflow, ending in a verdict the measurement actually earned.

    `--contamination 0.01` is passed explicitly even though it is the default,
    because the verdict below depends on it and a test should pin what it depends
    on. Contamination *is* the decision threshold here: a forest fitted to treat
    `c` of normal data as outlying flags about `c` of normal windows, and the
    gate's budget is 5% at a one-sided 95% upper bound -- which at sixty windows
    means zero false positives. The old 0.05 default aimed the model straight at
    that ceiling and almost always missed. If a scikit-learn upgrade moves these
    numbers, the `false_positive_count == 0` assertion is what will notice.
    """
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout())

    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"), "--contamination", "0.01",
        "--record", "--operator", "alice",
    ])
    assert code == 0

    states = _lifecycle_states(store)
    # Order matters as much as presence: the log has to show the measurement
    # existing before the decision that cites it.
    assert states == ["trained", "evaluated", "eligible"]
    assert store.verify_ml_lifecycle_chain()["ok"] is True

    rows = store.read_ml_lifecycle()
    assert all(row["actor"] == "alice" for row in rows)
    gate = rows[2]
    # The gate row commits to which windows were measured, not just how many.
    assert len(gate["evidence"]["holdout_window_ids"]) == gate["evidence"]["normal_window_count"]
    assert gate["evidence"]["normal_window_count"] == MIN_NORMAL_HOLDOUT_WINDOWS
    assert gate["evidence"]["false_positive_count"] == 0
    assert gate["evidence"]["acceptance"]["activation_eligible"] is True

    # Eligible is as far as this command goes: the model is still inactive, and
    # exit code 0 does not mean "activated".
    models = workflow._list_models(str(tmp_path / "ml.db"))
    assert len(models) == 1 and models[0]["active"] == 0


def test_gate_refusal_exits_2_and_names_reasons(tmp_path):
    store, training = _training_store(tmp_path)
    # Sixty windows clears the count floor, so the verdict turns on the measured
    # false-positive rate -- and at n=60 even one false positive puts the Wilson
    # upper bound (7.1%) outside the 5% budget. The same contamination as the
    # passing case, so the only difference between the two verdicts is the one
    # deliberately anomalous window.
    windows = _normal_holdout(MIN_NORMAL_HOLDOUT_WINDOWS - 1) + [_outlier_window(0)]
    holdout_db, holdout = _holdout_db(tmp_path, windows)

    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"), "--contamination", "0.01",
        "--record", "--operator", "alice",
    ])

    assert code == 2
    gate = store.read_ml_lifecycle()[-1]
    assert gate["to_state"] == "ineligible"
    assert gate["activation_eligible"] is False
    assert gate["evidence"]["false_positive_count"] == 1
    acceptance = gate["evidence"]["acceptance"]
    assert acceptance["activation_eligible"] is False
    # The refusal is recorded with the gate's own reasons, not a summary of them.
    assert acceptance["reasons"]
    assert any("upper bound" in reason for reason in acceptance["reasons"])
    # An ineligible model is still a model: the refusal is a record, not an erasure.
    assert workflow._list_models(str(tmp_path / "ml.db"))[0]["active"] == 0


def test_a_holdout_below_the_window_floor_is_refused_and_recorded(tmp_path):
    """
    The real-corpus case: a holdout below the 60-window floor cannot ever qualify.

    This is the outcome to expect against a collection program that has promoted a
    handful of windows, and it is the gate working rather than the tool failing.
    The refusal is *recorded* rather than raised: a model that was measured and
    found wanting is exactly the thing the chained log exists to remember, and
    pre-refusing would leave no evidence that anyone had tried. The artifact it
    leaves behind is inert -- `activate_ml_model` still demands an `eligible` row,
    and this run wrote the opposite.
    """
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout(4))
    argv = [
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"),
    ]

    # The dry run says so without training: the floor is arithmetic on the window
    # count, knowable before a model exists.
    assert workflow.main(argv) == 2
    assert not (tmp_path / "models").exists()
    assert store.read_ml_lifecycle() == []

    assert workflow.main([*argv, "--record", "--operator", "alice"]) == 2
    gate = store.read_ml_lifecycle()[-1]
    assert gate["to_state"] == "ineligible"
    assert gate["evidence"]["normal_window_count"] == 4
    assert any(
        str(MIN_NORMAL_HOLDOUT_WINDOWS) in reason
        for reason in gate["evidence"]["acceptance"]["reasons"]
    )
    assert workflow._list_models(str(tmp_path / "ml.db"))[0]["active"] == 0


def test_refuses_when_holdout_reuses_training_windows(tmp_path):
    store, training = _training_store(tmp_path)
    # Byte-identical content under a fresh row id in a different database, which is
    # exactly the case a row-id comparison would miss.
    reused = [_window(3)] + _normal_holdout(MIN_NORMAL_HOLDOUT_WINDOWS - 1)
    holdout_db, holdout = _holdout_db(tmp_path, reused)
    artifacts = tmp_path / "models"

    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(artifacts), "--record", "--operator", "alice",
    ])

    assert code == 2
    assert not artifacts.exists()
    assert store.read_ml_lifecycle() == []

    report, _windows = workflow._preflight(
        store, workflow.ReadOnlyCorpus(holdout_db), training, holdout
    )
    assert any("byte-identical to training windows" in reason for reason in report["refusals"])


def test_refuses_the_same_dataset_as_both_training_and_holdout(tmp_path):
    store, training = _training_store(tmp_path)
    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-dataset", training, "--artifact-dir", str(tmp_path / "models"),
        "--record", "--operator", "alice",
    ])
    assert code == 2
    assert store.read_ml_lifecycle() == []


def test_refuses_a_training_role_dataset_as_holdout(tmp_path):
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout(), role="training")

    code = workflow.main([
        "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"), "--record", "--operator", "alice",
    ])

    assert code == 2
    assert store.read_ml_lifecycle() == []
    report, _windows = workflow._preflight(
        store, workflow.ReadOnlyCorpus(holdout_db), training, holdout
    )
    assert any("role 'training'" in reason for reason in report["refusals"])


def test_activate_is_a_separate_invocation(tmp_path):
    """
    No single invocation can take raw data to an active model, and it is enforced.

    The eligible state here is reached with *supplied* counts, as
    `tests/test_ml_integration.py:_activated` does -- ten training windows cannot
    produce a sixty-window holdout measurement. What is under test is the
    separation and the evidence activation cites, not the measurement.
    """
    store, training = _training_store(tmp_path)
    db = str(tmp_path / "ml.db")
    metadata = train_isolation_forest(store, training, str(tmp_path / "models"))
    counts = {"false_positive_count": 0, "normal_window_count": MIN_NORMAL_HOLDOUT_WINDOWS}
    record_trained(store, metadata, actor="alice")
    record_evaluated(store, metadata["id"], {
        "normal_window_count": MIN_NORMAL_HOLDOUT_WINDOWS, "normal_false_positive_count": 0,
        "normal_false_positive_rate": 0.0, "labels_available": False, "confusion_matrix": None,
    }, actor="alice")
    record_activation_gate(store, metadata["id"], actor="alice", **counts)

    # Combining the two is refused outright, not merely discouraged by the docs.
    with pytest.raises(SystemExit) as refused:
        workflow.main([
            "--db", db, "--activate", "--model-id", metadata["id"], "--operator", "bob",
            "--training-dataset", training, "--holdout-dataset", "whatever",
        ])
    assert "separate invocation" in str(refused.value.code)
    assert store.read_ml_model(metadata["id"])["active"] is False

    # On its own it activates, citing the counts its own `eligible` row recorded
    # rather than any number typed on the command line -- there is no flag to type
    # one with.
    assert workflow.main(["--db", db, "--activate", "--model-id", metadata["id"], "--operator", "bob"]) == 0
    assert store.read_ml_model(metadata["id"])["active"] is True
    active = store.read_ml_lifecycle(metadata["id"])[-1]
    assert active["to_state"] == "active"
    assert active["evidence"]["normal_window_count"] == MIN_NORMAL_HOLDOUT_WINDOWS
    assert store.verify_ml_lifecycle_chain()["ok"] is True


def test_refuses_to_activate_a_model_that_is_not_eligible(tmp_path):
    store, training = _training_store(tmp_path)
    db = str(tmp_path / "ml.db")
    metadata = train_isolation_forest(store, training, str(tmp_path / "models"))

    # No history at all: a usage error, not a measured refusal.
    assert workflow.main(["--db", db, "--activate", "--model-id", metadata["id"], "--operator", "bob"]) == 1

    record_trained(store, metadata, actor="alice")
    # Trained but never measured: refused as a verdict, which is exit 2.
    assert workflow.main(["--db", db, "--activate", "--model-id", metadata["id"], "--operator", "bob"]) == 2
    assert store.read_ml_model(metadata["id"])["active"] is False


def test_recording_requires_an_operator(tmp_path):
    _store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout())
    with pytest.raises(SystemExit) as refused:
        workflow.main([
            "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
            "--holdout-db", holdout_db, "--holdout-dataset", holdout, "--record",
        ])
    # Exit 1, not argparse's default 2: exit 2 means the gate refused, and a
    # scheduled run tells the two apart on the status alone.
    assert "--operator" in str(refused.value.code)


@pytest.mark.parametrize("value", ["0", "-0.1", "0.6", "1.0"])
def test_contamination_outside_the_usable_range_is_a_usage_error(tmp_path, value):
    """
    Zero and above a half are both nonsense, and neither should reach the trainer.

    Rejected as a usage error (exit 1) rather than surviving into a run that would
    then refuse at the gate, because the distinction the exit codes carry is
    "you asked wrong" against "the measurement said no".
    """
    _store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout(3))
    with pytest.raises(SystemExit) as refused:
        workflow.main([
            "--db", str(tmp_path / "ml.db"), "--training-dataset", training,
            "--holdout-db", holdout_db, "--holdout-dataset", holdout,
            "--contamination", value,
        ])
    assert "--contamination" in str(refused.value.code)


def test_the_holdout_corpus_is_never_opened_writable(tmp_path):
    _store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout())
    corpus = workflow.ReadOnlyCorpus(holdout_db)

    assert len(corpus.read_ml_training_windows(holdout)) == MIN_NORMAL_HOLDOUT_WINDOWS
    assert corpus.read_ml_dataset(holdout)["environment"]["role"] == "holdout"
    assert corpus.read_ml_dataset("does-not-exist") is None

    connection = workflow._read_only(holdout_db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM ml_training_windows")
    finally:
        connection.close()


def test_list_datasets_names_the_role(tmp_path, capsys):
    _store, _training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout(3))
    assert workflow.main(["--holdout-db", holdout_db, "--list-datasets"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [(item["id"], item["role"], item["windows"]) for item in listed] == [(holdout, "holdout", 3)]


def test_score_features_matches_score_on_the_same_window(tmp_path):
    """
    Pins the `score`/`score_features` split: the two must agree bit for bit.

    `score()` is the detector's hot path and `score_features` is the evaluation
    path, and the activation gate is only meaningful if the model being measured
    is the model that will run. Equality of the whole payload, not just the score,
    because the payload is what a finding carries.
    """
    store, training = _training_store(tmp_path)
    metadata = train_isolation_forest(store, training, str(tmp_path / "models"))
    scorer = MLScorer(store, metadata["id"], allow_inactive=True)

    for index in (0, 5, 9):
        events = _window(index)
        assert scorer.score(events) == scorer.score_features(extract_features(events))


def test_calibrate_threshold_is_refused_alongside_a_training_or_activation_run(tmp_path):
    """
    Calibrating and gating in one command is refused, because it would be circular.

    A threshold fitted to a holdout and a false-positive rate measured on that
    same holdout are one number computed twice: the gate would hand the target
    back. Letting a single invocation do both would put that number into the
    chained lifecycle log wearing the shape of evidence. The refusal is a usage
    error -- `_Parser.error`, exit 1 -- rather than a verdict, keeping exit 2 for
    "the measurement said no".
    """
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout(3))
    base = [
        "--db", str(tmp_path / "ml.db"), "--model-id", "iforest-whatever",
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"), "--operator", "alice",
    ]

    with pytest.raises(SystemExit) as refused:
        workflow.main([*base, "--calibrate-threshold", "0.05", "--record"])
    assert "--calibrate-threshold cannot be combined" in str(refused.value.code)

    # The other half of the same mistake: a run that trains *and* calibrates fits
    # the threshold to the model it just produced, which is the same circle.
    with pytest.raises(SystemExit) as refused:
        workflow.main([*base, "--calibrate-threshold", "0.05", "--training-dataset", training])
    assert "--calibrate-threshold cannot be combined" in str(refused.value.code)

    # And from the --activate side, which is checked first and refuses just as hard.
    with pytest.raises(SystemExit) as refused:
        workflow.main([*base, "--calibrate-threshold", "0.05", "--activate"])
    assert "separate invocation" in str(refused.value.code)

    # A target outside (0, 1) is the same class of error, and is caught before any
    # model is loaded rather than surfacing as an exception out of the quantile.
    with pytest.raises(SystemExit) as refused:
        workflow.main([*base, "--calibrate-threshold", "0"])
    assert "--calibrate-threshold must be a false-positive rate in (0, 1)" in str(refused.value.code)

    # None of the four wrote anything.
    assert workflow._list_models(str(tmp_path / "ml.db")) == []
    assert store.read_ml_lifecycle() == []
    assert not (tmp_path / "models").exists()


def test_calibration_derives_an_inactive_model_carrying_only_a_trained_row(tmp_path, capsys):
    """
    The end-to-end calibrate run, and the reason it is off by default.

    What it produces is a *second* model -- artifacts are immutable and
    checksum-pinned, so moving a threshold means minting, never editing -- whose
    only lifecycle row is `trained`. No `evaluated` row and no gate verdict,
    because the only holdout it has is the one that set the threshold, and
    `activate_ml_model` demands an `eligible` latest state it therefore cannot
    reach from here.

    The last block is the part worth reading: calibrating *to* a 5% target made
    this model strictly worse at the gate than the uncalibrated parent, which
    flags none of the same sixty windows. "Calibrated" is not a synonym for
    "better", and an in-sample target is a number the gate would recite rather
    than test.
    """
    store, training = _training_store(tmp_path)
    holdout_db, holdout = _holdout_db(tmp_path, _normal_holdout())
    db = str(tmp_path / "ml.db")
    parent = train_isolation_forest(store, training, str(tmp_path / "models"))

    code = workflow.main([
        "--db", db, "--model-id", parent["id"],
        "--holdout-db", holdout_db, "--holdout-dataset", holdout,
        "--artifact-dir", str(tmp_path / "models"),
        "--calibrate-threshold", "0.05", "--operator", "alice",
    ])
    assert code == 0
    output = capsys.readouterr().out

    models = workflow._list_models(db)
    assert len(models) == 2 and [model["active"] for model in models] == [0, 0]
    derived_id = next(model["id"] for model in models if model["id"] != parent["id"])

    assert [row["to_state"] for row in store.read_ml_lifecycle(derived_id)] == ["trained"]
    assert store.read_ml_lifecycle(parent["id"]) == []
    assert store.verify_ml_lifecycle_chain()["ok"] is True

    row = store.read_ml_model(derived_id)
    descriptor = load_artifact(row["artifact_path"], row["artifact_checksum"])["descriptor"]
    assert descriptor["threshold"] != 0.0
    assert descriptor["threshold_provenance"].startswith("holdout_quantile(")
    assert descriptor["calibration"]["derived_from"] == parent["id"]
    assert descriptor["calibration"]["in_sample"] is True
    assert row["hyperparameters"]["derived_from"] == parent["id"]
    # The parent artifact is untouched: calibration mints, it never rewrites.
    assert load_artifact(parent["artifact_path"], parent["artifact_checksum"])["descriptor"]["threshold"] == 0.0

    # The caveat reaches the operator, not just the docstring.
    assert "in-sample" in output and "disjoint" in output

    holdout_windows = workflow.ReadOnlyCorpus(holdout_db).read_ml_training_windows(holdout)
    before = evaluate_threshold_from_windows(MLScorer(store, parent["id"], allow_inactive=True), holdout_windows)
    after = evaluate_threshold_from_windows(MLScorer(store, derived_id, allow_inactive=True), holdout_windows)
    assert before["normal_false_positive_count"] == 0
    assert before["acceptance"]["activation_eligible"] is True
    # Upper-bounded by the budget the calibration was given, and at least one --
    # the same `floor(target * n)` arithmetic `calibrate_threshold` uses. At n=60
    # even a single false positive bounds to 7.13%, outside the gate's 5%.
    budget = math.floor(0.05 * MIN_NORMAL_HOLDOUT_WINDOWS)
    assert 1 <= after["normal_false_positive_count"] <= budget
    assert after["acceptance"]["activation_eligible"] is False
