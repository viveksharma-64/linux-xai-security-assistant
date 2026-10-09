"""
Tests for the promotion door of the verified-normal corpus program.

`scripts/collect_normal_window.py` is the only sanctioned way a window enters
`ml_datasets`, which makes it the only place that can see what has already been
promoted -- `verify_capture_boot.py` inspects captures and can simply be skipped.
So the refusals here are the structural half of the independence argument in
`docs/NORMAL_CORPUS_PROGRAM.md`: the activation gate's Wilson bound counts each
holdout window as one independent trial, and nothing downstream re-checks that
claim. A second window over one login session would not merely be redundant, it
would overstate the evidence by one trial.

Each of the four holdout refusals (ambiguous, missing, already-promoted, and the
slicing case) therefore has its own test pinned to exit status 4, alongside the
two things that must *not* be restricted: a second session from the same boot,
and training windows. `main(argv)` is called directly so the exit codes are part
of the contract rather than an implementation detail.
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
_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_normal_window.py"
_spec = importlib.util.spec_from_file_location("collect_normal_window", _MODULE_PATH)
assert _spec and _spec.loader
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)

BOOT_A = "11111111-1111-4111-8111-111111111111"
BOOT_B = "22222222-2222-4222-8222-222222222222"

# The attestation flags. Spelled out once because every writing path needs all
# three -- that is itself the "cannot self-approve" boundary.
ATTEST = ["--operator", "tester", "--reason", "idle desktop, logs reviewed", "--i-verified-normal"]


def _capture(path, identities, *, count=3, start=1_000.0, manifest=None):
    """Write a source capture with ``count`` events per (boot_id, session_id) pair.

    pid varies so `_event_hash` sees distinct events: both identity fields are
    excluded from the dedup key on purpose, so events differing only in boot_id
    or session_id would otherwise collapse into one row. Timestamps follow pid,
    so a capture's events land at ``start + 100`` upward, one second apart.
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
    store.close()
    if manifest is not None:
        Path(f"{path}.manifest.json").write_text(
            manifest if isinstance(manifest, str) else json.dumps(manifest),
            encoding="utf-8",
        )
    return path


def _run(capsys, argv):
    """Run the CLI with --json and return (exit status, parsed summary or None)."""
    status = collector.main([*argv, "--json"])
    out = capsys.readouterr().out
    return status, (json.loads(out) if out.strip() else None)


def _windows(dataset_db, dataset_id):
    store = SQLiteEventStore(str(dataset_db))
    try:
        return store.read_ml_training_windows(dataset_id)
    finally:
        store.close()


def _all_windows(dataset_db):
    """Every window in the corpus, across datasets -- what the duplicate check reads."""
    store = SQLiteEventStore(str(dataset_db))
    try:
        return store.read_ml_training_windows()
    finally:
        store.close()


def _dataset_ids(dataset_db):
    connection = sqlite3.connect(f"file:{dataset_db}?mode=ro", uri=True)
    try:
        return [row[0] for row in connection.execute("SELECT id FROM ml_datasets ORDER BY created_at, id")]
    finally:
        connection.close()


def test_dry_run_reports_the_session_and_writes_nothing(tmp_path, capsys):
    """The review step. It names the session so the operator can check the claim."""
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(capsys, ["--source", str(source), "--dataset-db", str(dataset_db), "--dry-run"])

    assert status == 0
    assert summary["dry_run"] is True
    assert summary["would_write"] is False
    assert summary["session_identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    assert summary["session_count"] == 1
    assert summary["rows_without_session_id"] == 0
    assert summary["event_count"] == 3
    # Named a dataset store and still did not create one.
    assert not dataset_db.exists()


def test_writing_still_requires_the_operator_attestation(tmp_path, capsys):
    """`verified_normal` is a human's claim; a timer must not be able to assert it."""
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            "--operator", "tester",
            "--reason", "idle desktop",
        ]
    )

    assert status == 3
    assert "--i-verified-normal" in capsys.readouterr().err
    assert not dataset_db.exists()


def test_holdout_promotion_records_session_provenance_under_the_window_hash(tmp_path, capsys):
    """
    "Record enough provenance to audit the session later" -- and make that record
    tamper-evident. The provenance lives in `collector_context`, which
    `_training_window_digest` covers, so editing it to fit a later claim breaks
    the window's `immutable_hash`.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )

    assert status == 0
    assert summary["created_dataset"] is True
    dataset_id = summary["dataset_id"]

    windows = _windows(dataset_db, dataset_id)
    assert len(windows) == 1
    window = windows[0]

    provenance = window["collector_context"]["session_provenance"]
    assert provenance["identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    # The per-pair event count is kept out of `identity` (it is the comparison
    # key) and recorded beside it, where a reviewer can see how much of the
    # capture the attributed session accounts for.
    assert provenance["identities"] == [{"boot_id": BOOT_A, "session_id": "2", "events": 3}]
    assert provenance["rows_without_session_id"] == 0
    assert provenance["capture_manifest"] is None  # no sidecar in this fixture
    # Also on the attestation: "tester reviewed boot A session 2", not "tester
    # reviewed a window".
    assert window["verification"]["session_identity"] == {"boot_id": BOOT_A, "session_id": "2"}

    store = SQLiteEventStore(str(dataset_db))
    try:
        assert store.verify_ml_training_windows(dataset_id) == {
            "ok": True,
            "checked": 1,
            "mismatched_ids": [],
        }
    finally:
        store.close()

    # Rewrite the recorded session to a different one, exactly the edit that would
    # make two windows of one session look independent.
    tampered = dict(window["collector_context"])
    tampered["session_provenance"] = {
        **provenance,
        "identity": {"boot_id": BOOT_A, "session_id": "9"},
    }
    conn = sqlite3.connect(str(dataset_db))
    try:
        conn.execute(
            "UPDATE ml_training_windows SET collector_context_json = ? WHERE id = ?",
            (json.dumps(tampered, sort_keys=True), window["id"]),
        )
        conn.commit()
    finally:
        conn.close()

    store = SQLiteEventStore(str(dataset_db))
    try:
        verdict = store.verify_ml_training_windows(dataset_id)
    finally:
        store.close()
    assert verdict["ok"] is False
    assert verdict["mismatched_ids"] == [window["id"]]


def test_holdout_spanning_two_sessions_is_refused(tmp_path, capsys):
    """Ambiguous: one file, two logins. The gate would count it as one trial."""
    source = _capture(tmp_path / "fused.db", [(BOOT_A, "2"), (BOOT_A, "3")])
    dataset_db = tmp_path / "corpus.db"

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ]
    )

    assert status == 4
    error = capsys.readouterr().err
    assert "2 distinct login sessions" in error
    assert "verify_capture_boot.py" in error
    # Refused before the corpus store was even opened.
    assert not dataset_db.exists()


def test_holdout_without_a_session_id_is_refused(tmp_path, capsys):
    """
    Missing: every capture taken before migration 11 is in this state. The boot
    may be known, but a window that cannot name its session cannot be shown
    independent of the other windows from that boot.
    """
    source = _capture(tmp_path / "pre-session.db", [(BOOT_A, None)])
    dataset_db = tmp_path / "corpus.db"

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ]
    )

    assert status == 4
    error = capsys.readouterr().err
    assert "no attributable login session" in error
    assert "3 rows with a NULL session_id" in error
    assert not dataset_db.exists()


def test_re_promoting_an_already_promoted_session_is_refused(tmp_path, capsys):
    """Duplicate: the same capture offered twice must not become two windows."""
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"
    create = [
        "--source", str(source),
        "--dataset-db", str(dataset_db),
        "--dataset-name", "kali-desktop-holdout",
        "--role", "holdout",
        *ATTEST,
    ]
    status, summary = _run(capsys, create)
    assert status == 0
    dataset_id = summary["dataset_id"]

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-id", dataset_id,
            "--role", "holdout",
            *ATTEST,
        ]
    )

    assert status == 4
    error = capsys.readouterr().err
    assert f"boot {BOOT_A} session 2 is already window 1" in error
    assert len(_windows(dataset_db, dataset_id)) == 1


def test_slicing_one_session_into_two_windows_is_refused(tmp_path, capsys):
    """
    "One capture per session, no slicing or duplication." Two disjoint time
    ranges over one login are two windows that share every confounder the
    independence claim rests on, so they hit the same refusal as a re-promotion.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            "--window-end", "1101",
            *ATTEST,
        ],
    )
    assert status == 0
    assert summary["event_count"] == 1
    dataset_id = summary["dataset_id"]

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-id", dataset_id,
            "--role", "holdout",
            "--window-start", "1101",
            *ATTEST,
        ]
    )

    assert status == 4
    assert "slicing it" in capsys.readouterr().err
    assert len(_windows(dataset_db, dataset_id)) == 1


def test_the_same_session_cannot_be_promoted_into_a_second_dataset(tmp_path, capsys):
    """
    The gap this cluster of tests exists for. The duplicate check used to read only
    the dataset being appended to, so `--dataset-name` -- a brand new, empty
    dataset -- had nothing to compare against and the same capture promoted again
    with no refusal at all. Two windows, one login session, and nothing in the
    stored provenance marking them as the same evidence.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"
    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    first = summary["dataset_id"]

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout-take-two",
            "--role", "holdout",
            *ATTEST,
        ]
    )

    assert status == 4
    error = capsys.readouterr().err
    assert f"boot {BOOT_A} session 2 is already window 1 in dataset {first}" in error
    assert "belongs to one dataset" in error
    # The refusal is before the write *and* before the dataset is created, so a
    # rejected promotion leaves no empty dataset behind to confuse the counter.
    assert _dataset_ids(dataset_db) == [first]
    assert len(_all_windows(dataset_db)) == 1


def test_a_second_dataset_cannot_borrow_a_session_from_the_first(tmp_path, capsys):
    """
    Same rule on the `--dataset-id` append path, where the second dataset is
    legitimate -- built from its own session -- and then reaches for one the first
    dataset already holds.
    """
    dataset_db = tmp_path / "corpus.db"
    first_source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    second_source = _capture(tmp_path / "normal-b-s2.db", [(BOOT_B, "2")], start=9_000.0)

    status, summary = _run(
        capsys,
        [
            "--source", str(first_source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "holdout-one",
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    first = summary["dataset_id"]
    status, summary = _run(
        capsys,
        [
            "--source", str(second_source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "holdout-two",
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    second = summary["dataset_id"]
    assert second != first

    status = collector.main(
        [
            "--source", str(first_source),
            "--dataset-db", str(dataset_db),
            "--dataset-id", second,
            "--role", "holdout",
            *ATTEST,
        ]
    )

    assert status == 4
    assert f"is already window 1 in dataset {first}" in capsys.readouterr().err
    assert len(_windows(dataset_db, second)) == 1


def test_a_session_already_used_for_training_cannot_become_a_holdout(tmp_path, capsys):
    """
    Why the across-dataset rule ignores role. "Held out from training" is one of
    the independence criteria, and the overlap check in `ml_train_and_evaluate.py`
    compares window content byte-for-byte -- so this promotion, with its own
    `--window-start`, produces a holdout that shares a login session with training
    and does not match any training window closely enough to be caught.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"
    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-training",
            "--role", "training",
            *ATTEST,
        ],
    )
    assert status == 0
    training = summary["dataset_id"]

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            "--window-start", "1101",
            *ATTEST,
        ]
    )

    assert status == 4
    error = capsys.readouterr().err
    assert f"is already window 1 in dataset {training} (role training)" in error
    assert "held out from" in error
    assert len(_all_windows(dataset_db)) == 1


def test_a_holdout_session_cannot_be_pulled_into_a_training_dataset(tmp_path, capsys):
    """
    The same contamination in the other direction, which matters more: here the
    holdout window already exists and counts toward the gate, and this promotion
    would quietly stop it being held out from anything.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"
    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    holdout = summary["dataset_id"]

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-training",
            "--role", "training",
            *ATTEST,
        ]
    )

    assert status == 4
    assert f"in dataset {holdout} (role holdout)" in capsys.readouterr().err
    assert len(_all_windows(dataset_db)) == 1


def test_training_datasets_do_not_get_an_exemption_from_the_across_dataset_rule(tmp_path, capsys):
    """
    Training repeats are unrestricted *within* one dataset (below), and that is
    the exemption a later reader is most likely to over-generalise. Across two
    training datasets the same session is still one piece of evidence recorded
    twice, and which of the two a model was trained on stops being answerable
    from provenance.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    dataset_db = tmp_path / "corpus.db"
    status, _ = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "training-one",
            "--role", "training",
            *ATTEST,
        ],
    )
    assert status == 0

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "training-two",
            "--role", "training",
            *ATTEST,
        ]
    )

    assert status == 4
    assert len(_all_windows(dataset_db)) == 1


def test_a_separate_corpus_database_is_a_separate_corpus(tmp_path, capsys):
    """
    The limit of the rule, stated so it is a decision rather than an oversight:
    the check reads one `--dataset-db`, because that file is what the gate counts
    and what `corpus_status.py` measures. A deliberately separate corpus -- a
    second experiment, a re-run from scratch -- is not blocked by the first.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    for name in ("corpus-one.db", "corpus-two.db"):
        status, _ = _run(
            capsys,
            [
                "--source", str(source),
                "--dataset-db", str(tmp_path / name),
                "--dataset-name", "kali-desktop-holdout",
                "--role", "holdout",
                *ATTEST,
            ],
        )
        assert status == 0, f"{name} should be an independent corpus"
        assert len(_all_windows(tmp_path / name)) == 1


def test_a_second_session_from_the_same_boot_is_promotable(tmp_path, capsys):
    """
    The behaviour change that makes the program finishable: two logins on one
    boot are two windows. Without this the holdout budget costs 60 reboots.
    """
    first = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    second = _capture(tmp_path / "normal-a-s3.db", [(BOOT_A, "3")], start=9_000.0)
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(first),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    dataset_id = summary["dataset_id"]

    status, summary = _run(
        capsys,
        [
            "--source", str(second),
            "--dataset-db", str(dataset_db),
            "--dataset-id", dataset_id,
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    assert summary["session_identity"] == {"boot_id": BOOT_A, "session_id": "3"}

    windows = _windows(dataset_db, dataset_id)
    assert [w["collector_context"]["session_provenance"]["identity"] for w in windows] == [
        {"boot_id": BOOT_A, "session_id": "2"},
        {"boot_id": BOOT_A, "session_id": "3"},
    ]

    # And a different boot reusing session id 2 is likewise a distinct window --
    # which is why the key has to be the pair: logind renumbers from 1 at boot.
    third = _capture(tmp_path / "normal-b-s2.db", [(BOOT_B, "2")], start=20_000.0)
    status, _ = _run(
        capsys,
        [
            "--source", str(third),
            "--dataset-db", str(dataset_db),
            "--dataset-id", dataset_id,
            "--role", "holdout",
            *ATTEST,
        ],
    )
    assert status == 0
    assert len(_windows(dataset_db, dataset_id)) == 3


def test_training_windows_are_not_restricted_to_one_session(tmp_path, capsys):
    """
    Independence is a *holdout* property -- it is what the Wilson bound assumes.
    More training data is just more training data, so neither a two-session
    capture nor a repeat of one already promoted is refused here.
    """
    fused = _capture(tmp_path / "fused.db", [(BOOT_A, "2"), (BOOT_A, "3")])
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(fused),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-training",
            "--role", "training",
            *ATTEST,
        ],
    )
    assert status == 0
    assert summary["session_count"] == 2
    assert summary["session_identity"] is None
    dataset_id = summary["dataset_id"]

    status, _ = _run(
        capsys,
        [
            "--source", str(fused),
            "--dataset-db", str(dataset_db),
            "--dataset-id", dataset_id,
            "--role", "training",
            *ATTEST,
        ],
    )
    assert status == 0
    assert len(_windows(dataset_db, dataset_id)) == 2

    # The ambiguity is still *recorded*, so a reviewer who later mistook this for
    # a holdout dataset can see both sessions in the stored provenance.
    provenance = _windows(dataset_db, dataset_id)[0]["collector_context"]["session_provenance"]
    assert provenance["identity"] is None
    assert provenance["identities"] == [
        {"boot_id": BOOT_A, "session_id": "2", "events": 3},
        {"boot_id": BOOT_A, "session_id": "3", "events": 3},
    ]


def test_unattributed_daemon_rows_do_not_block_an_otherwise_single_session(tmp_path, capsys):
    """
    Captures stay host-wide on purpose: the always-on ingest service belongs to no
    login session, so NULL session_ids alongside one attributed session are
    expected. Filtering the window down to one session's processes would shift its
    feature distribution away from training and runtime scoring -- a worse problem
    than these NULLs -- so this promotes, and the count is recorded.
    """
    source = _capture(tmp_path / "mixed.db", [(BOOT_A, "2"), (BOOT_A, None)])
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )

    assert status == 0
    assert summary["session_identity"] == {"boot_id": BOOT_A, "session_id": "2"}
    assert summary["rows_without_session_id"] == 3
    provenance = _windows(dataset_db, summary["dataset_id"])[0]["collector_context"][
        "session_provenance"
    ]
    assert provenance["rows_without_session_id"] == 3


def test_the_capture_manifest_is_folded_into_the_window_provenance(tmp_path, capsys):
    """
    logind discards its session records at reboot, so the sidecar's login
    wall-clock (`REALTIME`, microseconds) is the only lasting evidence that two
    same-boot sessions did not overlap. It has to survive into the window.
    """
    manifest = {
        "schema": "normal-capture-session.v1",
        "boot_id": BOOT_A,
        "session_id": "2",
        "REALTIME": "1791460141208568",
        "SEAT": "seat0",
        "TYPE": "x11",
        "CLASS": "user",
    }
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")], manifest=manifest)
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )

    assert status == 0
    provenance = _windows(dataset_db, summary["dataset_id"])[0]["collector_context"][
        "session_provenance"
    ]
    assert provenance["capture_manifest"] == manifest
    assert provenance["capture_manifest"]["REALTIME"] == "1791460141208568"


def test_a_damaged_manifest_is_recorded_rather_than_blocking_promotion(tmp_path, capsys):
    """
    A corrupt sidecar is noted in the provenance, not treated as a refusal:
    independence is adjudicated from the event rows, and `verify_capture_boot.py`
    is where a capture is accepted or rejected. Silently dropping the error would
    be the bad outcome -- a reviewer must be able to see the snapshot is gone.
    """
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")], manifest="{not json")
    dataset_db = tmp_path / "corpus.db"

    status, summary = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(dataset_db),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )

    assert status == 0
    provenance = _windows(dataset_db, summary["dataset_id"])[0]["collector_context"][
        "session_provenance"
    ]
    assert "unreadable manifest" in provenance["capture_manifest"]["error"]


def test_an_empty_window_is_refused_before_any_session_check(tmp_path, capsys):
    """A window selection that matches nothing is a mistake, not a null session."""
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])

    status = collector.main(
        [
            "--source", str(source),
            "--dataset-db", str(tmp_path / "corpus.db"),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            "--window-start", "50000",
            *ATTEST,
        ]
    )

    assert status == 1
    assert "no events in the selected window" in capsys.readouterr().err


def test_promotion_never_writes_to_the_source_capture(tmp_path, capsys):
    """`mode=ro` is the mechanism; this pins the guarantee through a real write."""
    source = _capture(tmp_path / "normal-a-s2.db", [(BOOT_A, "2")])
    before = Path(source).read_bytes()

    status, _ = _run(
        capsys,
        [
            "--source", str(source),
            "--dataset-db", str(tmp_path / "corpus.db"),
            "--dataset-name", "kali-desktop-holdout",
            "--role", "holdout",
            *ATTEST,
        ],
    )

    assert status == 0
    assert Path(source).read_bytes() == before
