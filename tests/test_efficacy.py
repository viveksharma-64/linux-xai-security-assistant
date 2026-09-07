"""
Regression gate for the detection-efficacy harness (Deliverable 1).

Pins the published confusion matrix / precision / recall / FP-per-day from
``docs/DETECTION_EFFICACY.md`` against the committed, seeded corpus, and asserts
the harness never wrote through a verified-normal ML table (the contamination
guard). The numbers here and in the doc come from the same run
(``scripts/run_efficacy.py``); ``run_efficacy.py --check`` keeps the doc itself
byte-for-byte in sync, so this file pins the *measurement*, not the prose.

Robustness note. Every assertion here is anchored on a quantity with margin:
the confusion matrix depends only on flag decisions, and every flag decision
clears the MEDIUM gate (0.35) comfortably or sits at 0.0 -- none is near the
gate, so float noise cannot flip a count. The one knife-edge in the corpus is
``attack_multi_uid``, which fuses to *exactly* 0.60 (the HIGH/MEDIUM boundary);
its flag decision is rock-solid but its exact HIGH label is fragile, so we pin
the robust facts (flagged, matched rule) and deliberately do not pin its label.
"""

import os
import tempfile

import pytest

from simulation import efficacy
from storage.sqlite_store import SQLiteEventStore


@pytest.fixture(scope="module")
def report():
    """One deterministic harness run, shared across the metric assertions."""
    return efficacy.run_efficacy()


def test_report_configuration(report):
    # The published numbers are only meaningful against the documented config.
    assert report["seed"] == 1337
    assert report["flag_severity"] == "MEDIUM"
    assert report["windows_per_day"] == 288


def test_corpus_shape(report):
    counts = report["counts"]
    assert counts["total_windows"] == 55
    assert counts["attack_windows"] == 5
    assert counts["benign_windows"] == 50
    assert report["benign_window_count"] == 50


def test_confusion_matrix_is_pinned(report):
    assert report["confusion_matrix"] == {"tp": 5, "fp": 2, "tn": 48, "fn": 0}


def test_precision_recall_f1(report):
    assert report["recall"] == 1.0                      # every attack flagged
    assert report["precision"] == pytest.approx(5 / 7)  # 2 known FPs -> honestly < 1.0
    p, r = report["precision"], report["recall"]
    assert report["f1"] == pytest.approx(2 * p * r / (p + r))


def test_false_positive_rate_and_projection(report):
    assert report["false_positive_count"] == 2
    assert report["false_positive_rate"] == pytest.approx(0.04)
    # One-sided 95% Wilson upper bound and its 288-window/day projection, straight
    # from ml/evaluation.py:_wilson_upper_bound -- the same estimator the ML gate
    # uses, so the deterministic detector is reported on identical footing.
    assert report["false_positive_rate_upper_95"] == pytest.approx(0.1139002716361259)
    assert report["fp_per_day"] == pytest.approx(11.52)
    assert report["fp_per_day_upper_95"] == pytest.approx(32.80327823120426)


def test_every_attack_is_flagged(report):
    attacks = [o for o in report["outcomes"] if o.label == 1]
    assert len(attacks) == 5
    assert all(o.flagged for o in attacks)              # recall == 1.0, per window


def test_attack_matched_rules(report):
    # Matched rules are boolean gates, far from any score boundary, so they are
    # robust anchors on *why* each scenario fires -- a stronger regression signal
    # than the fused float, and immune to the multi_uid knife-edge.
    by_name = {o.name: o for o in report["outcomes"]}
    assert by_name["attack_reverse_shell"].matched_rules == [
        "privileged_unusual_execution",
        "suspicious_utility_activity",
    ]
    assert by_name["attack_dualuse_exfil"].matched_rules == ["suspicious_utility_activity"]
    assert by_name["attack_execution_burst"].matched_rules == ["execution_burst"]
    assert by_name["attack_multi_uid"].matched_rules == ["multi_uid_activity"]
    assert by_name["attack_privileged_recon"].matched_rules == ["privileged_unusual_execution"]


def test_reverse_shell_is_critical(report):
    by_name = {o.name: o for o in report["outcomes"]}
    # Measured 0.8377 -- comfortably inside the 0.80 CRITICAL band, so pinning
    # the label here is robust (unlike multi_uid at the 0.60 boundary).
    assert by_name["attack_reverse_shell"].severity == "CRITICAL"


def test_multi_uid_flags_without_pinning_the_boundary(report):
    # attack_multi_uid fuses to exactly 0.60 == the HIGH/MEDIUM boundary. Its
    # flag decision (>= MEDIUM) is what efficacy measures and is rock-solid; the
    # exact HIGH label is a knife-edge, so assert the robust facts and leave the
    # label to the regeneratable published doc (guarded by run_efficacy.py --check).
    by_name = {o.name: o for o in report["outcomes"]}
    outcome = by_name["attack_multi_uid"]
    assert outcome.flagged
    assert outcome.severity in {"MEDIUM", "HIGH"}


def test_known_false_positives_flag_by_design(report):
    # The two priv-maintenance windows are labeled benign but are *expected* to
    # flag: they are the honest cost of a conservative privileged-execution rule
    # and the reason precision is not 1.0.
    known = [o for o in report["outcomes"] if o.name.startswith("benign_priv_maintenance_")]
    assert len(known) == 2
    for outcome in known:
        assert outcome.label == 0
        assert outcome.flagged
        assert "privileged_unusual_execution" in outcome.matched_rules


def test_clean_benign_windows_are_silent(report):
    # Clean uid-1000 activity must separate cleanly from the attacks: no flag and
    # no finding at all -- it does not sit just under the gate.
    clean = [o for o in report["outcomes"] if o.name.startswith("benign_clean_")]
    assert len(clean) == 48
    for outcome in clean:
        assert not outcome.flagged
        assert outcome.finding_count == 0
        assert outcome.severity == "NONE"


def test_baseline_meets_readiness_gate(report):
    baseline = report["baseline"]
    assert baseline["minimum_required"] == 500
    assert baseline["exec_count"] >= baseline["minimum_required"]


def test_score_distribution_separates_cleanly(report):
    # Deliverable 2 evidence: clean traffic is silent and attacks clear it by a
    # wide margin, so the weights need no revision.
    dist = report["score_distribution"]
    assert dist["benign_clean"]["max"] == 0.0            # clean windows are silent
    assert dist["attack"]["min"] == pytest.approx(0.5079)
    assert dist["separation_gap"] == pytest.approx(dist["attack"]["min"])
    assert dist["separation_gap"] > 0.4                  # a wide, unambiguous gap
    assert dist["benign_known_fp"]["max"] == pytest.approx(0.7912)


def test_band_sweep_supports_keeping_the_medium_gate(report):
    # Deliverable 2 evidence: the MEDIUM gate is the only one with full recall,
    # and raising it is strictly worse. Pin the rock-solid MEDIUM operating point
    # exactly; assert the higher bands only via robust inequalities (HIGH sits on
    # the multi_uid 0.60 knife-edge, so its exact recall is not pinned).
    sweep = {row["band"]: row for row in report["band_sweep"]}
    medium, high, critical = sweep["MEDIUM"], sweep["HIGH"], sweep["CRITICAL"]

    # MEDIUM reproduces the harness's own confusion matrix: full recall, the two
    # known FPs the only impurity.
    assert (medium["tp"], medium["fp"], medium["fn"], medium["tn"]) == (5, 2, 0, 48)
    assert medium["recall"] == 1.0

    # HIGH strictly loses real detections yet removes NEITHER false positive
    # (both score 0.7912 > 0.60): a higher gate is strictly worse.
    assert high["recall"] < 1.0
    assert high["fp"] == 2

    # The FPs clear only at CRITICAL, and at the worst recall of the three.
    assert critical["fp"] == 0
    assert critical["recall"] < high["recall"]


def test_harness_writes_no_verified_normal_data():
    """
    Contamination guard.

    The harness promotes only a *throwaway behaviour baseline* via
    ``learn_normal(..., verified_normal=True)`` and scores with ``persist=False``.
    It must never write through the verified-normal ML path, so ``ml_datasets``
    and ``ml_training_windows`` stay empty; and because nothing persists, no
    findings or risk rows are left behind. A ``behavior_baselines`` row proves the
    legitimate baseline path *was* exercised (guarding against a vacuous pass).
    """
    with tempfile.TemporaryDirectory(prefix="efficacy-guard-") as tmp:
        store = SQLiteEventStore(os.path.join(tmp, "guard.db"))
        try:
            result = efficacy.run_efficacy(store=store)
            # Same deterministic run -> same headline, so the guard is auditing
            # the exact execution that produces the published numbers.
            assert result["confusion_matrix"] == {"tp": 5, "fp": 2, "tn": 48, "fn": 0}

            conn = store._connect()

            def count(table: str) -> int:
                return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

            # The verified-normal ML corpus was never touched.
            assert count("ml_datasets") == 0
            assert count("ml_training_windows") == 0
            # The legitimate behaviour-baseline path was used...
            assert count("behavior_baselines") >= 1
            # ...and persist=False held end to end.
            assert count("detection_findings") == 0
            assert count("behavior_risks") == 0
        finally:
            store.close()
