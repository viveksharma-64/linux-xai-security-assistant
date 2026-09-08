"""
Operational efficacy from analyst dispositions (Phase D).

Two things are pinned here. First, the arithmetic: precision and the reviewed
false-positive rate are computed over *reviewed fired findings only*, benign
folds in with false-positive for the rate, and "nothing reviewed yet" is an
honest None rather than a zero. Second -- and this is the load-bearing one --
this measurement is decoupled from the ML gate: it never recomputes population
FPR or recall, and its module never imports the seeded corpus harness or the ML
acceptance gate. Dispositions feed operational reporting only; they must not be
able to move a gate threshold.
"""

import ast
from pathlib import Path

from detection.operational_efficacy import (
    compute_operational_efficacy,
    operational_efficacy_from_store,
)
from storage.sqlite_store import SQLiteEventStore

MODULE = Path(__file__).parents[1] / "detection" / "operational_efficacy.py"


def _finding(entity_key, **overrides):
    finding = {
        "source_risk_id": 1,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": "command",
        "entity_key": entity_key,
        "risk_score": 0.7,
        "severity": "HIGH",
        "behavior_score": 0.7,
        "rule_score": 0.7,
        "context_score": 0.7,
        "evidence": [{"signal": "behavior_anomaly", "score": 0.7}],
        "explanation": f"finding for {entity_key}",
        "mode": "detection",
        "provenance_hash": f"ph-{entity_key}",
        "detector_version": "detector.v1",
    }
    finding.update(overrides)
    return finding


# --------------------------------------------------------------- pure fold


def test_nothing_reviewed_is_honest_none_not_zero():
    result = compute_operational_efficacy(total_findings=5, triage_state={})
    assert result["total_findings"] == 5
    assert result["reviewed"] == 0
    assert result["unreviewed"] == 5
    # An unmeasured precision is None, never a misleading 0.0.
    assert result["precision"] is None
    assert result["reviewed_false_positive_rate"] is None
    # The gate-owned population metrics are always None here.
    assert result["population_false_positive_rate"] is None
    assert result["recall"] is None


def test_precision_and_counts_from_dispositions():
    triage_state = {
        1: {"disposition": "true-positive"},
        2: {"disposition": "true-positive"},
        3: {"disposition": "false-positive"},
        4: {"disposition": "benign"},
        5: {"acknowledged": True},  # reviewed-but-not-dispositioned: not counted
    }
    result = compute_operational_efficacy(total_findings=6, triage_state=triage_state)
    assert result["counts"] == {
        "true_positive": 2,
        "false_positive": 1,
        "benign": 1,
    }
    assert result["reviewed"] == 4  # 2 tp + 1 fp + 1 benign; the ack-only row is not reviewed
    # precision = tp / reviewed = 2/4
    assert result["precision"] == 0.5
    # benign folds in with false-positive for the operational rate: (1+1)/4
    assert result["reviewed_false_positive_rate"] == 0.5
    # one finding acknowledged, none suppressed
    assert result["acknowledged"] == 1
    assert result["suppressed"] == 0
    # total 6, four dispositioned -> two unreviewed
    assert result["unreviewed"] == 2


def test_all_true_positive_is_perfect_precision():
    triage_state = {i: {"disposition": "true-positive"} for i in range(3)}
    result = compute_operational_efficacy(total_findings=3, triage_state=triage_state)
    assert result["precision"] == 1.0
    assert result["reviewed_false_positive_rate"] == 0.0


def test_benign_counts_as_a_non_true_positive_for_the_rate():
    # A benign disposition means "fired but should not have alarmed": precision 0.
    triage_state = {1: {"disposition": "benign"}}
    result = compute_operational_efficacy(total_findings=1, triage_state=triage_state)
    assert result["precision"] == 0.0
    assert result["reviewed_false_positive_rate"] == 1.0


def test_stale_total_never_yields_negative_unreviewed():
    # More dispositions than the reported total (a stale COUNT) clamps at zero.
    triage_state = {i: {"disposition": "true-positive"} for i in range(3)}
    result = compute_operational_efficacy(total_findings=1, triage_state=triage_state)
    assert result["unreviewed"] == 0


# --------------------------------------------------------------- via store


def test_operational_efficacy_from_store_reads_latest_state(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "e.db"))
    a = store.write_detection_finding(_finding("a"))
    b = store.write_detection_finding(_finding("b"))
    store.write_detection_finding(_finding("c"))  # never reviewed

    store.write_triage_annotation(a, "disposition", disposition="true-positive")
    # A correction: latest wins, and it is still one reviewed finding, not two.
    store.write_triage_annotation(b, "disposition", disposition="true-positive")
    store.write_triage_annotation(b, "disposition", disposition="false-positive")

    result = operational_efficacy_from_store(store)
    assert result["total_findings"] == 3
    assert result["reviewed"] == 2
    assert result["unreviewed"] == 1
    assert result["counts"] == {"true_positive": 1, "false_positive": 1, "benign": 0}
    assert result["precision"] == 0.5


# ------------------------------------------------ decoupled from the gate


def test_module_does_not_import_the_corpus_harness_or_ml_gate():
    """
    Static guarantee that operational efficacy cannot leak into -- or be
    contaminated by -- the seeded corpus evaluation or the ML acceptance gate.
    The module may *name* those files in prose (it explains why it is separate),
    but it must not import them, so there is no code path by which a disposition
    could move a gate threshold.
    """
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)

    forbidden = {
        "simulation.efficacy",
        "simulation.corpus",
        "scripts.run_efficacy",
        "ml.evaluation",
    }
    assert not (imported & forbidden), f"must not import gate modules: {imported & forbidden}"
    # Nor a submodule of any of them.
    for name in imported:
        for root in ("simulation", "scripts", "ml"):
            assert not name.startswith(root + "."), f"unexpected gate-side import: {name}"
