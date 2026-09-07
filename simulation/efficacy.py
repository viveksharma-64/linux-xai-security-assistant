"""
Detection-efficacy harness.

Runs the seeded labeled corpus (``simulation/corpus.py``) through the *real*
detection path -- ``BehaviorAnalyzer.monitor()`` -> ``DetectionEngine.detect()``
-- and computes a confusion matrix, precision/recall/F1, a one-sided 95% Wilson
upper bound on the benign false-positive rate, and a projected
false-positives-per-day, all against a documented, committed corpus.

Why this mirrors the ML gate
----------------------------
The ML subsystem is held behind a measured, CI-enforced gate
(``ml/evaluation.py`` + ``tests/test_ml_integration.py``). The rule/behaviour
detector had no equivalent: its weights and bands were asserted, not measured.
This harness gives the deterministic detector the same treatment -- published
numbers against a fixed corpus, re-derivable by ``scripts/run_efficacy.py`` and
pinned by ``tests/test_efficacy.py``.

Boundaries (load-bearing)
-------------------------
* The baseline is a **throwaway verified-normal stand-in** built only for this
  harness. It is promoted with
  ``BehaviorAnalyzer.learn_normal(..., verified_normal=True)``, which writes only
  a behaviour-baseline record. It is **never** written through ``ml/training.py``
  and **never** touches ``ml_datasets`` / ``ml_training_windows``. The efficacy
  test asserts exactly that (contamination guard). The behaviour analyzer's
  ``verified_normal`` flag is its own "these samples are normal" attestation and
  is unrelated to the ML verified-normal corpus, which this harness does not
  build.
* Nothing is executed on the host. Every event is a synthesized canonical
  ``Event`` (see ``simulation/corpus.py``); this is a read-only attack
  *simulation*.
* The harness only reads and scores. It persists nothing by default
  (``monitor(persist=False)`` and ``detect(persist=False)``), so a run leaves no
  risk rows or findings behind and the confusion matrix is a pure function of the
  seed.

Evaluation unit
---------------
One 5-minute window. A window is "flagged" iff the detector emits at least one
finding at severity >= ``FLAG_SEVERITY`` (MEDIUM). Precision/recall are over
windows, matching how an operator experiences alerting: a window either raises
an alert or it does not. Sub-MEDIUM findings (LOW) are treated as not-an-alert,
so a window can carry a finding yet still be a true negative.
"""

from dataclasses import dataclass, field
import os
import statistics
import tempfile
from typing import Any, Dict, List, Optional, Sequence

from baseline.behavior_analyzer import BehaviorAnalyzer
from detection.detector import DetectionEngine
from ml.evaluation import _wilson_upper_bound
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore

from simulation import corpus
from simulation.corpus import LabeledWindow

# --------------------------------------------------------------------------- #
# Evaluation policy
# --------------------------------------------------------------------------- #

# 288 five-minute windows per day (24 * 60 / 5). The FP-per-day projection is
# FP-per-benign-window * WINDOWS_PER_DAY, reported with the Wilson upper bound as
# a ceiling.
WINDOWS_PER_DAY = 288

# Severity ordering; a window is flagged iff any finding reaches FLAG_SEVERITY.
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
FLAG_SEVERITY = "MEDIUM"
_NONE_SEVERITY = "NONE"

# The severity bands from DetectionEngine._severity, as (label, lower-inclusive
# threshold). The harness flags at the MEDIUM band; the sweep in _threshold_sweep
# reports what precision/recall *would* be if the flag gate were raised to each
# band. That sweep is the measured evidence behind keeping the bands where they
# are (Deliverable 2) -- it is derived from the same run, never hand-tuned.
_SEVERITY_BANDS = (("MEDIUM", 0.35), ("HIGH", 0.60), ("CRITICAL", 0.80))


@dataclass
class WindowOutcome:
    """The measured result for a single labeled window."""

    name: str
    kind: str
    label: int  # 1 == attack, 0 == benign
    flagged: bool
    severity: str  # highest finding severity, or "NONE" when nothing was found
    max_risk_score: float  # highest fused score among findings, else 0.0
    finding_count: int
    matched_rules: List[str] = field(default_factory=list)
    attack: Optional[Dict[str, Any]] = None
    description: str = ""


def build_analyzer(
    store: SQLiteEventStore,
    baseline_execs: int = corpus.DEFAULT_BASELINE_EXECS,
    seed: int = corpus.DEFAULT_SEED,
) -> BehaviorAnalyzer:
    """
    Promote a throwaway baseline into a fresh ``BehaviorAnalyzer``.

    Uses the analyzer's own ``learn_normal(..., verified_normal=True)`` path (a
    ``behavior_baselines`` write only). Never calls ``ml/training.py`` and never
    writes an ML dataset/window. Raises if the baseline did not reach the
    minimum-normal-execs gate, so a mis-sized baseline fails loudly rather than
    silently producing a monitor() that reports "baseline_not_ready".
    """
    analyzer = BehaviorAnalyzer(store)
    result = analyzer.learn_normal(corpus.build_baseline_events(baseline_execs, seed), verified_normal=True)
    if result.get("status") != "baseline_ready":
        raise RuntimeError(
            f"throwaway baseline did not reach the readiness gate: {result!r} "
            f"(baseline_execs={baseline_execs})"
        )
    return analyzer


def _matched_rule_ids(finding: Dict[str, Any]) -> List[str]:
    for item in finding.get("evidence", []):
        if item.get("signal") == "rule_fusion":
            return sorted(rule["rule_id"] for rule in item.get("rules", []) if rule.get("matched"))
    return []


def evaluate_window(
    analyzer: BehaviorAnalyzer,
    engine: DetectionEngine,
    window: LabeledWindow,
) -> WindowOutcome:
    """
    Score one window through monitor() -> detect() and classify it.

    Neither call persists: ``monitor(persist=False)`` scores against the ready
    baseline without learning from the window, and ``detect(persist=False)``
    fuses and correlates in-memory without writing a finding row.
    """
    monitored = analyzer.monitor(window.events, persist=False)
    risks = monitored.get("risks", [])
    findings = engine.detect(risks=risks, events=window.events, persist=False)["findings"]

    max_rank = -1
    severity = _NONE_SEVERITY
    max_score = 0.0
    matched: set = set()
    for finding in findings:
        rank = _SEVERITY_RANK.get(finding["severity"], -1)
        if rank > max_rank:
            max_rank = rank
            severity = finding["severity"]
        max_score = max(max_score, float(finding["risk_score"]))
        matched.update(_matched_rule_ids(finding))

    flagged = max_rank >= _SEVERITY_RANK[FLAG_SEVERITY]
    return WindowOutcome(
        name=window.name,
        kind=window.kind,
        label=window.label,
        flagged=flagged,
        severity=severity,
        max_risk_score=round(max_score, 4),
        finding_count=len(findings),
        matched_rules=sorted(matched),
        attack=window.attack,
        description=window.description,
    )


def _confusion(outcomes: Sequence[WindowOutcome]) -> Dict[str, Any]:
    """
    Confusion matrix + precision/recall/F1 over windows.

    Deliberately mirrors the arithmetic and key names of
    ``ml/evaluation.py:evaluate_threshold`` so the deterministic detector is
    reported on the same footing as the ML scorer.
    """
    tp = sum(o.flagged and o.label == 1 for o in outcomes)
    fp = sum(o.flagged and o.label == 0 for o in outcomes)
    tn = sum(not o.flagged and o.label == 0 for o in outcomes)
    fn = sum(not o.flagged and o.label == 1 for o in outcomes)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _threshold_sweep(outcomes: Sequence[WindowOutcome]) -> List[Dict[str, Any]]:
    """
    Precision/recall at each severity band if the flag gate were set there.

    Swept over the *published* per-window score (``max_risk_score``, rounded to
    4dp) so the table reconciles exactly with the per-window numbers a reader
    sees. At the MEDIUM band this reproduces the harness's own confusion matrix;
    the higher bands quantify what raising the flag gate would cost, which is the
    evidence for leaving the bands unchanged (Deliverable 2).
    """
    rows: List[Dict[str, Any]] = []
    for band, threshold in _SEVERITY_BANDS:
        tp = sum(o.label == 1 and o.max_risk_score >= threshold for o in outcomes)
        fp = sum(o.label == 0 and o.max_risk_score >= threshold for o in outcomes)
        fn = sum(o.label == 1 and o.max_risk_score < threshold for o in outcomes)
        tn = sum(o.label == 0 and o.max_risk_score < threshold for o in outcomes)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        rows.append(
            {
                "band": band,
                "threshold": threshold,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": precision,
                "recall": recall,
            }
        )
    return rows


def _score_distribution(outcomes: Sequence[WindowOutcome]) -> Dict[str, Any]:
    """
    Per-group summary of the published per-window score, plus the separation gap.

    Groups: attack windows, clean benign windows, and the by-design known-FP
    benign windows. ``separation_gap`` is (lowest attack score - highest clean
    benign score): the margin by which real attacks clear clean traffic. The
    known-FP group overlaps the attack range on purpose (legitimate privileged
    execution), so it is reported separately rather than folded into "benign".
    """

    def summarize(group: List[WindowOutcome]) -> Optional[Dict[str, Any]]:
        if not group:
            return None
        scores = sorted(o.max_risk_score for o in group)
        return {
            "count": len(scores),
            "min": round(scores[0], 4),
            "median": round(statistics.median(scores), 4),
            "max": round(scores[-1], 4),
        }

    attack = [o for o in outcomes if o.label == 1]
    clean = [o for o in outcomes if o.name.startswith("benign_clean_")]
    known_fp = [o for o in outcomes if o.name.startswith("benign_priv_maintenance_")]
    gap = None
    if attack and clean:
        gap = round(
            min(o.max_risk_score for o in attack) - max(o.max_risk_score for o in clean),
            4,
        )
    return {
        "attack": summarize(attack),
        "benign_clean": summarize(clean),
        "benign_known_fp": summarize(known_fp),
        "separation_gap": gap,
    }


def run_efficacy(
    seed: int = corpus.DEFAULT_SEED,
    benign_clean: int = corpus.DEFAULT_BENIGN_CLEAN_WINDOWS,
    baseline_execs: int = corpus.DEFAULT_BASELINE_EXECS,
    store: Optional[SQLiteEventStore] = None,
) -> Dict[str, Any]:
    """
    Run the full corpus and return a published-metrics report.

    If ``store`` is None an in-memory store is created and used (and discarded on
    return). A caller that wants to assert the contamination guard passes its own
    store and inspects ``ml_datasets`` / ``ml_training_windows`` afterwards.
    """
    # A caller (the test) may pass its own store to assert the contamination
    # guard afterwards. Otherwise use a private temp-file store: this store's
    # schema is created by a migration on a dedicated connection that is then
    # closed, so a ":memory:" database -- where every connection is a distinct
    # in-memory DB -- would lose the schema before first use. A temp file is what
    # the store's tests use for the same reason.
    owned_store = store is None
    tmp_dir: Optional[tempfile.TemporaryDirectory] = None
    if owned_store:
        tmp_dir = tempfile.TemporaryDirectory(prefix="efficacy-")
        store = SQLiteEventStore(os.path.join(tmp_dir.name, "efficacy.db"))
    try:
        analyzer = build_analyzer(store, baseline_execs=baseline_execs, seed=seed)
        engine = DetectionEngine(store, persist=False)
        windows = corpus.labeled_windows(seed=seed, benign_clean=benign_clean)
        outcomes = [evaluate_window(analyzer, engine, window) for window in windows]
    finally:
        if owned_store:
            store.close()
            if tmp_dir is not None:
                tmp_dir.cleanup()

    confusion = _confusion(outcomes)
    cm = confusion["confusion_matrix"]
    benign_windows = cm["tn"] + cm["fp"]
    false_positives = cm["fp"]
    fp_rate = false_positives / benign_windows if benign_windows else None
    fp_rate_upper = _wilson_upper_bound(false_positives, benign_windows)
    fp_per_day = fp_rate * WINDOWS_PER_DAY if fp_rate is not None else None
    fp_per_day_upper = fp_rate_upper * WINDOWS_PER_DAY if fp_rate_upper is not None else None

    return {
        "seed": seed,
        "flag_severity": FLAG_SEVERITY,
        "windows_per_day": WINDOWS_PER_DAY,
        "baseline": {"exec_count": baseline_execs, "minimum_required": analyzer.baseline.minimum_samples},
        "counts": {
            "total_windows": len(outcomes),
            "attack_windows": sum(o.label == 1 for o in outcomes),
            "benign_windows": benign_windows,
        },
        **confusion,
        "benign_window_count": benign_windows,
        "false_positive_count": false_positives,
        "false_positive_rate": fp_rate,
        "false_positive_rate_upper_95": fp_rate_upper,
        "fp_per_day": fp_per_day,
        "fp_per_day_upper_95": fp_per_day_upper,
        "band_sweep": _threshold_sweep(outcomes),
        "score_distribution": _score_distribution(outcomes),
        "outcomes": outcomes,
        "manifest": corpus.manifest(seed=seed, benign_clean=benign_clean),
    }
