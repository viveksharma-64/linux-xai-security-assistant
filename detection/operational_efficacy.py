"""
Operational efficacy from analyst dispositions -- measurement, never a gate.

What this is
------------
Once analysts start dispositioning findings (Phase D), the system can report how
its *fired* findings fared in review: how many were confirmed true positives,
how many were false positives or benign, and therefore its operational
precision. This module computes exactly that, and nothing it cannot honestly
support.

Why it is not the ML gate, and cannot be
----------------------------------------
The seeded evaluation (`simulation/efficacy.py`, `scripts/run_efficacy.py`) and
the ML acceptance gate (`ml/evaluation.py:normal_fpr_acceptance`) measure the
detector against a *labelled corpus* with ground truth for every window,
including windows that did **not** fire. That is what lets them state a
population false-positive rate, a Wilson upper bound, and recall, and it is what
the >=60-window rule and the FPR<=5% gate are built on.

Dispositions cannot do that. An analyst only ever dispositions a finding that
*fired* -- there is no disposition for the vastly larger set of windows the
detector correctly left alone. With no observed true negatives and no observed
false negatives, population FPR and recall are simply not defined here, and any
number claiming to be one would be a fabrication. So this module reports
**precision** over reviewed fired findings and a **reviewed false-positive
rate**, both explicitly conditioned on "among findings an analyst reviewed", and
stops there.

The TP/FP split matches `simulation/efficacy.py:_confusion` (a true positive is
a fired finding that was a real detection; a false positive is a fired finding
that was not) so the two vocabularies reconcile. But this measurement is
deliberately kept out of the corpus harness, the seeded efficacy doc, and the ML
gate: dispositions feed operational reporting only and must never move a gate
threshold. Benign dispositions are folded in with false positives for the rate,
since operationally both are "this fired but should not have alarmed".
"""

from typing import Any, Dict, Mapping, Optional

# The disposition vocabulary, mirrored from the triage layer
# (`storage/sqlite_store.py:_TRIAGE_DISPOSITIONS`). `true-positive` is the only
# disposition that counts an alert as correct; `false-positive` and `benign` are
# both "should not have alarmed" for the operational rate.
_TRUE_POSITIVE = "true-positive"
_REVIEWED_DISPOSITIONS = ("true-positive", "false-positive", "benign")


def compute_operational_efficacy(
    total_findings: int,
    triage_state: Mapping[int, Mapping[str, Any]],
) -> Dict[str, Any]:
    """
    Precision and review counts from the latest per-finding triage state.

    `triage_state` is `SQLiteEventStore.read_latest_triage_state()` -- the folded
    effective state of the append-only annotation layer, keyed by finding id.
    `total_findings` is the number of persisted findings, so unreviewed can be
    reported without walking the annotations again.

    Returns counts plus `precision = tp / reviewed` and
    `reviewed_false_positive_rate = (fp + benign) / reviewed`, both `None` when
    nothing has been reviewed (an honest "not yet measurable", not a zero). No
    population FPR or recall is produced -- see the module docstring.
    """
    counts = {disposition: 0 for disposition in _REVIEWED_DISPOSITIONS}
    acknowledged = 0
    suppressed = 0
    for state in triage_state.values():
        if state.get("acknowledged"):
            acknowledged += 1
        if state.get("suppressed"):
            suppressed += 1
        disposition = state.get("disposition")
        if disposition in counts:
            counts[disposition] += 1

    reviewed = sum(counts.values())
    true_positives = counts[_TRUE_POSITIVE]
    false_positive_like = reviewed - true_positives
    # Clamp: triage_state only ever references persisted findings, but a caller
    # passing a stale total should not yield a negative unreviewed count.
    unreviewed = max(0, int(total_findings) - reviewed)

    precision: Optional[float] = true_positives / reviewed if reviewed else None
    reviewed_false_positive_rate: Optional[float] = (
        false_positive_like / reviewed if reviewed else None
    )

    return {
        "scope": "operational",
        "measures": "analyst-reviewed fired findings only",
        "total_findings": int(total_findings),
        "reviewed": reviewed,
        "unreviewed": unreviewed,
        "acknowledged": acknowledged,
        "suppressed": suppressed,
        "counts": {
            "true_positive": counts["true-positive"],
            "false_positive": counts["false-positive"],
            "benign": counts["benign"],
        },
        "precision": precision,
        "reviewed_false_positive_rate": reviewed_false_positive_rate,
        # Stated so the API/UI never presents these as the gate's guarantees.
        "population_false_positive_rate": None,
        "recall": None,
        "note": (
            "Precision and the reviewed false-positive rate are conditioned on "
            "findings an analyst dispositioned; dispositions exist only for fired "
            "findings, so population false-positive rate and recall are not "
            "measurable here and are reported by the seeded evaluation and the ML "
            "acceptance gate instead. This measurement never feeds those gates."
        ),
    }


def operational_efficacy_from_store(store: Any) -> Dict[str, Any]:
    """
    Convenience wrapper: read the counts this measurement needs from a store.

    Uses the paginated reader purely for its total (a COUNT, not a full
    materialisation) and the folded triage state, then defers to
    `compute_operational_efficacy`.
    """
    _, total = store.read_detection_findings_page(limit=1)
    return compute_operational_efficacy(total, store.read_latest_triage_state())
