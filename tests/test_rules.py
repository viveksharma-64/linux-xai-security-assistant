"""
Per-rule behaviour tests: match, no-match, and gating for each detection rule.

Each rule is constructed with explicit literal tunables here, rather than from
the bundled catalog, so these tests pin the rule's *logic* independent of its
calibration. The catalog's values -- and the fact that the loader binds them --
are covered separately in tests/test_rule_catalog.py, so a future calibration
change (Deliverable 2) cannot silently pass by moving a threshold under a logic
test. Every rule also emits its score as 0.0 on a miss and its configured score
on a match, and stamps the version/mitre provenance the explainer carries.
"""

from detection.rules import (
    ExecutionBurstRule,
    MultiUidActivityRule,
    PrivilegedUnusualExecutionRule,
    SuspiciousUtilityActivityRule,
)
from pipeline.event_stream import Event

_MITRE = {"tactic": "TA0002 Execution", "technique": "T1059"}


def _event(timestamp=1000.0, comm="bash", uid=1000, pid=1):
    return Event.from_raw_json(
        {"event_type": "process_exec", "timestamp": timestamp, "comm": comm, "uid": uid, "pid": pid}
    )


def _features(peak=0, freq=0, unique_uids=0):
    return {
        "execution_frequency": freq,
        "unique_uids": unique_uids,
        "burst_activity": {"peak_execs_per_second": peak},
    }


# --------------------------------------------- privileged unusual execution


def _priv_rule():
    return PrivilegedUnusualExecutionRule(
        safe_commands=["sudo", "systemd"],
        behavior_gate=0.45,
        rule_id="privileged_unusual_execution",
        version="1",
        score=0.80,
        mitre=_MITRE,
    )


def test_privileged_rule_matches_root_non_allowlisted_command():
    result = _priv_rule().evaluate(
        {"behavior_score": 0.6, "features": _features(), "events": [_event(comm="nc", uid=0)]}
    )
    assert result.matched is True
    assert result.score == 0.80
    assert result.version == "1"
    assert result.mitre["technique"] == "T1059"
    assert result.evidence["root_commands"] == ["nc"]


def test_privileged_rule_ignores_allowlisted_command():
    result = _priv_rule().evaluate(
        {"behavior_score": 0.9, "features": _features(), "events": [_event(comm="sudo", uid=0)]}
    )
    assert result.matched is False
    assert result.score == 0.0


def test_privileged_rule_ignores_non_root():
    result = _priv_rule().evaluate(
        {"behavior_score": 0.9, "features": _features(), "events": [_event(comm="nc", uid=1000)]}
    )
    assert result.matched is False


def test_privileged_rule_is_gated_on_behavior_score():
    # Root runs a non-allowlisted command, but the window is not anomalous.
    result = _priv_rule().evaluate(
        {"behavior_score": 0.44, "features": _features(), "events": [_event(comm="nc", uid=0)]}
    )
    assert result.matched is False
    assert result.score == 0.0


# ------------------------------------------------ suspicious utility activity


def _utility_rule():
    return SuspiciousUtilityActivityRule(
        utilities=["nc", "socat", "curl"],
        behavior_gate=0.45,
        rule_id="suspicious_utility_activity",
        version="1",
        score=0.65,
        mitre=_MITRE,
    )


def test_utility_rule_matches_dual_use_utility_with_anomaly():
    result = _utility_rule().evaluate(
        {"behavior_score": 0.5, "features": _features(), "events": [_event(comm="socat")]}
    )
    assert result.matched is True
    assert result.score == 0.65
    assert result.evidence["matched_utilities"] == ["socat"]


def test_utility_rule_ignores_non_utility_command():
    result = _utility_rule().evaluate(
        {"behavior_score": 0.9, "features": _features(), "events": [_event(comm="bash")]}
    )
    assert result.matched is False
    assert result.score == 0.0


def test_utility_rule_is_gated_on_behavior_score():
    result = _utility_rule().evaluate(
        {"behavior_score": 0.44, "features": _features(), "events": [_event(comm="nc")]}
    )
    assert result.matched is False


# ------------------------------------------------------------ execution burst


def _burst_rule():
    return ExecutionBurstRule(
        peak_execs_per_second=5,
        window_execs=10,
        rule_id="execution_burst",
        version="1",
        score=0.60,
        mitre=_MITRE,
    )


def test_burst_rule_matches_when_peak_and_volume_met():
    result = _burst_rule().evaluate(
        {"behavior_score": 0.0, "features": _features(peak=6, freq=12), "events": []}
    )
    assert result.matched is True
    assert result.score == 0.60
    assert result.evidence == {"peak_execs_per_second": 6, "window_execs": 12}


def test_burst_rule_no_match_when_peak_below_threshold():
    result = _burst_rule().evaluate(
        {"behavior_score": 0.0, "features": _features(peak=4, freq=99), "events": []}
    )
    assert result.matched is False
    assert result.score == 0.0


def test_burst_rule_no_match_when_volume_below_window():
    result = _burst_rule().evaluate(
        {"behavior_score": 0.0, "features": _features(peak=99, freq=9), "events": []}
    )
    assert result.matched is False


# ---------------------------------------------------------- multi-uid activity


def _multi_uid_rule():
    return MultiUidActivityRule(
        min_unique_uids=3,
        rule_id="multi_uid_activity",
        version="1",
        score=0.40,
        mitre=_MITRE,
    )


def test_multi_uid_rule_matches_at_threshold():
    result = _multi_uid_rule().evaluate(
        {"behavior_score": 0.0, "features": _features(unique_uids=3), "events": []}
    )
    assert result.matched is True
    assert result.score == 0.40


def test_multi_uid_rule_no_match_below_threshold():
    result = _multi_uid_rule().evaluate(
        {"behavior_score": 0.0, "features": _features(unique_uids=2), "events": []}
    )
    assert result.matched is False
    assert result.score == 0.0
