from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from pipeline.event_stream import Event


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    matched: bool
    score: float
    evidence: Dict[str, Any]
    explanation: str


class SecurityRule(ABC):
    rule_id: str

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        """Evaluate one explicit rule against a detection context."""
        raise NotImplementedError


class PrivilegedUnusualExecutionRule(SecurityRule):
    rule_id = "privileged_unusual_execution"
    safe_commands = frozenset({"sudo", "systemd", "(systemd-hostn)", "sshd", "login"})

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        events: Sequence[Event] = context["events"]
        behavior_score = float(context["behavior_score"])
        matches = [
            event for event in events
            if event.uid == 0 and (event.comm or "unknown") not in self.safe_commands
        ]
        matched = bool(matches) and behavior_score >= 0.45
        commands = sorted({event.comm or "unknown" for event in matches})
        return RuleResult(
            self.rule_id,
            matched,
            0.80 if matched else 0.0,
            {"root_event_count": len(matches), "root_commands": commands},
            "root execution uses a command outside the conservative system-command allowlist"
            if matched else "no anomalous privileged execution matched",
        )


class SuspiciousUtilityActivityRule(SecurityRule):
    rule_id = "suspicious_utility_activity"
    utilities = frozenset({"nc", "ncat", "socat", "curl", "wget", "openssl", "ssh"})

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        events: Sequence[Event] = context["events"]
        behavior_score = float(context["behavior_score"])
        commands = sorted({event.comm or "unknown" for event in events})
        matches = sorted(set(commands).intersection(self.utilities))
        matched = bool(matches) and behavior_score >= 0.45
        return RuleResult(
            self.rule_id,
            matched,
            0.65 if matched else 0.0,
            {"matched_utilities": matches, "behavior_score_gate": behavior_score},
            "dual-use utility activity coincides with a behavioral deviation"
            if matched else "no anomalous dual-use utility activity matched",
        )


class ExecutionBurstRule(SecurityRule):
    rule_id = "execution_burst"

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        features = context["features"]
        peak = int(features.get("burst_activity", {}).get("peak_execs_per_second", 0))
        total = int(features.get("execution_frequency", 0))
        matched = peak >= 5 and total >= 10
        return RuleResult(
            self.rule_id,
            matched,
            0.60 if matched else 0.0,
            {"peak_execs_per_second": peak, "window_execs": total},
            "execution volume is concentrated into a high-rate burst"
            if matched else "execution burst thresholds were not met",
        )


class MultiUidActivityRule(SecurityRule):
    rule_id = "multi_uid_activity"

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        features = context["features"]
        unique_uids = int(features.get("unique_uids", 0))
        matched = unique_uids >= 3
        return RuleResult(
            self.rule_id,
            matched,
            0.40 if matched else 0.0,
            {"unique_uids": unique_uids},
            "multiple user identities executed processes in the same behavior window"
            if matched else "multi-UID activity threshold was not met",
        )


def default_rules() -> List[SecurityRule]:
    return [
        PrivilegedUnusualExecutionRule(),
        SuspiciousUtilityActivityRule(),
        ExecutionBurstRule(),
        MultiUidActivityRule(),
    ]
