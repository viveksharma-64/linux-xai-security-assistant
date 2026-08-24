import logging
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from storage.sqlite_store import SQLiteEventStore


LOGGER = logging.getLogger(__name__)


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DRY_RUN = "DRY_RUN"
    ACTION_PENDING_APPROVAL = "ACTION_PENDING_APPROVAL"
    DENIED = "DENIED"


class PolicyConfigurationError(ValueError):
    """Policy configuration is malformed or contains unsupported values."""


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    priority: int
    match: Dict[str, Any]
    decision: PolicyDecision
    required_approval: bool
    proposed_action: str
    allowed_recommendation_keywords: tuple[str, ...]


class PolicyEngine:
    """
    Deterministic policy evaluation and dry-run decision control.

    This class never executes proposed actions. Detection score and severity are
    authoritative; assistant recommendations can only be accepted or rejected
    as advisory text.
    """

    _DANGEROUS_TERMS = (
        "kill", "terminate", "delete", "modify firewall", "sudoers",
        "execute", "run command", "block ip", "disable account",
    )
    _DECISIONS = {item.value for item in PolicyDecision}

    def __init__(self, store: SQLiteEventStore, policies: Iterable[PolicyRule], dry_run: bool = True):
        self.store = store
        self.policies = sorted(
            list(policies),
            key=lambda policy: (-policy.priority, policy.policy_id),
        )
        self.dry_run = dry_run
        if not self.policies:
            raise PolicyConfigurationError("at least one policy is required")

    @classmethod
    def from_yaml(cls, store: SQLiteEventStore, path: str, dry_run: bool = True) -> "PolicyEngine":
        try:
            with Path(path).open("r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError) as error:
            raise PolicyConfigurationError(f"unable to load policy configuration: {error}") from error
        return cls.from_document(store, document, dry_run=dry_run)

    @classmethod
    def from_document(cls, store: SQLiteEventStore, document: Any, dry_run: bool = True) -> "PolicyEngine":
        if not isinstance(document, dict) or document.get("version") != 1:
            raise PolicyConfigurationError("policy document must be a mapping with version: 1")
        raw_policies = document.get("policies")
        if not isinstance(raw_policies, list):
            raise PolicyConfigurationError("policies must be a list")

        parsed = []
        for raw in raw_policies:
            if not isinstance(raw, dict):
                raise PolicyConfigurationError("each policy must be a mapping")
            policy_id = raw.get("policy_id")
            match = raw.get("match")
            decision = raw.get("decision")
            if not isinstance(policy_id, str) or not policy_id.strip():
                raise PolicyConfigurationError("policy_id must be a non-empty string")
            if not isinstance(match, dict):
                raise PolicyConfigurationError(f"{policy_id}: match must be a mapping")
            unknown_match_keys = set(match).difference({
                "severity", "min_risk_score", "max_risk_score",
                "detection_type", "required_rule_ids", "telemetry_complete",
            })
            if unknown_match_keys:
                raise PolicyConfigurationError(f"{policy_id}: unknown match keys")
            if "severity" in match and (
                not isinstance(match["severity"], list)
                or not all(isinstance(item, str) for item in match["severity"])
            ):
                raise PolicyConfigurationError(f"{policy_id}: severity must be a string list")
            if "detection_type" in match and (
                not isinstance(match["detection_type"], list)
                or not all(isinstance(item, str) for item in match["detection_type"])
            ):
                raise PolicyConfigurationError(f"{policy_id}: detection_type must be a string list")
            if "required_rule_ids" in match and (
                not isinstance(match["required_rule_ids"], list)
                or not all(isinstance(item, str) for item in match["required_rule_ids"])
            ):
                raise PolicyConfigurationError(f"{policy_id}: required_rule_ids must be a string list")
            if decision not in cls._DECISIONS:
                raise PolicyConfigurationError(f"{policy_id}: unsupported decision")
            required_approval = raw.get("required_approval")
            if not isinstance(required_approval, bool):
                raise PolicyConfigurationError(f"{policy_id}: required_approval must be boolean")
            proposed_action = raw.get("proposed_action")
            if not isinstance(proposed_action, str) or not proposed_action.strip():
                raise PolicyConfigurationError(f"{policy_id}: proposed_action must be a string")
            if any(term in proposed_action.lower() for term in cls._DANGEROUS_TERMS):
                raise PolicyConfigurationError(f"{policy_id}: executing actions are not permitted")
            keywords = raw.get("allowed_recommendation_keywords", [])
            if not isinstance(keywords, list) or not all(isinstance(item, str) for item in keywords):
                raise PolicyConfigurationError(f"{policy_id}: allowed_recommendation_keywords must be a string list")
            priority = raw.get("priority", 0)
            if not isinstance(priority, int) or isinstance(priority, bool):
                raise PolicyConfigurationError(f"{policy_id}: priority must be an integer")
            parsed.append(PolicyRule(
                policy_id=policy_id,
                priority=priority,
                match=match,
                decision=PolicyDecision(decision),
                required_approval=required_approval,
                proposed_action=proposed_action,
                allowed_recommendation_keywords=tuple(keywords),
            ))
        return cls(store, parsed, dry_run=dry_run)

    def _validate_finding(self, finding: Dict[str, Any]) -> None:
        required = {"id", "risk_score", "severity", "entity_type", "entity_key", "evidence"}
        missing = sorted(required.difference(finding))
        if missing:
            raise PolicyConfigurationError(f"finding missing required fields: {', '.join(missing)}")
        score = float(finding["risk_score"])
        if not 0.0 <= score <= 1.0:
            raise PolicyConfigurationError("finding risk_score must be between 0 and 1")
        if not isinstance(finding["evidence"], list) or not finding["evidence"]:
            raise PolicyConfigurationError("finding evidence must be a non-empty list")

    def _matched_rule_ids(self, finding: Dict[str, Any]) -> set[str]:
        for item in finding["evidence"]:
            if item.get("signal") == "rule_fusion":
                return {
                    rule["rule_id"]
                    for rule in item.get("rules", [])
                    if rule.get("matched") is True and isinstance(rule.get("rule_id"), str)
                }
        return set()

    def _limitations(self, finding: Dict[str, Any], assistant: Optional[Dict[str, Any]]) -> List[str]:
        limitations = []
        if assistant and isinstance(assistant.get("limitations"), str):
            limitations.append(assistant["limitations"])
        if not limitations:
            limitations.append("TCP/network, file, and audit/auth telemetry availability is not established by this finding.")
        return limitations

    def _matches(self, policy: PolicyRule, finding: Dict[str, Any], limitations: List[str]) -> bool:
        criteria = policy.match
        severity = str(finding["severity"]).upper()
        if "severity" in criteria and severity not in {str(item).upper() for item in criteria["severity"]}:
            return False
        if "min_risk_score" in criteria and float(finding["risk_score"]) < float(criteria["min_risk_score"]):
            return False
        if "max_risk_score" in criteria and float(finding["risk_score"]) > float(criteria["max_risk_score"]):
            return False
        detection_type = str(finding.get("detection_type", finding["entity_type"]))
        if "detection_type" in criteria and detection_type not in criteria["detection_type"]:
            return False
        required_rules = set(criteria.get("required_rule_ids", []))
        if not required_rules.issubset(self._matched_rule_ids(finding)):
            return False
        if criteria.get("telemetry_complete") is True and limitations:
            return False
        return True

    def _advisory_check(self, policy: PolicyRule, assistant: Optional[Dict[str, Any]]) -> Optional[str]:
        if not assistant:
            return None
        recommendation = assistant.get("recommended_action", "")
        if not isinstance(recommendation, str):
            return "AI recommendation rejected: recommendation is not text."
        lowered = recommendation.lower()
        if any(term in lowered for term in self._DANGEROUS_TERMS):
            return "AI recommendation rejected: executing or destructive actions are not permitted."
        keywords = policy.allowed_recommendation_keywords
        if keywords and not any(keyword.lower() in lowered for keyword in keywords):
            return "AI recommendation rejected: it does not match this policy's allowed advisory scope."
        return None

    def evaluate(
        self,
        finding: Dict[str, Any],
        assistant_response: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        timestamp = time.time()
        try:
            self._validate_finding(finding)
            limitations = self._limitations(finding, assistant_response)
            selected = next(
                (policy for policy in self.policies if self._matches(policy, finding, limitations)),
                None,
            )
            if selected is None:
                decision = PolicyDecision.REVIEW_REQUIRED
                policy_id = "policy.fail_closed"
                reason = "No policy matched the authoritative finding; human review is required."
                proposed_action = "Review the finding and policy configuration."
                required_approval = True
                advisory_rejection = None
            else:
                policy_id = selected.policy_id
                decision = selected.decision
                reason = f"Policy {policy_id} matched severity={finding['severity']} risk_score={float(finding['risk_score']):.4f}."
                proposed_action = selected.proposed_action
                required_approval = selected.required_approval
                advisory_rejection = self._advisory_check(selected, assistant_response)
                if advisory_rejection:
                    reason = f"{reason} {advisory_rejection}"
                    decision = PolicyDecision.REVIEW_REQUIRED
                    required_approval = True
                if (dry_run if dry_run is not None else self.dry_run) and decision not in {PolicyDecision.ALLOW, PolicyDecision.LOG}:
                    decision = PolicyDecision.DRY_RUN
                    reason = f"{reason} No action is executed; this is a dry-run decision."

            result = {
                "finding_id": finding["id"],
                "policy_id": policy_id,
                "decision": decision.value,
                "reason": reason,
                "risk_score": float(finding["risk_score"]),
                "severity": str(finding["severity"]).upper(),
                "required_approval": required_approval,
                "proposed_action": proposed_action,
                "limitations": limitations,
                "timestamp": timestamp,
                "dry_run": dry_run if dry_run is not None else self.dry_run,
                "advisory_rejection": advisory_rejection,
            }
        except (KeyError, TypeError, ValueError, PolicyConfigurationError) as error:
            try:
                safe_score = float(finding.get("risk_score", 0.0)) if isinstance(finding, dict) else 0.0
                if not 0.0 <= safe_score <= 1.0:
                    safe_score = 0.0
            except (TypeError, ValueError):
                safe_score = 0.0
            result = {
                "finding_id": finding.get("id") if isinstance(finding, dict) else None,
                "policy_id": "policy.fail_closed",
                "decision": PolicyDecision.REVIEW_REQUIRED.value,
                "reason": f"Policy evaluation failed closed: {type(error).__name__}.",
                "risk_score": safe_score,
                "severity": str(finding.get("severity", "UNKNOWN")).upper() if isinstance(finding, dict) else "UNKNOWN",
                "required_approval": True,
                "proposed_action": "Review the malformed finding or policy input.",
                "limitations": ["Policy evaluation input was malformed or incomplete."],
                "timestamp": timestamp,
                "dry_run": True,
                "advisory_rejection": "Policy evaluation failed closed.",
            }
        if persist:
            self.store.write_policy_decision(result)
        return result

    def evaluate_all(self, findings: Iterable[Dict[str, Any]], assistant_responses: Optional[Dict[Any, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        responses = assistant_responses or {}
        return [
            self.evaluate(finding, responses.get(finding.get("id")))
            for finding in findings
        ]
