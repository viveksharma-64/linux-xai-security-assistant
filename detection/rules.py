"""
Externalized, versioned, MITRE-mapped detection rules.

Every rule's tunables -- score, behavioural gate, allowlists, thresholds -- and
its MITRE ATT&CK mapping live in `detection/rules_catalog.yaml`, not as hardcoded
constants here. `load_rules()` binds one rule instance per enabled catalog entry;
the bundled catalog beside this module is the default. This keeps a rule's
calibration and its ATT&CK provenance in one auditable, diffable place, and lets
the efficacy harness treat a score change as the calibration change it is.

Each rule stamps its `rule_id`, `version`, and `mitre` mapping onto the evidence
item it emits. Those are additive fields: the explainer reconstructs the fused
rule score from each item's `score`/`matched` and ignores the rest, so provenance
cannot perturb score reconstruction. A rule's `version` must be bumped whenever
its matching semantics, score, or tunables change, so a persisted finding is
traceable to the exact rule definition behind it.

The loader fails closed. A rules catalog is a security configuration: a malformed
document, a missing tunable, a duplicate id, or an entry with no ATT&CK mapping is
raised as `RuleCatalogError`, never silently defaulted -- the same posture
`observability/config.py` takes for the runtime config.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.event_stream import Event

# The bundled catalog shipped with the code; the default for load_rules().
DEFAULT_CATALOG_PATH = Path(__file__).with_name("rules_catalog.yaml")

# Fields every catalog entry must carry (per-rule tunables are validated by the
# rule class that consumes them, at construction).
_REQUIRED_ENTRY_FIELDS = (
    "rule_id",
    "version",
    "score",
    "mitre",
    "mapping_rationale",
    "description",
)
_REQUIRED_MITRE_FIELDS = ("tactic", "technique")


class RuleCatalogError(ValueError):
    """A rules catalog that cannot be parsed or is internally inconsistent."""


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    matched: bool
    score: float
    evidence: Dict[str, Any]
    explanation: str
    # Provenance stamped from the catalog entry. Defaulted so a RuleResult built
    # by hand in a test stays valid; every rule-produced result sets them.
    version: str = ""
    mitre: Mapping[str, Any] = field(default_factory=dict)


class SecurityRule(ABC):
    """
    One explicit detection rule, configured from a catalog entry.

    Subclasses take their own tunables as keyword arguments and implement
    `evaluate`. They build their result through `_result`, which applies the
    catalog score on a match (0.0 otherwise) and stamps `rule_id`/`version`/
    `mitre`, so no subclass can forget provenance or invent its own score.
    """

    def __init__(
        self,
        *,
        rule_id: str,
        version: Any,
        score: float,
        mitre: Mapping[str, Any],
        enabled: bool = True,
    ) -> None:
        self.rule_id = rule_id
        self.version = str(version)
        self.score = float(score)
        self.mitre = dict(mitre)
        self.enabled = bool(enabled)

    def _result(self, matched: bool, evidence: Dict[str, Any], explanation: str) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            matched=matched,
            score=self.score if matched else 0.0,
            evidence=evidence,
            explanation=explanation,
            version=self.version,
            mitre=dict(self.mitre),
        )

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        """Evaluate one explicit rule against a detection context."""
        raise NotImplementedError


def _common(entry: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": entry["rule_id"],
        "version": entry["version"],
        "score": entry["score"],
        "mitre": entry["mitre"],
        "enabled": entry.get("enabled", True),
    }


class PrivilegedUnusualExecutionRule(SecurityRule):
    def __init__(self, *, safe_commands: Sequence[str], behavior_gate: float, **common: Any) -> None:
        super().__init__(**common)
        self.safe_commands = frozenset(safe_commands)
        self.behavior_gate = float(behavior_gate)

    @classmethod
    def from_entry(cls, entry: Mapping[str, Any]) -> "PrivilegedUnusualExecutionRule":
        return cls(
            safe_commands=entry["safe_commands"],
            behavior_gate=entry["behavior_gate"],
            **_common(entry),
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        events: Sequence[Event] = context["events"]
        behavior_score = float(context["behavior_score"])
        matches = [
            event for event in events
            if event.uid == 0 and (event.comm or "unknown") not in self.safe_commands
        ]
        matched = bool(matches) and behavior_score >= self.behavior_gate
        commands = sorted({event.comm or "unknown" for event in matches})
        return self._result(
            matched,
            {"root_event_count": len(matches), "root_commands": commands},
            "root execution uses a command outside the conservative system-command allowlist"
            if matched else "no anomalous privileged execution matched",
        )


class SuspiciousUtilityActivityRule(SecurityRule):
    def __init__(self, *, utilities: Sequence[str], behavior_gate: float, **common: Any) -> None:
        super().__init__(**common)
        self.utilities = frozenset(utilities)
        self.behavior_gate = float(behavior_gate)

    @classmethod
    def from_entry(cls, entry: Mapping[str, Any]) -> "SuspiciousUtilityActivityRule":
        return cls(
            utilities=entry["utilities"],
            behavior_gate=entry["behavior_gate"],
            **_common(entry),
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        events: Sequence[Event] = context["events"]
        behavior_score = float(context["behavior_score"])
        commands = sorted({event.comm or "unknown" for event in events})
        matches = sorted(set(commands).intersection(self.utilities))
        matched = bool(matches) and behavior_score >= self.behavior_gate
        return self._result(
            matched,
            {"matched_utilities": matches, "behavior_score_gate": behavior_score},
            "dual-use utility activity coincides with a behavioral deviation"
            if matched else "no anomalous dual-use utility activity matched",
        )


class ExecutionBurstRule(SecurityRule):
    def __init__(self, *, peak_execs_per_second: int, window_execs: int, **common: Any) -> None:
        super().__init__(**common)
        self.peak_execs_per_second = int(peak_execs_per_second)
        self.window_execs = int(window_execs)

    @classmethod
    def from_entry(cls, entry: Mapping[str, Any]) -> "ExecutionBurstRule":
        return cls(
            peak_execs_per_second=entry["peak_execs_per_second"],
            window_execs=entry["window_execs"],
            **_common(entry),
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        features = context["features"]
        peak = int(features.get("burst_activity", {}).get("peak_execs_per_second", 0))
        total = int(features.get("execution_frequency", 0))
        matched = peak >= self.peak_execs_per_second and total >= self.window_execs
        return self._result(
            matched,
            {"peak_execs_per_second": peak, "window_execs": total},
            "execution volume is concentrated into a high-rate burst"
            if matched else "execution burst thresholds were not met",
        )


class MultiUidActivityRule(SecurityRule):
    def __init__(self, *, min_unique_uids: int, **common: Any) -> None:
        super().__init__(**common)
        self.min_unique_uids = int(min_unique_uids)

    @classmethod
    def from_entry(cls, entry: Mapping[str, Any]) -> "MultiUidActivityRule":
        return cls(min_unique_uids=entry["min_unique_uids"], **_common(entry))

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        features = context["features"]
        unique_uids = int(features.get("unique_uids", 0))
        matched = unique_uids >= self.min_unique_uids
        return self._result(
            matched,
            {"unique_uids": unique_uids},
            "multiple user identities executed processes in the same behavior window"
            if matched else "multi-UID activity threshold was not met",
        )


# rule_id -> implementing class. load_rules() dispatches on this; a catalog entry
# whose rule_id is absent here is an error, not a silently ignored rule.
_RULE_TYPES = {
    "privileged_unusual_execution": PrivilegedUnusualExecutionRule,
    "suspicious_utility_activity": SuspiciousUtilityActivityRule,
    "execution_burst": ExecutionBurstRule,
    "multi_uid_activity": MultiUidActivityRule,
}


def _validate_entry(catalog_path: Path, entry: Any, seen: set) -> None:
    if not isinstance(entry, Mapping):
        raise RuleCatalogError(f"rules catalog {catalog_path} has a non-mapping rule entry")
    missing = [name for name in _REQUIRED_ENTRY_FIELDS if name not in entry]
    if missing:
        raise RuleCatalogError(
            f"rule entry {entry.get('rule_id', '<unknown>')!r} is missing fields: {', '.join(missing)}"
        )
    rule_id = entry["rule_id"]
    if rule_id in seen:
        raise RuleCatalogError(f"duplicate rule_id in catalog {catalog_path}: {rule_id}")
    seen.add(rule_id)
    score = entry["score"]
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0.0 <= float(score) <= 1.0:
        raise RuleCatalogError(f"rule {rule_id} score must be a number in [0, 1], got {score!r}")
    mitre = entry["mitre"]
    if not isinstance(mitre, Mapping) or any(
        not str(mitre.get(name, "")).strip() for name in _REQUIRED_MITRE_FIELDS
    ):
        raise RuleCatalogError(f"rule {rule_id} must map a non-empty tactic and technique under 'mitre'")
    for text_field in ("mapping_rationale", "description"):
        if not str(entry.get(text_field, "")).strip():
            raise RuleCatalogError(f"rule {rule_id} needs a non-empty {text_field}")


def load_catalog(path: Optional[Any] = None) -> Dict[str, Any]:
    """
    Parse and validate a rules catalog, returning the whole document.

    Fails closed on anything malformed or internally inconsistent (unreadable
    file, non-mapping document, empty rule list, missing required field,
    duplicate id, out-of-range score, missing ATT&CK mapping). Returns the full
    document -- including disabled entries -- so integrity tooling can inspect
    every rule, not only the ones the engine will load.
    """
    import yaml

    catalog_path = Path(path) if path is not None else DEFAULT_CATALOG_PATH
    try:
        with catalog_path.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise RuleCatalogError(
            f"cannot read rules catalog {catalog_path}: {type(error).__name__}: {error}"
        ) from error
    if not isinstance(document, Mapping):
        raise RuleCatalogError(f"rules catalog {catalog_path} must be a YAML mapping")
    unknown = set(document) - {"version", "rules"}
    if unknown:
        raise RuleCatalogError(
            f"rules catalog {catalog_path} has unknown top-level keys: {', '.join(sorted(unknown))}"
        )
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RuleCatalogError(f"rules catalog {catalog_path} must define a non-empty 'rules' list")
    seen: set = set()
    for entry in rules:
        _validate_entry(catalog_path, entry, seen)
    return dict(document)


def load_rules(path: Optional[Any] = None) -> List[SecurityRule]:
    """
    Build one rule instance per enabled catalog entry (bundled catalog default).

    Disabled entries are skipped -- they never become a rule the engine fuses
    over. A per-rule tunable that is missing or the wrong type surfaces as a
    `RuleCatalogError` naming the offending rule, so a broken catalog fails at
    load, not mid-detection.
    """
    document = load_catalog(path)
    rules: List[SecurityRule] = []
    for entry in document["rules"]:
        if not entry.get("enabled", True):
            continue
        builder = _RULE_TYPES.get(entry["rule_id"])
        if builder is None:
            raise RuleCatalogError(
                f"catalog entry {entry['rule_id']!r} has no matching rule implementation"
            )
        try:
            rules.append(builder.from_entry(entry))
        except (KeyError, TypeError, ValueError) as error:
            raise RuleCatalogError(
                f"catalog entry {entry['rule_id']!r} is invalid: {type(error).__name__}: {error}"
            ) from error
    return rules


def default_rules() -> List[SecurityRule]:
    """The engine's default rule set: every enabled rule in the bundled catalog."""
    return load_rules()
