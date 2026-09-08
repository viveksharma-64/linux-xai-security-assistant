import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from detection.rules import RuleCatalogError, load_catalog
from storage.sqlite_store import SQLiteEventStore


UNAVAILABLE_TELEMETRY = []


# Counterfactual boundaries per rule: what observed signal had to cross which
# catalog threshold for the rule to match. Each builder reads the finding's own
# recorded rule evidence (the observed side) and the catalog entry (the threshold
# side), so the counterfactual is grounded in stored values, never re-derived.
# A rule_id absent here yields no boundary rather than a fabricated one; the
# comparator is `>=` because every rule below matches on meeting-or-exceeding.
def _boundaries_privileged_unusual_execution(
    item_evidence: Mapping[str, Any], entry: Mapping[str, Any], finding: Dict[str, Any]
) -> List[Dict[str, Any]]:
    return [
        {"signal": "behavior_score", "observed": round(float(finding["behavior_score"]), 4),
         "comparator": ">=", "threshold": float(entry["behavior_gate"])},
        {"signal": "root_event_count", "observed": int(item_evidence.get("root_event_count", 0)),
         "comparator": ">=", "threshold": 1},
    ]


def _boundaries_suspicious_utility_activity(
    item_evidence: Mapping[str, Any], entry: Mapping[str, Any], finding: Dict[str, Any]
) -> List[Dict[str, Any]]:
    observed_behavior = item_evidence.get("behavior_score_gate", finding["behavior_score"])
    return [
        {"signal": "behavior_score", "observed": round(float(observed_behavior), 4),
         "comparator": ">=", "threshold": float(entry["behavior_gate"])},
        {"signal": "matched_utilities", "observed": len(item_evidence.get("matched_utilities", [])),
         "comparator": ">=", "threshold": 1},
    ]


def _boundaries_execution_burst(
    item_evidence: Mapping[str, Any], entry: Mapping[str, Any], finding: Dict[str, Any]
) -> List[Dict[str, Any]]:
    return [
        {"signal": "peak_execs_per_second", "observed": int(item_evidence.get("peak_execs_per_second", 0)),
         "comparator": ">=", "threshold": int(entry["peak_execs_per_second"])},
        {"signal": "window_execs", "observed": int(item_evidence.get("window_execs", 0)),
         "comparator": ">=", "threshold": int(entry["window_execs"])},
    ]


def _boundaries_multi_uid_activity(
    item_evidence: Mapping[str, Any], entry: Mapping[str, Any], finding: Dict[str, Any]
) -> List[Dict[str, Any]]:
    return [
        {"signal": "unique_uids", "observed": int(item_evidence.get("unique_uids", 0)),
         "comparator": ">=", "threshold": int(entry["min_unique_uids"])},
    ]


_COUNTERFACTUAL_BOUNDARIES = {
    "privileged_unusual_execution": _boundaries_privileged_unusual_execution,
    "suspicious_utility_activity": _boundaries_suspicious_utility_activity,
    "execution_burst": _boundaries_execution_burst,
    "multi_uid_activity": _boundaries_multi_uid_activity,
}


class FindingExplainer:
    """
    Reconstruct deterministic explanations from persisted detection findings.

    This class is read-only with respect to detection decisions: it does not
    create findings, change scores, evaluate rules, or infer maliciousness.
    """

    def __init__(self, store: SQLiteEventStore):
        self.store = store
        # Lazily loaded, defensively cached map of rule_id -> catalog entry, used
        # only for counterfactual thresholds. Loading is deferred and never fatal:
        # a missing or malformed catalog degrades the counterfactual to "threshold
        # unavailable", it does not stop an explanation being produced.
        self._catalog_by_id: Optional[Dict[str, Mapping[str, Any]]] = None

    def _require_fields(self, finding: Dict[str, Any]) -> None:
        required = {
            "id",
            "window_start",
            "window_end",
            "entity_type",
            "entity_key",
            "risk_score",
            "severity",
            "behavior_score",
            "rule_score",
            "context_score",
            "evidence",
            "mode",
        }
        missing = sorted(required.difference(finding))
        if missing:
            raise ValueError(f"finding is missing required fields: {', '.join(missing)}")

    def _evidence_by_signal(self, finding: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        evidence = finding["evidence"]
        if not isinstance(evidence, list):
            raise ValueError("finding evidence must be a list")
        by_signal = {}
        for item in evidence:
            if not isinstance(item, dict) or not item.get("signal"):
                raise ValueError("each finding evidence item needs a signal")
            by_signal[item["signal"]] = item
        required_signals = {"behavior_anomaly", "rule_fusion", "process_context"}
        missing = sorted(required_signals.difference(by_signal))
        if missing:
            raise ValueError(f"finding evidence is missing signals: {', '.join(missing)}")
        return by_signal

    def _calculation(self, finding: Dict[str, Any], evidence: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        behavior_score = float(finding["behavior_score"])
        rule_score = float(finding["rule_score"])
        context_score = float(finding["context_score"])
        ml = evidence.get("ml_anomaly")
        if ml is not None:
            ml_score = float(ml["score"])
            calculated_score = min(1.0, 0.45 * behavior_score + 0.30 * rule_score + 0.15 * context_score + 0.10 * ml_score)
            formula = "min(1, 0.45 * behavior_score + 0.30 * rule_score + 0.15 * context_score + 0.10 * ml_score)"
        else:
            ml_score = None
            calculated_score = min(1.0, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)
            formula = "min(1, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)"
        stored_score = float(finding["risk_score"])
        if round(calculated_score, 4) != round(stored_score, 4):
            raise ValueError("stored finding score does not match its evidence components")

        rule_items = evidence["rule_fusion"].get("rules", [])
        matched_rule_scores = [
            float(item["score"])
            for item in rule_items
            if item.get("matched")
        ]
        remaining = 1.0
        for score in matched_rule_scores:
            remaining *= 1.0 - score
        reconstructed_rule_score = 1.0 - remaining
        if round(reconstructed_rule_score, 4) != round(rule_score, 4):
            raise ValueError("stored rule score does not match stored rule evidence")

        return {
            "formula": formula,
            "inputs": {
                "behavior_score": behavior_score,
                "rule_score": rule_score,
                "context_score": context_score,
                "ml_score": ml_score,
            },
            "matched_rule_scores": matched_rule_scores,
            "reconstructed_rule_score": round(reconstructed_rule_score, 4),
            "calculated_risk_score": round(calculated_score, 4),
            "stored_risk_score": round(stored_score, 4),
            "severity": finding["severity"],
        }

    def _rule_catalog(self) -> Dict[str, Mapping[str, Any]]:
        if self._catalog_by_id is None:
            try:
                document = load_catalog()
                self._catalog_by_id = {
                    entry["rule_id"]: entry for entry in document.get("rules", [])
                }
            except (RuleCatalogError, OSError, KeyError, TypeError):
                # Fail open to an empty map: an explanation must not depend on a
                # loadable catalog. Counterfactual thresholds are simply omitted.
                self._catalog_by_id = {}
        return self._catalog_by_id

    def _counterfactual_factor(
        self, finding: Dict[str, Any], evidence: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Which matched-rule thresholds, if not crossed, would drop the rule signal.

        INTERPRETATION: a what-if over the finding's own recorded rule evidence
        against the current catalog thresholds. It never claims the finding would
        vanish -- a finding rests first on its behavioral signal -- only that the
        rule-fusion contribution would fall toward 0.0 and the severity band could
        lower. Where the finding's rule version differs from the catalog's, that is
        surfaced so a stale threshold is never presented as the one that fired.
        """
        catalog = self._rule_catalog()
        matched = [
            item for item in evidence["rule_fusion"].get("rules", [])
            if item.get("matched")
        ]
        rule_score = round(float(finding["rule_score"]), 4)
        details: List[Dict[str, Any]] = []
        for item in matched:
            rule_id = item.get("rule_id")
            entry = catalog.get(rule_id)
            builder = _COUNTERFACTUAL_BOUNDARIES.get(rule_id)
            record: Dict[str, Any] = {
                "rule_id": rule_id,
                "score": round(float(item.get("score", 0.0)), 4),
                "version_recorded": item.get("version"),
                "version_in_catalog": entry.get("version") if entry else None,
            }
            if entry is not None and builder is not None:
                try:
                    record["boundaries"] = builder(item.get("evidence", {}), entry, finding)
                except (KeyError, TypeError, ValueError):
                    record["boundaries"] = []
                    record["note"] = "catalog entry lacked an expected threshold"
            else:
                record["boundaries"] = []
                record["note"] = "no catalog threshold available for this rule"
            details.append(record)

        if not matched:
            statement = (
                "No detection rule matched; the fused score rests on the behavioral "
                "and process-context signals, so there is no rule-threshold "
                "counterfactual for this finding."
            )
        else:
            dominant = max(details, key=lambda record: record["score"])
            primary = next(iter(dominant.get("boundaries", [])), None)
            ids = ", ".join(str(record["rule_id"]) for record in details)
            if primary is not None:
                lead = (
                    f"{dominant['rule_id']} contributed the largest matched score "
                    f"({dominant['score']:.2f}) and required {primary['signal']} "
                    f"{primary['comparator']} {primary['threshold']} "
                    f"(observed {primary['observed']}). "
                )
            else:
                lead = (
                    f"{dominant['rule_id']} contributed the largest matched score "
                    f"({dominant['score']:.2f}). "
                )
            statement = (
                f"Counterfactual: {len(matched)} rule(s) matched [{ids}]. {lead}"
                "Had the observed signals stayed on the non-matching side of these "
                "catalog thresholds, those rules would not have matched and the "
                f"rule-fusion component ({rule_score:.4f}) would fall toward 0.0, "
                "lowering the fused risk score. The finding would still be recorded "
                "from its behavioral signal, at a lower severity."
            )
        return {
            "label": "INTERPRETATION",
            "factor": "counterfactual",
            "statement": statement,
            "evidence": {
                "basis": "current rules_catalog.yaml thresholds vs the finding's recorded rule evidence",
                "matched_rule_count": len(matched),
                "rule_fusion_score": rule_score,
                "matched_rules": details,
            },
        }

    def _cross_finding_factor(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sibling findings sharing this finding's correlation id.

        INTERPRETATION: `correlation_id` groups a contiguous run of windows about
        one entity (a triage-grouping key, not a proven incident timeline). This
        enumerates the group honestly, including suppressed siblings, and states
        plainly when a finding stands alone or carries no correlation id.
        """
        correlation_id = finding.get("correlation_id")
        siblings = [
            other for other in self.store.read_findings_by_correlation(correlation_id)
            if other.get("id") != finding.get("id")
        ] if correlation_id else []
        sibling_summaries = [
            {
                "finding_id": other.get("id"),
                "window_start": float(other["window_start"]),
                "window_end": float(other["window_end"]),
                "severity": other.get("severity"),
                "risk_score": round(float(other["risk_score"]), 4),
                "suppressed": bool(other.get("suppressed", False)),
            }
            for other in siblings
        ]
        if not correlation_id:
            statement = (
                "This finding carries no correlation id, so it is not grouped with "
                "sibling findings."
            )
        elif not sibling_summaries:
            statement = (
                f"This finding is the only one in correlation group {correlation_id}; "
                "no sibling findings share it."
            )
        else:
            statement = (
                f"This finding shares correlation group {correlation_id} with "
                f"{len(sibling_summaries)} other finding(s) about the same entity "
                "across adjacent windows. Correlation groups adjacent windows for "
                "triage; it does not itself prove a single incident."
            )
        return {
            "label": "INTERPRETATION",
            "factor": "cross_finding_narrative",
            "statement": statement,
            "evidence": {
                "correlation_id": correlation_id,
                "sibling_count": len(sibling_summaries),
                "siblings": sibling_summaries,
            },
        }

    def _baseline_factors(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Baseline provenance (FACT) plus a sufficiency judgment (INTERPRETATION).

        The persisted baseline record is a fact; whether it is sufficient, and
        whether it is even the baseline that scored this finding, is bounded
        interpretation. Findings do not record a baseline id, so the FACT is "the
        latest ready baseline is X", never "this finding used X". When no ready
        baseline exists, the honest "insufficient normal data" state is surfaced.
        """
        baseline = self.store.read_latest_ready_baseline()
        if baseline is None:
            return [
                {
                    "label": "FACT",
                    "factor": "baseline_provenance",
                    "statement": "No ready behavioral baseline is persisted in the store.",
                    "evidence": {"ready_baseline": None},
                },
                {
                    "label": "INTERPRETATION",
                    "factor": "baseline_sufficiency",
                    "statement": (
                        "Insufficient normal data: without a ready baseline the "
                        "behavioral anomaly signal is not grounded in a learned normal "
                        "profile, so the behavior score should be read with caution."
                    ),
                    "evidence": {"status": "insufficient_normal_data"},
                },
            ]
        window_start = baseline.get("window_start")
        window_end = baseline.get("window_end")
        normal_count = baseline.get("normal_count")
        if window_start is not None and window_end is not None:
            window_text = f" over window {float(window_start):.3f}-{float(window_end):.3f}"
        else:
            window_text = ""
        return [
            {
                "label": "FACT",
                "factor": "baseline_provenance",
                "statement": (
                    f"Latest ready baseline {baseline.get('baseline_name')!r} was built "
                    f"from {int(normal_count or 0)} normal execution(s){window_text}."
                ),
                "evidence": {
                    "baseline_name": baseline.get("baseline_name"),
                    "normal_count": normal_count,
                    "window_start": window_start,
                    "window_end": window_end,
                    "status": baseline.get("status"),
                    "created_at": baseline.get("created_at"),
                },
            },
            {
                "label": "INTERPRETATION",
                "factor": "baseline_sufficiency",
                "statement": (
                    "A ready baseline backs the behavioral signal. Persisted findings do "
                    "not record a baseline id, so this is the latest ready baseline shown "
                    "as provenance context, not a proven link to this specific finding."
                ),
                "evidence": {
                    "normal_count": normal_count,
                    "linkage": "latest-ready, not finding-bound",
                },
            },
        ]

    def explain_finding(self, finding: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        """Build one explanation from a stored or detector-produced finding."""
        self._require_fields(finding)
        evidence = self._evidence_by_signal(finding)
        calculation = self._calculation(finding, evidence)
        entity = f"{finding['entity_type']}:{finding['entity_key']}"
        severity = finding["severity"]
        risk_score = round(float(finding["risk_score"]), 4)

        summary = (
            f"{severity} detection finding for {entity} with fused risk score "
            f"{risk_score:.4f} during window {float(finding['window_start']):.3f}-"
            f"{float(finding['window_end']):.3f}."
        )
        contributing_factors = [
            {
                "label": "FACT",
                "factor": "behavioral_anomaly",
                "statement": (
                    f"Stored behavior anomaly score was {float(finding['behavior_score']):.4f}."
                ),
                "evidence": evidence["behavior_anomaly"],
            },
            {
                "label": "FACT",
                "factor": "rule_evidence",
                "statement": (
                    f"Rule fusion score was {float(finding['rule_score']):.4f}; "
                    f"{sum(item.get('matched', False) for item in evidence['rule_fusion'].get('rules', []))} rule(s) matched."
                ),
                "evidence": evidence["rule_fusion"],
            },
            {
                "label": "FACT",
                "factor": "process_context",
                "statement": (
                    f"Process context score was {float(finding['context_score']):.4f} from "
                    f"{evidence['process_context'].get('event_count', 0)} event(s)."
                ),
                "evidence": evidence["process_context"],
            },
            {
                "label": "INTERPRETATION",
                "factor": "risk_context",
                "statement": (
                    "The independent behavioral, rule, and process-context signals together "
                    "justify the stored severity classification under the Phase 4 formula; "
                    "this explanation does not determine maliciousness."
                ),
                "evidence": {
                    "severity": severity,
                    "calculation": calculation,
                },
            },
        ]
        if "ml_anomaly" in evidence:
            model = evidence["ml_anomaly"].get("model", {})
            contributing_factors.append({
                "label": "FACT", "factor": "ml_anomaly_evidence",
                "statement": "Isolation Forest supplied an additional anomaly-evidence score; listed feature deviations are statistical, not causal explanations.",
                "evidence": {"model_version": model.get("model_version"), "schema_hash": model.get("schema_hash"), "threshold": model.get("threshold"), "contributing_feature_deviations": model.get("contributing_feature_deviations", [])},
            })
        # Additive depth (Phase D), appended so existing factor positions are
        # unchanged: a rule-threshold counterfactual and a cross-finding narrative
        # (both INTERPRETATION), and baseline provenance (FACT) with an explicit
        # sufficiency judgment (INTERPRETATION). None of these touch the score
        # reconstruction in `_calculation`.
        contributing_factors.append(self._counterfactual_factor(finding, evidence))
        contributing_factors.append(self._cross_finding_factor(finding))
        contributing_factors.extend(self._baseline_factors(finding))
        explanation = {
            "finding_id": finding["id"],
            "timestamp": float(finding["window_end"]),
            "window": {
                "start": float(finding["window_start"]),
                "end": float(finding["window_end"]),
            },
            "severity": severity,
            "risk_score": risk_score,
            "summary": summary,
            "contributing_factors": contributing_factors,
            "evidence": finding["evidence"],
            "calculation": calculation,
            "data_sources": [
                "persisted detection_findings evidence",
                "Phase 3 behavior_risks evidence embedded in the finding",
                "verified process_exec telemetry fields when present in stored context",
            ],
            "limitations": list(UNAVAILABLE_TELEMETRY),
            "mode": "explanation",
        }
        if persist:
            self.store.write_explanation(explanation)
        return explanation

    def explain_all(self, findings: Optional[Iterable[Dict[str, Any]]] = None, persist: bool = True) -> List[Dict[str, Any]]:
        records = list(findings) if findings is not None else self.store.read_detection_findings()
        return [self.explain_finding(finding, persist=persist) for finding in records]
