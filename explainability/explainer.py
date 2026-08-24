import json
from typing import Any, Dict, Iterable, List, Optional

from storage.sqlite_store import SQLiteEventStore


UNAVAILABLE_TELEMETRY = []


class FindingExplainer:
    """
    Reconstruct deterministic explanations from persisted Phase 4 findings.

    This class is read-only with respect to detection decisions: it does not
    create findings, change scores, evaluate rules, or infer maliciousness.
    """

    def __init__(self, store: SQLiteEventStore):
        self.store = store

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
