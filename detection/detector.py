import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from detection.rules import RuleResult, SecurityRule, default_rules
from pipeline.event_stream import Event
from storage.sqlite_store import SQLiteEventStore


class DetectionEngine:
    """
    Detection fusion over behavior risks and canonical events.

    This component detects and records findings only. It performs no response,
    remediation, process control, or system configuration changes.

    Findings are additionally correlated and given an explicit disposition before
    they are persisted. `correlation_id` groups findings that concern the same
    entity across a contiguous run of behaviour windows, so an operator can pivot
    on a single incident rather than a scatter of rows. Suppression is a
    disposition applied by explicit, operator-supplied specs: a suppressed finding
    is still scored, explained, persisted, and hash-chained -- it is never a
    silent drop -- and suppression touches only the `suppressed`/
    `suppression_reason` fields, never any score, so the explainer's score
    reconciliation is unaffected.
    """

    def __init__(
        self,
        store: SQLiteEventStore,
        rules: Sequence[SecurityRule] | None = None,
        persist: bool = True,
        ml_scorer: Any | None = None,
        suppressions: Sequence[Mapping[str, Any]] | None = None,
    ):
        self.store = store
        self.rules = list(rules) if rules is not None else default_rules()
        self.persist = persist
        self.ml_scorer = ml_scorer
        self.detector_version = "detector.v1"
        self.suppressions = self._validate_suppressions(suppressions or [])

    @staticmethod
    def _validate_suppressions(specs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """
        Normalize and fail-closed-validate operator suppression specs.

        A spec must carry a non-empty ``reason`` (an unexplained suppression is
        not auditable) and must constrain at least one of ``entity_key`` or
        ``matched_rule`` (a spec matching everything would silently mute the whole
        detector). ``entity_type`` is an optional additional constraint.
        """
        validated: list[dict[str, Any]] = []
        for spec in specs:
            if not isinstance(spec, Mapping):
                raise ValueError("each suppression spec must be a mapping")
            reason = str(spec.get("reason", "")).strip()
            if not reason:
                raise ValueError("suppression spec requires a non-empty 'reason'")
            entity_key = spec.get("entity_key")
            matched_rule = spec.get("matched_rule")
            if entity_key is None and matched_rule is None:
                raise ValueError(
                    "suppression spec must constrain 'entity_key' and/or 'matched_rule'"
                )
            validated.append(
                {
                    "entity_type": spec.get("entity_type"),
                    "entity_key": None if entity_key is None else str(entity_key),
                    "matched_rule": None if matched_rule is None else str(matched_rule),
                    "reason": reason,
                }
            )
        return validated

    def _provenance_hash(self, finding: dict[str, Any]) -> str:
        material = {
            "detector_version": self.detector_version,
            "window_start": finding["window_start"],
            "window_end": finding["window_end"],
            "entity_type": finding["entity_type"],
            "entity_key": finding["entity_key"],
            "risk_score": finding["risk_score"],
            "behavior_score": finding["behavior_score"],
            "rule_score": finding["rule_score"],
            "context_score": finding["context_score"],
            "evidence": finding["evidence"],
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _events_for_risk(self, risk: dict[str, Any], events: Sequence[Event]) -> list[Event]:
        start = float(risk["window_start"])
        end = float(risk["window_end"])
        entity_type = risk["entity_type"]
        entity_key = str(risk["entity_key"])
        matching = []
        for event in events:
            if not start <= float(event.timestamp) < end:
                continue
            if event.event_type.value != "process_exec":
                continue
            if entity_type == "command" and (event.comm or "unknown") == entity_key:
                matching.append(event)
            elif entity_type == "uid" and str(event.uid if event.uid is not None else "unknown") == entity_key:
                matching.append(event)
        return matching

    def _context_score(self, events: Sequence[Event], features: dict[str, Any]) -> float:
        score = 0.0
        if any(event.uid == 0 for event in events):
            score += 0.60
        if int(features.get("unique_uids", 0)) >= 2:
            score += 0.20
        if int(features.get("execution_frequency", 0)) >= 10:
            score += 0.20
        return min(1.0, score)

    def _window_events(self, risk: dict[str, Any], events: Sequence[Event]) -> list[Event]:
        return [event for event in events if float(risk["window_start"]) <= float(event.timestamp) < float(risk["window_end"])]

    def _ml_evidence(self, risk: dict[str, Any], events: Sequence[Event]) -> dict[str, Any]:
        if self.ml_scorer is None:
            return {"available": False, "reason": "no compatible ML model is configured"}
        try:
            return self.ml_scorer.score(self._window_events(risk, events))
        except Exception as error:
            return {"available": False, "reason": f"ML scoring unavailable: {error}"}

    def _fuse_rules(self, results: Sequence[RuleResult]) -> float:
        probability_remaining = 1.0
        for result in results:
            if result.matched:
                probability_remaining *= 1.0 - result.score
        return 1.0 - probability_remaining

    def _severity(self, score: float) -> str:
        if score >= 0.80:
            return "CRITICAL"
        if score >= 0.60:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        return "LOW"

    def _finding(
        self,
        risk: dict[str, Any],
        events: Sequence[Event],
    ) -> dict[str, Any]:
        behavior_score = float(risk["anomaly_score"])
        features = risk["contributing_features"]
        context = {
            "risk": risk,
            "events": events,
            "features": features,
            "behavior_score": behavior_score,
        }
        rule_results = [rule.evaluate(context) for rule in self.rules]
        rule_score = self._fuse_rules(rule_results)
        context_score = self._context_score(events, features)
        ml = self._ml_evidence(risk, events)
        if ml.get("available"):
            risk_score = min(1.0, 0.45 * behavior_score + 0.30 * rule_score + 0.15 * context_score + 0.10 * float(ml["normalized_score"]))
            fusion_formula = "min(1, 0.45 * behavior_score + 0.30 * rule_score + 0.15 * context_score + 0.10 * ml_score)"
        else:
            risk_score = min(1.0, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)
            fusion_formula = "min(1, 0.50 * behavior_score + 0.35 * rule_score + 0.15 * context_score)"

        # Every fused score the detector reports is rounded to 4 decimal places.
        # This is an invariant, not cosmetics: _provenance_hash (below) folds these
        # score fields into the finding's identity, so an unrounded float would let
        # a sub-ulp difference between runs or platforms produce a different hash
        # for the same finding and defeat deduplication. Rounding also keeps the
        # stored number identical to the .4f figures in `explanation`. The per-rule
        # scores nested under "rules" are passed through unrounded on purpose: each
        # is that rule's own reported value, not the detector's to restate.
        evidence = [
            {
                "signal": "behavior_anomaly",
                "score": round(behavior_score, 4),
                "features": features,
                "source": "behavior_risk",
            },
            {
                "signal": "rule_fusion",
                "score": round(rule_score, 4),
                "rules": [
                    {
                        "rule_id": result.rule_id,
                        "version": result.version,
                        "mitre": dict(result.mitre),
                        "matched": result.matched,
                        "score": result.score,
                        "evidence": result.evidence,
                        "explanation": result.explanation,
                    }
                    for result in rule_results
                ],
            },
            {
                "signal": "process_context",
                "score": round(context_score, 4),
                "event_count": len(events),
                "privileged_event_count": sum(event.uid == 0 for event in events),
            },
        ]
        if ml.get("available"):
            evidence.append({"signal": "ml_anomaly", "score": round(float(ml["normalized_score"]), 4), "model": ml})
        explanation = (
            f"behavior={behavior_score:.4f}; rules={rule_score:.4f}; "
            f"context={context_score:.4f}; fused={risk_score:.4f}; "
            f"entity={risk['entity_type']}:{risk['entity_key']}"
        )
        finding = {
            "detector_version": self.detector_version,
            "source_risk_id": risk.get("id"),
            "window_start": risk["window_start"],
            "window_end": risk["window_end"],
            "entity_type": risk["entity_type"],
            "entity_key": risk["entity_key"],
            "risk_score": round(risk_score, 4),
            "severity": self._severity(risk_score),
            "behavior_score": round(behavior_score, 4),
            "rule_score": round(rule_score, 4),
            "context_score": round(context_score, 4),
            "evidence": evidence,
            "explanation": explanation,
            "mode": "detection",
            "fusion_formula": fusion_formula,
        }
        finding["provenance_hash"] = self._provenance_hash(finding)
        # Correlation and disposition are assigned in detect() over the whole
        # finding batch and are deliberately excluded from _provenance_hash, so
        # they never perturb a finding's identity or its dedup behaviour.
        finding["correlation_id"] = None
        finding["suppressed"] = False
        finding["suppression_reason"] = None
        return finding

    @staticmethod
    def _correlation_id(entity_type: str, entity_key: str, anchor_window_start: float) -> str:
        key = f"{entity_type}|{entity_key}|{float(anchor_window_start)!r}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def _assign_correlation(self, findings: Sequence[dict[str, Any]]) -> None:
        """
        Group findings about one entity across a contiguous run of windows.

        Within a detect() batch, findings for the same (entity_type, entity_key)
        are ordered by window and walked: a run continues while windows are
        adjacent or overlapping and breaks on a gap. Every finding in a run shares
        a `correlation_id` anchored on the run's first window, so the id is stable
        for a given batch and identical inputs yield identical ids. It is a
        triage-grouping key, not an incident-timeline reconstruction.
        """
        by_entity: dict[Any, list[dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            by_entity[(finding["entity_type"], str(finding["entity_key"]))].append(finding)
        for (entity_type, entity_key), group in by_entity.items():
            group.sort(key=lambda item: float(item["window_start"]))
            run_anchor: float | None = None
            prev_end: float | None = None
            for finding in group:
                start = float(finding["window_start"])
                end = float(finding["window_end"])
                if prev_end is None or start > prev_end:  # a window gap starts a new run
                    run_anchor = start
                assert run_anchor is not None
                finding["correlation_id"] = self._correlation_id(entity_type, entity_key, run_anchor)
                prev_end = end if prev_end is None else max(prev_end, end)

    @staticmethod
    def _matched_rule_ids(finding: dict[str, Any]) -> set:
        for item in finding["evidence"]:
            if item.get("signal") == "rule_fusion":
                return {rule["rule_id"] for rule in item["rules"] if rule["matched"]}
        return set()

    def _apply_suppressions(self, findings: Sequence[dict[str, Any]]) -> None:
        """
        Apply operator suppression specs as a disposition, never a drop.

        The first matching spec sets `suppressed`/`suppression_reason` and nothing
        else -- no score, severity, evidence, or ordering is touched -- so a
        suppressed finding is still persisted, explained, and hash-chained.
        """
        if not self.suppressions:
            return
        for finding in findings:
            matched_rules: set | None = None
            for spec in self.suppressions:
                if spec["entity_type"] is not None and spec["entity_type"] != finding["entity_type"]:
                    continue
                if spec["entity_key"] is not None and spec["entity_key"] != str(finding["entity_key"]):
                    continue
                if spec["matched_rule"] is not None:
                    if matched_rules is None:
                        matched_rules = self._matched_rule_ids(finding)
                    if spec["matched_rule"] not in matched_rules:
                        continue
                finding["suppressed"] = True
                finding["suppression_reason"] = spec["reason"]
                break

    def detect(
        self,
        risks: Iterable[dict[str, Any]] | None = None,
        events: Iterable[Event] | None = None,
        persist: bool | None = None,
    ) -> dict[str, Any]:
        risk_records = list(risks) if risks is not None else self.store.read_risk_records()
        event_records = list(events) if events is not None else list(self.store.read_all())
        findings = []
        should_persist = self.persist if persist is None else persist

        for risk in sorted(
            risk_records,
            key=lambda item: (
                float(item["window_start"]),
                item["entity_type"],
                str(item["entity_key"]),
            ),
        ):
            relevant_events = self._events_for_risk(risk, event_records)
            findings.append(self._finding(risk, relevant_events))

        # Correlate and set disposition over the whole batch before persisting;
        # neither step alters a score or the provenance hash, so dedup and the
        # explainer's reconciliation are unaffected.
        self._assign_correlation(findings)
        self._apply_suppressions(findings)

        if should_persist:
            for finding in findings:
                finding["id"] = self.store.write_detection_finding(finding)

        return {
            "status": "detected",
            "mode": "detection",
            "findings": findings,
        }
