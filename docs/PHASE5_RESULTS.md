# Phase 5 Results - Explainability

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Deterministic reconstruction and explanation of persisted Phase 4 findings

> **Superseded telemetry note (2026-08-24):** The unavailable-telemetry statements below describe the Phase 5 implementation state on 2026-08-19. All planned telemetry families are now **LIVE VERIFIED**; see [AGENTS.md](../AGENTS.md) for the current matrix.

## Architecture

```text
persisted detection finding
        -> evidence reconstruction
        -> behavior/rule/context attribution
        -> formula verification
        -> structured FACT/INTERPRETATION explanation
        -> persisted explanation for future consumers
```

The explainability layer does not create detections, change scores or severity, evaluate rules, infer maliciousness, call an LLM, execute commands, or perform remediation.

## Explanation Schema

Each explanation contains:

- `finding_id`
- timestamp and window
- stored severity and risk score
- deterministic summary
- FACT and INTERPRETATION contributing factors
- original stored evidence list
- fusion calculation and reconstructed matched-rule score
- data sources
- unavailable telemetry limitations

Explanations are stored in SQLite table `finding_explanations`, keyed uniquely by detection finding ID.

## Evidence and Provenance

The explanation copies evidence from `detection_findings.evidence_json`. It verifies:

- the behavior, rule-fusion, and process-context signals exist
- the stored rule score matches its matched rule scores
- the stored final score matches the Phase 4 fusion formula

At this historical checkpoint, it reported TCP/network, file, and audit/auth as unavailable. Current explanations should describe the telemetry actually represented in their persisted evidence, not infer completeness from this historical report.

## Validation

- Phase 5 tests: 6 passed
- Complete repository tests: 26 passed
- Includes no-detection, insufficient-baseline, single-rule, multi-rule critical, persistence/readback, incomplete-evidence, and deterministic reload tests
- Real telemetry remains validation-only; no finding or explanation was fabricated from the 136-event capture
- No Phase 6 assistant, dashboard, policy, or remediation code was added

## Limitations

- Explanations are only as complete as the persisted Phase 4 evidence.
- A finding can only be explained from its persisted evidence; verified collectors that did not contribute events to that finding cannot be inferred.
- The interpretation text is deliberately bounded and does not label activity malicious.
