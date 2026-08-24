# Phase 4 Results - Detection Fusion and Risk Scoring

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Explicit Linux security rules, transparent fusion, severity classification, and SQLite findings

> **Superseded telemetry note (2026-08-24):** The telemetry limitations below describe the Phase 4 state on 2026-08-19. All planned telemetry families are now **LIVE VERIFIED**. The current ML layer is implemented but its model remains intentionally inactive; see [AGENTS.md](../AGENTS.md).

## Detection Flow

```text
Phase 3 behavior risk
        + explicit security rules
        + canonical process context
        -> weighted detection fusion
        -> bounded risk score and severity
        -> persisted detection finding
```

## Rules

- `privileged_unusual_execution`: anomalous root execution outside a conservative system-command allowlist.
- `suspicious_utility_activity`: dual-use utilities such as `nc`, `curl`, or `ssh` only contribute when behavior is already anomalous.
- `execution_burst`: concentrated process execution above configurable frequency thresholds.
- `multi_uid_activity`: multiple user identities active in one behavior window.

Rules are independent and return explicit scores plus evidence. No rule alone declares an event malicious.

## Fusion and Severity

```text
rule_fusion = 1 - product(1 - matched_rule_score)
final_score = min(1, 0.50 * behavior_score
                     + 0.35 * rule_fusion
                     + 0.15 * context_score)
```

- LOW: `< 0.35`
- MEDIUM: `0.35 - < 0.60`
- HIGH: `0.60 - < 0.80`
- CRITICAL: `>= 0.80`

## Finding Storage

SQLite table `detection_findings` stores:

- source behavior-risk ID
- time window and affected entity
- final, behavior, rule, and context scores
- severity
- structured evidence JSON
- deterministic explanation
- detection mode

## Validation

- Phase 4 tests: 6 passed
- Complete repository tests: 20 passed
- Real capture: 136 lines, 134 `process_exec`, 1 `telemetry_startup`, 1 `system_health`
- Real capture baseline: remained `insufficient_normal_data`
- Real capture findings: `0`
- Phase 1 collector compiled successfully
- No LLM, remediation, policy engine, dashboard, or Phase 5 component was added

## Known Limitations

- The historical Phase 4 rules primarily use process-execution and system-health evidence.
- A finding must not infer telemetry that is absent from its persisted evidence, even though the corresponding collector may be live verified.
- Dual-use command rules intentionally require behavioral deviation and can still require tuning for a specific host.
- SQLite validation uses file-backed databases; the existing connection-per-operation implementation does not support `:memory:` databases across operations.
