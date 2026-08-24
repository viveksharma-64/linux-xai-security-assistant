# Phase 7 Results - Policy Engine

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Deterministic policy evaluation, human approval gates, and dry-run decisions only

> **Superseded telemetry note (2026-08-24):** Any unavailable-telemetry references below are historical Phase 7 context. All planned telemetry families are now **LIVE VERIFIED**; see [AGENTS.md](../AGENTS.md) for the authoritative current status.

## Policy Flow

```text
authoritative detection finding
        -> YAML policy matching
        -> deterministic policy decision
        -> human approval or dry-run state
        -> future response executor boundary
```

The policy engine never executes an action. The AI assistant is advisory and cannot authorize or override policy.

## Policy Schema

YAML documents require `version: 1` and a `policies` list. Each policy defines:

- `policy_id`
- `priority`
- `match` criteria: severity, risk range, detection type, matched rule IDs, telemetry completeness
- `decision`
- `required_approval`
- non-executing `proposed_action`
- optional allowed advisory recommendation keywords

The checked-in default policy is [policy/default_policy.yaml](../policy/default_policy.yaml).

## Decision States

- `ALLOW`
- `LOG`
- `REVIEW_REQUIRED`
- `DRY_RUN`
- `ACTION_PENDING_APPROVAL`
- `DENIED`

Default critical and high-risk policies require approval. In dry-run mode, approval-gated decisions become `DRY_RUN` and explicitly state that no action is executed.

## Fail-Closed Behavior

- malformed YAML or unknown schema keys fail at configuration load
- unknown or unsupported decisions fail at configuration load
- missing finding evidence returns `REVIEW_REQUIRED`
- no matching policy returns `REVIEW_REQUIRED`
- malformed runtime findings return `REVIEW_REQUIRED`
- unavailable telemetry cannot satisfy a complete-telemetry condition
- missing telemetry is never treated as proof of safety

## AI Recommendation Handling

AI output is advisory only. Destructive or executing recommendations are rejected and recorded in `advisory_rejection`. A conflicting recommendation cannot change the authoritative detection score, severity, policy, or approval requirement.

## Persistence

SQLite table `policy_decisions` stores finding ID, policy ID, decision, reason, authoritative score/severity, approval requirement, proposed action, limitations, timestamp, dry-run state, and advisory rejection.

## Validation

- Focused Phase 7 tests: 10 passed
- Complete repository tests: pending final run
- No remediation, shell execution, firewall changes, sudoers changes, process control, dashboard, or new telemetry was added

## Limitations

- Policy matching uses currently available process-execution findings and their stored evidence.
- Policy decisions remain limited to the telemetry actually represented in each finding's evidence; collector verification alone does not establish evidence completeness for an individual finding.
- `ALLOW` is available as a policy state, but the default policy uses `LOG` for low-risk findings because missing telemetry must not imply safety.
