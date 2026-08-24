# Phase 3 Results - Behavior Analysis and Risk Generation

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Windowed behavioral aggregation, explicit normal-learning mode, monitoring mode, and persisted risk records

> **Superseded telemetry note (2026-08-24):** The telemetry limitations below describe the Phase 3 state on 2026-08-19. All planned telemetry families are now **LIVE VERIFIED**; see [AGENTS.md](../AGENTS.md) for the current status and ML activation gate.

## Data Flow

```text
SQLite canonical events
        -> configurable time windows
        -> command, UID, frequency, and burst features
        -> explicitly verified normal learning
        -> READY baseline promotion after sufficient process_exec data
        -> monitoring comparison
        -> persisted structured behavior risks
```

## State Model

- `learning`: accepts data only through `learn_normal(..., verified_normal=True)`.
- `insufficient_normal_data`: remains active until the configured minimum normal `process_exec` count is reached.
- `monitoring`: entered only after READY baseline promotion.
- Monitoring data is never appended to the normal learning set automatically.
- Monitoring cannot emit risks while a READY baseline is unavailable.

## Risk Record

Risk records are stored in SQLite table `behavior_risks` with:

- window start/end
- entity type and key (`command` or `uid`)
- bounded anomaly score
- risk level (`medium` or `high`)
- contributing execution, command, UID, and burst features
- deterministic explanation/evidence
- analysis mode

## Validation

- Phase 3 tests: 6 passed
- Complete repository tests: 14 passed
- Real capture sanity check: 136 lines, 134 `process_exec`, 1 `telemetry_startup`, 1 `system_health`
- Real capture result: `insufficient_normal_data` at the configured 500 normal execution threshold
- No LLM, remediation, policy engine, dashboard, or Phase 4 detection model was added

## Limitations

- This historical baseline implementation was initially exercised with process execution and system-health data.
- Current findings and behavior risks remain limited to the canonical events actually ingested into their analysis window; live collector verification does not imply every family is present in every window.
- Risk scoring remains a lightweight statistical extension of the Phase 2 baseline, not a production intrusion classifier.
