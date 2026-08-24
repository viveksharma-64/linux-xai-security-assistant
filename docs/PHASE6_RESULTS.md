# Phase 6 Results - Evidence-Grounded AI Security Assistant

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Provider-neutral, read-only narration and recommendation over Phase 5 explanations

> **Superseded telemetry note (2026-08-24):** The unavailable-telemetry references below describe the Phase 6 state on 2026-08-19. All planned telemetry families are now **LIVE VERIFIED**; see [AGENTS.md](../AGENTS.md) for the authoritative telemetry and ML status.

## Provider Abstraction

`assistant/provider.py` defines the provider-neutral `LLMProvider` interface and `ProviderResponse` value object. The repository includes a deterministic `MockProvider` for tests. No Anthropic, OpenAI, or other SDK is required, and no API key is hard-coded.

`ASSISTANT_PROVIDER=mock` enables the mock provider through environment configuration. Other provider names remain unconfigured until a provider adapter is deliberately added.

## Assistant Architecture

```text
Phase 5 structured explanation
        -> strict input validation
        -> prompt with untrusted evidence delimiters
        -> configured provider or deterministic fallback
        -> validated analyst narration
```

The assistant cannot create findings, change scores/severity, execute commands, access a shell, or perform remediation.

## Input and Output

Input is only the Phase 5 structured explanation. The response contains:

- `finding_id`
- authoritative `risk_score` and `severity`
- executive summary
- what happened
- why it was flagged
- evidence
- risk interpretation
- non-executing recommended action
- limitations
- confidence statement
- provider and fallback metadata

## Guardrails and Prompt-Injection Defense

- Evidence is serialized as structured JSON inside explicit untrusted-data delimiters.
- Provider output cannot override finding ID, score, or severity.
- Missing or malformed explanation evidence is rejected before provider invocation.
- Claims not supported by the supplied persisted evidence are rejected; collector verification alone is not evidence for an individual finding.
- Executing recommendations such as killing processes, modifying firewalls, changing sudoers, or running commands are rejected.
- Provider failures, timeouts, malformed responses, and validation failures use deterministic fallback output.
- Logs record provider, request ID, finding ID, status, latency, and fallback usage without logging prompts, responses, keys, or raw sensitive data.

## Validation

- Phase 6 tests: 10 passed
- Complete repository tests: 36 passed
- Mock provider used; no real API key or network call required
- Tested valid output, missing evidence, provider unavailability, malformed output, timeout, unsupported claims, prompt injection, score/severity preservation, non-string fields, and environment configuration
- Real telemetry remains validation-only and is not sent to any provider

## Limitations

- No production provider adapter is configured yet.
- The fallback narrator is intentionally deterministic and limited to stored evidence.
- The assistant does not independently assess maliciousness.
- The assistant reports evidence-specific limitations and does not infer telemetry that is absent from a finding.
