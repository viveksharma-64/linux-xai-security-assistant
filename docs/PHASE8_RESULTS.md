# Phase 8 Results - Read-Only Security API and Dashboard

**Date**: 2026-08-19  
**Status**: Implemented and tested  
**Scope**: Read-only FastAPI views and a lightweight static SOC-style dashboard over persisted SQLite data

> **Superseded status note (2026-08-24):** This is a historical Phase 8 report. All planned telemetry families are **LIVE VERIFIED**. See [AGENTS.md](../AGENTS.md) for the authoritative live-verification matrix.

## API Architecture

```text
SQLite read accessors
        -> FastAPI typed GET endpoints
        -> static dashboard fetches
        -> persisted security view
```

The API registers GET-only data routes. It does not expose event writes, finding mutation, baseline mutation, policy editing, approvals, remediation, shell access, or external tools.

## Endpoints

- `GET /api/health`
- `GET /api/status`
- `GET /api/events`
- `GET /api/detections`
- `GET /api/detections/{id}`
- `GET /api/explanations/{id}`
- `GET /api/assistant/{id}`
- `GET /api/policies`
- `GET /api/policy-decisions`
- `GET /api/telemetry/status`

The dashboard is served at `/dashboard/` and the root redirects there.

## Dashboard Capabilities

The static frontend displays:

- total events and persisted detections
- baseline status and read-only mode
- severity counts and risk meters
- telemetry source verification status
- detection table
- explanation facts, interpretation, evidence calculation, and limitations
- policy decision, approval, dry-run, and advisory rejection state
- explicit absence of persisted assistant responses

No action buttons or mutation controls are present.

## Security Controls

- Pydantic response models reject unexpected response fields.
- Numeric IDs and bounded event limits are validated by FastAPI.
- Missing records return 404; malformed route parameters return 422.
- Policy configuration errors return a safe 503 response.
- Telemetry source status is reported explicitly; the current source matrix is maintained in `api/app.py` and `AGENTS.md`.
- The API does not pass user input to the operating system.

## Validation

- Focused Phase 8 tests: 5 passed
- Complete repository tests: pending final run
- Python compilation and diagnostics included in final validation
- SQLite integration uses a temporary file-backed database
- Real telemetry remains validation-only; no data or findings were fabricated

## Limitations

- Phase 6 assistant responses are not persisted, so `/api/assistant/{id}` reports `not_persisted` rather than generating a response.
- WebSockets/live updates were not added; the dashboard reads persisted SQLite data and remains functional without a live stream.
- The dashboard's telemetry matrix is maintained in `api/app.py`; as of 2026-08-24, all planned telemetry families are LIVE VERIFIED. The dashboard may still display stale persisted collector data when no current collector is running.
