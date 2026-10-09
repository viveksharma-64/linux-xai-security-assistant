import time
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from api.auth import TokenAuthenticator, extract_token, unprotected_paths
from detection.operational_efficacy import operational_efficacy_from_store
from ml.drift import drift_summary
from ml.lifecycle import current_state, lifecycle_report
from observability import alerts as alerting
from observability import metrics as metrics_module
from observability.config import Settings
from observability.config import settings as load_process_settings
from storage.sqlite_store import (
    MAX_TRIAGE_ANNOTATION_LIMIT,
    MAX_TRIAGE_EXPORT_LIMIT,
    SQLiteEventStore,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "policy" / "default_policy.yaml"

# The telemetry surfaces this build can collect, and the canonical event types
# each one produces.
#
# `detail` describes a *capability* -- what the collector was built and
# live-verified to emit. It is deliberately not a status: whether a source is
# reporting right now is a property of the database, not of the build, and is
# derived per request in `telemetry_status()` from the newest event of each type.
# Conflating the two is how an operator ends up reading "verified" for a source
# that no deployed unit actually runs.
TELEMETRY_SOURCES = {
    "process_exec": {
        "event_types": ("process_exec",),
        "detail": "Live-verified BCC/eBPF process execution and post-exec context telemetry.",
    },
    "system_health": {
        "event_types": ("system_health",),
        "detail": "Live-verified psutil system-health telemetry.",
    },
    "tcp_network": {
        "event_types": ("tcp_connect",),
        "detail": "Live-verified BCC sock:inet_sock_set_state IPv4 TCP connect telemetry.",
    },
    "file_access": {
        "event_types": ("file_open", "file_write"),
        "detail": "Live-verified file-access telemetry; canonical file_open/file_write events are supported.",
    },
    "audit_auth": {
        "event_types": ("auth_session",),
        "detail": "Live-verified structured journald PAM authentication/session telemetry.",
    },
    "system_service": {
        "event_types": ("service_state",),
        "detail": "Live-verified structured journald/systemd service lifecycle telemetry.",
    },
    "pipes_streams": {
        "event_types": ("ipc_event",),
        "detail": "Live-verified BCC pipe/pipe2 IPC telemetry with validated file descriptors.",
    },
}

# The three observed states a source can be in. `not_collected` is the honest
# answer for a supported collector that nothing has ever fed -- it is neither
# healthy nor broken, and saying so is what tells an operator the unit is not
# wired rather than that the host is quiet.
TELEMETRY_LIVE = "live"
TELEMETRY_STALE = "stale"
TELEMETRY_NOT_COLLECTED = "not_collected"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictModel):
    status: str
    read_only: bool


class TelemetrySource(StrictModel):
    status: str
    detail: str
    last_event_timestamp: float | None = None


class TelemetryStatusResponse(StrictModel):
    sources: dict[str, TelemetrySource]


class StatusResponse(StrictModel):
    status: str
    read_only: bool
    total_events: int
    total_detections: int
    severity_counts: dict[str, int]
    baseline_status: str
    telemetry: dict[str, TelemetrySource]
    collector_status: str
    collector_detail: str
    event_count: int
    last_event_timestamp: float | None = None
    stale_data: bool
    dropped_event_count: int | None = None
    collector_error: str | None = None
    collector_throughput: float = 0.0
    collector_processed_count: int = 0
    collector_malformed_count: int = 0
    collector_updated_at: float | None = None
    # Backpressure and event-loss detail. Optional because a database written
    # before these columns existed, or one no collector has ever reported into,
    # has nothing to say -- and "unknown" must not be rendered as zero loss.
    collector_queue_depth: int | None = None
    collector_queue_capacity: int | None = None
    collector_queue_high_water_mark: int | None = None
    collector_backpressure_wait_count: int | None = None
    collector_backpressure_wait_seconds: float | None = None
    first_drop_timestamp: float | None = None
    last_drop_timestamp: float | None = None
    # Kernel-side loss, reported by the collector rather than observed by the
    # supervisor. Separate from dropped_event_count because a kernel ring-buffer
    # overrun (perf or BPF ring) and a full ingestion queue are different
    # failures with different fixes.
    kernel_lost_event_count: int | None = None
    first_kernel_loss_timestamp: float | None = None
    last_kernel_loss_timestamp: float | None = None


class EventResponse(StrictModel):
    id: int
    event_type: str
    timestamp: float
    timestamp_ns: int | None = None
    timestamp_monotonic: float | None = None
    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None
    gid: int | None = None
    comm: str | None = None
    executable: str | None = None
    parent_comm: str | None = None
    ancestry: list[dict[str, Any]] = Field(default_factory=list)
    source: str | None = None
    version: str | None = None
    event_hash: str | None = None
    # Which host, boot, and agent observed the event. Null for rows written
    # before identity existed, and for hosts with no readable machine-id -- the
    # dashboard must be able to say "unknown", not imply a single host.
    host_id: str | None = None
    boot_id: str | None = None
    agent_id: str | None = None
    # Login session (migration 11), and null for the majority of rows on purpose:
    # the ingest service belongs to no login session, so it stamps nothing rather
    # than guessing. Present here because `read_event_records` selects `*` and
    # this model forbids extras -- an event column the model does not know about
    # is a 500, not a missing field.
    session_id: str | None = None
    payload: dict[str, Any]


class FindingResponse(StrictModel):
    id: int
    source_risk_id: int | None = None
    window_start: float
    window_end: float
    entity_type: str
    entity_key: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str
    behavior_score: float = Field(ge=0.0, le=1.0)
    rule_score: float = Field(ge=0.0, le=1.0)
    context_score: float = Field(ge=0.0, le=1.0)
    evidence: list[dict[str, Any]]
    explanation: str
    mode: str
    provenance_hash: str | None = None
    detector_version: str | None = None
    created_at: float | None = None
    # Correlation/suppression disposition (migration 8). Suppression is a
    # disposition only -- it never alters a score; a suppressed finding is still
    # persisted, explained, and chained.
    correlation_id: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    # Append-only evidence-chain integrity (migration 8). Surfaced so an API
    # consumer can independently verify continuity; Optional so a pre-chain
    # legacy row still serializes rather than 500-ing the read API.
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    chain_hash: str | None = None
    # Effective triage state (Phase D, migration 9), folded read-only from the
    # append-only annotation layer -- never a mutation of the finding row above.
    # Both readers of this model do enrich, by different means: the paged list
    # computes all four in SQL (`read_detection_findings_page`), and the single
    # lookup folds the annotation log in Python and indexes it by id. The
    # defaults are for the readers that do *not* -- plain `read_detection_findings`
    # returns the stored columns only -- so an unenriched row still validates
    # instead of 500-ing, and an un-annotated finding reads as benign rather than
    # requiring a caller to spell out four zero values. `triage_suppressed` is the
    # *effective* suppression (config `suppressed` OR the latest analyst suppress
    # not since lifted); the immutable `suppressed` column is left truthful above.
    triage_disposition: str | None = None
    triage_acknowledged: bool = False
    triage_suppressed: bool = False
    triage_annotation_count: int = 0


class ExplanationResponse(StrictModel):
    finding_id: int
    timestamp: float
    window: dict[str, float]
    severity: str
    risk_score: float = Field(ge=0.0, le=1.0)
    summary: str
    contributing_factors: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    calculation: dict[str, Any]
    data_sources: list[str]
    limitations: list[str]
    mode: str


class AssistantStatusResponse(StrictModel):
    finding_id: int
    status: str
    message: str
    response: dict[str, Any] | None = None


class PolicyResponse(StrictModel):
    policy_id: str
    priority: int
    match: dict[str, Any]
    decision: str
    required_approval: bool
    proposed_action: str
    allowed_recommendation_keywords: list[str]


class PolicyDecisionResponse(StrictModel):
    id: int
    finding_id: int | None = None
    policy_id: str
    decision: str
    reason: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str
    required_approval: bool
    proposed_action: str
    limitations: list[str]
    timestamp: float
    dry_run: bool
    advisory_rejection: str | None = None
    # Append-only evidence-chain integrity (migration 8), Optional for the same
    # reason as FindingResponse: a pre-chain legacy row still serializes.
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    chain_hash: str | None = None


class LivenessResponse(StrictModel):
    status: str
    collected_at: float


class ReadinessResponse(StrictModel):
    status: str
    # Every failing condition, not the first one. An operator restarting a service
    # because of stale data should also learn in the same response that the file
    # permissions are wrong, rather than after the restart fails to help.
    reasons: list[str]
    event_count: int
    data_age_seconds: float | None = None
    degraded_sources: list[str]
    collected_at: float


class AlertResponse(StrictModel):
    name: str
    severity: str
    summary: str
    value: float | None = None
    threshold: float | None = None
    labels: dict[str, str]


class AlertsResponse(StrictModel):
    firing: int
    critical: int
    warning: int
    alerts: list[AlertResponse]
    collected_at: float


class SourceStateResponse(StrictModel):
    name: str
    status: str
    detail: str | None = None
    error: str | None = None
    started_at: float | None = None
    stopped_at: float | None = None
    last_event_timestamp: float | None = None
    processed_count: int
    restart_count: int
    consecutive_failures: int
    last_failure_at: float | None = None
    next_restart_at: float | None = None
    backoff_seconds: float
    crash_looping: bool
    quarantined_batch_count: int
    quarantined_event_count: int
    updated_at: float | None = None


class MaintenanceRecordResponse(StrictModel):
    id: int
    action: str
    reason: str
    events_deleted: int
    rows_deleted: int
    cutoff_timestamp: float | None = None
    oldest_retained_timestamp: float | None = None
    db_bytes_before: int | None = None
    db_bytes_after: int | None = None
    duration_seconds: float
    detail: str | None = None
    created_at: float


# --------------------------------------------------------------------------- #
# Triage (Phase D). Analyst write-back is an append-only annotation layer that
# never mutates a finding row or the evidence chain: an acknowledge, note,
# disposition, suppress, or unsuppress is a new event, and a correction is a
# later event, not an edit. `extra="forbid"` (StrictModel) rejects unexpected
# body fields with 422 rather than silently dropping them. `actor` is a
# self-reported claim -- the token proves the writer is authorized, not who they
# are -- and is labeled as such wherever it surfaces.
# --------------------------------------------------------------------------- #

# The disposition vocabulary as a request/response type. Mirrors
# storage.sqlite_store._TRIAGE_DISPOSITIONS and detection.operational_efficacy;
# a Literal gives an automatic 422 on an unknown value and documents the
# allowlist in the schema. The store re-validates as a defense-in-depth backstop.
TriageDisposition = Literal["true-positive", "false-positive", "benign"]

# Bounds on free-text fields: long enough for a real analyst note, short enough
# that the write surface cannot be used to stuff the evidence database.
_MAX_NOTE = 4000
_MAX_ACTOR = 256


class TriageAcknowledgeRequest(StrictModel):
    note: str | None = Field(default=None, max_length=_MAX_NOTE)
    actor: str | None = Field(default=None, max_length=_MAX_ACTOR)


class TriageAnnotateRequest(StrictModel):
    note: str = Field(min_length=1, max_length=_MAX_NOTE)
    actor: str | None = Field(default=None, max_length=_MAX_ACTOR)


class TriageDispositionRequest(StrictModel):
    disposition: TriageDisposition
    note: str | None = Field(default=None, max_length=_MAX_NOTE)
    actor: str | None = Field(default=None, max_length=_MAX_ACTOR)


class TriageSuppressRequest(StrictModel):
    # A reason is required for suppress and unsuppress: suppression is an
    # alerting/presentation decision the record must justify, never a silent
    # drop. Stored as the annotation's note.
    reason: str = Field(min_length=1, max_length=_MAX_NOTE)
    actor: str | None = Field(default=None, max_length=_MAX_ACTOR)


class TriageAnnotationResponse(StrictModel):
    id: int
    finding_id: int
    action: str
    disposition: str | None = None
    note: str | None = None
    actor: str | None = None
    created_at: float
    # The triage layer is itself hash-chained (migration 9), so a recorded
    # disposition is as tamper-evident as the finding it annotates.
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    chain_hash: str | None = None


class TriageStateResponse(StrictModel):
    finding_id: int
    disposition: str | None = None
    acknowledged: bool = False
    # Config suppression lives on the immutable finding row; analyst suppression
    # is the latest suppress/unsuppress in the annotation layer. Both are shown,
    # and `effective_suppressed` is their OR -- the value alerting honours.
    config_suppressed: bool = False
    effective_suppressed: bool = False
    annotation_count: int = 0


class TriageHistoryResponse(StrictModel):
    finding_id: int
    state: TriageStateResponse
    annotations: list[TriageAnnotationResponse]


class ChainVerdictResponse(StrictModel):
    ok: bool
    checked: int
    break_seq: int | None = None
    reason: str | None = None


class TrainingWindowVerificationResponse(StrictModel):
    """
    A set of independent digest recomputations -- deliberately not a chain verdict.

    `ml_training_windows.immutable_hash` is recorded per row and covers that row
    only, so a break is attributable to specific ids rather than to a position in a
    sequence, and a deleted row is invisible here by construction. That is why this
    reports `mismatched_ids` instead of `break_seq`, and why it must not be read as
    a fifth hash chain: it proves the surviving rows are unedited, not that the set
    is complete.
    """

    ok: bool
    checked: int
    mismatched_ids: list[int]


class IntegrityResponse(StrictModel):
    findings: ChainVerdictResponse
    policy: ChainVerdictResponse
    triage: ChainVerdictResponse
    # The model lifecycle log. Reported alongside the evidence chains because it
    # answers a question of the same kind: whether an ML model was ever allowed to
    # influence a finding, and on what measurement. It also carries the content
    # hash of each drift assessment, so a break here can mean an edited
    # assessment as well as an edited lifecycle row.
    ml_lifecycle: ChainVerdictResponse
    # The training data behind the model currently influencing findings. Scoped to
    # the active model's own `training_window_ids` rather than to the whole table:
    # verification is a digest per row, so an unscoped form is a full scan, and this
    # endpoint is on a request path. The scope is also the stronger claim -- "the
    # data behind what is scoring right now is unedited" -- and on a default install,
    # with no active model, it is a vacuous ok over zero rows, which is the honest
    # answer when detection is running deterministically.
    active_model_training_windows: TrainingWindowVerificationResponse
    # A single overall verdict for the dashboard's banner: false if any chain is
    # broken. The per-chain detail carries the break location and reason.
    ok: bool


# --- ML model transparency surface (read-only) --------------------------------
# A window onto the recorded ML-fitness state -- provenance, lifecycle history, the
# activation-gate verdict, and the latest drift summary -- not a control on it. The
# gate stays the only door: `activation_eligible` and the gate `acceptance` block are
# surfaced verbatim from the recorded lifecycle rows, never recomputed here. Every
# field is Optional-tolerant like FindingResponse, so a partial history (a model that
# was trained but never evaluated, say) still serializes rather than 500-ing the read.
class ModelLifecycleTransitionResponse(StrictModel):
    model_id: str
    from_state: str | None = None
    to_state: str
    reason: str
    # The recorded gate verdict lives under evidence['acceptance'] for eligible/active
    # rows; passed through as-is so the numbers behind an eligibility claim travel with it.
    evidence: dict[str, Any] = Field(default_factory=dict)
    activation_eligible: bool = False
    actor: str | None = None
    created_at: float
    # The lifecycle log is itself hash-chained (migration 10), so this history is as
    # tamper-evident as the findings it can influence.
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    chain_hash: str | None = None


class DriftSummaryResponse(StrictModel):
    # The compact `ml/drift.py:drift_summary` shape -- the few fields an operator needs
    # without the per-feature detail. Present only when a drift assessment was recorded.
    status: str
    model_id: str
    comparison_dataset_id: str
    drifted_feature_count: int
    drifted_features: list[str]
    out_of_range_rate: float | None = None
    reference_window_count: int
    comparison_window_count: int
    alpha: float
    method: str
    reasons: list[str]


class ModelSummaryResponse(StrictModel):
    id: str
    version: str
    algorithm: str
    active: bool
    schema_version: str
    schema_hash: str
    created_at: float
    training_window_count: int
    # Latest recorded lifecycle state and the eligibility that row carried; None/False
    # on a model with no history yet. `latest_drift_status` is the newest assessment's
    # status, or None if none has been run.
    state: str | None = None
    activation_eligible: bool = False
    latest_drift_status: str | None = None


class ModelDetailResponse(StrictModel):
    # Provenance: identifying evidence (checksum, training-window provenance), never
    # the artifact_path -- the read surface must not leak host filesystem layout.
    id: str
    version: str
    algorithm: str
    active: bool
    schema_version: str
    schema_hash: str
    created_at: float
    artifact_checksum: str
    training_window_count: int
    training_window_ids: list[int]
    hyperparameters: dict[str, Any]
    # Lifecycle: the latest state, the full transition history, and the chain verdict
    # that says whether to trust it -- all read from `ml/lifecycle.py:lifecycle_report`.
    state: str | None = None
    activation_eligible: bool = False
    transitions: list[ModelLifecycleTransitionResponse]
    latest_drift: DriftSummaryResponse | None = None
    drift_assessment_count: int = 0
    chain: ChainVerdictResponse
    # Whether this model's own training windows still match their recorded digests.
    # Beside `chain` because the two answer different questions: the chain says the
    # lifecycle decisions were not rewritten, this says the data behind them was not.
    training_windows: TrainingWindowVerificationResponse


class OperationalEfficacyCounts(StrictModel):
    true_positive: int
    false_positive: int
    benign: int


class OperationalEfficacyResponse(StrictModel):
    scope: str
    measures: str
    total_findings: int
    reviewed: int
    unreviewed: int
    acknowledged: int
    suppressed: int
    counts: OperationalEfficacyCounts
    # Precision and the reviewed false-positive rate are conditioned on reviewed
    # fired findings; None until something is reviewed (an honest "not yet
    # measurable", not a zero). Population FPR and recall are not measurable from
    # dispositions -- they are always None here and reported by the seeded
    # evaluation and the ML acceptance gate instead. See detection.operational_efficacy.
    precision: float | None = None
    reviewed_false_positive_rate: float | None = None
    population_false_positive_rate: float | None = None
    recall: float | None = None
    note: str


def _read_policies() -> list[dict[str, Any]]:
    try:
        with DEFAULT_POLICY_PATH.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise HTTPException(status_code=503, detail=f"policy configuration unavailable: {type(error).__name__}") from error
    if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(document.get("policies"), list):
        raise HTTPException(status_code=503, detail="policy configuration is invalid")
    return document["policies"]


def create_app(
    store: SQLiteEventStore | None = None,
    config: Settings | None = None,
) -> FastAPI:
    """
    Build the application.

    Both the store and the settings are injectable so the suite can exercise
    authentication, staleness, and alert thresholds without touching `/etc` or the
    process environment. When neither is given, the layered configuration
    (defaults < config file < environment) decides -- so a packaged install is
    configured in exactly one place.
    """
    resolved = config or load_process_settings()
    stale_after_seconds = resolved.stale_after_seconds
    event_store = store or SQLiteEventStore(
        resolved.db_path,
        file_mode=resolved.db_file_mode,
        enforce_file_mode=resolved.db_enforce_mode,
    )
    app = FastAPI(
        title="Linux XAI Security Assistant API",
        version="0.9.0",
        description="Read-only security telemetry, detection, explanation, assistant, and policy views.",
    )
    app.state.store = event_store
    app.state.settings = resolved
    # Constructed at startup, not per request: a token file that cannot be read, or
    # a token too short to be a credential, must stop the service coming up rather
    # than surface as a 500 on whichever request happens to arrive first.
    app.state.authenticator = TokenAuthenticator(resolved)
    app.mount("/dashboard", StaticFiles(directory=str(ROOT / "dashboard"), html=True), name="dashboard")

    open_paths = frozenset(unprotected_paths())

    @app.middleware("http")
    async def require_token(request: Request, call_next):
        """
        Gate every path on a valid token unless it is explicitly opened.

        Implemented as middleware rather than a per-route dependency so that a
        route added later is protected by default. Forgetting a dependency on one
        new endpoint would silently expose it; there is nothing to forget here.

        The rule is **default-deny**, and that is load-bearing rather than
        stylistic. It was previously an allowlist of gated prefixes (`/metrics`
        and `/api/*`), which left anything outside those prefixes open -- and
        FastAPI mounts three such routes itself (`/openapi.json`, `/docs`,
        `/redoc`). The schema names every route, parameter, and response field of
        the evidence feed, so it was exactly the reconnaissance document the gate
        exists to withhold, served to anyone who asked. Denying by default means a
        route *this file does not know about* is still covered. Do not turn this
        back into a list of what to gate; add to the open set below instead, and
        only for something that discloses nothing.

        Open, deliberately:

        * `unprotected_paths()` -- static, DB-free liveness and health summary,
          which a process manager must reach before a credential exists.
        * `/` -- a redirect to the dashboard, carrying no telemetry. It stays open
          so an operator landing on the host gets the page where they enter their
          token, rather than a 401 with nowhere to go.
        * `/dashboard/*` -- markup and JavaScript with no telemetry in it. The
          data it renders comes from `/api/*`, which is gated; the browser
          supplies the token from there.
        """
        path = request.url.path
        authenticator: TokenAuthenticator = app.state.authenticator
        if path in open_paths or path == "/" or path == "/dashboard" or path.startswith("/dashboard/"):
            return await call_next(request)
        if authenticator.required and not authenticator.configured:
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "API authentication is required but no tokens are configured; set api_token_file "
                        "or api_tokens"
                    )
                },
            )
        presented = extract_token(request.headers.get("authorization"), request.headers.get("x-api-key"))
        if not authenticator.verify(presented):
            # WWW-Authenticate is what makes a 401 actionable to a generic client,
            # and the body names the two accepted headers so a human debugging a
            # curl does not have to read this file.
            return JSONResponse(
                status_code=401,
                content={"detail": "missing or invalid API token; send Authorization: Bearer <token> or X-API-Key"},
                headers={"WWW-Authenticate": 'Bearer realm="linux-xai-security"'},
            )
        return await call_next(request)

    def _snapshot() -> metrics_module.MetricsSnapshot:
        return metrics_module.collect_snapshot(event_store, resolved)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/")

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", read_only=True)

    @app.get("/api/health/live", response_model=LivenessResponse)
    def liveness() -> LivenessResponse:
        """
        Process liveness, for `systemd`/`ExecStartPost` and container probes.

        Answers without touching the database on purpose: a wedged or missing
        database is a readiness failure, and restarting this process on it would
        destroy the only component still able to report the problem.
        """
        _, detail = metrics_module.liveness(metrics_module.MetricsSnapshot(collected_at=time.time()))
        return LivenessResponse(**detail)

    @app.get("/api/health/ready", response_model=ReadinessResponse)
    def readiness() -> JSONResponse:
        """
        Whether this instance's answers can be trusted, as 200 or 503.

        The status code carries the verdict so a load balancer or `curl -f` needs
        no JSON parsing; the body carries every reason so a human needs no second
        request.
        """
        ready, detail = metrics_module.readiness(_snapshot(), resolved)
        payload = ReadinessResponse(**detail)
        return JSONResponse(status_code=200 if ready else 503, content=payload.model_dump())

    @app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
    def metrics() -> PlainTextResponse:
        """Prometheus text exposition of ingestion, loss, storage, and supervision state."""
        body = metrics_module.render_prometheus(_snapshot())
        return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/alerts", response_model=AlertsResponse)
    def alerts() -> AlertsResponse:
        snapshot = _snapshot()
        firing = alerting.evaluate(snapshot, resolved)
        return AlertsResponse(
            firing=len(firing),
            critical=sum(1 for alert in firing if alert.severity == alerting.SEVERITY_CRITICAL),
            warning=sum(1 for alert in firing if alert.severity == alerting.SEVERITY_WARNING),
            alerts=[AlertResponse(**alert.to_dict()) for alert in firing],
            collected_at=snapshot.collected_at,
        )

    @app.get("/api/sources", response_model=list[SourceStateResponse])
    def sources() -> list[SourceStateResponse]:
        """Per-source supervision state: which collector is running, restarting, or given up on."""
        return event_store.read_source_states()

    @app.get("/api/maintenance", response_model=list[MaintenanceRecordResponse])
    def maintenance(limit: int = Query(default=50, ge=1, le=500)) -> list[MaintenanceRecordResponse]:
        """
        The retention audit trail.

        Exposed because an analyst who cannot find an event needs to distinguish
        "never collected" from "pruned at 03:00", and those lead to different next
        steps.
        """
        return event_store.read_maintenance_records(limit=limit)

    @app.get("/api/telemetry/status", response_model=TelemetryStatusResponse)
    def telemetry_status() -> TelemetryStatusResponse:
        """
        What each supported telemetry source is *observed* to be doing.

        Derived from the newest stored event of each source's canonical event
        types, not from a build-time list: a source is `live` if something
        arrived within `stale_after_seconds`, `stale` if it once reported and has
        gone quiet, and `not_collected` if no event of its type was ever stored.

        The distinction matters operationally. A deployment that never wired a
        collector and a deployment whose collector died look identical in a
        static list, and the static list reads as an all-clear for both.
        `detail` still carries the capability description, so an operator can see
        that a `not_collected` source is supported but unwired rather than
        missing from the build.
        """
        now = time.time()
        latest_by_type = event_store.latest_event_timestamp_by_type()
        sources = {}
        for key, source in TELEMETRY_SOURCES.items():
            seen = [
                latest_by_type[event_type]
                for event_type in source["event_types"]
                if event_type in latest_by_type
            ]
            newest = max(seen) if seen else None
            if newest is None:
                status_value = TELEMETRY_NOT_COLLECTED
            elif now - newest > stale_after_seconds:
                status_value = TELEMETRY_STALE
            else:
                status_value = TELEMETRY_LIVE
            sources[key] = TelemetrySource(
                status=status_value,
                detail=source["detail"],
                last_event_timestamp=newest,
            )
        return TelemetryStatusResponse(sources=sources)

    @app.get("/api/status", response_model=StatusResponse)
    def status() -> StatusResponse:
        # Counts come from a SQL aggregate rather than from reading every
        # finding: the summary needs two numbers, and materialising the whole
        # table (evidence JSON and all) to produce them made this endpoint --
        # which the dashboard polls -- cost more the longer the system ran.
        severity_counts = event_store.count_findings_by_severity()
        baseline = event_store.read_latest_ready_baseline()
        event_count = event_store.count_events()
        last_event_timestamp = event_store.latest_event_timestamp()
        collector = event_store.read_collector_health() or {}
        stale_data = (
            last_event_timestamp is None
            or time.time() - last_event_timestamp > stale_after_seconds
        )
        return StatusResponse(
            status="ok",
            read_only=True,
            total_events=event_count,
            total_detections=sum(severity_counts.values()),
            severity_counts=severity_counts,
            baseline_status="ready" if baseline else "insufficient_normal_data",
            telemetry=telemetry_status().sources,
            collector_status=collector.get("status", "unknown"),
            collector_detail=collector.get("detail") or "No supervised collector health has been recorded.",
            event_count=event_count,
            last_event_timestamp=last_event_timestamp,
            stale_data=stale_data,
            dropped_event_count=collector.get("dropped_event_count"),
            collector_error=collector.get("error"),
            collector_throughput=float(collector.get("throughput") or 0.0),
            collector_processed_count=int(collector.get("processed_count") or 0),
            collector_malformed_count=int(collector.get("malformed_count") or 0),
            collector_updated_at=collector.get("updated_at"),
            collector_queue_depth=collector.get("queue_depth"),
            collector_queue_capacity=collector.get("queue_capacity"),
            collector_queue_high_water_mark=collector.get("queue_high_water_mark"),
            collector_backpressure_wait_count=collector.get("backpressure_wait_count"),
            collector_backpressure_wait_seconds=collector.get("backpressure_wait_seconds"),
            first_drop_timestamp=collector.get("first_drop_timestamp"),
            last_drop_timestamp=collector.get("last_drop_timestamp"),
            kernel_lost_event_count=collector.get("kernel_lost_event_count"),
            first_kernel_loss_timestamp=collector.get("first_kernel_loss_timestamp"),
            last_kernel_loss_timestamp=collector.get("last_kernel_loss_timestamp"),
        )

    @app.get("/api/events", response_model=list[EventResponse])
    def events(
        limit: int = Query(default=100, ge=1, le=500),
        event_type: str | None = Query(default=None, min_length=1, max_length=64),
    ) -> list[EventResponse]:
        return event_store.read_event_records(limit=limit, event_type=event_type)

    @app.get("/api/detections", response_model=list[FindingResponse])
    def detections(
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        # sort/order/disposition are Literals so an unknown value is a 422 at the
        # boundary and documents the allowlist; the store re-checks sort/order as
        # a backstop. The sort allowlist mirrors _FINDING_SORT_EXPRESSIONS.
        sort: Literal[
            "id", "window_start", "window_end", "risk_score", "severity", "entity_type"
        ] = "window_start",
        order: Literal["asc", "desc"] = "desc",
        severity: str | None = Query(default=None, min_length=1, max_length=32),
        entity_type: str | None = Query(default=None, min_length=1, max_length=64),
        disposition: Literal["true-positive", "false-positive", "benign", "none"] | None = None,
        acknowledged: bool | None = None,
        suppressed: bool | None = None,
        window_start: float | None = Query(default=None),
        window_end: float | None = Query(default=None),
    ) -> list[FindingResponse]:
        """
        A filtered, sorted, paginated page of findings, enriched with effective
        triage state.

        Filtering and sorting are server-side (`read_detection_findings_page`) so
        the dashboard never fetches the whole table to filter in the browser. The
        response body stays a JSON array of findings -- the historical shape -- and
        the page metadata rides in headers (`X-Total-Count`, `X-Limit`,
        `X-Offset`), which is non-breaking for existing consumers. `disposition`,
        `acknowledged`, and `suppressed` filter on the *effective* triage state
        computed from the append-only annotation layer, never a mutated finding.
        """
        findings, total = event_store.read_detection_findings_page(
            limit=limit,
            offset=offset,
            sort=sort,
            order=order,
            severity=severity,
            entity_type=entity_type,
            disposition=disposition,
            acknowledged=acknowledged,
            suppressed=suppressed,
            window_start=window_start,
            window_end=window_end,
        )
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Limit"] = str(limit)
        response.headers["X-Offset"] = str(offset)
        return findings

    @app.get("/api/detections/{finding_id}", response_model=FindingResponse)
    def detection(finding_id: int) -> FindingResponse:
        finding = event_store.read_detection_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="detection finding not found")
        # Enrich this one finding with its effective triage state so a single-row
        # read agrees with the paged list. Folded read-only from the annotation
        # layer; the immutable `suppressed` column above is left untouched, and
        # `triage_suppressed` is config OR the latest analyst suppress.
        state = event_store.read_latest_triage_state().get(finding_id, {})
        finding["triage_disposition"] = state.get("disposition")
        finding["triage_acknowledged"] = bool(state.get("acknowledged", False))
        finding["triage_suppressed"] = bool(finding.get("suppressed")) or bool(
            state.get("suppressed", False)
        )
        finding["triage_annotation_count"] = int(state.get("annotation_count", 0))
        return finding

    @app.get("/api/explanations/{finding_id}", response_model=ExplanationResponse)
    def explanation(finding_id: int) -> ExplanationResponse:
        record = event_store.read_explanation(finding_id)
        if record is None:
            raise HTTPException(status_code=404, detail="explanation not found")
        return record

    @app.get("/api/assistant/{finding_id}", response_model=AssistantStatusResponse)
    def assistant(finding_id: int) -> AssistantStatusResponse:
        if event_store.read_detection_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="detection finding not found")
        response = event_store.read_assistant_response(finding_id)
        if response is not None:
            return AssistantStatusResponse(
                finding_id=finding_id,
                status="persisted",
                message="Evidence-grounded assistant response loaded from SQLite.",
                response=response,
            )
        return AssistantStatusResponse(
            finding_id=finding_id,
            status="not_persisted",
            message="No assistant response is persisted for this finding; the dashboard does not generate one.",
        )

    @app.get("/api/policies", response_model=list[PolicyResponse])
    def policies() -> list[PolicyResponse]:
        return _read_policies()

    @app.get("/api/policy-decisions", response_model=list[PolicyDecisionResponse])
    def policy_decisions(
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        finding_id: int | None = Query(default=None, ge=1),
    ) -> list[PolicyDecisionResponse]:
        """
        A page of policy decisions in chain order, newest-last.

        Bounded because it used to return the whole `policy_decisions` table in
        one response. Decisions accumulate once per acted-on finding and are
        never pruned -- retention deliberately exempts the hash-chained tables --
        so the unbounded read grew without limit and made response size a
        function of uptime. That is a denial-of-service lever against the API
        process, not a feature.

        Paging follows the `/api/detections` contract exactly: the body stays a
        JSON array, so existing consumers keep parsing it unchanged, and the page
        metadata rides in `X-Total-Count` / `X-Limit` / `X-Offset`. Order is
        unchanged (`timestamp ASC`), so a page is a window onto the same sequence
        callers already saw rather than a re-sorted one.

        `finding_id` narrows to one finding's decision. It exists because the
        dashboard's detail pane wanted exactly that and previously got it by
        fetching the entire table and scanning client-side -- which a `limit`
        alone would have broken, since the oldest 100 decisions are the ones
        least likely to contain a recently-viewed finding.
        """
        decisions, total = event_store.read_policy_decisions_page(
            limit=limit,
            offset=offset,
            finding_id=finding_id,
        )
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Limit"] = str(limit)
        response.headers["X-Offset"] = str(offset)
        return decisions

    # --------------------------------------------------------------------- #
    # Triage write-back (Phase D). Append-only, authenticated by the same
    # middleware that gates every /api/ path (default-deny: no token, no write),
    # POST-only (no PUT/DELETE/PATCH -- nothing edits or destroys), and never a
    # mutation of the finding row or the evidence chain. Each write records a new
    # event; a correction is a later event. A missing finding is a 404 before any
    # write, so the annotation layer never references a finding that does not
    # exist. Suppress/unsuppress are alerting annotations only -- they never drop a
    # finding from any read or from the export.
    # --------------------------------------------------------------------- #

    def _require_finding(finding_id: int) -> None:
        if event_store.read_detection_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="detection finding not found")

    @app.post(
        "/api/triage/{finding_id}/acknowledge", response_model=TriageAnnotationResponse
    )
    def triage_acknowledge(
        finding_id: int, body: TriageAcknowledgeRequest
    ) -> TriageAnnotationResponse:
        _require_finding(finding_id)
        return event_store.write_triage_annotation(
            finding_id, "acknowledge", note=body.note, actor=body.actor
        )

    @app.post(
        "/api/triage/{finding_id}/annotate", response_model=TriageAnnotationResponse
    )
    def triage_annotate(
        finding_id: int, body: TriageAnnotateRequest
    ) -> TriageAnnotationResponse:
        _require_finding(finding_id)
        return event_store.write_triage_annotation(
            finding_id, "annotate", note=body.note, actor=body.actor
        )

    @app.post(
        "/api/triage/{finding_id}/disposition", response_model=TriageAnnotationResponse
    )
    def triage_disposition(
        finding_id: int, body: TriageDispositionRequest
    ) -> TriageAnnotationResponse:
        _require_finding(finding_id)
        return event_store.write_triage_annotation(
            finding_id,
            "disposition",
            disposition=body.disposition,
            note=body.note,
            actor=body.actor,
        )

    @app.post(
        "/api/triage/{finding_id}/suppress", response_model=TriageAnnotationResponse
    )
    def triage_suppress(
        finding_id: int, body: TriageSuppressRequest
    ) -> TriageAnnotationResponse:
        _require_finding(finding_id)
        # The reason is the annotation's note: suppression must carry a
        # justification into the record, never omit the finding from it.
        return event_store.write_triage_annotation(
            finding_id, "suppress", note=body.reason, actor=body.actor
        )

    @app.post(
        "/api/triage/{finding_id}/unsuppress", response_model=TriageAnnotationResponse
    )
    def triage_unsuppress(
        finding_id: int, body: TriageSuppressRequest
    ) -> TriageAnnotationResponse:
        _require_finding(finding_id)
        return event_store.write_triage_annotation(
            finding_id, "unsuppress", note=body.reason, actor=body.actor
        )

    def _triage_state_for(finding: dict[str, Any], state: dict[str, Any]) -> TriageStateResponse:
        config_suppressed = bool(finding.get("suppressed"))
        return TriageStateResponse(
            finding_id=int(finding["id"]),
            disposition=state.get("disposition"),
            acknowledged=bool(state.get("acknowledged", False)),
            config_suppressed=config_suppressed,
            effective_suppressed=config_suppressed or bool(state.get("suppressed", False)),
            annotation_count=int(state.get("annotation_count", 0)),
        )

    @app.get("/api/triage/export")
    def triage_export(
        limit: int = Query(default=MAX_TRIAGE_EXPORT_LIMIT, ge=1, le=MAX_TRIAGE_EXPORT_LIMIT),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        """
        A faithful export of the evidence record and its triage trail.

        Every finding in the requested range is included -- suppressed ones too,
        marked as such under `triage.effective_suppressed`. Suppression is a
        presentation/alerting annotation; it never removes a finding from this
        document. The three chain verdicts are embedded so a downstream consumer
        can confirm the export was taken from an intact record. Annotations are
        grouped in one pass to avoid a per-finding query.

        Why this is paged at all
        ------------------------
        It used to read the entire `detection_findings` table into one response.
        Retention deliberately exempts the hash-chained tables, so findings are
        never pruned and that response grew with uptime without bound -- a
        denial-of-service lever against the API process. `limit` therefore caps a
        single response at `MAX_TRIAGE_EXPORT_LIMIT`, and `offset` walks the rest
        in chain order. The cap equals the annotation cap that already bounded
        this same document, so a deployment holding fewer findings than that
        exports byte-identical content apart from the new metadata keys below.

        It is not possible to both bound this endpoint and keep returning an
        unbounded document, so what is preserved is the invariant that matters:
        nothing is ever *silently* omitted. `findings_total` is a SQL count over
        the whole table, and `findings_truncated` says whether more remains past
        this page -- the same contract `annotations_truncated` already provided
        for annotation history, which is why a consumer assembling a complete
        archive can do so by following `offset` until it clears.

        The annotation read is unchanged and remains global and oldest-first
        rather than scoped to this page, so on a record with more than
        `annotation_limit` annotations a late page may show findings whose
        annotations were crowded out by earlier findings'. Each finding's
        `triage.annotation_count` is computed over the whole table and stays
        authoritative, so a consumer can always tell which findings lost history.

        Declared before `/api/triage/{finding_id}` so the static path wins the
        route match; otherwise "export" would be parsed as a finding id.

        Deliberately has no `response_model`, unlike every other read route. The
        contract here is "every stored column of a finding, faithfully", written
        with a `**finding` splat; a `StrictModel` forbids extras, so the next
        migration that adds a column would turn this endpoint into a 500 instead
        of exporting the new field. Fidelity to the record wins over a documented
        schema on this one route.
        """
        findings_total = event_store.count_detection_findings()
        findings = event_store.read_detection_findings(limit=limit, offset=offset)
        findings_truncated = (offset + len(findings)) < findings_total
        states = event_store.read_latest_triage_state()
        all_annotations = event_store.read_triage_annotations(
            limit=MAX_TRIAGE_ANNOTATION_LIMIT
        )
        annotations_truncated = len(all_annotations) >= MAX_TRIAGE_ANNOTATION_LIMIT
        by_finding: dict[int, list[dict[str, Any]]] = {}
        for annotation in all_annotations:
            by_finding.setdefault(int(annotation["finding_id"]), []).append(annotation)
        exported = []
        for finding in findings:
            fid = int(finding["id"])
            state = states.get(fid, {})
            config_suppressed = bool(finding.get("suppressed"))
            exported.append(
                {
                    **finding,
                    "triage": {
                        "effective_disposition": state.get("disposition"),
                        "acknowledged": bool(state.get("acknowledged", False)),
                        "config_suppressed": config_suppressed,
                        "effective_suppressed": config_suppressed
                        or bool(state.get("suppressed", False)),
                        "annotation_count": int(state.get("annotation_count", 0)),
                        "annotations": by_finding.get(fid, []),
                    },
                }
            )
        return {
            "schema": "linux-xai-security/triage-export/v1",
            "generated_at": time.time(),
            "chain_integrity": {
                "findings": event_store.verify_findings_chain(),
                "policy": event_store.verify_policy_chain(),
                "triage": event_store.verify_triage_chain(),
            },
            "note": (
                "Faithful evidence record. Suppressed findings are "
                "included and marked (triage.effective_suppressed); suppression is "
                "a presentation annotation only and never removes a finding from "
                "the record or this export. 'actor' is a self-reported claim."
                + (
                    " FINDINGS ARE PAGED: this document carries "
                    f"{len(exported)} of {findings_total} findings starting at "
                    f"offset {offset}. Request the next page with "
                    f"?offset={offset + len(exported)} and repeat until "
                    "findings_truncated is false to assemble the complete record."
                    if findings_truncated
                    else ""
                )
                + (
                    " ANNOTATION HISTORY IS TRUNCATED: the oldest "
                    f"{MAX_TRIAGE_ANNOTATION_LIMIT} annotations are included and "
                    "newer ones are omitted. Compare triage.annotation_count, "
                    "which is authoritative, against the annotations listed."
                    if annotations_truncated
                    else ""
                )
            ),
            "findings_total": findings_total,
            "findings_returned": len(exported),
            "findings_offset": offset,
            "findings_limit": limit,
            "findings_truncated": findings_truncated,
            "annotations_truncated": annotations_truncated,
            "annotation_limit": MAX_TRIAGE_ANNOTATION_LIMIT,
            "findings": exported,
        }

    @app.get("/api/triage/{finding_id}", response_model=TriageHistoryResponse)
    def triage_history(finding_id: int) -> TriageHistoryResponse:
        finding = event_store.read_detection_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="detection finding not found")
        annotations = event_store.read_triage_annotations(finding_id=finding_id)
        state = event_store.read_latest_triage_state().get(finding_id, {})
        return TriageHistoryResponse(
            finding_id=finding_id,
            state=_triage_state_for(finding, state),
            annotations=annotations,
        )

    @app.get("/api/integrity", response_model=IntegrityResponse)
    def integrity() -> IntegrityResponse:
        """
        The tamper-evidence verdict for all four append-only chains, plus the active
        model's training-data verification.

        Recomputes each chain from on-disk columns and reports `{ok, checked,
        break_seq, reason}` per chain plus an overall `ok`. A false anywhere means
        a row was mutated, reordered, deleted, or inserted -- the dashboard raises
        an unmissable banner on that. This mutates nothing.

        The fifth term is a verification, not a chain: it recomputes each training
        window's own `immutable_hash` and names the rows that fail. It is folded into
        the same overall `ok` because a chain proving which decisions were made says
        nothing about whether the data they were made on still matches its digest.
        """
        findings = event_store.verify_findings_chain()
        policy = event_store.verify_policy_chain()
        triage = event_store.verify_triage_chain()
        ml_lifecycle = event_store.verify_ml_lifecycle_chain()
        # `read_ml_models` reports a window *count*, not the ids, so the active
        # model's row is re-read for its provenance list. Both reads are cheap;
        # `ml_models` holds one row per trained model, not per window.
        active = next((record for record in event_store.read_ml_models() if record["active"]), None)
        provenance = event_store.read_ml_model(active["id"]) if active else None
        training_windows = event_store.verify_ml_training_windows(
            window_ids=list(provenance["training_window_ids"]) if provenance else []
        )
        return IntegrityResponse(
            findings=ChainVerdictResponse(**findings),
            policy=ChainVerdictResponse(**policy),
            triage=ChainVerdictResponse(**triage),
            ml_lifecycle=ChainVerdictResponse(**ml_lifecycle),
            active_model_training_windows=TrainingWindowVerificationResponse(**training_windows),
            ok=bool(
                findings["ok"]
                and policy["ok"]
                and triage["ok"]
                and ml_lifecycle["ok"]
                and training_windows["ok"]
            ),
        )

    @app.get("/api/models", response_model=list[ModelSummaryResponse])
    def models() -> list[ModelSummaryResponse]:
        """
        Enumerate recorded ML models with their latest lifecycle state and drift status.

        Read-only: reads the `ml_models` table, then attaches the latest recorded
        lifecycle state and the newest drift status from the append-only logs. It
        recomputes no gate and writes nothing. On a default install this is `[]` --
        the honest and expected answer, since detection runs deterministically until
        a model passes the activation gate.
        """
        summaries: list[ModelSummaryResponse] = []
        for record in event_store.read_ml_models():
            latest = current_state(event_store, record["id"])
            drift = event_store.read_ml_drift_assessments(record["id"], limit=1)
            summaries.append(
                ModelSummaryResponse(
                    id=record["id"],
                    version=record["version"],
                    algorithm=record["algorithm"],
                    active=record["active"],
                    schema_version=record["schema_version"],
                    schema_hash=record["schema_hash"],
                    created_at=record["created_at"],
                    training_window_count=record["training_window_count"],
                    state=latest["to_state"] if latest else None,
                    activation_eligible=bool(latest["activation_eligible"]) if latest else False,
                    latest_drift_status=drift[0]["status"] if drift else None,
                )
            )
        return summaries

    @app.get("/api/models/{model_id}", response_model=ModelDetailResponse)
    def model_detail(model_id: str) -> ModelDetailResponse:
        """
        One model's provenance, lifecycle history, gate verdict, and latest drift.

        Backed by `ml/lifecycle.py:lifecycle_report` (history, chain verdict,
        training-window verification, and the recorded gate acceptance) and
        `ml/drift.py:drift_summary`. The activation gate
        is not re-run: `activation_eligible` and each transition's `acceptance` block
        are surfaced verbatim from the recorded rows. `artifact_path` is deliberately
        not exposed -- the checksum identifies the model without leaking host layout.
        """
        provenance = event_store.read_ml_model(model_id)
        if provenance is None:
            raise HTTPException(status_code=404, detail="ML model not found")
        report = lifecycle_report(event_store, model_id)
        transitions = [
            ModelLifecycleTransitionResponse(
                model_id=row["model_id"],
                from_state=row["from_state"],
                to_state=row["to_state"],
                reason=row["reason"],
                evidence=row["evidence"],
                activation_eligible=row["activation_eligible"],
                actor=row["actor"],
                created_at=row["created_at"],
                chain_seq=row["chain_seq"],
                chain_prev_hash=row["chain_prev_hash"],
                chain_hash=row["chain_hash"],
            )
            for row in report["transitions"]
        ]
        drift_rows = report["drift_assessments"]
        latest_drift = DriftSummaryResponse(**drift_summary(drift_rows[0])) if drift_rows else None
        return ModelDetailResponse(
            id=provenance["id"],
            version=provenance["version"],
            algorithm=provenance["algorithm"],
            active=provenance["active"],
            schema_version=provenance["schema_version"],
            schema_hash=provenance["schema_hash"],
            created_at=provenance["created_at"],
            artifact_checksum=provenance["artifact_checksum"],
            training_window_count=len(provenance["training_window_ids"]),
            training_window_ids=list(provenance["training_window_ids"]),
            hyperparameters=provenance["hyperparameters"],
            state=report["state"],
            activation_eligible=report["activation_eligible"],
            transitions=transitions,
            latest_drift=latest_drift,
            drift_assessment_count=len(drift_rows),
            chain=ChainVerdictResponse(**report["chain"]),
            training_windows=TrainingWindowVerificationResponse(**report["training_windows"]),
        )

    @app.get("/api/efficacy/operational", response_model=OperationalEfficacyResponse)
    def efficacy_operational() -> OperationalEfficacyResponse:
        """
        Operational efficacy from analyst dispositions -- measurement, not a gate.

        Reports precision and a reviewed false-positive rate over findings an
        analyst dispositioned. It is deliberately distinct from the ML acceptance
        gate and the seeded evaluation, which measure a labelled corpus; population
        false-positive rate and recall are not measurable here and are reported
        there instead. Dispositions never move a gate threshold.
        """
        return OperationalEfficacyResponse(**operational_efficacy_from_store(event_store))

    return app


app = create_app()
