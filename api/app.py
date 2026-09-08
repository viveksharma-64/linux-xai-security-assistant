import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from api.auth import TokenAuthenticator, extract_token, unprotected_paths
from detection.operational_efficacy import operational_efficacy_from_store
from observability import alerts as alerting
from observability import metrics as metrics_module
from observability.config import Settings
from observability.config import settings as load_process_settings
from storage.sqlite_store import SQLiteEventStore


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "policy" / "default_policy.yaml"
TELEMETRY_SOURCES = {
    "tcp_network": {
        "status": "verified",
        "detail": "Live-verified BCC sock:inet_sock_set_state IPv4 TCP connect telemetry.",
    },
    "file_access": {
        "status": "verified",
        "detail": "Live-verified file-access telemetry; canonical file_open/file_write events are supported.",
    },
    "audit_auth": {
        "status": "verified",
        "detail": "Live-verified structured journald PAM authentication/session telemetry.",
    },
    "system_service": {
        "status": "verified",
        "detail": "Live-verified structured journald/systemd service lifecycle telemetry.",
    },
    "pipes_streams": {
        "status": "verified",
        "detail": "Live-verified BCC pipe/pipe2 IPC telemetry with validated file descriptors.",
    },
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictModel):
    status: str
    read_only: bool


class TelemetrySource(StrictModel):
    status: str
    detail: str


class TelemetryStatusResponse(StrictModel):
    sources: Dict[str, TelemetrySource]


class StatusResponse(StrictModel):
    status: str
    read_only: bool
    total_events: int
    total_detections: int
    severity_counts: Dict[str, int]
    baseline_status: str
    telemetry: Dict[str, TelemetrySource]
    collector_status: str
    collector_detail: str
    event_count: int
    last_event_timestamp: Optional[float] = None
    stale_data: bool
    dropped_event_count: Optional[int] = None
    collector_error: Optional[str] = None
    collector_throughput: float = 0.0
    collector_processed_count: int = 0
    collector_malformed_count: int = 0
    collector_updated_at: Optional[float] = None
    # Backpressure and event-loss detail. Optional because a database written
    # before these columns existed, or one no collector has ever reported into,
    # has nothing to say -- and "unknown" must not be rendered as zero loss.
    collector_queue_depth: Optional[int] = None
    collector_queue_capacity: Optional[int] = None
    collector_queue_high_water_mark: Optional[int] = None
    collector_backpressure_wait_count: Optional[int] = None
    collector_backpressure_wait_seconds: Optional[float] = None
    first_drop_timestamp: Optional[float] = None
    last_drop_timestamp: Optional[float] = None
    # Kernel-side loss, reported by the collector rather than observed by the
    # supervisor. Separate from dropped_event_count because a perf ring overrun
    # and a full ingestion queue are different failures with different fixes.
    kernel_lost_event_count: Optional[int] = None
    first_kernel_loss_timestamp: Optional[float] = None
    last_kernel_loss_timestamp: Optional[float] = None


class EventResponse(StrictModel):
    id: int
    event_type: str
    timestamp: float
    timestamp_ns: Optional[int] = None
    timestamp_monotonic: Optional[float] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    comm: Optional[str] = None
    executable: Optional[str] = None
    parent_comm: Optional[str] = None
    ancestry: List[Dict[str, Any]] = Field(default_factory=list)
    source: Optional[str] = None
    version: Optional[str] = None
    event_hash: Optional[str] = None
    # Which host, boot, and agent observed the event. Null for rows written
    # before identity existed, and for hosts with no readable machine-id -- the
    # dashboard must be able to say "unknown", not imply a single host.
    host_id: Optional[str] = None
    boot_id: Optional[str] = None
    agent_id: Optional[str] = None
    payload: Dict[str, Any]


class FindingResponse(StrictModel):
    id: int
    source_risk_id: Optional[int] = None
    window_start: float
    window_end: float
    entity_type: str
    entity_key: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str
    behavior_score: float = Field(ge=0.0, le=1.0)
    rule_score: float = Field(ge=0.0, le=1.0)
    context_score: float = Field(ge=0.0, le=1.0)
    evidence: List[Dict[str, Any]]
    explanation: str
    mode: str
    provenance_hash: Optional[str] = None
    detector_version: Optional[str] = None
    created_at: Optional[float] = None
    # Correlation/suppression disposition (migration 8). Suppression is a
    # disposition only -- it never alters a score; a suppressed finding is still
    # persisted, explained, and chained.
    correlation_id: Optional[str] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    # Append-only evidence-chain integrity (migration 8). Surfaced so an API
    # consumer can independently verify continuity; Optional so a pre-chain
    # legacy row still serializes rather than 500-ing the read API.
    chain_seq: Optional[int] = None
    chain_prev_hash: Optional[str] = None
    chain_hash: Optional[str] = None
    # Effective triage state (Phase D, migration 9), folded read-only from the
    # append-only annotation layer -- never a mutation of the finding row above.
    # Defaulted so the readers that do not enrich (single lookup falls back to a
    # targeted fold; `/api/status` counts do not need it) still serialize, and so
    # a pre-triage client sees benign defaults. `triage_suppressed` is the
    # *effective* suppression (config `suppressed` OR the latest analyst suppress
    # not since lifted); the immutable `suppressed` column is left truthful above.
    triage_disposition: Optional[str] = None
    triage_acknowledged: bool = False
    triage_suppressed: bool = False
    triage_annotation_count: int = 0


class ExplanationResponse(StrictModel):
    finding_id: int
    timestamp: float
    window: Dict[str, float]
    severity: str
    risk_score: float = Field(ge=0.0, le=1.0)
    summary: str
    contributing_factors: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    calculation: Dict[str, Any]
    data_sources: List[str]
    limitations: List[str]
    mode: str


class AssistantStatusResponse(StrictModel):
    finding_id: int
    status: str
    message: str
    response: Optional[Dict[str, Any]] = None


class PolicyResponse(StrictModel):
    policy_id: str
    priority: int
    match: Dict[str, Any]
    decision: str
    required_approval: bool
    proposed_action: str
    allowed_recommendation_keywords: List[str]


class PolicyDecisionResponse(StrictModel):
    id: int
    finding_id: Optional[int] = None
    policy_id: str
    decision: str
    reason: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str
    required_approval: bool
    proposed_action: str
    limitations: List[str]
    timestamp: float
    dry_run: bool
    advisory_rejection: Optional[str] = None
    # Append-only evidence-chain integrity (migration 8), Optional for the same
    # reason as FindingResponse: a pre-chain legacy row still serializes.
    chain_seq: Optional[int] = None
    chain_prev_hash: Optional[str] = None
    chain_hash: Optional[str] = None


class LivenessResponse(StrictModel):
    status: str
    collected_at: float


class ReadinessResponse(StrictModel):
    status: str
    # Every failing condition, not the first one. An operator restarting a service
    # because of stale data should also learn in the same response that the file
    # permissions are wrong, rather than after the restart fails to help.
    reasons: List[str]
    event_count: int
    data_age_seconds: Optional[float] = None
    degraded_sources: List[str]
    collected_at: float


class AlertResponse(StrictModel):
    name: str
    severity: str
    summary: str
    value: Optional[float] = None
    threshold: Optional[float] = None
    labels: Dict[str, str]


class AlertsResponse(StrictModel):
    firing: int
    critical: int
    warning: int
    alerts: List[AlertResponse]
    collected_at: float


class SourceStateResponse(StrictModel):
    name: str
    status: str
    detail: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    last_event_timestamp: Optional[float] = None
    processed_count: int
    restart_count: int
    consecutive_failures: int
    last_failure_at: Optional[float] = None
    next_restart_at: Optional[float] = None
    backoff_seconds: float
    crash_looping: bool
    quarantined_batch_count: int
    quarantined_event_count: int
    updated_at: Optional[float] = None


class MaintenanceRecordResponse(StrictModel):
    id: int
    action: str
    reason: str
    events_deleted: int
    rows_deleted: int
    cutoff_timestamp: Optional[float] = None
    oldest_retained_timestamp: Optional[float] = None
    db_bytes_before: Optional[int] = None
    db_bytes_after: Optional[int] = None
    duration_seconds: float
    detail: Optional[str] = None
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
    note: Optional[str] = Field(default=None, max_length=_MAX_NOTE)
    actor: Optional[str] = Field(default=None, max_length=_MAX_ACTOR)


class TriageAnnotateRequest(StrictModel):
    note: str = Field(min_length=1, max_length=_MAX_NOTE)
    actor: Optional[str] = Field(default=None, max_length=_MAX_ACTOR)


class TriageDispositionRequest(StrictModel):
    disposition: TriageDisposition
    note: Optional[str] = Field(default=None, max_length=_MAX_NOTE)
    actor: Optional[str] = Field(default=None, max_length=_MAX_ACTOR)


class TriageSuppressRequest(StrictModel):
    # A reason is required for suppress and unsuppress: suppression is an
    # alerting/presentation decision the record must justify, never a silent
    # drop. Stored as the annotation's note.
    reason: str = Field(min_length=1, max_length=_MAX_NOTE)
    actor: Optional[str] = Field(default=None, max_length=_MAX_ACTOR)


class TriageAnnotationResponse(StrictModel):
    id: int
    finding_id: int
    action: str
    disposition: Optional[str] = None
    note: Optional[str] = None
    actor: Optional[str] = None
    created_at: float
    # The triage layer is itself hash-chained (migration 9), so a recorded
    # disposition is as tamper-evident as the finding it annotates.
    chain_seq: Optional[int] = None
    chain_prev_hash: Optional[str] = None
    chain_hash: Optional[str] = None


class TriageStateResponse(StrictModel):
    finding_id: int
    disposition: Optional[str] = None
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
    annotations: List[TriageAnnotationResponse]


class ChainVerdictResponse(StrictModel):
    ok: bool
    checked: int
    break_seq: Optional[int] = None
    reason: Optional[str] = None


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
    # A single overall verdict for the dashboard's banner: false if any chain is
    # broken. The per-chain detail carries the break location and reason.
    ok: bool


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
    precision: Optional[float] = None
    reviewed_false_positive_rate: Optional[float] = None
    population_false_positive_rate: Optional[float] = None
    recall: Optional[float] = None
    note: str


def _read_policies() -> List[Dict[str, Any]]:
    try:
        with DEFAULT_POLICY_PATH.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise HTTPException(status_code=503, detail=f"policy configuration unavailable: {type(error).__name__}") from error
    if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(document.get("policies"), list):
        raise HTTPException(status_code=503, detail="policy configuration is invalid")
    return document["policies"]


def create_app(
    store: Optional[SQLiteEventStore] = None,
    config: Optional[Settings] = None,
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
        Gate every telemetry-bearing path on a valid token.

        Implemented as middleware rather than a per-route dependency so that a
        route added later is protected by default. Forgetting a dependency on one
        new endpoint would silently expose it; there is nothing to forget here.

        The static dashboard is excluded because it is markup and JavaScript with
        no telemetry in it -- the data it renders comes from `/api/*`, which is
        gated. The browser supplies the token from there.
        """
        path = request.url.path
        authenticator: TokenAuthenticator = app.state.authenticator
        gated = path == "/metrics" or path.startswith("/api/")
        if not gated or path in open_paths:
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

    @app.get("/api/sources", response_model=List[SourceStateResponse])
    def sources() -> List[SourceStateResponse]:
        """Per-source supervision state: which collector is running, restarting, or given up on."""
        return event_store.read_source_states()

    @app.get("/api/maintenance", response_model=List[MaintenanceRecordResponse])
    def maintenance(limit: int = Query(default=50, ge=1, le=500)) -> List[MaintenanceRecordResponse]:
        """
        The retention audit trail.

        Exposed because an analyst who cannot find an event needs to distinguish
        "never collected" from "pruned at 03:00", and those lead to different next
        steps.
        """
        return event_store.read_maintenance_records(limit=limit)

    @app.get("/api/telemetry/status", response_model=TelemetryStatusResponse)
    def telemetry_status() -> TelemetryStatusResponse:
        sources = {
            "process_exec": TelemetrySource(status="verified", detail="Live-verified BCC/eBPF process execution and post-exec context telemetry."),
            "system_health": TelemetrySource(status="verified", detail="Real psutil system-health telemetry is verified."),
            **{key: TelemetrySource(**value) for key, value in TELEMETRY_SOURCES.items()},
        }
        return TelemetryStatusResponse(sources=sources)

    @app.get("/api/status", response_model=StatusResponse)
    def status() -> StatusResponse:
        findings = event_store.read_detection_findings()
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
            total_events=event_store.count_events(),
            total_detections=len(findings),
            severity_counts=dict(Counter(item["severity"] for item in findings)),
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

    @app.get("/api/events", response_model=List[EventResponse])
    def events(
        limit: int = Query(default=100, ge=1, le=500),
        event_type: Optional[str] = Query(default=None, min_length=1, max_length=64),
    ) -> List[EventResponse]:
        return event_store.read_event_records(limit=limit, event_type=event_type)

    @app.get("/api/detections", response_model=List[FindingResponse])
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
        severity: Optional[str] = Query(default=None, min_length=1, max_length=32),
        entity_type: Optional[str] = Query(default=None, min_length=1, max_length=64),
        disposition: Optional[
            Literal["true-positive", "false-positive", "benign", "none"]
        ] = None,
        acknowledged: Optional[bool] = None,
        suppressed: Optional[bool] = None,
        window_start: Optional[float] = Query(default=None),
        window_end: Optional[float] = Query(default=None),
    ) -> List[FindingResponse]:
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

    @app.get("/api/policies", response_model=List[PolicyResponse])
    def policies() -> List[PolicyResponse]:
        return _read_policies()

    @app.get("/api/policy-decisions", response_model=List[PolicyDecisionResponse])
    def policy_decisions() -> List[PolicyDecisionResponse]:
        return event_store.read_policy_decisions()

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

    def _triage_state_for(finding: Dict[str, Any], state: Dict[str, Any]) -> TriageStateResponse:
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
    def triage_export() -> Dict[str, Any]:
        """
        A faithful, complete export of the evidence record and its triage trail.

        Every finding is included -- suppressed ones too, marked as such under
        `triage.effective_suppressed`. Suppression is a presentation/alerting
        annotation; it never removes a finding from this document. The three chain
        verdicts are embedded so a downstream consumer can confirm the export was
        taken from an intact record. Annotations are grouped in one pass to avoid
        a per-finding query.

        Declared before `/api/triage/{finding_id}` so the static path wins the
        route match; otherwise "export" would be parsed as a finding id.
        """
        findings = event_store.read_detection_findings()
        states = event_store.read_latest_triage_state()
        all_annotations = event_store.read_triage_annotations(limit=5000)
        by_finding: Dict[int, List[Dict[str, Any]]] = {}
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
                "Faithful complete evidence record. Suppressed findings are "
                "included and marked (triage.effective_suppressed); suppression is "
                "a presentation annotation only and never removes a finding from "
                "the record or this export. 'actor' is a self-reported claim."
            ),
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
        The tamper-evidence verdict for all four append-only chains.

        Recomputes each chain from on-disk columns and reports `{ok, checked,
        break_seq, reason}` per chain plus an overall `ok`. A false anywhere means
        a row was mutated, reordered, deleted, or inserted -- the dashboard raises
        an unmissable banner on that. This mutates nothing.
        """
        findings = event_store.verify_findings_chain()
        policy = event_store.verify_policy_chain()
        triage = event_store.verify_triage_chain()
        ml_lifecycle = event_store.verify_ml_lifecycle_chain()
        return IntegrityResponse(
            findings=ChainVerdictResponse(**findings),
            policy=ChainVerdictResponse(**policy),
            triage=ChainVerdictResponse(**triage),
            ml_lifecycle=ChainVerdictResponse(**ml_lifecycle),
            ok=bool(findings["ok"] and policy["ok"] and triage["ok"] and ml_lifecycle["ok"]),
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
