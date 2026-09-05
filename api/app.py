import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

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


def _read_policies() -> List[Dict[str, Any]]:
    try:
        with DEFAULT_POLICY_PATH.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise HTTPException(status_code=503, detail=f"policy configuration unavailable: {type(error).__name__}") from error
    if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(document.get("policies"), list):
        raise HTTPException(status_code=503, detail="policy configuration is invalid")
    return document["policies"]


def create_app(store: Optional[SQLiteEventStore] = None) -> FastAPI:
    database_path = os.getenv("SECURITY_DB_PATH", "phase2_events.db")
    stale_after_seconds = float(os.getenv("TELEMETRY_STALE_AFTER_SECONDS", "300"))
    if stale_after_seconds <= 0:
        stale_after_seconds = 300.0
    event_store = store or SQLiteEventStore(database_path)
    app = FastAPI(
        title="Linux XAI Security Assistant API",
        version="0.8.0",
        description="Read-only security telemetry, detection, explanation, assistant, and policy views.",
    )
    app.state.store = event_store
    app.mount("/dashboard", StaticFiles(directory=str(ROOT / "dashboard"), html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/")

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", read_only=True)

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
    def detections() -> List[FindingResponse]:
        return event_store.read_detection_findings()

    @app.get("/api/detections/{finding_id}", response_model=FindingResponse)
    def detection(finding_id: int) -> FindingResponse:
        finding = event_store.read_detection_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="detection finding not found")
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

    return app


app = create_app()
