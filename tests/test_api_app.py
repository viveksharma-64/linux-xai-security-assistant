from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from detection.detector import DetectionEngine
from assistant.service import AssistantService
from explainability.explainer import FindingExplainer
from pipeline.event_stream import Event
from policy.engine import PolicyEngine
from storage.sqlite_store import SQLiteEventStore


ROOT = Path(__file__).parents[1]
DEFAULT_POLICY = ROOT / "policy" / "default_policy.yaml"


def _setup(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    event = Event.from_raw_json({
        "event_type": "process_exec",
        "timestamp": 1000.0,
        "comm": "nc",
        "uid": 1000,
        "pid": 9,
    })
    store.write(event)
    risk = {
        "id": 1,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": "command",
        "entity_key": "nc",
        "anomaly_score": 0.7,
        "contributing_features": {
            "execution_frequency": 1,
            "unique_commands": 1,
            "unique_uids": 1,
            "command_frequency": {"nc": 1},
            "uid_activity": {"1000": 1},
            "burst_activity": {"active_seconds": 1, "peak_execs_per_second": 1},
            "entity_event_count": 1,
            "event_max_score": 0.7,
        },
        "explanation": "test-only simulated risk",
        "mode": "monitoring",
    }
    finding = DetectionEngine(store).detect([risk], [event])["findings"][0]
    explanation = FindingExplainer(store).explain_finding(finding)
    PolicyEngine.from_yaml(store, str(DEFAULT_POLICY)).evaluate(finding)
    AssistantService(None, store=store).generate(explanation)
    return store, explanation


def test_health_and_status_are_read_only(tmp_path):
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/api/health").json() == {"status": "ok", "read_only": True}
    status = client.get("/api/status")
    assert status.status_code == 200
    assert status.json()["total_events"] == 1
    assert status.json()["event_count"] == 1
    assert status.json()["collector_status"] == "unknown"
    assert status.json()["dropped_event_count"] is None
    assert status.json()["stale_data"] is True
    assert status.json()["read_only"] is True


def test_event_detection_explanation_and_policy_retrieval(tmp_path):
    store, explanation = _setup(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/api/events").json()[0]["event_type"] == "process_exec"
    detection = client.get("/api/detections").json()[0]
    assert detection["id"] == 1
    # The read-only evidence API surfaces the D4 disposition and the D5
    # append-only chain (migration 8), not just the score. Genesis link:
    # seq 0, all-zero prev hash, a 64-hex chain hash; suppression defaults off.
    assert detection["suppressed"] is False
    assert detection["correlation_id"]
    assert detection["chain_seq"] == 0
    assert detection["chain_prev_hash"] == "0" * 64
    assert len(detection["chain_hash"]) == 64
    assert client.get("/api/detections/1").json()["risk_score"] == 0.5775
    assert client.get("/api/explanations/1").json()["finding_id"] == explanation["finding_id"]
    assistant = client.get("/api/assistant/1").json()
    assert assistant["status"] == "persisted"
    assert assistant["response"]["finding_id"] == 1
    assert client.get("/api/policies").json()
    decision = client.get("/api/policy-decisions").json()[0]
    assert decision["finding_id"] == 1
    assert len(decision["chain_hash"]) == 64  # policy chain is surfaced too


def test_telemetry_status_reports_all_live_verified_sources(tmp_path):
    store, _ = _setup(tmp_path)
    response = TestClient(create_app(store)).get("/api/telemetry/status")
    sources = response.json()["sources"]
    assert sources["process_exec"]["status"] == "verified"
    assert sources["tcp_network"]["status"] == "verified"
    assert sources["file_access"]["status"] == "verified"
    assert sources["audit_auth"]["status"] == "verified"
    assert sources["system_service"]["status"] == "verified"
    assert sources["pipes_streams"]["status"] == "verified"


def test_missing_and_malformed_ids_are_safe_errors(tmp_path):
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/api/detections/999").status_code == 404
    assert client.get("/api/explanations/999").status_code == 404
    assert client.get("/api/assistant/999").status_code == 404
    assert client.get("/api/detections/not-an-id").status_code == 422
    assert client.get("/api/events?limit=0").status_code == 422


def test_dashboard_is_served_without_mutation_routes(tmp_path):
    store, _ = _setup(tmp_path)
    app = create_app(store)
    client = TestClient(app)
    dashboard = client.get("/dashboard/")
    assert dashboard.status_code == 200
    assert "READ-ONLY VIEW" in dashboard.text
    assert all(
        method in {"GET", "HEAD"}
        for route in app.routes
        for method in getattr(route, "methods", {"GET"})
    )
    assert client.post("/api/health").status_code == 405
