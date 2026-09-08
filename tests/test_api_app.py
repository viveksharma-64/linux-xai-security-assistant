from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from detection.detector import DetectionEngine
from assistant.service import AssistantService
from explainability.explainer import FindingExplainer
from observability.config import Settings
from pipeline.event_stream import Event
from policy.engine import PolicyEngine
from storage.sqlite_store import SQLiteEventStore


ROOT = Path(__file__).parents[1]
DEFAULT_POLICY = ROOT / "policy" / "default_policy.yaml"

# A token long enough to pass MIN_TOKEN_LENGTH, for the default-deny assertions.
TOKEN = "0123456789abcdef-a-long-enough-token"


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

    # Phase D adds analyst write-back, so "every route is GET/HEAD" can no longer
    # be literally true -- but the invariant is tightened, not relaxed. The
    # evidence surface stays read-only: every route is GET/HEAD except triage
    # writes, and those are POST-only (no PUT/DELETE/PATCH -- nothing edits or
    # destroys), live under the /api/triage/ prefix, and are exactly the five
    # append-only triage actions and no more.
    triage_writes = {
        "/api/triage/{finding_id}/acknowledge",
        "/api/triage/{finding_id}/annotate",
        "/api/triage/{finding_id}/disposition",
        "/api/triage/{finding_id}/suppress",
        "/api/triage/{finding_id}/unsuppress",
    }
    found_writes = set()
    for route in app.routes:
        methods = set(getattr(route, "methods", {"GET"}) or {"GET"})
        path = getattr(route, "path", "")
        non_read = methods - {"GET", "HEAD"}
        if not non_read:
            continue
        assert path.startswith("/api/triage/"), f"unexpected non-GET route {path}"
        assert non_read == {"POST"}, f"{path} exposes {non_read}, expected POST only"
        assert path in triage_writes, f"unexpected triage write {path}"
        found_writes.add(path)
    assert found_writes == triage_writes  # all five present, and nothing else is a write

    # Health stays GET-only.
    assert client.post("/api/health").status_code == 405

    # Default-deny: each triage write is refused without a token (401), checked
    # against an auth-required app. Auth is enforced in middleware before body
    # parsing, so no unauthenticated write ever reaches the store.
    authed = TestClient(create_app(store, Settings(api_require_auth=True, api_tokens=TOKEN)))
    for path in triage_writes:
        url = path.replace("{finding_id}", "1")
        response = authed.post(url, json={})
        assert response.status_code == 401, f"{url} was not default-denied"
        assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_detections_carry_effective_triage_state_defaults(tmp_path):
    # Before any analyst action, a finding reads as untriaged -- not as suppressed
    # or dispositioned. The immutable `suppressed` column and the effective
    # `triage_suppressed` agree at the benign default.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    finding = client.get("/api/detections").json()[0]
    assert finding["triage_disposition"] is None
    assert finding["triage_acknowledged"] is False
    assert finding["triage_suppressed"] is False
    assert finding["triage_annotation_count"] == 0
    # The single-row read agrees with the list.
    one = client.get("/api/detections/1").json()
    assert one["triage_disposition"] is None
    assert one["triage_annotation_count"] == 0


def test_detections_pagination_metadata_rides_in_headers(tmp_path):
    # The response body stays a JSON array (historical shape); paging metadata is
    # in headers so existing consumers are unaffected.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    page = client.get("/api/detections?limit=1&offset=0")
    assert page.status_code == 200
    assert isinstance(page.json(), list) and len(page.json()) == 1
    assert page.headers["X-Total-Count"] == "1"
    assert page.headers["X-Limit"] == "1"
    assert page.headers["X-Offset"] == "0"
    # Past the end: empty page, but the total still reports the whole match set.
    beyond = client.get("/api/detections?limit=1&offset=1")
    assert beyond.json() == []
    assert beyond.headers["X-Total-Count"] == "1"


def test_detections_server_side_filter_and_sort(tmp_path):
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    # A filter that matches nothing returns an empty array and a zero total,
    # computed server-side (not fetch-all-then-filter-in-JS).
    miss = client.get("/api/detections?entity_type=does-not-exist")
    assert miss.json() == []
    assert miss.headers["X-Total-Count"] == "0"
    # A disposition filter targets the effective triage state; nothing is
    # dispositioned yet, so `none` matches and a real disposition does not.
    assert client.get("/api/detections?disposition=none").headers["X-Total-Count"] == "1"
    assert client.get("/api/detections?disposition=true-positive").headers["X-Total-Count"] == "0"
    # Sorting is accepted from the allowlist.
    assert client.get("/api/detections?sort=risk_score&order=asc").status_code == 200


def test_detections_reject_invalid_query_params_with_422(tmp_path):
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/api/detections?limit=0").status_code == 422  # ge=1
    assert client.get("/api/detections?limit=501").status_code == 422  # le=500
    assert client.get("/api/detections?offset=-1").status_code == 422  # ge=0
    assert client.get("/api/detections?sort=evil").status_code == 422  # not in allowlist
    assert client.get("/api/detections?order=sideways").status_code == 422
    assert client.get("/api/detections?disposition=maybe").status_code == 422


def test_integrity_reports_all_three_chains_intact(tmp_path):
    # A freshly written record verifies: findings and policy chains have content,
    # the triage chain is empty (which is a valid append-only log), all ok.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    body = client.get("/api/integrity").json()
    assert body["ok"] is True
    assert body["findings"]["ok"] is True and body["findings"]["checked"] == 1
    assert body["policy"]["ok"] is True and body["policy"]["checked"] == 1
    assert body["triage"]["ok"] is True and body["triage"]["checked"] == 0
    assert body["findings"]["break_seq"] is None


def test_operational_efficacy_endpoint_is_honest_before_review(tmp_path):
    # With nothing reviewed, precision is None (not zero), and the population
    # metrics the ML gate owns are explicitly None here.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    body = client.get("/api/efficacy/operational").json()
    assert body["scope"] == "operational"
    assert body["total_findings"] == 1
    assert body["reviewed"] == 0
    assert body["unreviewed"] == 1
    assert body["precision"] is None
    assert body["reviewed_false_positive_rate"] is None
    assert body["population_false_positive_rate"] is None
    assert body["recall"] is None
