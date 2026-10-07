import time
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from assistant.service import AssistantService
from detection.detector import DetectionEngine
from explainability.explainer import FindingExplainer
from ml.feature_schema import SCHEMA_VERSION, schema_hash
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


def test_status_counts_findings_by_aggregate_and_counts_events_once(tmp_path, monkeypatch):
    # The dashboard polls /api/status. It used to read every finding to produce
    # two numbers -- so the cost of the summary grew with the evidence record --
    # and it counted the events table twice per request for one field.
    store, _ = _setup(tmp_path)
    calls = {"count_events": 0}
    real_count_events = store.count_events

    def counted():
        calls["count_events"] += 1
        return real_count_events()

    def loud():
        raise AssertionError("/api/status read the whole findings table")

    monkeypatch.setattr(store, "count_events", counted)
    monkeypatch.setattr(store, "read_detection_findings", loud)

    body = TestClient(create_app(store)).get("/api/status").json()

    assert calls["count_events"] == 1
    assert body["total_events"] == body["event_count"] == 1
    # The breakdown still sums to the total -- severity is NOT NULL, so the
    # aggregate accounts for every finding.
    assert body["total_detections"] == 1
    assert sum(body["severity_counts"].values()) == body["total_detections"]


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


def _decision(finding_id=1, policy_id="p", timestamp=1000.0, **overrides):
    decision = {
        "finding_id": finding_id,
        "policy_id": policy_id,
        "decision": "advisory_only",
        "reason": "dry-run, approval required",
        "risk_score": 0.7,
        "severity": "HIGH",
        "required_approval": True,
        "proposed_action": "notify_operator",
        # A list, as PolicyEngine emits and PolicyDecisionResponse declares --
        # the store-level helper in test_evidence_chain.py uses a dict because it
        # never round-trips through the response model.
        "limitations": ["Dry-run mode: no action was taken."],
        "timestamp": timestamp,
        "dry_run": True,
        "advisory_rejection": None,
    }
    decision.update(overrides)
    return decision


def test_policy_decisions_are_paged_and_can_be_narrowed_to_one_finding(tmp_path):
    """
    `/api/policy-decisions` is bounded, and says how much it did not return.

    It used to `SELECT *` the whole table. Decisions accumulate once per acted-on
    finding and retention deliberately exempts the hash-chained tables, so that
    response grew with uptime without bound -- a denial-of-service lever against
    the API process rather than a feature.

    The paging contract is `/api/detections`': the body stays a JSON array so
    existing consumers parse it unchanged, and the page metadata rides in headers.
    Order is unchanged (`timestamp ASC`), so a page is a window onto the sequence
    callers already saw.
    """
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    for index in range(3):
        store.write_policy_decision(
            _decision(finding_id=1 + index // 2, policy_id=f"p{index}", timestamp=1000.0 + index)
        )
    client = TestClient(create_app(store))

    first = client.get("/api/policy-decisions?limit=2")
    assert [d["policy_id"] for d in first.json()] == ["p0", "p1"]
    assert first.headers["X-Total-Count"] == "3"
    assert first.headers["X-Limit"] == "2"
    assert first.headers["X-Offset"] == "0"

    second = client.get("/api/policy-decisions?limit=2&offset=2")
    assert [d["policy_id"] for d in second.json()] == ["p2"]
    assert second.headers["X-Total-Count"] == "3"
    assert second.headers["X-Offset"] == "2"

    # Unchanged for any deployment under one page: same array, same order.
    whole = client.get("/api/policy-decisions")
    assert [d["policy_id"] for d in whole.json()] == ["p0", "p1", "p2"]
    assert whole.headers["X-Total-Count"] == "3"
    assert whole.headers["X-Limit"] == "100"

    # `finding_id` narrows server-side. This exists because the dashboard detail
    # pane wanted one finding's decision and got it by fetching the entire table
    # and scanning client-side -- which a bare `limit` would have broken, since
    # the oldest 100 decisions are the ones least likely to hold a recently
    # viewed finding. The total reflects the filter, not the table.
    narrowed = client.get("/api/policy-decisions?finding_id=2")
    assert [d["policy_id"] for d in narrowed.json()] == ["p2"]
    assert [d["finding_id"] for d in narrowed.json()] == [2]
    assert narrowed.headers["X-Total-Count"] == "1"

    # The ceiling is a ceiling: asking past it is refused, not honoured.
    assert client.get("/api/policy-decisions?limit=501").status_code == 422
    store.close()


def test_telemetry_status_is_derived_from_stored_events_not_a_static_list(tmp_path):
    """
    A supported source that nothing collects must not read as healthy.

    The surface used to be a hardcoded literal that reported every source as
    "verified", which told an operator that file, auth, and service telemetry
    were fine on a deployment where no collector for them was even running.
    """
    store, _ = _setup(tmp_path)  # writes one process_exec event at t=1000.0
    store.write(Event.from_raw_json({
        "event_type": "file_open",
        "timestamp": time.time(),
        "comm": "cat",
        "uid": 0,
        "pid": 11,
        "payload": {"path": "/etc/passwd"},
    }))

    sources = TestClient(create_app(store)).get("/api/telemetry/status").json()["sources"]

    # Just arrived.
    assert sources["file_access"]["status"] == "live"
    # Recorded once, long ago: quiet, not absent -- and distinguishable from both.
    assert sources["process_exec"]["status"] == "stale"
    assert sources["process_exec"]["last_event_timestamp"] == 1000.0
    # Supported by the build, but nothing ever fed it.
    for key in ("tcp_network", "audit_auth", "system_service", "pipes_streams", "system_health"):
        assert sources[key]["status"] == "not_collected", key
        assert sources[key]["last_event_timestamp"] is None
    # The capability description survives, so "not_collected" reads as unwired
    # rather than unsupported.
    assert "journald" in sources["audit_auth"]["detail"]


def test_telemetry_status_honours_the_configured_staleness_window(tmp_path):
    store, _ = _setup(tmp_path)
    store.write(Event.from_raw_json({
        "event_type": "file_open",
        "timestamp": time.time() - 120.0,
        "comm": "cat",
        "uid": 0,
        "pid": 11,
        "payload": {"path": "/etc/passwd"},
    }))

    fresh = create_app(store, Settings(api_require_auth=False, stale_after_seconds=300.0))
    tight = create_app(store, Settings(api_require_auth=False, stale_after_seconds=60.0))

    assert TestClient(fresh).get("/api/telemetry/status").json()["sources"]["file_access"]["status"] == "live"
    assert TestClient(tight).get("/api/telemetry/status").json()["sources"]["file_access"]["status"] == "stale"


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


def test_integrity_reports_all_four_chains_intact(tmp_path):
    # A freshly written record verifies: findings and policy chains have content,
    # the triage and ML lifecycle chains are empty (which is a valid append-only
    # log, and the expected state where no model has been trained), all ok.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    body = client.get("/api/integrity").json()
    assert body["ok"] is True
    assert body["findings"]["ok"] is True and body["findings"]["checked"] == 1
    assert body["policy"]["ok"] is True and body["policy"]["checked"] == 1
    assert body["triage"]["ok"] is True and body["triage"]["checked"] == 0
    assert body["ml_lifecycle"]["ok"] is True and body["ml_lifecycle"]["checked"] == 0
    assert body["findings"]["break_seq"] is None


def _seed_model(store, model_id="model-1"):
    # Provenance row (migration 10). The artifact is never opened -- the transparency
    # surface reads recorded columns, not the file -- so a nonexistent path is fine and
    # deliberately never surfaced by the API. Mirrors tests/test_ml_drift.py:_model.
    #
    # No `active=` parameter: `write_ml_model` refuses an active row outright, so
    # one here could only ever be False. A test that needs an active model walks
    # it through the gate with `ml/lifecycle.py:record_activation`.
    store.write_ml_model({
        "id": model_id,
        "version": "1",
        "algorithm": "IsolationForest",
        "hyperparameters": {"n_estimators": 100, "random_state": 42},
        "artifact_path": "/nonexistent/model.model.json",
        "artifact_checksum": "a" * 64,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": schema_hash(),
        "training_window_ids": [1, 2, 3],
        "runtime": {"python": "3.11"},
        "evaluation": {},
        "active": False,
        "created_at": 2000.0,
    })
    return {
        "id": model_id,
        "artifact_checksum": "a" * 64,
        "artifact_format": "iforest-native.v1",
        "schema_hash": schema_hash(),
        "schema_version": SCHEMA_VERSION,
        "training_window_ids": [1, 2, 3],
        "hyperparameters": {"n_estimators": 100, "random_state": 42},
    }


def test_models_endpoint_is_empty_on_a_default_install(tmp_path):
    # No model has passed the gate, so detection runs deterministically and the
    # transparency surface honestly reports an empty list -- not an error.
    store, _ = _setup(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/api/models").json() == []
    assert client.get("/api/models/does-not-exist").status_code == 404


def test_models_endpoint_lists_and_details_an_eligible_model(tmp_path):
    from ml.lifecycle import record_activation_gate, record_evaluated, record_trained

    store, _ = _setup(tmp_path)
    metadata = _seed_model(store)
    record_trained(store, metadata)
    record_evaluated(store, "model-1", {
        "normal_window_count": 60,
        "normal_false_positive_count": 0,
        "normal_false_positive_rate": 0.0,
        "labels_available": False,
        "confusion_matrix": None,
    })
    # PASSING_COUNTS: 0 false positives over 60 holdout windows clears the gate.
    record_activation_gate(store, "model-1", false_positive_count=0, normal_window_count=60)

    client = TestClient(create_app(store))
    listing = client.get("/api/models").json()
    assert len(listing) == 1
    summary = listing[0]
    assert summary["id"] == "model-1"
    assert summary["state"] == "eligible"
    assert summary["activation_eligible"] is True
    assert summary["training_window_count"] == 3
    assert summary["latest_drift_status"] is None  # no drift assessment run
    # The list row carries provenance but never the artifact path.
    assert "artifact_path" not in summary

    detail = client.get("/api/models/model-1").json()
    assert detail["artifact_checksum"] == "a" * 64
    assert detail["training_window_count"] == 3
    assert detail["training_window_ids"] == [1, 2, 3]
    assert detail["state"] == "eligible"
    assert detail["activation_eligible"] is True
    # Full transition history, tamper-evident: trained -> evaluated -> eligible.
    assert [t["to_state"] for t in detail["transitions"]] == ["trained", "evaluated", "eligible"]
    assert detail["chain"]["ok"] is True
    assert detail["latest_drift"] is None
    assert detail["drift_assessment_count"] == 0
    # Hardening: the detail payload never leaks host filesystem layout.
    assert "artifact_path" not in detail
    # The recorded gate verdict rides in the eligible transition's evidence, verbatim.
    eligible = detail["transitions"][-1]
    assert eligible["evidence"]["acceptance"]["activation_eligible"] is True


def test_models_endpoint_surfaces_an_ineligible_gate_verdict_faithfully(tmp_path):
    from ml.lifecycle import record_activation_gate, record_evaluated, record_trained

    store, _ = _setup(tmp_path)
    metadata = _seed_model(store)
    record_trained(store, metadata)
    record_evaluated(store, "model-1", {
        "normal_window_count": 60,
        "normal_false_positive_count": 1,
        "normal_false_positive_rate": 1 / 60,
        "labels_available": False,
        "confusion_matrix": None,
    })
    # FAILING_COUNTS: 1 false positive over 60 windows -- the Wilson upper bound (7.13%)
    # exceeds the 5% ceiling, so the gate refuses. The refusal is recorded, not hidden.
    record_activation_gate(store, "model-1", false_positive_count=1, normal_window_count=60)

    client = TestClient(create_app(store))
    summary = client.get("/api/models").json()[0]
    assert summary["state"] == "ineligible"
    assert summary["activation_eligible"] is False
    detail = client.get("/api/models/model-1").json()
    assert detail["state"] == "ineligible"
    assert detail["activation_eligible"] is False
    assert detail["transitions"][-1]["to_state"] == "ineligible"
    assert detail["transitions"][-1]["evidence"]["acceptance"]["activation_eligible"] is False


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
