"""
Analyst triage workflow (Phase D) -- the append-only annotation layer.

The crux these tests defend: write-back must not compromise immutability. Triage
lives in a separate, append-only, hash-chained layer; it never edits a finding
row or the finding/policy chains, and "suppress" is an alerting/presentation
annotation that never removes a finding from a read or from the export. Every
write is authenticated and default-deny.

Store-level chaining is pinned in test_evidence_chain.py; these exercise the same
guarantees end-to-end through the HTTP surface, plus the effective-state fold,
the export's completeness, and the auth gate.
"""

from fastapi.testclient import TestClient

from api.app import create_app
from observability.config import Settings
from storage.sqlite_store import SQLiteEventStore

# A token long enough to satisfy MIN_TOKEN_LENGTH, for the default-deny checks.
TOKEN = "0123456789abcdef-a-long-enough-token"


def _finding(entity_key="nc", **overrides):
    finding = {
        "source_risk_id": 1,
        "window_start": 1000.0,
        "window_end": 1300.0,
        "entity_type": "command",
        "entity_key": entity_key,
        "risk_score": 0.7,
        "severity": "HIGH",
        "behavior_score": 0.7,
        "rule_score": 0.7,
        "context_score": 0.7,
        "evidence": [{"signal": "behavior_anomaly", "score": 0.7}],
        "explanation": f"finding for {entity_key}",
        "mode": "detection",
        "provenance_hash": f"ph-{entity_key}",
        "detector_version": "detector.v1",
    }
    finding.update(overrides)
    return finding


def _store_with_finding(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "events.db"))
    fid = store.write_detection_finding(_finding())
    return store, fid


def test_acknowledge_appends_a_chained_annotation(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))

    created = client.post(f"/api/triage/{fid}/acknowledge", json={"actor": "analyst-a"})
    assert created.status_code == 200
    body = created.json()
    assert body["finding_id"] == fid
    assert body["action"] == "acknowledge"
    assert body["actor"] == "analyst-a"
    # The triage layer is itself hash-chained: genesis link is seq 0, all-zero
    # prev hash, a 64-hex chain hash.
    assert body["chain_seq"] == 0
    assert body["chain_prev_hash"] == "0" * 64
    assert len(body["chain_hash"]) == 64

    history = client.get(f"/api/triage/{fid}").json()
    assert history["state"]["acknowledged"] is True
    assert history["state"]["annotation_count"] == 1
    assert [a["action"] for a in history["annotations"]] == ["acknowledge"]


def test_annotate_requires_a_note(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))
    # note is required and min_length=1 -- an empty body is a 422 at the boundary.
    assert client.post(f"/api/triage/{fid}/annotate", json={}).status_code == 422
    assert client.post(f"/api/triage/{fid}/annotate", json={"note": ""}).status_code == 422
    ok = client.post(f"/api/triage/{fid}/annotate", json={"note": "pivoted from web shell"})
    assert ok.status_code == 200
    assert ok.json()["note"] == "pivoted from web shell"


def test_unexpected_fields_are_rejected(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))
    # StrictModel(extra="forbid"): a stray field is a 422, not silently dropped.
    response = client.post(
        f"/api/triage/{fid}/acknowledge", json={"note": "ok", "escalate": True}
    )
    assert response.status_code == 422


def test_disposition_flows_into_effective_state_and_efficacy(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))

    posted = client.post(
        f"/api/triage/{fid}/disposition", json={"disposition": "true-positive"}
    )
    assert posted.status_code == 200
    assert posted.json()["disposition"] == "true-positive"

    # The read-only detection view surfaces the effective disposition without the
    # finding row ever being mutated.
    detection = client.get(f"/api/detections/{fid}").json()
    assert detection["triage_disposition"] == "true-positive"
    assert detection["triage_annotation_count"] == 1

    # Dispositions feed operational efficacy -- measurement only.
    efficacy = client.get("/api/efficacy/operational").json()
    assert efficacy["reviewed"] == 1
    assert efficacy["counts"]["true_positive"] == 1
    assert efficacy["precision"] == 1.0
    # The gate metrics stay None: dispositions cannot measure them.
    assert efficacy["population_false_positive_rate"] is None
    assert efficacy["recall"] is None


def test_disposition_correction_appends_and_latest_wins(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))

    client.post(f"/api/triage/{fid}/disposition", json={"disposition": "true-positive"})
    client.post(f"/api/triage/{fid}/disposition", json={"disposition": "false-positive"})

    history = client.get(f"/api/triage/{fid}").json()
    # Both dispositions remain in the immutable history; latest wins as state.
    assert [a["disposition"] for a in history["annotations"]] == [
        "true-positive",
        "false-positive",
    ]
    assert history["state"]["disposition"] == "false-positive"

    efficacy = client.get("/api/efficacy/operational").json()
    assert efficacy["reviewed"] == 1  # one finding reviewed, not two
    assert efficacy["counts"]["false_positive"] == 1
    assert efficacy["counts"]["true_positive"] == 0
    assert efficacy["precision"] == 0.0


def test_suppress_sets_effective_state_but_never_drops_the_finding(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))

    client.post(f"/api/triage/{fid}/suppress", json={"reason": "known internal scanner"})

    detection = client.get(f"/api/detections/{fid}").json()
    assert detection["triage_suppressed"] is True
    # The immutable config column is NOT flipped -- suppression is an annotation.
    assert detection["suppressed"] is False
    # Suppression never removes the finding from a read.
    listed = client.get("/api/detections").json()
    assert [f["id"] for f in listed] == [fid]

    # A suppressed finding is still discoverable via the effective filter, and the
    # untouched immutable state is shown truthfully in the history.
    state = client.get(f"/api/triage/{fid}").json()["state"]
    assert state["effective_suppressed"] is True
    assert state["config_suppressed"] is False

    # Unsuppress is a new append that lifts the effective state again.
    client.post(f"/api/triage/{fid}/unsuppress", json={"reason": "false alarm, re-enable"})
    assert client.get(f"/api/detections/{fid}").json()["triage_suppressed"] is False
    assert client.get(f"/api/triage/{fid}").json()["state"]["effective_suppressed"] is False


def test_suppressed_finding_is_included_and_marked_in_export(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))
    client.post(f"/api/triage/{fid}/suppress", json={"reason": "noisy but benign cron"})
    client.post(f"/api/triage/{fid}/disposition", json={"disposition": "benign"})

    export = client.get("/api/triage/export").json()
    assert export["schema"] == "linux-xai-security/triage-export/v1"
    # The suppressed finding is present, not dropped, and marked as suppressed.
    assert [f["id"] for f in export["findings"]] == [fid]
    triage = export["findings"][0]["triage"]
    assert triage["effective_suppressed"] is True
    assert triage["config_suppressed"] is False
    assert triage["effective_disposition"] == "benign"
    # The full append-only history rides along.
    assert [a["action"] for a in triage["annotations"]] == ["suppress", "disposition"]
    # The export embeds chain verdicts so a consumer can confirm it came from an
    # intact record.
    assert export["chain_integrity"]["findings"]["ok"] is True
    assert export["chain_integrity"]["triage"]["ok"] is True


def test_triage_write_to_a_missing_finding_is_404(tmp_path):
    store, _ = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))
    assert client.post("/api/triage/999/acknowledge", json={}).status_code == 404
    assert client.get("/api/triage/999").status_code == 404


def test_triage_writes_are_default_deny_and_open_for_a_valid_token(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    authed = TestClient(create_app(store, Settings(api_require_auth=True, api_tokens=TOKEN)))

    bodies = {
        "acknowledge": {},
        "annotate": {"note": "n"},
        "disposition": {"disposition": "true-positive"},
        "suppress": {"reason": "r"},
        "unsuppress": {"reason": "r"},
    }
    for action, body in bodies.items():
        url = f"/api/triage/{fid}/{action}"
        # No token: refused before the body is ever parsed.
        denied = authed.post(url, json=body)
        assert denied.status_code == 401, f"{url} was not default-denied"
        assert denied.headers["WWW-Authenticate"].startswith("Bearer")
        # Valid token: the gate opens and the append succeeds.
        allowed = authed.post(url, json=body, headers={"Authorization": f"Bearer {TOKEN}"})
        assert allowed.status_code == 200, f"{url} refused a valid token"


def test_triage_never_mutates_the_finding_or_the_evidence_chains(tmp_path):
    store, fid = _store_with_finding(tmp_path)
    client = TestClient(create_app(store))

    finding_hash_before = store.read_detection_finding(fid)["chain_hash"]

    client.post(f"/api/triage/{fid}/acknowledge", json={})
    client.post(f"/api/triage/{fid}/disposition", json={"disposition": "true-positive"})
    client.post(f"/api/triage/{fid}/suppress", json={"reason": "presentation only"})

    after = store.read_detection_finding(fid)
    # The finding row and its chain link are byte-for-byte unchanged.
    assert after["chain_hash"] == finding_hash_before
    assert after["suppressed"] is False
    # All three chains still verify: triage wrote only to its own log.
    assert store.verify_findings_chain()["ok"] is True
    assert store.verify_policy_chain()["ok"] is True
    assert store.verify_triage_chain()["ok"] is True
    assert store.verify_triage_chain()["checked"] == 3
