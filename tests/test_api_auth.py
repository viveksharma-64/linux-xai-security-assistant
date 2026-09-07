"""
Tests for the API authentication gate.

Carrying `@pytest.mark.api_auth` so conftest leaves authentication on: every other
test in the suite predates the gate and turns it off. These assert the four
properties the gate exists for -- fail closed when misconfigured, gate every
telemetry path by default, leave only liveness open, and accept a valid token
through either header -- plus the constant-time comparison the token check relies
on for its confidentiality claim.

The token comparison is unit-tested directly rather than through HTTP because the
property under test is that a wrong token costs the same number of digest
comparisons as a right one, which a request-level test cannot observe.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import AuthConfigurationError, TokenAuthenticator, extract_token
from observability.config import Settings
from storage.sqlite_store import SQLiteEventStore

pytestmark = pytest.mark.api_auth

TOKEN = "0123456789abcdef-a-long-enough-token"


@pytest.fixture
def store(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "auth.db"))
    yield store
    store.close()


def authed_config(**overrides) -> Settings:
    base = Settings(api_require_auth=True, api_tokens=TOKEN)
    return base.replace(**overrides)


# ------------------------------------------------------------------ the gate

def test_gated_paths_are_refused_without_a_token(store):
    client = TestClient(create_app(store, authed_config()))
    response = client.get("/api/telemetry/status")
    assert response.status_code == 401
    # WWW-Authenticate is what makes the 401 actionable to a generic client.
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_a_valid_bearer_token_is_accepted(store):
    client = TestClient(create_app(store, authed_config()))
    response = client.get(
        "/api/telemetry/status", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert response.status_code == 200


def test_the_x_api_key_header_is_also_accepted(store):
    # Accepted so operators are not pushed to put the token in a query string,
    # where it lands in access logs and browser history.
    client = TestClient(create_app(store, authed_config()))
    response = client.get("/api/telemetry/status", headers={"X-API-Key": TOKEN})
    assert response.status_code == 200


def test_a_wrong_token_is_refused(store):
    client = TestClient(create_app(store, authed_config()))
    response = client.get(
        "/api/telemetry/status", headers={"Authorization": "Bearer not-the-token-value"}
    )
    assert response.status_code == 401


def test_metrics_is_gated_because_volumes_are_reconnaissance(store):
    client = TestClient(create_app(store, authed_config()))
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"X-API-Key": TOKEN}).status_code == 200


def test_liveness_is_open_but_readiness_and_metrics_are_not(store):
    client = TestClient(create_app(store, authed_config()))
    # Liveness runs from the process manager before a credential exists and
    # discloses only "this process responds".
    assert client.get("/api/health/live").status_code == 200
    assert client.get("/api/health").status_code == 200
    # Readiness reports data age and degraded collector names, so it is gated.
    assert client.get("/api/health/ready").status_code == 401


def test_the_static_dashboard_is_not_gated(store):
    # It is markup and JavaScript with no telemetry; the data comes from /api/*,
    # which is gated, and the browser supplies the token from there.
    client = TestClient(create_app(store, authed_config()))
    assert client.get("/dashboard/").status_code == 200


def test_auth_required_but_unconfigured_fails_closed_with_503(store):
    # The dangerous alternative is serving the evidence feed unauthenticated; an
    # operator who forgot the token file gets an outage they fix in a minute.
    client = TestClient(create_app(store, Settings(api_require_auth=True, api_tokens=None)))
    response = client.get("/api/telemetry/status")
    assert response.status_code == 503
    assert "no tokens" in response.json()["detail"]


def test_disabling_auth_serves_without_a_token(store):
    client = TestClient(create_app(store, Settings(api_require_auth=False)))
    assert client.get("/api/telemetry/status").status_code == 200


# ---------------------------------------------------------- token handling

def test_a_short_token_is_refused_at_construction():
    # A placeholder like "changeme" must not be able to be the control.
    with pytest.raises(AuthConfigurationError, match="shorter than"):
        TokenAuthenticator(Settings(api_require_auth=True, api_tokens="short"))


def test_a_group_readable_token_file_is_refused(tmp_path):
    path = tmp_path / "tokens"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(AuthConfigurationError, match="group or other"):
        TokenAuthenticator(Settings(api_require_auth=True, api_token_file=str(path)))


def test_token_file_supports_multiple_tokens_for_rotation(tmp_path):
    old, new = TOKEN, TOKEN + "-rotated"
    path = tmp_path / "tokens"
    path.write_text(f"# rotating\n{old}\n{new}\n", encoding="utf-8")
    path.chmod(0o600)
    auth = TokenAuthenticator(Settings(api_require_auth=True, api_token_file=str(path)))
    # Both accepted at once is what lets a consumer be moved without an outage.
    assert auth.verify(old)
    assert auth.verify(new)
    assert auth.token_count == 2


def test_verify_checks_every_digest_even_after_a_match(monkeypatch):
    # The confidentiality claim rests on response time not revealing which token
    # matched or how many exist, so the loop must not short-circuit on the first
    # hit. Counting comparisons is how that is observable at the unit level.
    auth = TokenAuthenticator(
        Settings(api_require_auth=True, api_tokens=f"{TOKEN},{TOKEN}-two,{TOKEN}-three")
    )
    calls = {"n": 0}
    import api.auth as auth_module

    real = auth_module.secrets.compare_digest

    def counting(a, b):
        calls["n"] += 1
        return real(a, b)

    monkeypatch.setattr(auth_module.secrets, "compare_digest", counting)
    assert auth.verify(TOKEN) is True
    assert calls["n"] == auth.token_count


def test_extract_token_reads_bearer_and_api_key_and_ignores_other_schemes():
    assert extract_token("Bearer abc", None) == "abc"
    assert extract_token("bearer abc", None) == "abc"  # scheme is case-insensitive
    assert extract_token(None, "xyz") == "xyz"
    assert extract_token("Basic dXNlcjpwYXNz", None) is None
    assert extract_token(None, None) is None
