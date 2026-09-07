"""
Shared test fixtures.

Two concerns, both about the process-wide configuration singleton.

Isolation. `observability.config.settings()` caches the resolved `Settings` for the
lifetime of the process. Under pytest that process runs every test, so a cache
populated by one test's environment is the configuration every later test sees.
The autouse fixture clears it on both sides of each test, which makes config-
dependent tests order-independent -- otherwise a failure only reproduces when the
whole file is run, which is the worst kind of flake to chase.

Authentication. The API fails closed: `api_require_auth` defaults to true, and with
no tokens configured every gated route answers 503. That is the correct production
default and it would otherwise make every pre-existing API test assert against an
auth error instead of the behaviour it was written to check. Rather than weaken the
default, tests that are not about authentication turn it off explicitly through
`SECURITY_API_REQUIRE_AUTH`, and the tests in test_api_auth.py turn it back on to
exercise the gate itself.
"""

from __future__ import annotations

import pytest

from observability.config import reset_settings_cache


@pytest.fixture(scope="session")
def _empty_config_file(tmp_path_factory):
    """An empty config file, so the file layer is present but contributes nothing."""
    path = tmp_path_factory.mktemp("config") / "config.yaml"
    path.write_text("{}\n", encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch, _empty_config_file):
    """Give every test a clean, non-inherited configuration cache."""
    # An installed /etc/linux-xai-security/config.yaml must not change test
    # results, so the file layer is pinned to an empty file. Pinned to a real file
    # rather than to a missing path because `config_file_path` treats an explicitly
    # named file that does not exist as a fatal misconfiguration.
    monkeypatch.setenv("SECURITY_CONFIG_FILE", str(_empty_config_file))
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture(autouse=True)
def _api_auth_disabled(monkeypatch, request):
    """
    Serve the API unauthenticated unless a test opts back in.

    Opting in is `@pytest.mark.api_auth`, used by the authentication tests. Every
    other test predates the auth gate and is asserting on payloads, not on access
    control.
    """
    if request.node.get_closest_marker("api_auth"):
        return
    monkeypatch.setenv("SECURITY_API_REQUIRE_AUTH", "0")
    reset_settings_cache()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "api_auth: leave API authentication enabled for this test"
    )
