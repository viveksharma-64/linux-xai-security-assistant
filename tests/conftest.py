"""
Shared test fixtures.

Three concerns. The first two are about the process-wide configuration singleton,
the third about store handles outliving the test that opened them.

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

Store lifetime. `SQLiteEventStore` pools one connection per thread and reclaims
them in `close()`. Most tests build a store inline and never close it, which is
only visible once a request has been served on an API worker thread -- see
`_close_stores`.
"""

from __future__ import annotations

import weakref

import pytest

from observability.config import reset_settings_cache
from storage.sqlite_store import SQLiteEventStore


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


@pytest.fixture(autouse=True)
def _close_stores(monkeypatch):
    """
    Close every store a test opens, including handles opened on API worker threads.

    `SQLiteEventStore` caches one connection per thread, so a request served
    through `TestClient` -- which runs a sync endpoint on an anyio worker thread --
    leaves that thread's pooled handle in `store._connections` until someone calls
    `close()`. Tests that build a store, hand it to `create_app` and then POST
    through the client mostly never do, so the handle survives the test and SQLite
    reports it as an `unclosed database` ResourceWarning during interpreter
    shutdown -- blamed on whichever test happened to trigger the collection, which
    is why it never reproduces when that file is run on its own.

    Closing is driven off construction rather than a `gc.get_objects()` sweep at
    teardown: the sweep reaches the same result but walks every live object once
    per test, costing more than the rest of the suite put together (167s against
    62s). `close()` is idempotent, so tests that close their own store are
    unaffected.
    """
    live: weakref.WeakSet[SQLiteEventStore] = weakref.WeakSet()
    original_init = SQLiteEventStore.__init__

    def tracking_init(self, *args, **kwargs):
        # Tracked only once __init__ returns: a store whose construction raised
        # (unreadable path, rejected file mode) has no connections to reclaim.
        original_init(self, *args, **kwargs)
        live.add(self)

    monkeypatch.setattr(SQLiteEventStore, "__init__", tracking_init)
    yield
    # Materialised first: holding strong references for the duration keeps the set
    # from shrinking under collection while it is being iterated.
    for store in list(live):
        store.close()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "api_auth: leave API authentication enabled for this test"
    )
