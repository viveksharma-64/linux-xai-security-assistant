"""
Entry point for the read-only API and dashboard host.

Two refusals here, both deliberate and both about default-deny. The service will
not bind a non-loopback address unless the operator says so explicitly, and it
will not serve without authentication unless the operator says so explicitly.
Either one alone is insufficient: loopback-only still exposes the evidence feed to
every local account, and a token on a wide-open bind is one leaked token away from
remote reconnaissance.
"""

import logging
import os

import uvicorn

from observability import configure_logging
from observability.config import ConfigError, load_settings

LOGGER = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def main() -> None:
    configure_logging()
    try:
        settings = load_settings()
    except ConfigError as error:
        # Configuration is a security control here (auth, file modes, retention),
        # so an unreadable one is fatal rather than defaulted. See
        # observability/config.py.
        raise SystemExit(f"invalid configuration: {error}") from error

    if settings.api_host not in LOOPBACK_HOSTS and os.getenv("ALLOW_NON_LOOPBACK_API") != "1":
        raise SystemExit("Refusing non-loopback API host; set ALLOW_NON_LOOPBACK_API=1 explicitly.")
    if not settings.api_require_auth and settings.api_host not in LOOPBACK_HOSTS:
        raise SystemExit(
            "Refusing to serve an unauthenticated API on a non-loopback address; "
            "set api_require_auth true and configure api_token_file."
        )
    LOGGER.info(
        "api_start host=%s port=%d require_auth=%s db=%s",
        settings.api_host,
        settings.api_port,
        settings.api_require_auth,
        settings.db_path,
    )
    uvicorn.run("api.app:app", host=settings.api_host, port=settings.api_port)


if __name__ == "__main__":
    main()
