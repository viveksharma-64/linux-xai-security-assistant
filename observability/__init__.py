"""Process-level logging configuration for the executable entry points."""

import logging
import os
import sys

# Matches the key=value message bodies used by the application loggers, so a line
# is greppable as a whole: timestamp, level, logger, then the event's own fields.
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

_configured = False


def configure_logging(default_level: str = "INFO") -> None:
    """
    Send application logs to stderr, honouring $SECURITY_LOG_LEVEL.

    Call this from entry points only; importing a library must never reconfigure
    the host application's logging. Without it the root logger has no handler and
    `logging.lastResort` drops everything below WARNING, so the INFO-level audit
    trail in assistant/service.py and policy/engine.py is silently discarded.

    stderr is deliberate. Stdout is a data channel: collectors emit JSON lines on
    it and `pipeline/live_ingestion.main` emits a single health object, so a log
    line written there would corrupt a consumer's parse.

    Idempotent, and never steals a configuration the caller already installed.
    """
    global _configured
    if _configured or logging.getLogger().handlers:
        return

    requested = os.getenv("SECURITY_LOG_LEVEL", default_level)
    level = logging.getLevelNamesMapping().get(requested.strip().upper())
    invalid = level is None
    if invalid:
        level = logging.getLevelNamesMapping().get(default_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        stream=sys.stderr,
    )
    _configured = True

    if invalid:
        # Reported rather than fatal: an unreadable log level must not stop a
        # security service from starting. The raw value is echoed, not the
        # normalised one, so a typo or stray whitespace is visible as typed.
        logging.getLogger(__name__).warning(
            "invalid_log_level requested=%r fallback=%s", requested, default_level.upper()
        )
