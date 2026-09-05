"""
Diagnostics channel tests.

Stdout is a data channel in this system: collectors emit JSON lines on it and
`pipeline/live_ingestion.main` emits a single health object on it. Library code
that prints a warning there corrupts a consumer's parse, so these tests pin
diagnostics to logging and keep stdout empty.

Also covers the two contracts fixed alongside that change: `normalize()` leaving
the caller's record alone, and `EventStore.write` reporting whether it stored.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline.event_stream import (
    CanonicalNormalizer,
    InMemoryEventStore,
    JSONLineCollector,
    TelemetryPipeline,
)

_REPO_ROOT = Path(__file__).parents[1]


def _run_configured(body: str, **env) -> subprocess.CompletedProcess:
    """
    Exercise configure_logging() in a clean interpreter.

    It is deliberately a no-op when the root logger already has handlers, and
    pytest reinstalls its own capture handler around every test body, so the
    function cannot be exercised in-process. A subprocess also checks what
    actually matters at an entry point: which stream records land on.
    """
    script = "from observability import configure_logging\nimport logging\n" + body
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONPATH": str(_REPO_ROOT), **env},
    )


def _jsonl(tmp_path, *lines) -> str:
    path = tmp_path / "telemetry.jsonl"
    path.write_text("".join(line + "\n" for line in lines))
    return str(path)


def test_library_diagnostics_never_reach_stdout(tmp_path, capsys, caplog):
    """
    A malformed line and a rejected event both used to print to stdout. Nothing
    the pipeline reports about bad input may appear there.
    """
    path = _jsonl(
        tmp_path,
        '{"event_type": "process_exec", "timestamp": 1.0, "pid": 5, "comm": "bash"}',
        "{not json at all",
        '{"event_type": "process_exec", "timestamp": "not-a-number"}',
    )
    pipeline = TelemetryPipeline(
        JSONLineCollector(path), CanonicalNormalizer(), InMemoryEventStore()
    )

    with caplog.at_level(logging.INFO, logger="pipeline.event_stream"):
        pipeline.run()

    assert capsys.readouterr().out == "", "library code wrote diagnostics to stdout"
    assert pipeline.processed_count == 1
    assert pipeline.skipped_count == 1

    messages = [record.getMessage() for record in caplog.records]
    assert any(m.startswith("jsonl_malformed_line ") for m in messages), messages
    assert any(m.startswith("normalization_failed ") for m in messages), messages
    assert any("batch_pipeline_complete processed=1 skipped=1" == m for m in messages), messages
    assert {record.levelno for record in caplog.records} == {logging.INFO, logging.WARNING}


def test_normalize_does_not_mutate_the_caller_record():
    """
    Coercion wrote pid/ppid/gid/parent_comm/ancestry back into the caller's dict.
    The caller may still log, retry, or route that record, so it must be intact --
    while the Event still receives the coerced values.
    """
    raw = {"event_type": "process_exec", "timestamp": 1.0, "pid": "7", "gid": "9"}
    before = json.dumps(raw, sort_keys=True)

    event = CanonicalNormalizer().normalize(raw)

    assert json.dumps(raw, sort_keys=True) == before, "normalize edited the caller's record"
    assert event is not None
    assert event.pid == 7 and event.gid == 9, "coercion must still reach the Event"


def test_normalize_does_not_alias_the_caller_ancestry_list():
    """A shallow copy would still share the list, so mutation would cross over."""
    raw = {"event_type": "process_exec", "timestamp": 1.0, "ancestry": ["systemd"]}

    event = CanonicalNormalizer().normalize(raw)
    event.ancestry.append("injected")

    assert raw["ancestry"] == ["systemd"]


def test_normalize_still_rejects_invalid_records():
    """The copy must not soften validation."""
    normalizer = CanonicalNormalizer()

    assert normalizer.normalize({"timestamp": 1.0}) is None
    assert normalizer.normalize({"event_type": "process_exec"}) is None
    assert normalizer.normalize({"event_type": "process_exec", "timestamp": "x"}) is None
    assert normalizer.normalize({"event_type": "nope", "timestamp": 1.0}) is None


def test_in_memory_store_write_reports_whether_it_stored():
    """
    Declared `-> None` while LiveIngestionService._consume branches on the result,
    so every event would have been counted as a duplicate.
    """
    store = InMemoryEventStore()
    event = CanonicalNormalizer().normalize(
        {"event_type": "process_exec", "timestamp": 1.0, "pid": 1}
    )

    assert store.write(event) is True
    assert store.write(None) is False
    assert len(store.events) == 1


def test_configure_logging_sends_records_to_stderr():
    result = _run_configured(
        "configure_logging()\n"
        "logging.getLogger('pipeline.event_stream').warning('probe key=value')\n"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "", "log records must not reach the stdout data channel"
    assert "probe key=value" in result.stderr
    assert "WARNING pipeline.event_stream" in result.stderr, result.stderr


def test_configure_logging_enables_the_info_audit_trail():
    """
    The default has to be INFO, not WARNING: the assistant audit records in
    assistant/service.py are INFO, and lastResort would drop them.
    """
    result = _run_configured(
        "configure_logging()\n"
        "print(logging.getLogger().level, "
        "logging.getLogger('assistant.service').isEnabledFor(logging.INFO))\n"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{logging.INFO} True"


def test_configure_logging_honours_the_environment_level():
    result = _run_configured(
        "configure_logging()\nprint(logging.getLogger().level)\n",
        SECURITY_LOG_LEVEL="debug",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(logging.DEBUG)


def test_configure_logging_falls_back_on_an_invalid_level():
    """An unreadable log level must not stop a security service from starting."""
    result = _run_configured(
        "configure_logging()\nprint(logging.getLogger().level)\n",
        SECURITY_LOG_LEVEL="chatty",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(logging.INFO)
    assert "invalid_log_level" in result.stderr
    assert "chatty" in result.stderr


def test_configure_logging_leaves_an_existing_configuration_alone():
    """Importing this project must not hijack a host application's logging."""
    result = _run_configured(
        "root = logging.getLogger()\n"
        "existing = logging.NullHandler()\n"
        "root.addHandler(existing)\n"
        "root.setLevel(logging.CRITICAL)\n"
        "configure_logging()\n"
        "print(root.handlers == [existing], root.level == logging.CRITICAL)\n"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True True"


def test_configure_logging_is_idempotent():
    result = _run_configured(
        "configure_logging()\n"
        "first = logging.getLogger().handlers[:]\n"
        "configure_logging()\n"
        "print(logging.getLogger().handlers == first)\n"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_entry_points_configure_logging():
    """
    A channel no entry point configures is no better than print(): the root logger
    would have no handler and lastResort would drop every INFO record.
    """
    for module in ("pipeline/live_ingestion.py", "api/__main__.py"):
        source = (_REPO_ROOT / module).read_text()
        assert "configure_logging()" in source, f"{module} does not configure logging"
