"""
Tests for the dedicated host health collector (telemetry/health/system_health_probe.py).

This collector exists because `detection/system_failure.py` had no live source:
the BCC variants that sampled memory are deprecated or bolted onto a
`process_exec` poll loop, and none of them sampled disk at all, so the disk
rules could never fire. The assertions below pin the two things that make the
collector useful rather than merely present -- that its records normalize into a
`SYSTEM_HEALTH` event with a populated payload (the field names are a contract,
not a convention), and that a metric it cannot read is reported as unknown
rather than as a healthy zero.
"""

from __future__ import annotations

import io
import json
import threading

import pytest

from pipeline.event_stream import Event, EventType
from telemetry.health.system_health_probe import (
    DEFAULT_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    SystemHealthCollector,
    main,
)

psutil = pytest.importorskip("psutil")

HEALTH_FIELDS = ("cpu_percent", "mem_percent", "disk_percent", "mem_available_mb")


def _collector(**kwargs) -> tuple[SystemHealthCollector, io.StringIO]:
    stream = io.StringIO()
    return SystemHealthCollector(output=stream, **kwargs), stream


def _lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The pipeline contract
# ---------------------------------------------------------------------------

def test_sample_carries_the_health_fields_at_the_top_level():
    # `Event.from_raw_json` reads these four keys off the top level of the
    # record. Nesting them under "payload" would normalize to an all-null
    # payload and the detector would silently never fire -- so the shape is
    # asserted, not assumed.
    collector, _ = _collector()
    record = collector.sample()
    assert record["event_type"] == "system_health"
    for field in HEALTH_FIELDS:
        assert field in record, field
    assert isinstance(record["timestamp"], float)


def test_a_sample_normalizes_into_a_scoreable_system_health_event():
    # The end-to-end contract: what the collector prints is what the detector
    # reads. Sampled twice so cpu_percent is past its priming call.
    collector, _ = _collector()
    collector.sample()
    event = Event.from_raw_json(collector.sample())

    assert event.event_type == EventType.SYSTEM_HEALTH
    payload = event.payload or {}
    # Memory and disk are always readable on a running host.
    assert isinstance(payload["mem_percent"], float)
    assert isinstance(payload["mem_available_mb"], int)
    assert isinstance(payload["disk_percent"], float)
    assert isinstance(payload["cpu_percent"], float)
    # Percentages, not ratios -- the thresholds are expressed in percent.
    assert 0.0 <= payload["mem_percent"] <= 100.0
    assert 0.0 <= payload["disk_percent"] <= 100.0


def test_the_first_cpu_sample_is_unknown_rather_than_a_fabricated_zero():
    # psutil.cpu_percent(interval=None) measures since the previous call, so the
    # priming call has nothing to difference against and answers 0.0. Publishing
    # that would report an idle host; the detector treats the field as optional
    # for exactly this reason.
    collector, _ = _collector()
    assert collector.sample()["cpu_percent"] is None
    assert isinstance(collector.sample()["cpu_percent"], float)


def test_an_unreadable_metric_is_null_and_does_not_suppress_the_others():
    # A disk path that has gone away must not take the memory readings with it:
    # "not measured" and "measured and fine" are different states, and the
    # scorer distinguishes them.
    collector, _ = _collector(disk_path="/nonexistent-mount-for-tests")
    record = collector.sample()
    assert record["disk_percent"] is None
    assert record["mem_percent"] is not None
    assert record["mem_available_mb"] is not None


# ---------------------------------------------------------------------------
# The supervised-subprocess contract
# ---------------------------------------------------------------------------

def test_run_emits_one_flushed_json_line_per_sample():
    collector, stream = _collector(interval=MIN_INTERVAL_SECONDS)
    assert collector.run(max_samples=3) == 0
    records = _lines(stream)
    assert len(records) == 3
    assert {r["event_type"] for r in records} == {"system_health"}


def test_stop_ends_the_loop_without_waiting_out_the_interval():
    # The supervisor terminates children and then waits on them, so a stop
    # arriving mid-interval has to end the process now. A 1-hour interval makes
    # the assertion unambiguous: if the wait were not interruptible this test
    # would hang rather than fail.
    collector, stream = _collector(interval=3600.0)
    finished = threading.Event()

    def drive():
        collector.run()
        finished.set()

    worker = threading.Thread(target=drive, daemon=True)
    worker.start()
    collector.stop()
    assert finished.wait(timeout=10), "run() did not return promptly after stop()"
    # The sample taken before the stop was observed still reached the stream.
    assert len(_lines(stream)) == 1


def test_a_closed_stdout_ends_the_session_quietly():
    # stdout going away is the supervisor leaving, which is a normal end of
    # session -- not a fault worth a traceback in the journal.
    collector, stream = _collector()
    stream.close()
    assert collector.run(max_samples=1) == 0


def test_interval_is_floored_rather_than_trusted():
    # A sub-second interval adds load without adding signal: the detector
    # aggregates into 300s windows and needs consecutive breaching windows
    # before it fires.
    collector, _ = _collector(interval=0.0)
    assert collector.interval == MIN_INTERVAL_SECONDS
    collector, _ = _collector(interval=45.0)
    assert collector.interval == 45.0


def test_default_interval_is_well_inside_the_detector_window():
    # Several samples per 300s window, so one unreadable sample cannot decide a
    # window on its own.
    assert DEFAULT_INTERVAL_SECONDS < 300.0 / 2


def test_cli_runs_a_bounded_session(capsys):
    # The entry point systemd invokes. --max-samples keeps it bounded here.
    assert main(["--max-samples", "1", "--interval", "1"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert len(records) == 1
    assert records[0]["event_type"] == "system_health"
