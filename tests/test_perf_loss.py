"""
Kernel perf-buffer loss reporting tests.

A BCC ring buffer that overruns discards samples before userspace hears about
them, and `open_perf_buffer(handler)` with no `lost_cb` makes that completely
silent. These tests pin the three properties that make the loss reportable at
all: the reporter matches the callback contract bcc actually calls it with, no
count is ever lost to rate limiting, and every canonical collector is wired to
it.

The transport choices are pinned too, because both are load-bearing and neither
is obvious from the code: the record goes to stdout (collector stderr dead-ends
in a small ring the supervisor reads only to explain a non-zero exit), and it is
deliberately *not* a canonical `EventType` (it describes the collector, not the
machine, and a real event type would add rows to the evidence table and shift the
window features the baseline and ML stages read).
"""

import ast
import inspect
import io
import json
from pathlib import Path

import pytest

from pipeline.event_stream import Event, EventType
from pipeline.live_ingestion import LOSS_EVENT_TYPE as PIPELINE_LOSS_EVENT_TYPE
from telemetry.bcc.perf_loss import (
    DEFAULT_REPORT_INTERVAL_SECONDS,
    LOSS_EVENT_TYPE,
    PerfBufferLossReporter,
)

REPO_ROOT = Path(__file__).parents[1]

# The three collectors the README documents as current. The other probes in
# telemetry/bcc are superseded proofs of concept and are not wired to anything.
CANONICAL_COLLECTORS = (
    ("telemetry_basic.py", "exec_events"),
    ("network_state_probe.py", "state_events"),
    ("ipc_pipe_probe.py", "pipe_events"),
)


class FakeClock:
    """A monotonic clock the test advances explicitly, so coalescing is exact."""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _reporter(**overrides) -> tuple[PerfBufferLossReporter, io.StringIO, FakeClock]:
    stream = io.StringIO()
    clock = FakeClock()
    kwargs = {
        "buffer_name": "exec_events",
        "source": "telemetry_bcc",
        "stream": stream,
        "clock": clock,
        "wall_clock": lambda: 1700000000.0,
    }
    kwargs.update(overrides)
    return PerfBufferLossReporter(**kwargs), stream, clock


def _records(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


# --------------------------------------------------------------------------
# The callback contract
# --------------------------------------------------------------------------


def test_reporter_is_callable_with_exactly_one_argument():
    """
    bcc calls `lost_cb(lost)`. A reporter that expected `(cpu, lost)` or bound
    self differently would raise inside the poll loop -- during loss, which is
    exactly when the collector must not crash.
    """
    reporter, _, _ = _reporter()
    signature = inspect.signature(reporter.__call__)
    assert list(signature.parameters) == ["lost"]
    reporter(1)


def test_bcc_open_perf_buffer_still_accepts_lost_cb():
    """
    Pin the upstream contract the wiring depends on. Skipped rather than faked
    when bcc is absent: a green assertion against a stub would prove nothing
    about the library the collectors actually load.
    """
    bcc = pytest.importorskip("bcc", reason="bcc is not installed in the active Python environment")
    parameters = inspect.signature(bcc.table.PerfEventArray.open_perf_buffer).parameters
    assert "lost_cb" in parameters
    assert "callback" in parameters


# --------------------------------------------------------------------------
# Reporting and coalescing
# --------------------------------------------------------------------------


def test_first_loss_reports_immediately():
    """The onset of loss is the most informative moment; it must not be rate limited."""
    reporter, stream, _ = _reporter()
    reporter(7)
    records = _records(stream)
    assert len(records) == 1
    assert records[0]["lost_events"] == 7
    assert records[0]["total_lost_events"] == 7


def test_report_shape_is_the_documented_wire_contract():
    reporter, stream, _ = _reporter(buffer_name="pipe_events", source="telemetry_bcc_pipe_syscalls")
    reporter(3)
    record = _records(stream)[0]
    assert record == {
        "event_type": "telemetry_loss",
        "timestamp": 1700000000.0,
        "lost_events": 3,
        "total_lost_events": 3,
        "buffer": "pipe_events",
        "source": "telemetry_bcc_pipe_syscalls",
        "version": "1.0",
    }


def test_loss_inside_the_interval_is_coalesced_not_discarded():
    """
    Rate limiting a log line may drop a line. Rate limiting the transport must
    never drop a count, or the total an analyst reads understates the gap in the
    evidence. The suppressed samples must appear in the next record.
    """
    reporter, stream, clock = _reporter(report_interval_seconds=1.0)
    reporter(5)
    clock.advance(0.1)
    reporter(10)
    clock.advance(0.1)
    reporter(20)
    assert len(_records(stream)) == 1, "coalescing window emitted more than one record"

    clock.advance(1.0)
    reporter(1)
    records = _records(stream)
    assert len(records) == 2
    # 10 + 20 suppressed, plus the 1 that triggered the report.
    assert records[1]["lost_events"] == 31
    assert records[1]["total_lost_events"] == 36
    assert sum(item["lost_events"] for item in records) == 36


def test_total_accumulates_while_reports_are_suppressed():
    reporter, _, clock = _reporter(report_interval_seconds=1.0)
    reporter(4)
    clock.advance(0.1)
    reporter(6)
    assert reporter.total_lost_events == 10


def test_flush_reports_the_coalesced_tail():
    """
    Without this, a burst that stopped inside the last reporting window would
    only ever surface if loss happened to resume.
    """
    reporter, stream, clock = _reporter(report_interval_seconds=1.0)
    reporter(2)
    clock.advance(0.1)
    reporter(40)
    assert len(_records(stream)) == 1

    reporter.flush()
    records = _records(stream)
    assert len(records) == 2
    assert records[1]["lost_events"] == 40
    assert sum(item["lost_events"] for item in records) == 42


def test_flush_without_pending_loss_emits_nothing():
    """Every collector calls flush() on shutdown; a clean run must stay silent."""
    reporter, stream, _ = _reporter()
    reporter.flush()
    assert _records(stream) == []


def test_flush_is_idempotent():
    reporter, stream, _ = _reporter()
    reporter(3)
    reporter.flush()
    reporter.flush()
    assert len(_records(stream)) == 1


def test_zero_and_negative_losses_are_ignored():
    """bcc reports 0 for a poll with no loss; that is not an event worth a record."""
    reporter, stream, _ = _reporter()
    reporter(0)
    reporter(-5)
    assert _records(stream) == []
    assert reporter.total_lost_events == 0


def test_unreadable_loss_count_is_ignored_rather_than_guessed():
    reporter, stream, _ = _reporter()
    reporter(None)
    reporter("many")
    assert _records(stream) == []
    assert reporter.total_lost_events == 0


def test_negative_report_interval_is_rejected():
    with pytest.raises(ValueError):
        PerfBufferLossReporter(buffer_name="b", source="s", report_interval_seconds=-1.0)


def test_zero_report_interval_reports_every_call():
    """An opt-out of coalescing, for a collector that would rather have the detail."""
    reporter, stream, _ = _reporter(report_interval_seconds=0.0)
    reporter(1)
    reporter(1)
    reporter(1)
    assert len(_records(stream)) == 3


def test_default_interval_coalesces():
    """A sane default matters: the class is constructed with no interval argument."""
    assert DEFAULT_REPORT_INTERVAL_SECONDS > 0


def test_one_instance_shared_across_cpus_produces_a_process_wide_total():
    """
    `open_perf_buffer` registers the callback once per online CPU. A per-CPU
    reporter would report one total per CPU and understate the real gap by the
    core count, which is why the collectors hold a single module-level instance.
    """
    reporter, stream, clock = _reporter(report_interval_seconds=1.0)
    for cpu in range(8):
        # Simulate bcc invoking the shared instance from each CPU's registration.
        reporter(10)
        clock.advance(1.0)
    records = _records(stream)
    assert len(records) == 8
    assert reporter.total_lost_events == 80
    assert records[-1]["total_lost_events"] == 80


def test_stream_is_resolved_at_emit_time(monkeypatch):
    """
    Resolved per emit, not captured in __init__, so a reopened stdout is honoured
    rather than written to a stale file object.
    """
    reporter = PerfBufferLossReporter(buffer_name="exec_events", source="telemetry_bcc")
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    reporter(3)
    assert json.loads(captured.getvalue())["lost_events"] == 3


def test_record_is_flushed_on_write():
    """
    The collector's stdout is a pipe, so an unflushed record sits in the buffer
    until the next event happens to fill it -- and under sustained loss the next
    event is exactly what is not arriving. A loss report that reaches the
    supervisor minutes late is a loss report that arrived after the alert window.
    """

    class FlushTrackingStream(io.StringIO):
        def __init__(self):
            super().__init__()
            self.flush_calls = 0

        def flush(self):
            self.flush_calls += 1
            super().flush()

    stream = FlushTrackingStream()
    PerfBufferLossReporter(buffer_name="exec_events", source="telemetry_bcc", stream=stream)(1)
    assert stream.flush_calls > 0, "the record was written without a flush"


def test_default_destination_is_stdout_not_stderr(monkeypatch):
    """
    Stdout is the only channel the supervisor parses. Collector stderr is
    captured into a bounded ring used solely to build the detail of a non-zero
    exit, so a loss report written there would never reach the health record.
    """
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    PerfBufferLossReporter(buffer_name="exec_events", source="telemetry_bcc")(1)
    assert json.loads(out.getvalue())["event_type"] == LOSS_EVENT_TYPE
    assert err.getvalue() == ""


# --------------------------------------------------------------------------
# The record is deliberately not a canonical event
# --------------------------------------------------------------------------


def test_loss_record_is_not_a_canonical_event_type():
    """
    Promoting this to an `EventType` would store loss reports as evidence rows
    and move `unique_event_types`, the one type-sensitive ML feature, for every
    window on the host. The supervisor intercepts these records instead.
    """
    assert LOSS_EVENT_TYPE not in {member.value for member in EventType}
    reporter, stream, _ = _reporter()
    reporter(1)
    assert Event.from_raw_json(_records(stream)[0]) is None


def test_wire_name_matches_the_supervisor_constant():
    """
    `pipeline.live_ingestion` carries its own copy of this name: a collector run
    as a bare script under sudo cannot import the package, and the supervisor must
    not import a module that pulls in bcc. Nothing but this test keeps the two
    honest.
    """
    assert LOSS_EVENT_TYPE == PIPELINE_LOSS_EVENT_TYPE


# --------------------------------------------------------------------------
# Every canonical collector is wired to it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("filename,buffer_name", CANONICAL_COLLECTORS)
def test_canonical_collector_registers_lost_cb(filename, buffer_name):
    """
    Source-text assertions because these files call `BPF(...)` at import time
    and cannot be imported by the test process. Without `lost_cb=`, a ring
    overrun in that collector is silent again -- which is the whole defect.
    """
    text = (REPO_ROOT / "telemetry" / "bcc" / filename).read_text(encoding="utf-8")
    assert f'b["{buffer_name}"].open_perf_buffer(' in text
    assert "lost_cb=loss_reporter" in text
    assert "PerfBufferLossReporter(" in text
    assert f'buffer_name="{buffer_name}"' in text


@pytest.mark.parametrize("filename,buffer_name", CANONICAL_COLLECTORS)
def test_canonical_collector_flushes_on_shutdown(filename, buffer_name):
    text = (REPO_ROOT / "telemetry" / "bcc" / filename).read_text(encoding="utf-8")
    assert "loss_reporter.flush()" in text


@pytest.mark.parametrize("filename,buffer_name", CANONICAL_COLLECTORS)
def test_canonical_collector_does_not_swallow_keyboard_interrupt(filename, buffer_name):
    """
    The flush above only runs if KeyboardInterrupt actually reaches the shutdown
    handler. A bare `except:` (or `except BaseException`) anywhere inside the
    poll loop -- for instance around best-effort health reporting -- catches the
    Ctrl+C first, so the interrupt is discarded, the loop keeps polling, and the
    pending loss count dies with the process instead of being reported.

    Parsed rather than grepped so `except Exception` is not mistaken for a bare
    handler and the words in a docstring cannot fail the test.
    """
    source = (REPO_ROOT / "telemetry" / "bcc" / filename).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler):
            continue
        assert node.type is not None, (
            f"{filename}:{node.lineno} uses a bare `except:`, which swallows "
            "KeyboardInterrupt before the shutdown flush"
        )
        caught = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        names = {n.id for n in caught if isinstance(n, ast.Name)}
        assert "BaseException" not in names, (
            f"{filename}:{node.lineno} catches BaseException, which swallows "
            "KeyboardInterrupt before the shutdown flush"
        )


@pytest.mark.parametrize("filename,buffer_name", CANONICAL_COLLECTORS)
def test_canonical_collector_holds_one_shared_reporter(filename, buffer_name):
    """
    One instance per collector, at module level. Constructing a reporter inside
    the registration call -- or per CPU -- would split the total.
    """
    text = (REPO_ROOT / "telemetry" / "bcc" / filename).read_text(encoding="utf-8")
    assert text.count("PerfBufferLossReporter(") == 1
    assert "\nloss_reporter = PerfBufferLossReporter(" in text


@pytest.mark.parametrize("filename,buffer_name", CANONICAL_COLLECTORS)
def test_canonical_collector_imports_reporter_both_ways(filename, buffer_name):
    """
    The documented invocation is `sudo python3 telemetry/bcc/<file>.py`, where the
    repository root is not on sys.path, so the package import must have a sibling
    fallback or the collector will not start at all.
    """
    text = (REPO_ROOT / "telemetry" / "bcc" / filename).read_text(encoding="utf-8")
    assert "from telemetry.bcc.perf_loss import PerfBufferLossReporter" in text
    assert "from perf_loss import PerfBufferLossReporter" in text


def test_perf_loss_module_does_not_import_bcc():
    """
    The supervisor-side test suite imports this module. Pulling bcc in here would
    make loss accounting untestable on any host without a kernel headers tree,
    and would make the reporter unusable from `pipeline` for the same reason.
    Parsed rather than grepped, so the word appearing in a docstring is not a
    failure and an import hidden inside a function is not a pass.
    """
    source = (REPO_ROOT / "telemetry" / "bcc" / "perf_loss.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "bcc" not in imported
    assert imported <= {"json", "sys", "time", "typing"}
