"""
Resource lifetime regression tests.

These pin the fixes for two leaks that the suite could not previously see, because
Python silences ResourceWarning by default:

  * storage/sqlite_store.py held connections open past their transaction.
    `sqlite3.Connection.__exit__` ends the transaction but does not close, so
    `with self._connect() as conn` left the connection to garbage collection.
  * pipeline/live_ingestion.py never closed a collector subprocess's stdout and
    stderr pipes, and overwrote `self.process` on re-iteration.

Descriptors are counted directly rather than asserting on ResourceWarning:
ResourceWarning is raised during finalization, so it cannot be turned into a test
failure -- Python only prints "Exception ignored while finalizing".
"""

import os
import sys
import time

import pytest

from pipeline.event_stream import Event, EventType
from pipeline.live_ingestion import SubprocessJSONLSource
from storage.sqlite_store import SQLiteEventStore


def _open_fd_count() -> int:
    """Open descriptors for this process. Linux-only, which matches the target."""
    return len(os.listdir("/proc/self/fd"))


def _sample_event(**extra):
    base = {
        "event_type": "process_exec",
        "timestamp": 1700000000.0,
        "pid": 100,
        "uid": 1000,
        "comm": "bash",
    }
    base.update(extra)
    return Event.from_raw_json(base)


def _seeded_store(tmp_path, count=5) -> SQLiteEventStore:
    store = SQLiteEventStore(str(tmp_path / "resource_lifetime.db"))
    for pid in range(count):
        store.write(_sample_event(pid=1000 + pid))
    return store


def test_abandoned_read_all_generator_holds_no_connection(tmp_path):
    """
    The discriminating case for the store fix.

    read_all() materialises its rows, so the connection must be closed before the
    first yield. Previously the `with` block stayed suspended inside the generator
    and the connection lived for as long as the consumer took to iterate -- or
    forever, if the consumer abandoned it.
    """
    store = _seeded_store(tmp_path)
    baseline = _open_fd_count()

    stream = store.read_all()
    first = next(stream)
    assert first.comm == "bash"
    assert _open_fd_count() == baseline, "connection still open while generator is suspended"

    stream.close()
    assert _open_fd_count() == baseline


def test_abandoned_query_generator_holds_no_connection(tmp_path):
    store = _seeded_store(tmp_path)
    baseline = _open_fd_count()

    stream = store.query({"event_type": "process_exec"})
    next(stream)
    assert _open_fd_count() == baseline

    stream.close()
    assert _open_fd_count() == baseline


def test_repeated_store_operations_do_not_grow_descriptors(tmp_path):
    """
    Guards against a regression that stops closing connections altogether, and
    against runtimes that do not promptly refcount the connection away. This is a
    weaker signal than the generator tests above: under CPython the pre-fix code
    still closed at method return, so unbounded growth was not the pre-fix symptom.
    """
    store = _seeded_store(tmp_path, count=1)
    # Warm up first, so creating -wal/-shm is not counted as growth.
    list(store.read_all())
    store.count_events()
    store.read_event_records(limit=5)

    baseline = _open_fd_count()
    for pid in range(50):
        store.write(_sample_event(pid=2000 + pid))
        list(store.read_all())
        store.count_events()
        store.read_event_records(limit=5)
    assert _open_fd_count() == baseline


def test_query_rejects_columns_outside_the_whitelist(tmp_path):
    """Filter keys are interpolated into SQL, so unknown keys must be refused."""
    store = _seeded_store(tmp_path, count=1)

    with pytest.raises(ValueError, match="unsupported query column"):
        list(store.query({"1=1 OR comm": "bash"}))
    with pytest.raises(ValueError, match="unsupported query column"):
        list(store.query({"payload_json": "{}"}))

    # A whitelisted column still works, and a None value is still ignored.
    assert len(list(store.query({"event_type": EventType.PROCESS_EXEC.value}))) == 1
    assert len(list(store.query({"comm": None}))) == 1


def test_write_returns_false_for_a_missing_event(tmp_path):
    """Declared `-> bool`; previously fell through to a bare `return`."""
    store = _seeded_store(tmp_path, count=0)
    assert store.write(None) is False


def test_subprocess_source_closes_its_pipes_after_iteration():
    """
    The discriminating case for the ingestion fix. The pipes are reachable from
    self.process, so nothing collected them; they stayed open for the lifetime of
    the source, which in production is the lifetime of the service.
    """
    source = SubprocessJSONLSource(
        [sys.executable, "-c", 'print(\'{"event_type": "process_exec"}\')']
    )
    baseline = _open_fd_count()

    lines = list(source)

    assert lines and lines[0].strip().startswith("{")
    assert source.process is not None
    assert source.process.stdout is not None and source.process.stdout.closed
    assert source.process.stderr is not None and source.process.stderr.closed
    assert _open_fd_count() == baseline


def test_subprocess_source_closes_pipes_when_iteration_is_abandoned():
    """
    Abandoning the reader must reap promptly. Closing a stream that _read_stderr
    is blocked on waits for that thread's in-flight read, which does not finish
    until the collector exits -- so reaping has to stop the child first. The child
    here sleeps far longer than the budget, which is what makes the bound load-bearing.
    """
    source = SubprocessJSONLSource(
        [sys.executable, "-c", "import time\nprint('{}', flush=True)\ntime.sleep(30)"]
    )
    baseline = _open_fd_count()

    stream = iter(source)
    next(stream)
    started = time.monotonic()
    stream.close()
    source.close()
    elapsed = time.monotonic() - started

    assert elapsed < 10, f"reaping an abandoned collector stalled for {elapsed:.1f}s"
    assert source.process is not None
    assert source.process.stdout is not None and source.process.stdout.closed
    assert source.process.stderr is not None and source.process.stderr.closed
    assert source.process.poll() is not None, "collector was left running"
    assert _open_fd_count() == baseline


def test_subprocess_source_refuses_to_orphan_a_running_child():
    """
    Re-entering __iter__ used to overwrite self.process, orphaning the previous
    child and leaking its pipes.
    """
    source = SubprocessJSONLSource(
        [sys.executable, "-c", "import time\nprint('{}', flush=True)\ntime.sleep(30)"]
    )
    stream = iter(source)
    next(stream)
    try:
        with pytest.raises(RuntimeError, match="already running"):
            next(iter(source))
    finally:
        started = time.monotonic()
        stream.close()
        source.close()
        assert time.monotonic() - started < 10


def test_subprocess_source_reports_a_failing_collector_with_stderr_detail():
    """Pipe closing must not cost the diagnostic detail carried in the error."""
    source = SubprocessJSONLSource(
        [sys.executable, "-c", "import sys; sys.stderr.write('probe load failed\\n'); sys.exit(3)"]
    )
    with pytest.raises(RuntimeError, match="collector exited with status 3.*probe load failed"):
        list(source)
