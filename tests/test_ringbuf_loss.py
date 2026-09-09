"""RingBufferLossReporter: delta accounting, its guards, and — most importantly —
that a ring-buffer drop produces the *same* frozen `telemetry_loss` wire record
the perf path emits.

No bcc and no kernel here: the reporter is handed a loaded-BPF stand-in and only
indexes it, exactly as it does on a real host, so the accounting is testable
off-host.
"""

import io
import json

from telemetry.bcc.perf_loss import PerfBufferLossReporter
from telemetry.bcc.ringbuf_loss import RingBufferLossReporter


class _Leaf:
    """A ctypes-style leaf whose count is read via `.value` (bcc's u64 array)."""

    def __init__(self, value):
        self.value = value


class _Holder:
    """Mutable backing for the fake counter so one BPF object changes between polls."""

    def __init__(self, raw=False):
        self._value = 0
        self.raw = raw
        self.raise_on_read = None

    def set(self, value):
        self._value = value

    @property
    def leaf(self):
        # `raw` returns a bare int (some bcc leaves are plain ints); otherwise a
        # `.value` leaf. RingBufferLossReporter._read must accept both.
        return self._value if self.raw else _Leaf(self._value)


class _FakeMap:
    def __init__(self, holder):
        self._holder = holder

    def __getitem__(self, key):  # key is _COUNTER_KEY; a len-1 array ignores it
        if self._holder.raise_on_read is not None:
            raise self._holder.raise_on_read
        return self._holder.leaf


class _FakeBPF:
    """Indexes like a loaded BPF object: bpf[map_name] -> map."""

    def __init__(self, map_name, holder):
        self._map_name = map_name
        self._map = _FakeMap(holder)

    def __getitem__(self, name):
        if name != self._map_name:
            raise KeyError(name)
        return self._map


class _Recorder:
    """Captures the deltas handed to the wrapped reporter."""

    def __init__(self):
        self.deltas = []

    def __call__(self, delta):
        self.deltas.append(delta)


def test_delta_reporting_across_polls():
    holder = _Holder()
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="x_dropped")
    bpf = _FakeBPF("x_dropped", holder)

    holder.set(0)
    ring.poll(bpf)
    assert rec.deltas == []  # no loss yet
    holder.set(5)
    ring.poll(bpf)
    assert rec.deltas == [5]  # 0 -> 5
    ring.poll(bpf)
    assert rec.deltas == [5]  # unchanged: emit nothing
    holder.set(8)
    ring.poll(bpf)
    assert rec.deltas == [5, 3]  # 5 -> 8


def test_counter_reset_resyncs_without_a_bogus_delta():
    holder = _Holder()
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="x_dropped")
    bpf = _FakeBPF("x_dropped", holder)

    holder.set(10)
    ring.poll(bpf)
    assert rec.deltas == [10]
    holder.set(2)  # went backwards -> map recreated on reload
    ring.poll(bpf)
    assert rec.deltas == [10]  # adopt new baseline, no negative delta
    holder.set(5)
    ring.poll(bpf)
    assert rec.deltas == [10, 3]  # counted from the new baseline (2 -> 5)


def test_unreadable_counter_reports_nothing_and_keeps_baseline():
    holder = _Holder()
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="x_dropped")
    bpf = _FakeBPF("x_dropped", holder)

    holder.set(10)
    ring.poll(bpf)
    assert rec.deltas == [10]
    holder.raise_on_read = RuntimeError("map temporarily unreadable")
    ring.poll(bpf)
    assert rec.deltas == [10]  # silence is not a "no loss" signal
    holder.raise_on_read = None
    holder.set(13)
    ring.poll(bpf)
    assert rec.deltas == [10, 3]  # baseline survived the failed read (10 -> 13)


def test_missing_map_is_unreadable_not_zero():
    holder = _Holder()
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="absent_dropped")
    bpf = _FakeBPF("present_dropped", holder)  # different name -> KeyError in _read

    holder.set(7)
    ring.poll(bpf)
    assert rec.deltas == []


def test_raw_integer_leaf_is_accepted():
    holder = _Holder(raw=True)
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="x_dropped")
    bpf = _FakeBPF("x_dropped", holder)

    holder.set(4)
    ring.poll(bpf)
    assert rec.deltas == [4]


def test_non_integer_leaf_is_ignored():
    holder = _Holder()
    rec = _Recorder()
    ring = RingBufferLossReporter(rec, map_name="x_dropped")
    bpf = _FakeBPF("x_dropped", holder)

    holder.set("not-a-number")
    ring.poll(bpf)
    assert rec.deltas == []


def test_ringbuf_loss_emits_the_frozen_perf_wire_record():
    """
    The whole design rests on this: a drop counted on the ring-buffer path is
    reported through the shared PerfBufferLossReporter, so the record on the wire
    is byte-for-byte the version-1.0 telemetry_loss the perf path emits. In
    particular `buffer` is the buffer name, never the `_dropped` map name.
    """
    stream = io.StringIO()
    reporter = PerfBufferLossReporter(
        buffer_name="pipe_events",
        source="telemetry_bcc_pipe_syscalls",
        stream=stream,
        report_interval_seconds=3600.0,  # coalesce; first call still emits
        wall_clock=lambda: 1700000000.0,
    )
    ring = RingBufferLossReporter(reporter, map_name="pipe_events_dropped")
    holder = _Holder()
    holder.set(3)

    ring.poll(_FakeBPF("pipe_events_dropped", holder))
    reporter.flush()  # no-op here (already emitted), mirrors the shutdown path

    record = json.loads(stream.getvalue().strip())
    assert record == {
        "event_type": "telemetry_loss",
        "timestamp": 1700000000.0,
        "lost_events": 3,
        "total_lost_events": 3,
        "buffer": "pipe_events",
        "source": "telemetry_bcc_pipe_syscalls",
        "version": "1.0",
    }
