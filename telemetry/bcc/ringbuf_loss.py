"""
Kernel-side event-loss accounting for BCC BPF ring buffers.

Why a second reporter exists
----------------------------
The perf buffer reports discards through `open_perf_buffer(..., lost_cb=...)`: bcc
hands userspace the exact number of samples the kernel dropped. The ring buffer
has no such callback -- `open_ring_buffer(callback)` takes no `lost_cb` -- so a
`bpf_ringbuf_reserve` that returns NULL because the buffer is full is invisible
unless the BPF program counts it. Each ring-buffer collector therefore keeps a
one-element `BPF_ARRAY(<buffer>_dropped, u64, 1)` and does
`__sync_fetch_and_add(dropped, 1)` on every refused reservation.

`RingBufferLossReporter` reads that absolute counter and turns it into the same
per-poll *delta* the perf path's `lost_cb` delivers -- then hands the delta to the
*shared* `PerfBufferLossReporter`. That single delegation is deliberate: the
coalescing window, the running `total_lost_events`, and the exact `telemetry_loss`
wire record (frozen at version 1.0) are then one implementation across both
transports. The supervisor cannot tell the two apart from the loss record, and is
not meant to; the active transport is announced once, at startup, through the
durable `telemetry_warning`.

Guards (each protects the loss-accounting invariant that a count is never
invented and never silently dropped):
  * An unreadable map is not zero. Returning 0 would manufacture a "no loss"
    signal out of a transient read failure, so an unreadable counter reports
    nothing and leaves the last-seen value untouched.
  * A counter that went *backwards* means the map was recreated (a program
    reload -- the counter only grows within one loaded program). Resync to the
    new value without emitting a negative or bogus delta.
  * An unchanged counter emits nothing.

This module, like `perf_loss`, does not import bcc: it is handed the loaded `BPF`
object and only indexes it, so it stays importable and unit-testable off-host.
"""

from __future__ import annotations

import ctypes
from typing import Any, Optional

# The drop counter is a BPF_ARRAY of length 1; its only element lives at key 0.
_COUNTER_KEY = ctypes.c_int(0)


class RingBufferLossReporter:
    """Poll a BPF drop counter and forward deltas to a PerfBufferLossReporter."""

    def __init__(self, reporter: Any, *, map_name: str) -> None:
        # `reporter` is the shared PerfBufferLossReporter (a callable taking a
        # lost-count int). Delegating to it keeps one wire format for both paths.
        self._reporter = reporter
        self.map_name = map_name
        self._last_seen = 0

    def poll(self, bpf: Any) -> None:
        """Read the counter once and report any newly dropped samples."""
        current = self._read(bpf)
        if current is None:
            # Unreadable: silence is not evidence of no loss. Do not emit, and do
            # not advance the baseline -- the next successful read still counts
            # everything dropped in the meantime.
            return
        if current < self._last_seen:
            # The map was recreated (reload). Adopt the new baseline without
            # inventing a loss event from a counter that appears to have shrunk.
            self._last_seen = current
            return
        delta = current - self._last_seen
        self._last_seen = current
        if delta:
            self._reporter(delta)

    def _read(self, bpf: Any) -> Optional[int]:
        try:
            leaf = bpf[self.map_name][_COUNTER_KEY]
        except Exception:
            # Any indexing/lookup failure (map absent, bcc quirk) is treated as
            # "unreadable", never as zero. KeyboardInterrupt is a BaseException
            # and is intentionally not caught here.
            return None
        value = getattr(leaf, "value", leaf)
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
