"""
Kernel-side event-loss reporting for BCC perf buffers.

Why this exists
---------------
`open_perf_buffer(handler)` with no `lost_cb` makes a ring-buffer overrun
completely silent. The kernel discards samples the collector never reads, the
JSONL stream simply has a hole in it, and nothing anywhere records that a hole
exists. That is the same failure the ingestion queue's drop accounting was built
to close, one layer lower and strictly worse: a queue drop happens to an event
this process has already seen and could count, while a perf overrun destroys the
event before userspace ever hears about it. A gap in the evidence behind a
security finding has to be stated, not inferred from a quiet graph.

What it reports and where
-------------------------
A JSON record on the collector's stdout, the same channel the events themselves
travel on, because that is the only channel the supervisor parses -- collector
stderr is captured into a small ring used solely to explain a non-zero exit, so
a loss report written there would never reach the health record. The record is
deliberately not a canonical `EventType`: it describes the collector, not the
machine, and storing it as an event would add rows to the evidence table and
move the window features every baseline and ML stage reads.

Coalescing
----------
`lost_cb` fires per poll per CPU that overran, so under sustained loss it can
fire many times a second -- and it does so exactly when the pipe it would write
to is already congested. Reports are therefore coalesced to at most one per
`report_interval_seconds`, with the suppressed counts accumulated into the next
record rather than discarded. Rate limiting a log line may drop a line; rate
limiting the transport must never drop a count, or the total the analyst reads
understates the gap.

Registration is per online CPU
------------------------------
`PerfEventArray.open_perf_buffer` registers the callback once for every online
CPU, so one reporter instance must be shared across those registrations to
produce a process-wide total. bcc invokes the callback synchronously on whichever
thread called `perf_buffer_poll`, so the per-CPU registrations are serialized and
the counters need no lock; a collector polling one `BPF` object from two threads
would be broken for reasons well beyond this accounting.
"""

import json
import sys
import time
from typing import Any, Optional, TextIO

# The wire name of the loss record. `pipeline.live_ingestion` carries its own
# copy because a collector run as a bare script -- which is how the README
# invokes them -- cannot import the package. `tests/test_perf_loss.py` pins the
# two together.
LOSS_EVENT_TYPE = "telemetry_loss"

DEFAULT_REPORT_INTERVAL_SECONDS = 1.0


class PerfBufferLossReporter:
    """
    A one-argument `lost_cb` that reports dropped samples on stdout.

    Pass the instance straight to `open_perf_buffer(handler, lost_cb=reporter)`:
    bcc calls it as `lost_cb(lost)` with the number of samples the kernel
    discarded since the previous report for that CPU.
    """

    def __init__(
        self,
        buffer_name: str,
        source: str,
        stream: Optional[TextIO] = None,
        report_interval_seconds: float = DEFAULT_REPORT_INTERVAL_SECONDS,
        clock: Any = time.monotonic,
        wall_clock: Any = time.time,
    ):
        if report_interval_seconds < 0:
            raise ValueError("report_interval_seconds must not be negative")
        self.buffer_name = buffer_name
        self.source = source
        self.report_interval_seconds = report_interval_seconds
        # `total_lost_events` is this collector's running total since it started.
        # The supervisor sums the per-record increments instead of trusting this,
        # because a restarted collector resets it -- but it travels in the record
        # so the two can be cross-checked when they disagree.
        self.total_lost_events = 0
        self._stream = stream
        self._clock = clock
        self._wall_clock = wall_clock
        self._pending = 0
        self._last_report: Optional[float] = None

    def __call__(self, lost: int) -> None:
        try:
            lost = int(lost)
        except (TypeError, ValueError):
            return
        if lost <= 0:
            return
        self.total_lost_events += lost
        self._pending += lost
        now = self._clock()
        if self._last_report is not None and now - self._last_report < self.report_interval_seconds:
            return
        self._emit(now)

    def flush(self) -> None:
        """
        Report any coalesced remainder.

        Called on the collector's shutdown path so a burst that stopped inside
        the last reporting window is still accounted for. Without this the tail
        of a loss episode would only surface if loss happened to resume.
        """
        self._emit(self._clock())

    def _emit(self, now: float) -> None:
        if self._pending <= 0:
            return
        record = {
            "event_type": LOSS_EVENT_TYPE,
            "timestamp": self._wall_clock(),
            "lost_events": self._pending,
            "total_lost_events": self.total_lost_events,
            "buffer": self.buffer_name,
            "source": self.source,
            "version": "1.0",
        }
        # Resolved here rather than in __init__ so a stream swapped after
        # construction -- a test's capture, or a reopened stdout -- is honoured.
        stream = self._stream if self._stream is not None else sys.stdout
        print(json.dumps(record), file=stream, flush=True)
        self._pending = 0
        self._last_report = now
