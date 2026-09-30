#!/usr/bin/env python3
"""
Read-only host health telemetry sampled from psutil.

Why this exists
---------------
`detection/system_failure.py` scores `system_health` events into availability
findings -- disk exhaustion, memory pressure, sustained CPU saturation. Until
this collector existed nothing in a deployment emitted that event type: the two
BCC collectors that sampled memory are both marked DEPRECATED/LEGACY and
explicitly not for live telemetry, and the one live variant
(`telemetry/bcc/telemetry_basic.py`) emits health from inside a `process_exec`
poll loop, so wiring it alongside the already-supervised `process_exec_probe.py`
would have double-counted every exec. The detector was therefore live but
unreachable, and none of its disk rules could ever fire because no variant
sampled disk at all.

A dedicated sampler is the honest fix: one process, one event type, no overlap
with the security collectors.

Deliberately not eBPF
---------------------
Every signal here comes from `/proc` via psutil, so this collector needs **no
capabilities** -- no `CAP_BPF`, no `CAP_SYS_ADMIN`, no root. It is the one
supervised source that keeps working on a kernel where BCC cannot attach, which
also makes it the source that proves the pipeline is alive when the eBPF probes
are degraded.

Sampling, not averaging
-----------------------
Each emission is an instantaneous sample, except CPU: `psutil.cpu_percent`
measures utilisation *since the previous call*, so the value published at each
tick is the mean over the preceding interval. The first call after start has no
predecessor and would report a meaningless 0.0, so the first sample publishes
`cpu_percent: null` rather than a fabricated idle reading. The detector already
treats the field as optional (`float | None`) for exactly this reason.

Contract with the pipeline
--------------------------
JSONL on stdout, one object per line, flushed per record -- the supervised
`SubprocessJSONLSource` contract. Field names are top-level and match what
`Event.from_raw_json` reads for `SYSTEM_HEALTH` (cpu_percent, mem_percent,
disk_percent, mem_available_mb); nesting them would silently normalize to a
payload of all-null and the detector would never fire.
"""

import argparse
import json
import signal
import sys
import threading
import time
from typing import Any, Dict, Optional, TextIO

try:  # Importable both as a package module and as a sibling file.
    import psutil
except ImportError:  # pragma: no cover - exercised only on a host without psutil
    psutil = None  # type: ignore[assignment]

COLLECTOR_NAME = "system_health"
DEFAULT_INTERVAL_SECONDS = 30.0
DEFAULT_DISK_PATH = "/"
SOURCE = "psutil_host"
VERSION = "1.0"

# A sample cadence below this would add measurable load without adding signal:
# the detector aggregates into 300s windows and requires several consecutive
# breaching windows before it fires, so sub-second sampling changes nothing it
# can observe.
MIN_INTERVAL_SECONDS = 1.0


class SystemHealthCollector:
    """
    Emit one `system_health` record per interval until asked to stop.

    Split from `main()` so a test can drive `sample()` and `run()` directly
    against a fake clock and an in-memory stream, without a subprocess.
    """

    def __init__(
        self,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        disk_path: str = DEFAULT_DISK_PATH,
        output: Optional[TextIO] = None,
    ) -> None:
        self.interval = max(MIN_INTERVAL_SECONDS, float(interval))
        self.disk_path = disk_path
        self._output = output
        # An Event rather than `time.sleep`: a stop arriving mid-interval must
        # end the process now, not up to `interval` seconds later, because the
        # supervisor terminates and then waits on its children.
        self._stop = threading.Event()
        self._cpu_primed = False

    @property
    def output(self) -> TextIO:
        # Resolved late so a caller can swap sys.stdout before run().
        return self._output if self._output is not None else sys.stdout

    def stop(self) -> None:
        """Ask the loop to end. Safe from a signal handler."""
        self._stop.set()

    def sample(self) -> Dict[str, Any]:
        """
        One health reading, with every metric independently best-effort.

        A metric that cannot be read is published as `null` rather than omitted
        or faked: the detector distinguishes "not measured" from "measured and
        fine", and a failing disk path must not suppress the memory rules.
        """
        record: Dict[str, Any] = {
            "event_type": "system_health",
            "timestamp": time.time(),
            "cpu_percent": None,
            "mem_percent": None,
            "disk_percent": None,
            "mem_available_mb": None,
            "source": SOURCE,
            "version": VERSION,
        }
        if psutil is None:
            return record

        try:
            memory = psutil.virtual_memory()
            record["mem_percent"] = float(memory.percent)
            record["mem_available_mb"] = int(memory.available // (1024 * 1024))
        except (OSError, psutil.Error, ValueError):
            pass

        try:
            usage = psutil.disk_usage(self.disk_path)
            record["disk_percent"] = float(usage.percent)
        except (OSError, psutil.Error, ValueError):
            pass

        try:
            cpu = psutil.cpu_percent(interval=None)
            # The priming call has no previous sample to difference against and
            # always answers 0.0; publishing that would report an idle host.
            record["cpu_percent"] = float(cpu) if self._cpu_primed else None
            self._cpu_primed = True
        except (OSError, psutil.Error, ValueError):
            pass

        return record

    def emit(self, record: Dict[str, Any]) -> None:
        print(json.dumps(record, sort_keys=True), file=self.output, flush=True)

    def run(self, max_samples: Optional[int] = None) -> int:
        """
        Sample and emit until stopped, or until `max_samples` records (tests).

        A broken stdout is the supervisor going away, which is a normal end of
        session rather than a fault, so it ends the loop quietly instead of
        raising into a traceback in the journal.
        """
        emitted = 0
        while not self._stop.is_set():
            try:
                self.emit(self.sample())
            except (BrokenPipeError, ValueError):
                return 0
            emitted += 1
            if max_samples is not None and emitted >= max_samples:
                return 0
            self._stop.wait(self.interval)
        return 0


def install_signal_handlers(collector: SystemHealthCollector) -> tuple:
    """Make SIGTERM and SIGINT end the loop cleanly. Returns the signals handled."""

    def _handle(signum, _frame):  # pragma: no cover - exercised by signal delivery
        collector.stop()

    handled = []
    for signal_number in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(signal_number, _handle)
        except ValueError:
            # Not the main thread, or the platform lacks the signal; the loop
            # still stops through stop().
            continue
        handled.append(signal_number)
    return tuple(handled)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only host health telemetry (CPU, memory, disk) sampled from psutil.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"seconds between samples (default {DEFAULT_INTERVAL_SECONDS:g}, minimum {MIN_INTERVAL_SECONDS:g})",
    )
    parser.add_argument(
        "--disk-path",
        default=DEFAULT_DISK_PATH,
        help=f"filesystem to report usage for (default {DEFAULT_DISK_PATH})",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="stop after this many samples (default: run until signalled)",
    )
    args = parser.parse_args(argv)

    if psutil is None:
        print("psutil is required for health telemetry", file=sys.stderr)
        return 1

    collector = SystemHealthCollector(interval=args.interval, disk_path=args.disk_path)
    install_signal_handlers(collector)
    return collector.run(max_samples=args.max_samples)


if __name__ == "__main__":
    raise SystemExit(main())
