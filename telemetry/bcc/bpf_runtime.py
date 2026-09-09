"""
Deferred BPF availability check, shared by the eBPF collectors.

Why this exists
---------------
The probe modules serve two audiences. Run as a script, a probe attaches kernel
programs and needs `bcc`. Imported, the same module offers pure functions --
`normalize_pipe_event`, `format_address`, the `BPF_PROGRAM` source itself -- that
parse and shape collector output with no kernel involvement at all. Those helpers
are what the test suite exercises, and what an offline analysis of recorded
telemetry would use.

Killing the interpreter at import time collapses those two audiences into one. A
module-level `raise SystemExit(1)` in the `except ImportError` branch means that on
any host without `bcc` -- every CI runner, every developer laptop -- importing the
module to call a pure function terminates the process instead. Under pytest that is
not even a test failure: collection aborts with INTERNALERROR, because the
collector is importing a module that decides to end the run.

So the import is allowed to fail softly, `BPF` is left as `None`, and the check
moves to the point where it is actually true that the program cannot continue:
`main()`, where a kernel probe is about to be attached. A host that cannot attach
probes still gets the same message and the same non-zero exit; a host that only
wanted to parse a JSON line gets to do it.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Mapping, Optional

INSTALL_HINT = (
    "ERROR: could not import bcc (BPF Compiler Collection). Install with:\n"
    "    sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc\n"
    "Kernel probes also require root and CAP_BPF/CAP_SYS_ADMIN.\n"
)

# Operator knob choosing how a collector ships events from kernel to userspace.
#   auto    -- ringbuf when both kernel and bcc support it, else perf (default)
#   ringbuf -- force the BPF ring buffer
#   perf    -- force the per-CPU perf buffer
# An explicit choice is honoured verbatim: it is never silently downgraded to the
# other transport. If the chosen mechanism then fails to load, the collector
# reports the failure and exits, rather than quietly running on the fallback --
# the same fail-closed posture the rest of the pipeline takes.
EVENT_BUFFER_ENV = "SECURITY_BPF_EVENT_BUFFER"
EVENT_BUFFER_AUTO = "auto"
EVENT_BUFFER_RINGBUF = "ringbuf"
EVENT_BUFFER_PERF = "perf"
_VALID_EVENT_BUFFERS = (EVENT_BUFFER_AUTO, EVENT_BUFFER_RINGBUF, EVENT_BUFFER_PERF)

# BPF ring buffers (BPF_RINGBUF_OUTPUT / bpf_ringbuf_reserve) landed in 5.8.
_RINGBUF_MIN_KERNEL = (5, 8)

# The ring buffer has no lost_cb, so its drop counter is read by polling a BPF
# map rather than delivered by a callback. A bounded poll timeout (milliseconds)
# guarantees the counter is read on a regular cadence even when the buffer is so
# full that no completed samples wake the poller, and keeps shutdown responsive.
RINGBUF_POLL_TIMEOUT_MS = 200


def _kernel_supports_ringbuf() -> bool:
    """True when the running kernel is new enough for BPF ring buffers."""
    try:
        release = os.uname().release
    except (AttributeError, OSError):
        return False
    numeric = release.split("-", 1)[0].split(".")
    try:
        major = int(numeric[0])
        minor = int(numeric[1]) if len(numeric) > 1 else 0
    except (IndexError, ValueError):
        return False
    return (major, minor) >= _RINGBUF_MIN_KERNEL


def ringbuf_supported(bpf: Optional[Any]) -> bool:
    """
    True only when both halves of the ring buffer are present.

    The kernel must be >= 5.8 for the ring buffer to exist, and the installed bcc
    must expose `ring_buffer_poll` to drive it from userspace. Either missing --
    or bcc not importable at all (`bpf is None`) -- means the perf buffer is the
    only transport actually available.
    """
    if bpf is None:
        return False
    return hasattr(bpf, "ring_buffer_poll") and _kernel_supports_ringbuf()


def select_event_buffer(
    bpf: Optional[Any], *, env: Optional[Mapping[str, str]] = None
) -> str:
    """
    Resolve SECURITY_BPF_EVENT_BUFFER to a concrete transport: 'ringbuf' or 'perf'.

    `auto` (the default) picks the ring buffer when `ringbuf_supported` says both
    kernel and bcc can drive it, otherwise the perf buffer. An explicit `ringbuf`
    or `perf` is returned unchanged -- deciding to downgrade an explicit choice is
    the caller's business, not this function's, and it does not. An unrecognised
    value raises ValueError so a typo fails closed rather than silently meaning
    'perf'.
    """
    source = os.environ if env is None else env
    raw = source.get(EVENT_BUFFER_ENV, EVENT_BUFFER_AUTO)
    choice = raw.strip().lower() or EVENT_BUFFER_AUTO
    if choice not in _VALID_EVENT_BUFFERS:
        raise ValueError(
            f"{EVENT_BUFFER_ENV}={raw!r} is not one of "
            f"{', '.join(_VALID_EVENT_BUFFERS)}"
        )
    if choice == EVENT_BUFFER_AUTO:
        return EVENT_BUFFER_RINGBUF if ringbuf_supported(bpf) else EVENT_BUFFER_PERF
    return choice


def request_keyboard_interrupt_on_sigterm() -> None:
    """
    Route SIGTERM through the same shutdown path as Ctrl+C.

    The supervisor stops a collector with SIGTERM, whose default action is to
    terminate the process without raising anything. The `except KeyboardInterrupt`
    branch that flushes the loss reporter would then never run on a normal stop,
    and a loss burst inside the final reporting window would die unreported with
    the process. Translating SIGTERM into KeyboardInterrupt sends both stop
    signals through the one flushing shutdown path the collectors already have.
    """
    import signal

    def _raise(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _raise)


def load_bpf() -> Optional[Any]:
    """Return the `BPF` class, or None when bcc is not installed."""
    try:
        from bcc import BPF  # type: ignore[import-not-found]
    except ImportError:
        return None
    return BPF


def require_bpf(bpf: Optional[Any]) -> Any:
    """
    Assert that bcc was importable, exiting with the install hint if it was not.

    Called from `main()` rather than at import so the exit happens when a kernel
    probe is genuinely needed. Raises SystemExit, which propagates through `main()`
    to the interpreter as exit status 1 without a traceback.
    """
    if bpf is None:
        sys.stderr.write(INSTALL_HINT)
        raise SystemExit(1)
    return bpf
