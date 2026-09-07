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

import sys
from typing import Any, Optional

INSTALL_HINT = (
    "ERROR: could not import bcc (BPF Compiler Collection). Install with:\n"
    "    sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc\n"
    "Kernel probes also require root and CAP_BPF/CAP_SYS_ADMIN.\n"
)


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
