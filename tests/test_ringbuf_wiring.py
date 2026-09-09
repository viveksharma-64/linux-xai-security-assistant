"""Source-text gates locking the ring-buffer wiring into all three canonical
collectors.

These assert on the module source rather than importing it, for the same reason
`tests/test_perf_loss.py` does: the collectors need bcc to run but not to be read,
and the properties that matter here -- that a ring-buffer drop is *counted*, that
the perf path was not replaced but sits alongside it, that the transport is chosen
through the fail-closed selector and announced -- are all visible in the text.

If a future edit silently drops the drop counter, the perf fallback, or the
transport announcement, one of these fails.
"""

from pathlib import Path

import pytest

BCC_DIR = Path(__file__).resolve().parents[1] / "telemetry" / "bcc"

# filename -> (perf/ring buffer name, submit context arg used by perf_submit)
CANONICAL = {
    "telemetry_basic.py": "exec_events",
    "network_state_probe.py": "state_events",
    "ipc_pipe_probe.py": "pipe_events",
}

_CASES = list(CANONICAL.items())


def _source(filename: str) -> str:
    return (BCC_DIR / filename).read_text(encoding="utf-8")


@pytest.mark.parametrize("filename,buffer", _CASES)
def test_defines_ringbuf_output_and_drop_counter(filename, buffer):
    text = _source(filename)
    assert "#ifdef USE_RINGBUF" in text
    assert f"BPF_RINGBUF_OUTPUT({buffer}, " in text
    # The drop counter is what replaces the perf path's lost_cb. Without it a
    # full-ring reservation refusal is invisible.
    assert f"BPF_ARRAY({buffer}_dropped, u64, 1)" in text


@pytest.mark.parametrize("filename,buffer", _CASES)
def test_counts_every_refused_reservation(filename, buffer):
    text = _source(filename)
    assert f"{buffer}.ringbuf_reserve(sizeof(*out))" in text
    assert f"{buffer}.ringbuf_submit(out, 0)" in text
    # On a NULL reservation the program must bump the counter, not silently return.
    assert f"{buffer}_dropped.lookup(&slot)" in text
    assert "__sync_fetch_and_add(dropped, 1)" in text


@pytest.mark.parametrize("filename,buffer", _CASES)
def test_opens_ring_buffer_and_polls_the_counter(filename, buffer):
    text = _source(filename)
    assert f'["{buffer}"].open_ring_buffer(' in text
    assert "ring_buffer_poll(timeout=" in text  # bounded so the counter is read
    assert "ring_loss.poll(b)" in text
    assert f'RingBufferLossReporter(loss_reporter, map_name="{buffer}_dropped")' in text


@pytest.mark.parametrize("filename,buffer", _CASES)
def test_perf_path_is_preserved_alongside_ringbuf(filename, buffer):
    # Ring buffer is strictly additive: the perf output, its lost_cb, and its
    # unbounded poll must all still be present so a host without ring-buffer
    # support keeps the transport (and loss accounting) it always had.
    text = _source(filename)
    assert f"BPF_PERF_OUTPUT({buffer})" in text
    assert "perf_submit(" in text
    assert "open_perf_buffer(" in text
    assert "lost_cb=loss_reporter" in text


@pytest.mark.parametrize("filename", list(CANONICAL))
def test_transport_is_selected_fail_closed_and_announced(filename):
    text = _source(filename)
    # Chosen through the shared selector (which raises on an unknown knob)...
    assert "select_event_buffer(BPF)" in text
    # ...announced once at startup as the durable mechanism signal...
    assert '"event_type": "telemetry_warning"' in text
    assert '"buffer_transport": mechanism' in text
    # ...and SIGTERM routed through the flushing shutdown path.
    assert "request_keyboard_interrupt_on_sigterm()" in text


def test_pipe_drop_path_still_reaps_per_call_state():
    # ipc keeps a BPF_HASH entry per in-flight syscall. The ringbuf drop branch
    # must delete it too, or a refused reservation leaks an entry the return path
    # would otherwise never reap. One delete on the drop path + one on the submit
    # tail == two occurrences in the source.
    text = _source("ipc_pipe_probe.py")
    assert text.count("pipe_args.delete(&id)") == 2
