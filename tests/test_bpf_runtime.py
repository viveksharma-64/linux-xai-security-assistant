"""Unit tests for the BPF event-buffer transport selection in bpf_runtime.

These exercise only pure Python (no bcc, no kernel): the env parsing, the
fail-closed posture on an unrecognised knob, and the "explicit choice is never
downgraded" rule. Kernel/library capability is stubbed so the logic is tested
independently of the host these tests run on.
"""

import pytest

from telemetry.bcc import bpf_runtime
from telemetry.bcc.bpf_runtime import (
    EVENT_BUFFER_ENV,
    EVENT_BUFFER_PERF,
    EVENT_BUFFER_RINGBUF,
    ringbuf_supported,
    select_event_buffer,
)


class _RingCapableBPF:
    def ring_buffer_poll(self, timeout=0):  # pragma: no cover - presence only
        return 0


class _PerfOnlyBPF:
    pass


def test_auto_selects_ringbuf_when_supported(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: True)
    assert select_event_buffer(object(), env={}) == EVENT_BUFFER_RINGBUF
    assert (
        select_event_buffer(object(), env={EVENT_BUFFER_ENV: "auto"})
        == EVENT_BUFFER_RINGBUF
    )


def test_auto_selects_perf_when_unsupported(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: False)
    assert select_event_buffer(object(), env={}) == EVENT_BUFFER_PERF


def test_explicit_ringbuf_is_never_downgraded(monkeypatch):
    # No capability at all (bpf is None): an explicit choice still stands, so the
    # collector fails to load rather than silently running on the perf buffer.
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: False)
    assert (
        select_event_buffer(None, env={EVENT_BUFFER_ENV: "ringbuf"})
        == EVENT_BUFFER_RINGBUF
    )


def test_explicit_perf_overrides_available_ringbuf(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: True)
    assert (
        select_event_buffer(object(), env={EVENT_BUFFER_ENV: "perf"})
        == EVENT_BUFFER_PERF
    )


def test_value_is_case_and_whitespace_insensitive(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: False)
    assert (
        select_event_buffer(object(), env={EVENT_BUFFER_ENV: "  RingBuf \n"})
        == EVENT_BUFFER_RINGBUF
    )


def test_blank_value_is_treated_as_auto(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: True)
    assert (
        select_event_buffer(object(), env={EVENT_BUFFER_ENV: "   "})
        == EVENT_BUFFER_RINGBUF
    )


def test_unrecognised_value_fails_closed():
    with pytest.raises(ValueError):
        select_event_buffer(object(), env={EVENT_BUFFER_ENV: "ringbuffer"})


def test_missing_env_defaults_to_auto(monkeypatch):
    monkeypatch.delenv(EVENT_BUFFER_ENV, raising=False)
    monkeypatch.setattr(bpf_runtime, "ringbuf_supported", lambda bpf: True)
    assert select_event_buffer(object()) == EVENT_BUFFER_RINGBUF


def test_ringbuf_supported_requires_kernel_and_library(monkeypatch):
    monkeypatch.setattr(bpf_runtime, "_kernel_supports_ringbuf", lambda: True)
    assert ringbuf_supported(_RingCapableBPF()) is True
    assert ringbuf_supported(_PerfOnlyBPF()) is False  # bcc lacks ring_buffer_poll
    assert ringbuf_supported(None) is False  # bcc not importable

    monkeypatch.setattr(bpf_runtime, "_kernel_supports_ringbuf", lambda: False)
    assert ringbuf_supported(_RingCapableBPF()) is False  # kernel too old


def test_kernel_version_gate_parses_distro_suffix(monkeypatch):
    class _Uname:
        def __init__(self, release):
            self.release = release

    monkeypatch.setattr(bpf_runtime.os, "uname", lambda: _Uname("5.8.0-1-amd64"))
    assert bpf_runtime._kernel_supports_ringbuf() is True
    monkeypatch.setattr(bpf_runtime.os, "uname", lambda: _Uname("7.1.5+kali-amd64"))
    assert bpf_runtime._kernel_supports_ringbuf() is True
    monkeypatch.setattr(bpf_runtime.os, "uname", lambda: _Uname("5.7.19-amd64"))
    assert bpf_runtime._kernel_supports_ringbuf() is False
    monkeypatch.setattr(bpf_runtime.os, "uname", lambda: _Uname("4.19.0-amd64"))
    assert bpf_runtime._kernel_supports_ringbuf() is False
    monkeypatch.setattr(bpf_runtime.os, "uname", lambda: _Uname("not-a-version"))
    assert bpf_runtime._kernel_supports_ringbuf() is False
