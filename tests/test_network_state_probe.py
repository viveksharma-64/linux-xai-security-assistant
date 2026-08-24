import socket
from types import SimpleNamespace

import pytest

from pipeline.event_stream import Event, EventType
from storage.sqlite_store import SQLiteEventStore
from telemetry.bcc.network_state_probe import (
    AF_INET,
    IPPROTO_TCP,
    TCP_ESTABLISHED,
    TCP_SYN_SENT,
    BPF_PROGRAM,
    normalize_state_event,
)
import telemetry.bcc.network_state_probe as network_state_probe


def test_tracepoint_constants_match_kernel_contract():
    assert (AF_INET, IPPROTO_TCP, TCP_ESTABLISHED, TCP_SYN_SENT) == (2, 6, 1, 2)
    assert "TRACEPOINT_PROBE(sock, inet_sock_set_state)" in BPF_PROGRAM
    assert "args->family" in BPF_PROGRAM
    assert "args->protocol" in BPF_PROGRAM
    assert "args->oldstate" in BPF_PROGRAM
    assert "args->newstate" in BPF_PROGRAM
    assert "args->family != AF_INET || args->protocol != IPPROTO_TCP" in BPF_PROGRAM
    assert "args->oldstate != TCP_SYN_SENT || args->newstate != TCP_ESTABLISHED" in BPF_PROGRAM
    assert "args->daddr" in BPF_PROGRAM
    assert "bpf_get_current_pid_tgid" in BPF_PROGRAM
    assert "bpf_get_current_uid_gid" in BPF_PROGRAM
    assert "bpf_get_current_comm" in BPF_PROGRAM
    assert "event.daddr[0] = args->daddr[0]" in BPF_PROGRAM
    assert "event.dport = args->dport" in BPF_PROGRAM
    assert "ntohs(args->dport)" not in BPF_PROGRAM
    assert "<net/sock.h>" not in BPF_PROGRAM


def test_established_ipv4_state_normalizes_to_tcp_connect():
    event = SimpleNamespace(
        pid=1234,
        uid=1000,
        comm=b"curl\0ignored",
        daddr=bytes((127, 0, 0, 1)),
        dport=443,
        timestamp_ns=987654321,
    )
    normalized = normalize_state_event(event, timestamp=1700000000.5)

    assert normalized == {
        "event_type": "tcp_connect",
        "timestamp": 1700000000.5,
        "timestamp_ns": 987654321,
        "pid": 1234,
        "uid": 1000,
        "comm": "curl",
        "dest_ip": "127.0.0.1",
        "dest_port": 443,
        "source": "telemetry_bcc_network_state",
        "version": "1.0",
    }


def test_normalized_tcp_event_round_trips_through_canonical_sqlite(tmp_path):
    event = SimpleNamespace(
        pid=4321,
        uid=1000,
        comm="python",
        daddr=bytes((127, 0, 0, 1)),
        dport=8443,
        timestamp_ns=123,
    )
    raw = normalize_state_event(event, timestamp=1700000001.0)
    canonical = Event.from_raw_json(raw)
    assert canonical.event_type == EventType.TCP_CONNECT
    assert canonical.payload == {"dest_ip": "127.0.0.1", "dest_port": 8443}

    store = SQLiteEventStore(str(tmp_path / "network-state.db"))
    assert store.write(canonical) is True
    stored = list(store.read_all())[0]
    assert stored.event_type == EventType.TCP_CONNECT
    assert stored.payload["dest_ip"] == "127.0.0.1"
    assert stored.payload["dest_port"] == 8443


def test_tracepoint_address_bytes_and_network_order_port_are_decoded_once():
    event = SimpleNamespace(
        pid=789,
        uid=1000,
        comm=b"curl\0",
        daddr=bytes((93, 184, 216, 34)),
        dport=443,
        timestamp_ns=10,
    )
    normalized = normalize_state_event(event, timestamp=1.0)

    assert normalized["dest_ip"] == "93.184.216.34"
    assert normalized["dest_port"] == 443
    assert normalized["pid"] == 789
    assert normalized["uid"] == 1000
    assert normalized["comm"] == "curl"


@pytest.mark.parametrize(
    "event",
    [
        SimpleNamespace(pid=0, uid=1000, comm="curl", daddr=bytes((1, 2, 3, 4)), dport=443, timestamp_ns=1),
        SimpleNamespace(pid=1, uid=-1, comm="curl", daddr=bytes((1, 2, 3, 4)), dport=443, timestamp_ns=1),
        SimpleNamespace(pid=1, uid=1000, comm="curl", daddr=bytes((1, 2, 3)), dport=443, timestamp_ns=1),
        SimpleNamespace(pid=1, uid=1000, comm="curl", daddr=bytes((1, 2, 3, 4)), dport=0, timestamp_ns=1),
    ],
)
def test_malformed_state_payload_is_rejected(event):
    assert normalize_state_event(event, timestamp=1.0) is None


def test_invalid_perf_payload_does_not_emit_json_null(monkeypatch, capsys):
    invalid = SimpleNamespace(
        pid=0,
        uid=1000,
        comm=b"curl\0",
        daddr=bytes((127, 0, 0, 1)),
        dport=443,
        timestamp_ns=1,
    )
    monkeypatch.setattr(
        network_state_probe,
        "b",
        {"state_events": SimpleNamespace(event=lambda _: invalid)},
        raising=False,
    )

    network_state_probe.handle_state_event(0, object(), 0)

    assert capsys.readouterr().out == ""
