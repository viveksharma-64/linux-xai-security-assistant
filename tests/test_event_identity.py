"""
Regression tests for event observation identity, dual clocks, and immutability.

The failure these guard against is quiet: two hosts that ran the same command at
the same second produced byte-identical events, so the deduplicating store
merged them and one host's evidence vanished with no error anywhere.
"""

import time

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from pipeline import identity
from pipeline.event_stream import CanonicalNormalizer, Event, EventType
from storage.sqlite_store import SQLiteEventStore


def _raw(**overrides):
    record = {
        "event_type": "process_exec",
        "timestamp": 1000.0,
        "pid": 1412,
        "uid": 1000,
        "comm": "bash",
        "filename": "/usr/bin/bash",
    }
    record.update(overrides)
    return record


@pytest.fixture(autouse=True)
def _clear_identity_cache():
    """Identity is process-cached; tests that change its sources must not leak."""
    identity.reset_cache()
    yield
    identity.reset_cache()


def test_normalizer_stamps_host_boot_and_agent_identity():
    event = CanonicalNormalizer().normalize(_raw())

    assert event is not None
    assert event.host_id, "events carry no host identity"
    assert event.boot_id, "events carry no boot identity"
    assert event.agent_id, "events carry no agent identity"


def test_host_id_is_derived_rather_than_the_raw_machine_id(tmp_path, monkeypatch):
    """
    machine-id(5) states the raw value is confidential and must not be used
    directly by applications. It is a stable cross-boot fingerprint of the
    machine, and this database is shipped to analysts.
    """
    machine_id = "0123456789abcdef0123456789abcdef"
    source = tmp_path / "machine-id"
    source.write_text(machine_id + "\n", encoding="utf-8")
    monkeypatch.setattr(identity, "MACHINE_ID_PATH", str(source))
    identity.reset_cache()

    derived = identity.host_id()

    assert derived is not None
    assert machine_id not in derived, "the raw machine-id leaked into the event record"
    assert derived != machine_id
    # Stability is what makes it usable as a deduplication key at all.
    identity.reset_cache()
    assert identity.host_id() == derived


def test_identity_degrades_to_unknown_rather_than_failing_ingestion(tmp_path, monkeypatch):
    """
    A container with no /etc/machine-id must still ingest. Losing telemetry is
    worse than recording it with an incomplete provenance field.
    """
    monkeypatch.setattr(identity, "MACHINE_ID_PATH", str(tmp_path / "absent"))
    identity.reset_cache()

    event = CanonicalNormalizer().normalize(_raw())

    assert event is not None, "unreadable machine-id stopped ingestion"
    assert event.host_id is None, "an unknown host was reported as a known one"


def test_agent_id_can_be_supplied_by_the_deployment(monkeypatch):
    monkeypatch.setenv(identity.AGENT_ID_ENV, "collector-7")
    identity.reset_cache()

    assert CanonicalNormalizer().normalize(_raw()).agent_id == "collector-7"


def test_recorded_identity_is_preserved_rather_than_relabelled():
    """
    A replayed capture arrives carrying the identity of the host that first saw
    it. Overwriting that would relabel another machine's evidence as this one's
    -- a confident false statement, which is worse than a null.
    """
    event = CanonicalNormalizer().normalize(
        _raw(host_id="other-host", boot_id="other-boot", agent_id="other-agent")
    )

    assert (event.host_id, event.boot_id, event.agent_id) == ("other-host", "other-boot", "other-agent")


def test_monotonic_timestamp_accompanies_the_wall_clock():
    """
    The wall clock can step backwards under NTP correction, so it cannot measure
    an interval honestly. The monotonic reading can -- but only within one boot,
    which is why boot_id must be present alongside it.
    """
    first = CanonicalNormalizer().normalize(_raw())
    time.sleep(0.01)
    second = CanonicalNormalizer().normalize(_raw(timestamp=1001.0))

    assert first.timestamp_monotonic is not None
    assert second.timestamp_monotonic > first.timestamp_monotonic
    assert first.boot_id is not None, "a monotonic reading without a boot id cannot be ordered"


def test_recorded_monotonic_timestamp_is_not_overwritten():
    assert CanonicalNormalizer().normalize(_raw(timestamp_monotonic=42.5)).timestamp_monotonic == 42.5


def test_event_is_immutable():
    """
    The evidence behind a finding must be write-once. If a stage could adjust a
    field after scoring, the value an analyst reads in an explanation would not
    provably be the value that produced the score.
    """
    event = CanonicalNormalizer().normalize(_raw())

    for attribute, value in (("timestamp", 0.0), ("uid", 0), ("host_id", "elsewhere")):
        with pytest.raises(Exception) as caught:
            setattr(event, attribute, value)
        assert "FrozenInstance" in type(caught.value).__name__, f"{attribute} is still mutable"


def test_normalizer_coercion_survives_freezing():
    """
    Coercion used to be applied by reassigning attributes after construction.
    Freezing forced it into the constructor; these are the values that path
    produced, and they must not have been lost in the move.
    """
    event = CanonicalNormalizer().normalize(_raw(timestamp="1000.5", uid="1000", pid="1412"))

    assert event.timestamp == 1000.5
    assert isinstance(event.timestamp, float)
    assert event.uid == 1000
    assert event.pid == 1412


def test_events_from_two_hosts_are_not_deduplicated_into_one(tmp_path):
    """
    The defect this whole item exists to close. Identical activity on two
    machines produced identical hashes, so the unique index dropped the second
    as a duplicate and an entire host's evidence disappeared silently.
    """
    store = SQLiteEventStore(str(tmp_path / "cross_host.db"))
    normalizer = CanonicalNormalizer()

    first = normalizer.normalize(_raw(host_id="host-a"))
    second = normalizer.normalize(_raw(host_id="host-b"))

    assert store._event_hash(first) != store._event_hash(second)
    assert store.write(first) is True
    assert store.write(second) is True, "a second host's event was swallowed as a duplicate"
    assert store.count_events() == 2


def test_restarted_agent_still_deduplicates_the_same_event(tmp_path):
    """
    The other half of the hash decision. boot_id, agent_id, and the monotonic
    reading describe the observation session and change on every restart; if
    they entered the key, re-ingesting a capture would insert a second copy of
    every row. Each is varied separately so no one of them can slip into the
    hash unnoticed behind the other two.
    """
    store = SQLiteEventStore(str(tmp_path / "restart_dedup.db"))
    normalizer = CanonicalNormalizer()
    original = normalizer.normalize(_raw())

    assert store.write(original) is True

    for excluded, value in (
        ("timestamp_monotonic", 88888.0),
        ("boot_id", "a-later-boot"),
        ("agent_id", "a-later-agent-run"),
    ):
        replayed = normalizer.normalize(_raw(**{excluded: value}))
        assert store._event_hash(replayed) == store._event_hash(original), (
            f"{excluded} entered the deduplication key"
        )
        assert store.write(replayed) is False, f"a changed {excluded} duplicated existing evidence"

    assert store.count_events() == 1


def test_equality_ignores_observation_session_but_not_host():
    """
    Equality and deduplication must agree on what "the same event" means, or
    aggregation and storage disagree about how many events there were.
    `baseline.behavior_analyzer.aggregate_windows` is documented deterministic
    and depends on this.

    Each excluded field is varied on its own. Normalizing twice in one process
    only varies the monotonic reading -- boot_id and agent_id are cached and
    identical -- so that alone would leave two of the three exclusions untested.
    """
    normalizer = CanonicalNormalizer()
    first = normalizer.normalize(_raw())
    time.sleep(0.01)
    second = normalizer.normalize(_raw())

    assert first.timestamp_monotonic != second.timestamp_monotonic
    assert first == second, "the same event read twice compared unequal"

    # Session identity varies across agent restarts and reboots; the event it
    # describes does not.
    for excluded, value in (
        ("timestamp_monotonic", 99999.0),
        ("boot_id", "a-different-boot"),
        ("agent_id", "a-different-agent"),
    ):
        assert first == normalizer.normalize(_raw(**{excluded: value})), (
            f"{excluded} makes two readings of one event compare unequal"
        )

    # host_id is on the other side of that line: two hosts doing the same thing
    # at the same instant are two events, not one.
    assert first != normalizer.normalize(_raw(host_id="somewhere-else")), (
        "two hosts' events compared equal"
    )


def test_identity_round_trips_through_storage(tmp_path):
    """
    A field the store cannot read back is a field the API and dashboard can
    never show, however carefully it was collected.
    """
    store = SQLiteEventStore(str(tmp_path / "roundtrip.db"))
    original = CanonicalNormalizer().normalize(_raw())
    store.write(original)

    restored = list(store.read_all())[0]

    assert restored == original
    assert restored.host_id == original.host_id
    assert restored.boot_id == original.boot_id
    assert restored.agent_id == original.agent_id
    assert restored.timestamp_monotonic == original.timestamp_monotonic


def test_events_are_queryable_by_host(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "by_host.db"))
    normalizer = CanonicalNormalizer()
    store.write(normalizer.normalize(_raw(host_id="host-a")))
    store.write(normalizer.normalize(_raw(host_id="host-b")))

    assert [event.host_id for event in store.query({"host_id": "host-b"})] == ["host-b"]


def test_api_exposes_event_identity(tmp_path):
    """
    read_event_records does SELECT *, and EventResponse forbids extra fields, so
    a new column that the model does not declare turns /api/events into a 500.
    """
    store = SQLiteEventStore(str(tmp_path / "identity_api.db"))
    event = CanonicalNormalizer().normalize(_raw())
    store.write(event)

    response = TestClient(create_app(store)).get("/api/events")

    assert response.status_code == 200
    record = response.json()[0]
    assert record["host_id"] == event.host_id
    assert record["boot_id"] == event.boot_id
    assert record["agent_id"] == event.agent_id
    assert record["timestamp_monotonic"] == event.timestamp_monotonic


def test_event_serialization_carries_identity():
    """
    Identity must survive both directions of the wire format, or a captured
    event loses its provenance the moment it is written to disk and read back.
    """
    event = CanonicalNormalizer().normalize(_raw())
    data = event.to_dict()

    for field_name in ("host_id", "boot_id", "agent_id", "timestamp_monotonic"):
        assert field_name in data, f"{field_name} is dropped on serialization"
        assert data[field_name] == getattr(event, field_name)

    # `from_raw_json` reads the collector wire format, where payload fields are
    # top level rather than nested, so `to_dict` output is not its input -- the
    # asymmetry predates identity. What matters here is that it reads identity
    # off the record rather than restamping it with this host's.
    revived = Event.from_raw_json({**_raw(), **{
        key: data[key] for key in ("host_id", "boot_id", "agent_id", "timestamp_monotonic")
    }})
    assert revived.host_id == event.host_id
    assert revived.boot_id == event.boot_id
    assert revived.agent_id == event.agent_id
    assert revived.timestamp_monotonic == event.timestamp_monotonic


def test_defaulted_event_has_no_invented_identity():
    """
    Constructing an Event directly must not fabricate identity. Only the
    normalizer stamps it, so a hand-built event is honestly unattributed.
    """
    event = Event(event_type=EventType.PROCESS_EXEC, timestamp=1.0)

    assert event.host_id is None
    assert event.boot_id is None
    assert event.agent_id is None
    assert event.timestamp_monotonic is None
