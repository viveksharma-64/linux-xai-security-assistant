from pipeline.event_stream import CanonicalNormalizer, EventType
from storage.sqlite_store import SQLiteEventStore
from telemetry.journald.service_monitor import normalize_journal_record, parse_journal_json


def _record(message, **values):
    return {
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": "1700000000123456",
        "_SYSTEMD_UNIT": "init.scope",
        "SYSLOG_IDENTIFIER": "systemd",
        "_PID": "1",
        "_UID": "0",
        **values,
    }


def test_explicit_systemd_start_normalizes_to_canonical_service_event():
    raw = normalize_journal_record(_record("Started example.service - Example Service."))

    assert raw["unit"] == "example.service"
    assert raw["action"] == "started"
    assert raw["result"] == "success"
    event = CanonicalNormalizer().normalize(raw)
    assert event.event_type == EventType.SERVICE_STATE
    assert event.payload == {
        "unit": "example.service", "reporter_unit": "init.scope", "action": "started", "result": "success",
        "message": "Started example.service - Example Service.",
    }


def test_explicit_stop_and_failure_are_classified():
    stopped = normalize_journal_record(_record("Stopped example.service - Example Service."))
    failed = normalize_journal_record(_record("Failed to start example.service - Example Service."))

    assert (stopped["action"], stopped["result"]) == ("stopped", "success")
    assert (failed["action"], failed["result"]) == ("failed", "failure")


def test_missing_optional_metadata_and_sqlite_persistence_are_supported(tmp_path):
    raw = normalize_journal_record(_record("Started example.service - Example Service.", _PID=None, _UID=None))
    event = CanonicalNormalizer().normalize(raw)
    store = SQLiteEventStore(str(tmp_path / "service.db"))

    assert event.pid is None and event.uid is None
    assert store.write(event) is True
    assert list(store.read_all())[0].event_type == EventType.SERVICE_STATE


def test_non_systemd_or_ambiguous_records_are_ignored():
    records = [
        _record("Started example.service - Example Service.", SYSLOG_IDENTIFIER="example"),
        _record("Example service is running"),
        _record("Started example.service - Example Service.", _SYSTEMD_UNIT=None),
    ]
    assert [normalize_journal_record(record) for record in records] == [None, None, None]
    assert list(parse_journal_json(['not json'])) == []
