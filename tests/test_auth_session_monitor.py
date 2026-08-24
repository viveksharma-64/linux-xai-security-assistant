from pipeline.event_stream import CanonicalNormalizer, EventType
from storage.sqlite_store import SQLiteEventStore
from telemetry.journald.auth_session_monitor import normalize_journal_record, parse_journal_json


def _record(message, **values):
    return {
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": "1700000000123456",
        "_PID": "77",
        "_UID": "0",
        "SYSLOG_IDENTIFIER": "cron",
        **values,
    }


def test_pam_session_record_normalizes_to_canonical_auth_event():
    raw = normalize_journal_record(_record("pam_unix(cron:session): session opened for user root(uid=0)"))

    assert raw["action"] == "session_opened"
    assert raw["result"] == "success"
    assert raw["service"] == "cron"
    assert raw["account"] == "root"
    event = CanonicalNormalizer().normalize(raw)
    assert event.event_type == EventType.AUTH_SESSION
    assert event.pid == 77
    assert event.payload == {
        "action": "session_opened", "result": "success", "service": "cron",
        "account": "root", "message": raw["message"],
    }


def test_auth_event_persists_through_existing_sqlite_boundary(tmp_path):
    raw = normalize_journal_record(_record("pam_unix(sudo:session): session closed for user root"))
    event = CanonicalNormalizer().normalize(raw)
    store = SQLiteEventStore(str(tmp_path / "auth.db"))

    assert store.write(event) is True
    stored = list(store.read_all())[0]
    assert stored.event_type == EventType.AUTH_SESSION
    assert stored.payload["service"] == "sudo"


def test_pam_auth_failure_is_retained_without_inventing_an_account():
    raw = normalize_journal_record(_record("pam_unix(sudo:auth): authentication failure; logname=user uid=1000"))

    assert raw["action"] == "authentication"
    assert raw["result"] == "failure"
    assert raw["service"] == "sudo"
    assert raw["account"] is None


def test_unrelated_or_malformed_journal_records_are_skipped():
    records = [
        json_line for json_line in (
            '{"MESSAGE":"ordinary daemon message","__REALTIME_TIMESTAMP":"1700000000123456"}',
            'not json',
            '{"MESSAGE":"pam_unix(cron:session): session opened for user root"}',
        )
    ]
    assert list(parse_journal_json(records)) == []
