"""
Regression bar for streaming journald collection with cursor persistence.

The properties pinned here are the ones whose violation is silent. A journald
collector that loses its place does not crash and does not log an error; it just
reports less than the host did, which is indistinguishable from a quiet host and
is exactly the shape of an intrusion nobody noticed. So the tests below are
weighted toward the invisible failures:

* a cursor that cannot be resumed from is reported, not silently substituted;
* a cursor is never persisted ahead of the event it claims to cover;
* the cursor advances over records the collector does not care about, so a quiet
  period cannot turn a restart into hours of re-reading;
* the one-shot query path and the streaming path derive the same events, so the
  tested-but-unused function cannot drift away from the live one.

Almost everything runs against a fake journalctl injected through
`journalctl_command`, because the real journal's content is not reproducible and
the failure cases (a cursor past the end of the journal, a rotation mid-stream)
cannot be provoked on demand. Two tests do use the real journalctl, guarded by
`shutil.which`, to keep the fake honest about the wire behaviour it imitates.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from telemetry.journald.auth_session_monitor import (
    normalize_journal_record as normalize_auth,
    parse_journal_json as parse_auth,
)
from telemetry.journald.journal_stream import (
    CURSOR_RESUMABLE,
    CURSOR_UNREADABLE,
    CURSOR_UNRESOLVABLE,
    CursorStore,
    JournalCollector,
    JournalReadError,
    JournalStream,
    StaleCursorError,
    build_command,
    default_cursor_path,
    default_state_dir,
    is_valid_cursor,
)
from telemetry.journald.service_monitor import (
    normalize_journal_record as normalize_service,
    parse_journal_json as parse_service,
)

VALID_CURSOR = (
    "s=a0c625cc5fe04058a3411389ce43c6d6;i=39646;"
    "b=c0c84a4353e447269bbb0bba7a8281ce;m=333303b;t=65aa84297bf34;x=154f10d27daee621"
)
OTHER_CURSOR = VALID_CURSOR.replace("i=39646", "i=39647")

FAKE_JOURNALCTL = '''
import json, os, sys, time
config = json.load(open(os.environ["FAKE_JOURNALCTL_CONFIG"]))
with open(os.environ["FAKE_JOURNALCTL_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
mode = "probe" if any(a == "--lines=1" for a in sys.argv[1:]) else "stream"
response = config.get(mode, {})
time.sleep(response.get("delay", 0))
between = response.get("between", 0)
lines = response.get("stdout", []) * response.get("repeat", 1)
for index, line in enumerate(lines):
    if index and between:
        time.sleep(between)
    sys.stdout.write(line + "\\n")
    sys.stdout.flush()
sys.stderr.write(response.get("stderr", ""))
sys.exit(response.get("returncode", 0))
'''


def _auth_record(message, cursor=VALID_CURSOR, **values):
    record = {
        "__CURSOR": cursor,
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": "1700000000123456",
        "_PID": "77",
        "_UID": "0",
        "SYSLOG_IDENTIFIER": "cron",
    }
    record.update(values)
    return record


def _session_opened(user="root", cursor=VALID_CURSOR):
    return _auth_record(
        f"pam_unix(cron:session): session opened for user {user}(uid=0)", cursor=cursor
    )


def _unrelated(cursor=VALID_CURSOR):
    return _auth_record("ordinary daemon message that matches nothing", cursor=cursor)


class RecordingStream:
    """Collects written lines and exposes the parsed JSON objects."""

    def __init__(self):
        self.lines = []

    def write(self, text):
        if text.strip():
            self.lines.append(text.strip())
        return len(text)

    def flush(self):
        pass

    def _parsed(self):
        return [json.loads(line) for line in self.lines]

    @property
    def events(self):
        return [r for r in self._parsed() if not r["event_type"].startswith("telemetry_")]

    @property
    def notices(self):
        return [r for r in self._parsed() if r["event_type"].startswith("telemetry_")]

    def of_type(self, event_type):
        return [r for r in self._parsed() if r["event_type"] == event_type]


class FlushTrackingStream(RecordingStream):
    """Counts writes since the last flush, so buffered output is observable."""

    def __init__(self):
        super().__init__()
        self.unflushed = 0

    def write(self, text):
        self.unflushed += 1
        return super().write(text)

    def flush(self):
        self.unflushed = 0


class FakeJournalctl:
    """A journalctl stand-in whose output, exit status, and argv are controllable."""

    def __init__(self, tmp_path, monkeypatch):
        self.script = tmp_path / "fake_journalctl.py"
        self.script.write_text(FAKE_JOURNALCTL, encoding="utf-8")
        self.config_path = tmp_path / "fake_config.json"
        self.log_path = tmp_path / "fake_argv.log"
        self.log_path.write_text("", encoding="utf-8")
        monkeypatch.setenv("FAKE_JOURNALCTL_CONFIG", str(self.config_path))
        monkeypatch.setenv("FAKE_JOURNALCTL_LOG", str(self.log_path))
        self.configure()

    def configure(self, probe=None, stream=None):
        config = {
            "probe": probe if probe is not None else {"stdout": ["{}"], "returncode": 0},
            "stream": stream if stream is not None else {"stdout": [], "returncode": 0},
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

    def serve(self, records, returncode=0, stderr="", probe=None, repeat=1):
        self.configure(
            probe=probe,
            stream={
                "stdout": [json.dumps(record) for record in records],
                "returncode": returncode,
                "stderr": stderr,
                "repeat": repeat,
            },
        )

    @property
    def command(self):
        return [sys.executable, str(self.script)]

    @property
    def invocations(self):
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def new_stream(self):
        return JournalStream(journalctl_command=self.command)


@pytest.fixture
def fake_journalctl(tmp_path, monkeypatch):
    return FakeJournalctl(tmp_path, monkeypatch)


def _collector(fake_journalctl, tmp_path, normalize=normalize_auth, **overrides):
    output = RecordingStream()
    collector = JournalCollector(
        name=overrides.pop("name", "auth"),
        normalize=normalize,
        cursor_store=overrides.pop("cursor_store", CursorStore(tmp_path / "c.cursor")),
        stream=fake_journalctl.new_stream(),
        output=output,
        **overrides,
    )
    return collector, output


# --------------------------------------------------------------------------
# Cursor validation. The value is read off disk and passed to a subprocess.
# --------------------------------------------------------------------------


def test_real_journald_cursor_shape_is_accepted():
    assert is_valid_cursor(VALID_CURSOR) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        None,
        123,
        ["s=abc"],
        "s=abc;i=1;--after-cursor=x;b=1;m=1;t=1;x=1",  # a dash could parse as an option
        "s=abc\ni=1;b=1;m=1;t=1;xxxxxxxxxxxxx=1",  # newline could forge a log line
        "s=" + "a" * 600,  # unbounded length
        "s=abc;i=1;b=1;m=1;t=1;x=1 --follow",  # whitespace could split into argv
    ],
)
def test_unusable_cursor_values_are_rejected(value):
    assert is_valid_cursor(value) is False


def test_cursor_validation_rejects_a_dash_so_a_cursor_cannot_become_an_option():
    # Not a hypothetical: a truncated or partially-overwritten cursor file is the
    # normal way this value goes wrong, and argv is the only place it is used.
    assert is_valid_cursor("-s=abc;i=1;b=1;m=1;t=1;x=1") is False


# --------------------------------------------------------------------------
# CursorStore: a cursor is only useful if it is either the old value or the new.
# --------------------------------------------------------------------------


def test_cursor_round_trips_through_the_store(tmp_path):
    store = CursorStore(tmp_path / "nested" / "journald-auth.cursor")

    assert store.save(VALID_CURSOR) is True
    assert store.load() == VALID_CURSOR


def test_store_creates_its_parent_directory(tmp_path):
    store = CursorStore(tmp_path / "a" / "b" / "c.cursor")

    assert store.save(VALID_CURSOR) is True
    assert store.path.parent.is_dir()


def test_absent_cursor_file_loads_as_none(tmp_path):
    assert CursorStore(tmp_path / "missing.cursor").load() is None


@pytest.mark.parametrize("content", ["", "   ", "truncated", "s=abc -x", "\x00\x01binary"])
def test_corrupt_cursor_file_loads_as_none_instead_of_being_handed_to_journalctl(
    tmp_path, content
):
    path = tmp_path / "c.cursor"
    path.write_text(content, encoding="utf-8")

    assert CursorStore(path).load() is None


def test_stored_cursor_is_stripped_of_surrounding_whitespace(tmp_path):
    path = tmp_path / "c.cursor"
    path.write_text(f"  {VALID_CURSOR}\n", encoding="utf-8")

    assert CursorStore(path).load() == VALID_CURSOR


def test_saving_an_invalid_cursor_is_refused_and_leaves_the_previous_value(tmp_path):
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)

    assert store.save("nonsense -x") is False
    assert store.load() == VALID_CURSOR


def test_save_leaves_no_temporary_files_behind(tmp_path):
    store = CursorStore(tmp_path / "c.cursor")
    for cursor in (VALID_CURSOR, OTHER_CURSOR, VALID_CURSOR):
        store.save(cursor)

    assert [p.name for p in tmp_path.iterdir()] == ["c.cursor"]


def test_file_contains_exactly_the_cursor_with_no_trailing_newline(tmp_path):
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)

    assert (tmp_path / "c.cursor").read_text(encoding="utf-8") == VALID_CURSOR


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_unwritable_destination_reports_failure_rather_than_raising(tmp_path):
    # A collector that cannot checkpoint must keep collecting: losing cheap
    # resumption is far less bad than stopping the telemetry stream.
    directory = tmp_path / "readonly"
    directory.mkdir()
    store = CursorStore(directory / "c.cursor")
    os.chmod(directory, 0o500)
    try:
        assert store.save(VALID_CURSOR) is False
    finally:
        os.chmod(directory, 0o700)


def test_a_failed_write_does_not_leave_a_partial_file_in_place(tmp_path, monkeypatch):
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)

    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("telemetry.journald.journal_stream.os.replace", explode)
    assert store.save(OTHER_CURSOR) is False
    # The old value survives intact and no temp file is orphaned.
    assert store.load() == VALID_CURSOR
    assert sorted(p.name for p in tmp_path.iterdir()) == ["c.cursor"]


# --------------------------------------------------------------------------
# argv construction.
# --------------------------------------------------------------------------


def test_stored_cursor_replaces_the_since_window():
    command = build_command(("journalctl",), VALID_CURSOR, "10 minutes ago", follow=True)

    assert f"--after-cursor={VALID_CURSOR}" in command
    assert not any(arg.startswith("--since") for arg in command)


def test_absent_cursor_falls_back_to_the_since_window():
    command = build_command(("journalctl",), None, "3 hours ago", follow=False)

    assert "--since=3 hours ago" in command
    assert not any(arg.startswith("--after-cursor") for arg in command)


def test_cursor_is_a_single_argument_not_a_separated_pair():
    # Passed as two arguments, a cursor beginning with "-" would be consumed as an
    # option and the next real option consumed as the cursor: a parse that
    # succeeds and reads the wrong thing.
    command = build_command(("journalctl",), VALID_CURSOR, "now", follow=False)

    assert "--after-cursor" not in command
    assert f"--after-cursor={VALID_CURSOR}" in command


def test_follow_is_requested_only_when_asked():
    assert "--follow" in build_command(("journalctl",), None, "now", follow=True)
    assert "--follow" not in build_command(("journalctl",), None, "now", follow=False)


def test_output_is_always_machine_readable_and_unpaged():
    command = build_command(("journalctl",), None, "now", follow=True)

    assert "--output=json" in command
    assert "--no-pager" in command


def test_no_journalctl_level_match_filtering_is_applied():
    # Filtering in argv would advance the cursor only over matching entries, so a
    # quiet hour would leave the cursor an hour behind and turn every restart into
    # an hour of re-read. It would also move eligibility out of the tested Python
    # predicates into an untested argv string.
    command = build_command(("journalctl",), None, "now", follow=True)

    assert not any(
        arg.startswith(("--facility", "--identifier", "--unit", "_COMM=", "SYSLOG_"))
        for arg in command
    )


# --------------------------------------------------------------------------
# Resolving a stored cursor. This is the fix for the silent-blackout case.
# --------------------------------------------------------------------------


def test_cursor_that_names_a_real_entry_is_resumable(fake_journalctl):
    fake_journalctl.configure(probe={"stdout": [json.dumps(_session_opened())], "returncode": 0})

    verdict, _ = fake_journalctl.new_stream().resolve_cursor(VALID_CURSOR)

    assert verdict == CURSOR_RESUMABLE


def test_cursor_past_the_end_of_the_journal_is_unresolvable_not_resumable(fake_journalctl):
    # Measured against systemd 261: journalctl exits 0, writes nothing to stdout,
    # and writes nothing to stderr. Streaming from such a cursor produces no
    # records indefinitely -- a telemetry blackout that looks like a quiet host.
    fake_journalctl.configure(probe={"stdout": [], "returncode": 0, "stderr": ""})

    verdict, detail = fake_journalctl.new_stream().resolve_cursor(VALID_CURSOR)

    assert verdict == CURSOR_UNRESOLVABLE
    assert detail


def test_unparseable_cursor_is_classified_as_unreadable(fake_journalctl):
    fake_journalctl.configure(
        probe={"stdout": [], "returncode": 1, "stderr": "Failed to seek to cursor: Invalid argument"}
    )

    verdict, detail = fake_journalctl.new_stream().resolve_cursor(VALID_CURSOR)

    assert verdict == CURSOR_UNREADABLE
    assert "seek" in detail.lower()


def test_a_hanging_probe_times_out_instead_of_blocking_startup(fake_journalctl):
    fake_journalctl.configure(probe={"stdout": [], "returncode": 0, "delay": 5})

    verdict, detail = fake_journalctl.new_stream().resolve_cursor(VALID_CURSOR, timeout=0.4)

    assert verdict == CURSOR_UNREADABLE
    assert "timed out" in detail


def test_a_missing_journalctl_binary_is_reported_not_raised(tmp_path):
    stream = JournalStream(journalctl_command=(str(tmp_path / "does-not-exist"),))

    verdict, detail = stream.resolve_cursor(VALID_CURSOR)

    assert verdict == CURSOR_UNREADABLE
    assert detail


def test_probe_seeks_to_the_cursor_rather_than_after_it(fake_journalctl):
    # --after-cursor cannot answer "does this position exist": it is legitimately
    # empty on a caught-up host and empty for a cursor past the end of the journal
    # alike. --cursor distinguishes them.
    fake_journalctl.new_stream().resolve_cursor(VALID_CURSOR)

    argv = fake_journalctl.invocations[0]
    assert f"--cursor={VALID_CURSOR}" in argv
    assert not any(arg.startswith("--after-cursor") for arg in argv)
    assert "--lines=1" in argv


# --------------------------------------------------------------------------
# Streaming: records in, events out.
# --------------------------------------------------------------------------


def test_matching_records_become_events_and_others_are_skipped(fake_journalctl, tmp_path):
    fake_journalctl.serve([_session_opened("alice"), _unrelated(), _session_opened("bob")])
    collector, output = _collector(fake_journalctl, tmp_path)

    assert collector.run(follow=False) == 0
    assert [event["account"] for event in output.events] == ["alice", "bob"]
    assert collector.record_count == 3
    assert collector.emitted_count == 2


def test_records_are_streamed_rather_than_buffered_to_completion(fake_journalctl):
    # A --follow stream never reaches EOF, so a reader that waited for the child
    # to finish before yielding anything would deliver nothing, ever. Timing is
    # the only way to see the difference: the fake spaces its lines out, and each
    # one must arrive as it is written rather than in a batch at the end.
    gap = 0.35
    fake_journalctl.configure(
        stream={
            "stdout": [json.dumps(_session_opened(f"user{index}")) for index in range(3)],
            "between": gap,
            "returncode": 0,
        }
    )
    stream = fake_journalctl.new_stream()

    started = time.monotonic()
    arrivals = [
        time.monotonic() - started
        for _record, _cursor in stream.read(cursor=None, since="now", follow=False)
    ]

    assert len(arrivals) == 3
    assert arrivals[-1] - arrivals[0] >= gap


@pytest.mark.parametrize("line", ["not json", "", "   ", "[1,2,3]", '"a string"', "null"])
def test_malformed_or_non_object_lines_do_not_end_the_stream(fake_journalctl, tmp_path, line):
    fake_journalctl.configure(
        stream={"stdout": [line, json.dumps(_session_opened("carol"))], "returncode": 0}
    )
    collector, output = _collector(fake_journalctl, tmp_path)

    assert collector.run(follow=False) == 0
    assert [event["account"] for event in output.events] == ["carol"]


def test_a_normalizer_that_raises_is_reported_and_the_stream_continues(
    fake_journalctl, tmp_path
):
    calls = {"count": 0}

    def flaky(record):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ValueError("secret value from the record")
        return normalize_auth(record)

    fake_journalctl.serve([_session_opened("first"), _session_opened("second")])
    collector, output = _collector(fake_journalctl, tmp_path, normalize=flaky)

    assert collector.run(follow=False) == 0
    assert [event["account"] for event in output.events] == ["second"]
    warnings = output.of_type("telemetry_warning")
    assert len(warnings) == 1
    # The exception type is named; its message is not, because a normalizer's
    # exception text can quote the record it choked on and this line is telemetry.
    assert "ValueError" in warnings[0]["message"]
    assert "secret value" not in warnings[0]["message"]


def test_a_nonzero_exit_without_a_cursor_is_a_failure_not_a_silent_stop(
    fake_journalctl, tmp_path
):
    fake_journalctl.serve([], returncode=1, stderr="No journal files were found.")
    collector, output = _collector(fake_journalctl, tmp_path)

    assert collector.run(follow=False) == 1
    assert any("No journal files" in n["message"] for n in output.of_type("telemetry_warning"))


def test_startup_and_shutdown_notices_carry_the_counts_and_the_cursor_file(
    fake_journalctl, tmp_path
):
    fake_journalctl.serve([_session_opened(), _unrelated()])
    store = CursorStore(tmp_path / "journald-auth.cursor")
    collector, output = _collector(fake_journalctl, tmp_path, cursor_store=store)

    collector.run(follow=False)

    startup = output.of_type("telemetry_startup")[0]
    shutdown = output.of_type("telemetry_shutdown")[0]
    assert startup["cursor_file"] == str(store.path)
    assert startup["follow"] is False
    assert (shutdown["records_read"], shutdown["events_emitted"]) == (2, 1)


# --------------------------------------------------------------------------
# Checkpointing: where the silent losses live.
# --------------------------------------------------------------------------


def test_cursor_is_persisted_so_a_restart_resumes_instead_of_reguessing(
    fake_journalctl, tmp_path
):
    store = CursorStore(tmp_path / "c.cursor")
    fake_journalctl.serve([_session_opened(cursor=OTHER_CURSOR)])
    collector, _ = _collector(fake_journalctl, tmp_path, cursor_store=store)

    collector.run(follow=False)

    assert store.load() == OTHER_CURSOR


def test_cursor_advances_over_records_the_collector_does_not_care_about(
    fake_journalctl, tmp_path
):
    # Most of the journal matches neither collector. A cursor that only moved on
    # matches would sit hours behind during quiet periods, and every restart would
    # re-read those hours.
    store = CursorStore(tmp_path / "c.cursor")
    fake_journalctl.serve([_unrelated(cursor=OTHER_CURSOR)])
    collector, output = _collector(fake_journalctl, tmp_path, cursor_store=store)

    collector.run(follow=False)

    assert output.events == []
    assert store.load() == OTHER_CURSOR


def test_a_record_without_a_cursor_does_not_clobber_the_stored_position(
    fake_journalctl, tmp_path
):
    store = CursorStore(tmp_path / "c.cursor")
    record = _session_opened(cursor=OTHER_CURSOR)
    no_cursor = _session_opened("dave")
    no_cursor.pop("__CURSOR")
    fake_journalctl.serve([record, no_cursor])
    collector, _ = _collector(fake_journalctl, tmp_path, cursor_store=store)

    collector.run(follow=False)

    assert store.load() == OTHER_CURSOR


def test_cursor_is_never_saved_ahead_of_the_event_it_covers(fake_journalctl, tmp_path):
    """
    The at-least-once invariant.

    The collector prints events; the supervisor stores them. If the cursor were
    advanced before the event was written and flushed, a crash in between would
    skip an event that no longer appears anywhere -- invisible loss, which is the
    failure this module exists to remove. Re-reading is the acceptable direction.
    """
    cursors = [VALID_CURSOR.replace("i=39646", f"i=3964{index}") for index in range(1, 4)]
    fake_journalctl.serve(
        [_session_opened(f"user{index}", cursor=cursor) for index, cursor in enumerate(cursors)]
    )
    output = RecordingStream()
    timeline = []

    class TracingStore(CursorStore):
        def save(self, cursor):
            timeline.append(("save", cursor, len(output.events)))
            return super().save(cursor)

    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=TracingStore(tmp_path / "c.cursor"),
        stream=fake_journalctl.new_stream(),
        output=output,
        checkpoint_interval_seconds=0,
    )
    collector.run(follow=False)

    assert timeline, "no checkpoint was attempted"
    for _kind, cursor, events_written in timeline:
        # The event derived from the record bearing this cursor must already have
        # been written, so the count of flushed events is at least its position.
        assert events_written >= cursors.index(cursor) + 1


def test_checkpoints_are_coalesced_so_a_burst_does_not_fsync_per_line(
    fake_journalctl, tmp_path
):
    # journald is quiet most of the time, where checkpointing is effectively
    # per-record. An authentication burst -- a brute-force attempt, the case that
    # matters most -- must not pay a synchronous disk write per line.
    clock = {"now": 0.0}
    fake_journalctl.serve(
        [
            _session_opened(f"user{index}", cursor=VALID_CURSOR.replace("i=39646", f"i={index:x}0"))
            for index in range(1, 41)
        ]
    )
    collector, _ = _collector(
        fake_journalctl,
        tmp_path,
        checkpoint_interval_seconds=10.0,
        clock=lambda: clock["now"],
    )

    collector.run(follow=False)

    assert collector.record_count == 40
    # One inside the window plus the forced checkpoint on shutdown.
    assert collector.checkpoint_count == 2


def test_the_shutdown_checkpoint_is_forced_past_the_interval(fake_journalctl, tmp_path):
    store = CursorStore(tmp_path / "c.cursor")
    last = VALID_CURSOR.replace("i=39646", "i=3ffff")
    fake_journalctl.serve([_session_opened(cursor=VALID_CURSOR), _unrelated(cursor=last)])
    collector, _ = _collector(
        fake_journalctl,
        tmp_path,
        cursor_store=store,
        checkpoint_interval_seconds=3600.0,
        clock=lambda: 0.0,
    )

    collector.run(follow=False)

    assert store.load() == last


def test_an_unchanged_cursor_is_not_rewritten(fake_journalctl, tmp_path):
    fake_journalctl.serve([_session_opened(), _unrelated(), _session_opened("eve")])
    collector, _ = _collector(fake_journalctl, tmp_path, checkpoint_interval_seconds=0)

    collector.run(follow=False)

    # All three records carry the same cursor, so only one write is warranted.
    assert collector.checkpoint_count == 1


def test_a_checkpoint_failure_is_reported_and_collection_continues(
    fake_journalctl, tmp_path
):
    class FailingStore(CursorStore):
        def save(self, cursor):
            return False

    fake_journalctl.serve([_session_opened("frank")])
    output = RecordingStream()
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=FailingStore(tmp_path / "c.cursor"),
        stream=fake_journalctl.new_stream(),
        output=output,
        checkpoint_interval_seconds=0,
    )

    assert collector.run(follow=False) == 0
    assert [event["account"] for event in output.events] == ["frank"]
    warnings = output.of_type("telemetry_warning")
    assert warnings and "cursor" in warnings[0]["message"]
    assert str(collector.cursor_store.path) in warnings[0]["message"]


def test_a_negative_checkpoint_interval_is_refused_at_construction(tmp_path):
    with pytest.raises(ValueError):
        JournalCollector(
            name="auth",
            normalize=normalize_auth,
            cursor_store=CursorStore(tmp_path / "c.cursor"),
            checkpoint_interval_seconds=-1.0,
        )


# --------------------------------------------------------------------------
# Recovery: an unusable cursor is reported, never silently substituted.
# --------------------------------------------------------------------------


def test_an_unresolvable_cursor_is_reported_as_an_event_and_the_window_is_used(
    fake_journalctl, tmp_path
):
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)
    fake_journalctl.serve(
        [_session_opened("grace")], probe={"stdout": [], "returncode": 0}
    )
    collector, output = _collector(fake_journalctl, tmp_path, cursor_store=store)

    assert collector.run(since="7 minutes ago", follow=False) == 0

    warnings = output.of_type("telemetry_warning")
    assert len(warnings) == 1
    assert warnings[0]["stale_cursor"] == VALID_CURSOR
    assert warnings[0]["recovery"] == "since_window"
    assert warnings[0]["reason"] == CURSOR_UNRESOLVABLE
    assert "7 minutes ago" in warnings[0]["message"]
    assert collector.discarded_cursor_count == 1
    # Recovered rather than merely complained about.
    assert [event["account"] for event in output.events] == ["grace"]


def test_the_gap_report_is_a_telemetry_warning_so_it_becomes_a_durable_row(
    fake_journalctl, tmp_path
):
    # telemetry_warning is a real EventType, so this reaches SQLite and the
    # evidence record. A log line would scroll away and the hole would be
    # unexplainable after the fact.
    from pipeline.event_stream import Event, EventType

    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)
    fake_journalctl.serve([], probe={"stdout": [], "returncode": 0})
    collector, output = _collector(fake_journalctl, tmp_path, cursor_store=store)
    collector.run(follow=False)

    warning = output.of_type("telemetry_warning")[0]
    event = Event.from_raw_json(warning)
    assert event is not None
    assert event.event_type is EventType.TELEMETRY_WARNING


def test_the_since_window_is_used_after_a_cursor_is_discarded(fake_journalctl, tmp_path):
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)
    fake_journalctl.serve([], probe={"stdout": [], "returncode": 0})
    collector, _ = _collector(fake_journalctl, tmp_path, cursor_store=store)

    collector.run(since="42 minutes ago", follow=False)

    stream_argv = [argv for argv in fake_journalctl.invocations if "--lines=1" not in argv][0]
    assert "--since=42 minutes ago" in stream_argv
    assert not any(arg.startswith("--after-cursor") for arg in stream_argv)


def test_a_rotation_between_probe_and_stream_recovers_and_reports(fake_journalctl, tmp_path):
    # The probe said resumable, then journalctl refused the same cursor when the
    # stream opened. Recovered on a second read without the cursor.
    store = CursorStore(tmp_path / "c.cursor")
    store.save(VALID_CURSOR)
    output = RecordingStream()
    stream = fake_journalctl.new_stream()
    attempts = {"count": 0}
    original_read = stream.read

    def read(cursor=None, since="now", follow=True):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise StaleCursorError("Failed to seek to cursor: Invalid argument")
        return original_read(cursor=cursor, since=since, follow=follow)

    stream.read = read
    fake_journalctl.serve([_session_opened("heidi")])
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=store,
        stream=stream,
        output=output,
    )

    assert collector.run(follow=False) == 0
    warning = output.of_type("telemetry_warning")[0]
    assert warning["stale_cursor"] == VALID_CURSOR
    assert warning["reason"] == CURSOR_UNREADABLE
    assert [event["account"] for event in output.events] == ["heidi"]


def test_a_stale_cursor_error_is_only_raised_when_a_cursor_was_actually_used(
    fake_journalctl, tmp_path
):
    fake_journalctl.serve(
        [], returncode=1, stderr="Failed to seek to cursor: Invalid argument"
    )
    stream = fake_journalctl.new_stream()

    with pytest.raises(JournalReadError) as caught:
        list(stream.read(cursor=None, since="now", follow=False))

    assert not isinstance(caught.value, StaleCursorError)


def test_no_stored_cursor_announces_the_window_it_will_read_instead(
    fake_journalctl, tmp_path
):
    fake_journalctl.serve([])
    collector, output = _collector(fake_journalctl, tmp_path)

    collector.run(since="15 minutes ago", follow=False)

    info = output.of_type("telemetry_info")
    assert len(info) == 1
    assert "15 minutes ago" in info[0]["message"]
    # No probe is worth running when there is nothing to probe.
    assert all("--lines=1" not in argv for argv in fake_journalctl.invocations)


# --------------------------------------------------------------------------
# The one-shot path must not drift away from the streaming one.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "normalize,parse,records",
    [
        (
            normalize_auth,
            parse_auth,
            [
                _session_opened("alice"),
                _unrelated(),
                _auth_record("pam_unix(sudo:auth): authentication failure; logname=x"),
                _auth_record("pam_unix(sudo:session): session closed for user root"),
            ],
        ),
        (
            normalize_service,
            parse_service,
            [
                {
                    "__CURSOR": VALID_CURSOR,
                    "MESSAGE": "Started example.service - Example Service.",
                    "__REALTIME_TIMESTAMP": "1700000000123456",
                    "_SYSTEMD_UNIT": "init.scope",
                    "SYSLOG_IDENTIFIER": "systemd",
                    "_PID": "1",
                    "_UID": "0",
                },
                {
                    "__CURSOR": OTHER_CURSOR,
                    "MESSAGE": "Something unremarkable happened",
                    "__REALTIME_TIMESTAMP": "1700000000123457",
                    "_SYSTEMD_UNIT": "init.scope",
                    "SYSLOG_IDENTIFIER": "systemd",
                },
            ],
        ),
    ],
    ids=["auth", "service"],
)
def test_streaming_and_one_shot_paths_derive_the_same_events(
    fake_journalctl, tmp_path, normalize, parse, records
):
    """
    `read_journal`/`parse_journal_json` remain for scripted use while
    `JournalCollector` runs live. Two code paths over one journal is a drift risk,
    so the equivalence is pinned rather than assumed.
    """
    lines = [json.dumps(record) for record in records]
    fake_journalctl.serve(records)
    collector, output = _collector(fake_journalctl, tmp_path, normalize=normalize)

    collector.run(follow=False)

    assert output.events == list(parse(lines))


def test_an_event_is_flushed_before_the_cursor_that_covers_it_is_saved(
    fake_journalctl, tmp_path
):
    """
    The other half of at-least-once, and the half a buffer hides.

    Writing the event in the right order is not enough if it is still sitting in
    stdout's buffer when the cursor is persisted: a crash then loses an event the
    cursor claims was handled, which is exactly the invisible loss the ordering
    above exists to prevent. So the check is that nothing is unflushed at the
    moment of the save, not merely that the write came first.
    """
    fake_journalctl.serve(
        [
            _session_opened("ivan", cursor=VALID_CURSOR),
            _session_opened("judy", cursor=OTHER_CURSOR),
        ]
    )
    output = FlushTrackingStream()
    unflushed_at_save = []

    class TracingStore(CursorStore):
        def save(self, cursor):
            unflushed_at_save.append(output.unflushed)
            return super().save(cursor)

    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=TracingStore(tmp_path / "c.cursor"),
        stream=fake_journalctl.new_stream(),
        output=output,
        checkpoint_interval_seconds=0,
    )
    collector.run(follow=False)

    assert unflushed_at_save, "no checkpoint was attempted"
    assert unflushed_at_save == [0] * len(unflushed_at_save)


def test_a_checkpoint_is_never_taken_before_the_event_is_written(
    fake_journalctl, tmp_path
):
    # Guards the ordering inside the loop body directly: were the checkpoint
    # hoisted above the emit, the cursor would be durable while the event was not.
    fake_journalctl.serve([_session_opened("karl", cursor=OTHER_CURSOR)])
    output = RecordingStream()
    events_at_save = []

    class TracingStore(CursorStore):
        def save(self, cursor):
            events_at_save.append(len(output.events))
            return super().save(cursor)

    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=TracingStore(tmp_path / "c.cursor"),
        stream=fake_journalctl.new_stream(),
        output=output,
        checkpoint_interval_seconds=0,
    )
    collector.run(follow=False)

    assert events_at_save == [1]


def test_a_record_carrying_a_corrupt_cursor_is_treated_as_having_none(
    fake_journalctl, tmp_path
):
    # journald should never emit one, but the value is read from a pipe and then
    # passed to a subprocess. An unvalidated cursor would be written to the state
    # file and handed to journalctl on the next start.
    store = CursorStore(tmp_path / "c.cursor")
    fake_journalctl.serve(
        [
            _session_opened("lena", cursor=OTHER_CURSOR),
            _session_opened("mira", cursor="-x not a cursor"),
        ]
    )
    collector, output = _collector(
        fake_journalctl, tmp_path, cursor_store=store, checkpoint_interval_seconds=0
    )

    collector.run(follow=False)

    # Both events are emitted; only the good cursor is persisted.
    assert [event["account"] for event in output.events] == ["lena", "mira"]
    assert store.load() == OTHER_CURSOR
    assert output.of_type("telemetry_warning") == []


def test_a_cursorless_record_does_not_discard_an_uncheckpointed_position(
    fake_journalctl, tmp_path
):
    # The dangerous ordering: a cursor is pending but not yet written when a
    # record with no cursor arrives. Clearing the pending value there would make
    # the forced shutdown checkpoint save the older position, and the next start
    # would re-read everything in between. Three records, because the first
    # checkpoint always fires -- the loss only shows once one is being held back
    # by the coalescing interval.
    store = CursorStore(tmp_path / "c.cursor")
    first = VALID_CURSOR
    second = OTHER_CURSOR
    cursorless = _session_opened("nora")
    cursorless.pop("__CURSOR")
    fake_journalctl.serve(
        [
            _session_opened("omar", cursor=first),
            _session_opened("pia", cursor=second),
            cursorless,
        ]
    )
    collector, _ = _collector(
        fake_journalctl,
        tmp_path,
        cursor_store=store,
        checkpoint_interval_seconds=3600.0,
        clock=lambda: 0.0,
    )

    collector.run(follow=False)

    assert store.load() == second


def test_a_non_string_cursor_is_rejected_without_being_stringified():
    # str() of a value that is not a cursor usually fails the pattern anyway, so
    # the type check only shows its worth against a value whose text form looks
    # valid. Dropping it would let a non-string reach `handle.write`, which raises
    # a TypeError that `CursorStore.save` does not catch.
    class LooksLikeACursor:
        def __str__(self):
            return VALID_CURSOR

    assert is_valid_cursor(LooksLikeACursor()) is False


def test_stop_abandons_buffered_records_instead_of_draining_them(fake_journalctl):
    """
    What makes SIGTERM shutdown fit in the supervisor's five-second grace period.

    `live_ingestion` escalates to SIGKILL five seconds after SIGTERM. When stop()
    is called the pipe may already hold a large backlog, and draining it before
    returning would blow that budget and lose the shutdown checkpoint to SIGKILL.
    Abandoning the backlog is safe precisely because the cursor was not advanced
    over it: those records are re-read on the next start.

    The producer here writes far more than a pipe buffer can hold, so it is still
    running and blocked on write() when stop() arrives -- the shape a `--follow`
    stream on a busy host actually has. A finite batch that the fake finishes
    writing would not test anything: the loop would end at EOF whether or not
    stop() was honoured, which is how an earlier version of this test passed
    against a build that ignored the flag entirely.
    """
    fake_journalctl.serve(
        [_session_opened(f"user{index}") for index in range(500)], repeat=200
    )
    stream = fake_journalctl.new_stream()

    read = 0
    still_producing = None
    for _record, _cursor in stream.read(cursor=None, since="now", follow=True):
        read += 1
        if read == 1:
            still_producing = stream.process.poll()
            stream.stop()

    assert still_producing is None, "the fake finished before stop(); no backlog existed"
    assert read == 1, f"drained {read} buffered records after stop() instead of 1"


def test_signal_handlers_report_which_signals_they_took_and_stop_the_collector(
    tmp_path, monkeypatch
):
    # The return value is how a caller knows the clean-shutdown checkpoint is
    # actually reachable. Installed handlers are recorded rather than assumed.
    import signal as signal_module

    from telemetry.journald.journal_stream import install_signal_handlers

    installed = {}
    monkeypatch.setattr(
        signal_module,
        "signal",
        lambda number, handler: installed.setdefault(number, handler),
    )
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=CursorStore(tmp_path / "c.cursor"),
    )
    stopped = []
    monkeypatch.setattr(collector, "stop", lambda: stopped.append(True))

    handled = install_signal_handlers(collector)

    assert set(handled) == {signal_module.SIGTERM, signal_module.SIGINT}
    installed[signal_module.SIGTERM](signal_module.SIGTERM, None)
    assert stopped == [True]


def test_a_collector_that_cannot_install_handlers_still_runs(tmp_path, monkeypatch):
    # Installing from a non-main thread raises ValueError. Losing the clean
    # shutdown checkpoint is acceptable there; refusing to collect is not.
    import signal as signal_module

    from telemetry.journald.journal_stream import install_signal_handlers

    def refuse(_number, _handler):
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr(signal_module, "signal", refuse)
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=CursorStore(tmp_path / "c.cursor"),
    )

    assert install_signal_handlers(collector) == ()


def test_the_cursor_write_is_fsynced_before_the_rename():
    """
    Structural, not behavioural, and deliberately so.

    `os.replace` makes the rename atomic but says nothing about whether the bytes
    reached the disk; without the fsync a power loss can leave the renamed file
    empty, which demotes the next start to the fallback window. No unit test can
    observe that without cutting the machine's power, so the call is pinned by
    inspection rather than left unguarded.
    """
    source = (
        Path(__file__).resolve().parents[1] / "telemetry" / "journald" / "journal_stream.py"
    ).read_text(encoding="utf-8")
    body = source.split("def save(")[1]
    fsync_at = body.index("os.fsync(")
    replace_at = body.index("os.replace(")

    assert fsync_at < replace_at


# --------------------------------------------------------------------------
# Defaults and layout.
# --------------------------------------------------------------------------


def test_state_directory_is_anchored_to_the_repository_not_the_working_directory(
    monkeypatch
):
    # A cwd-relative default would create a second, empty cursor file whenever the
    # collector was started from elsewhere, and silently re-read the fallback
    # window every time.
    monkeypatch.delenv("SECURITY_STATE_DIR", raising=False)
    repo_root = Path(__file__).resolve().parents[1]

    assert default_state_dir() == repo_root / "state"
    assert default_state_dir().is_absolute()


def test_state_directory_is_overridable_by_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_STATE_DIR", str(tmp_path / "elsewhere"))

    assert default_state_dir() == tmp_path / "elsewhere"


def test_blank_state_directory_setting_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("SECURITY_STATE_DIR", "   ")

    assert default_state_dir() == Path(__file__).resolve().parents[1] / "state"


def test_each_collector_gets_its_own_cursor_file(monkeypatch, tmp_path):
    # The two collectors are separate processes reading at independent positions;
    # a shared file would have each overwrite the other's place.
    monkeypatch.setenv("SECURITY_STATE_DIR", str(tmp_path))

    assert default_cursor_path("auth") != default_cursor_path("service")
    assert default_cursor_path("auth").name == "journald-auth.cursor"


def test_the_generated_state_directory_is_not_tracked_by_git():
    # Cursor files are per-host runtime state. Committing one would make every
    # clone try to resume from a position that only existed on another machine.
    ignore = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")

    assert "state/" in ignore.splitlines()


# --------------------------------------------------------------------------
# Collector wiring: flags and the shared loop.
# --------------------------------------------------------------------------


def test_the_streaming_flags_default_to_following_and_are_all_parseable():
    import argparse

    from telemetry.journald.journal_stream import add_stream_arguments

    parser = argparse.ArgumentParser()
    add_stream_arguments(parser)

    # Following is the default because the point of this item is real-time
    # detection; a collector that has to be asked to stream would silently keep
    # the old batch behaviour for anyone who did not read the flags.
    assert parser.parse_args([]).follow is True
    assert parser.parse_args(["--no-follow"]).follow is False
    assert parser.parse_args(["--cursor-file", "/x/y"]).cursor_file == "/x/y"
    assert parser.parse_args(["--checkpoint-interval", "0.5"]).checkpoint_interval == 0.5
    assert parser.parse_args([]).since == "10 minutes ago"


def test_follow_and_no_follow_cannot_both_be_given():
    import argparse

    from telemetry.journald.journal_stream import add_stream_arguments

    parser = argparse.ArgumentParser()
    add_stream_arguments(parser)

    with pytest.raises(SystemExit):
        parser.parse_args(["--follow", "--no-follow"])


@pytest.mark.parametrize(
    "module", ["auth_session_monitor", "service_monitor"], ids=["auth", "service"]
)
def test_both_collectors_run_through_the_shared_streaming_loop(module):
    # Neither collector may keep a private copy of the resumption logic: the
    # cursor handling is what was verified, and a second implementation would not
    # be covered by any of the tests above.
    source = (
        Path(__file__).resolve().parents[1] / "telemetry" / "journald" / f"{module}.py"
    ).read_text(encoding="utf-8")

    assert "add_stream_arguments(parser)" in source
    assert "run_collector(COLLECTOR_NAME, normalize_journal_record, args)" in source
    assert "--since" not in source.split("def main")[1]


@pytest.mark.parametrize(
    "module", ["auth_session_monitor", "service_monitor"], ids=["auth", "service"]
)
def test_both_collectors_are_runnable_as_a_sibling_file_without_the_package(module):
    # The documented invocation is `python3 telemetry/journald/<file>.py`, where
    # the repository root is not on sys.path. service_monitor could not do this
    # before it gained the fallback import.
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo_root / "telemetry" / "journald" / f"{module}.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(repo_root),
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
    )

    assert result.returncode == 0, result.stderr
    assert "--no-follow" in result.stdout


@pytest.mark.parametrize(
    "module", ["auth_session_monitor", "service_monitor"], ids=["auth", "service"]
)
def test_collectors_remain_observation_only(module):
    source = (
        Path(__file__).resolve().parents[1] / "telemetry" / "journald" / f"{module}.py"
    ).read_text(encoding="utf-8")

    for forbidden in ("kill(", "systemctl", "iptables", "SIGKILL", "os.remove", "shutil.rmtree"):
        assert forbidden not in source


def test_the_shared_module_does_not_import_the_project_package():
    # Collectors run as standalone files under sudo; importing the package would
    # make the sibling-file invocation fail, and would let a collector reach the
    # database it is forbidden to write.
    import ast

    source = (
        Path(__file__).resolve().parents[1] / "telemetry" / "journald" / "journal_stream.py"
    ).read_text(encoding="utf-8")
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    assert imported <= {
        "json", "os", "re", "signal", "subprocess", "sys",
        "tempfile", "threading", "time", "collections", "pathlib", "typing",
    }


def test_stop_is_safe_before_a_stream_has_started(tmp_path):
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=CursorStore(tmp_path / "c.cursor"),
    )

    collector.stop()  # must not raise


def test_output_is_resolved_per_write_so_a_reopened_stdout_is_honoured(
    tmp_path, monkeypatch
):
    # Captured in __init__, a collector would keep writing to a file object the
    # supervisor had already replaced, and its events would go nowhere.
    collector = JournalCollector(
        name="auth",
        normalize=normalize_auth,
        cursor_store=CursorStore(tmp_path / "c.cursor"),
    )
    before = collector.output
    replacement = RecordingStream()

    monkeypatch.setattr(sys, "stdout", replacement)

    assert collector.output is replacement
    assert collector.output is not before


# --------------------------------------------------------------------------
# Against the real journalctl, so the fake cannot quietly diverge.
# --------------------------------------------------------------------------

requires_journalctl = pytest.mark.skipif(
    shutil.which("journalctl") is None, reason="journalctl is not available"
)


@requires_journalctl
def test_real_journal_entries_all_carry_a_cursor_of_the_expected_shape():
    result = subprocess.run(
        ["journalctl", "--no-pager", "--output=json", "--lines=25"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        pytest.skip("no readable journal entries on this host")

    records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert records
    for record in records:
        assert is_valid_cursor(record.get("__CURSOR")), record.get("__CURSOR")


@requires_journalctl
def test_real_journalctl_classifies_a_valid_and_an_invalid_cursor_distinctly():
    """
    Pins the wire behaviour the fake imitates. If a future systemd changed how a
    cursor failure is reported, this fails here rather than silently in
    production, where the symptom would be a collector that reads nothing.
    """
    probe = subprocess.run(
        ["journalctl", "--no-pager", "--output=json", "--lines=1"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if probe.returncode != 0 or not probe.stdout.strip():
        pytest.skip("no readable journal entries on this host")
    newest = json.loads(probe.stdout.splitlines()[0])["__CURSOR"]
    stream = JournalStream()

    assert stream.resolve_cursor(newest)[0] == CURSOR_RESUMABLE
    # Well-formed but far past the end of the journal: exit 0, no output, no
    # stderr. The case that would otherwise be an indefinite blackout.
    beyond = newest.split(";i=")[0] + ";i=fffffff0;" + newest.split(";", 2)[2]
    assert stream.resolve_cursor(beyond)[0] == CURSOR_UNRESOLVABLE
    assert stream.resolve_cursor("not-a-cursor-at-all")[0] == CURSOR_UNREADABLE
