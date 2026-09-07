"""
Tests for batch quarantine.

The claim being tested is the one the exit criterion depends on: a database write
that fails does not lose the events. That means the batch has to survive on disk,
be readable without this process, and be bounded so that a full disk -- the most
likely cause of the original failure -- is not made worse.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from pipeline.quarantine import FILE_MODE, BatchQuarantine


@dataclass
class Recordish:
    pid: int
    comm: str


class WithToDict:
    def __init__(self, value):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


def test_a_failed_batch_is_written_and_can_be_read_back(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"))
    assert quarantine.store([{"pid": 1}, {"pid": 2}], reason="disk full", source="exec") is True

    batches = quarantine.batches()
    assert len(batches) == 1
    document = quarantine.load(batches[0])
    # Self-describing on purpose: replay must not need this process to interpret it.
    assert document["reason"] == "disk full"
    assert document["source"] == "exec"
    assert document["event_count"] == 2
    assert document["events"] == [{"pid": 1}, {"pid": 2}]
    assert isinstance(document["quarantined_at"], float)


def test_the_directory_is_not_created_until_a_batch_fails(tmp_path):
    directory = tmp_path / "unused"
    BatchQuarantine(str(directory))
    # Constructing the quarantine is part of every startup; a service that never
    # fails a write should not leave an empty directory behind to be triaged.
    assert not directory.exists()


def test_quarantine_files_are_not_readable_by_other_accounts(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"))
    quarantine.store([{"comm": "nc", "args": "-e /bin/sh"}], reason="locked")
    path = quarantine.batches()[0]
    # Same contents as the database -- command lines, paths, usernames -- so the
    # same mode. A 0644 quarantine would be a way around the database's 0600.
    assert os.stat(path).st_mode & 0o777 == FILE_MODE
    assert os.stat(path).st_mode & 0o077 == 0


def test_the_cap_refuses_the_newest_batch_rather_than_evicting_the_oldest(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"), max_batches=2)
    assert quarantine.store([{"n": 1}], reason="first") is True
    assert quarantine.store([{"n": 2}], reason="second") is True
    assert quarantine.store([{"n": 3}], reason="third") is False

    reasons = {quarantine.load(path)["reason"] for path in quarantine.batches()}
    # The first batches after a fault hold the evidence of what was happening when
    # it started; by the time the cap is hit, later batches are more of the same.
    assert reasons == {"first", "second"}
    assert quarantine.count() == 2


def test_a_zero_cap_disables_quarantine_without_erroring(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"), max_batches=0)
    assert quarantine.store([{"n": 1}], reason="off") is False
    assert not (tmp_path / "q").exists()


def test_an_empty_batch_is_not_written(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"))
    assert quarantine.store([], reason="nothing") is False
    assert quarantine.batches() == []


def test_an_unwritable_directory_returns_false_instead_of_raising(tmp_path):
    # The caller is a consumer thread already handling a write failure. Raising
    # here would kill the consumer, which turns one lost batch into a stalled
    # queue and total loss under backpressure.
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    quarantine = BatchQuarantine(str(blocker / "q"))
    assert quarantine.store([{"n": 1}], reason="unwritable") is False


def test_events_of_several_shapes_are_all_encoded(tmp_path):
    quarantine = BatchQuarantine(str(tmp_path / "q"))
    quarantine.store(
        [Recordish(pid=7, comm="bash"), WithToDict(3), {"plain": True}, object()],
        reason="mixed",
    )
    events = quarantine.load(quarantine.batches()[0])["events"]
    assert events[0] == {"pid": 7, "comm": "bash"}
    assert events[1] == {"value": 3}
    assert events[2] == {"plain": True}
    # An unexpected type still leaves a record: a lossy event beats an exception
    # that discards the batch.
    assert "repr" in events[3]


def test_no_partial_file_is_left_behind_when_serialisation_fails(tmp_path, monkeypatch):
    quarantine = BatchQuarantine(str(tmp_path / "q"))
    quarantine.store([{"n": 0}], reason="prime")

    import json as json_module

    def explode(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(json_module, "dump", explode)
    assert quarantine.store([{"n": 1}], reason="fails") is False
    # A truncated file under a name a replay tool trusts would put a partial batch
    # into the evidence path, so the temporary file is removed on any failure.
    assert quarantine.count() == 1
    assert not any(path.name.endswith(".partial") for path in (tmp_path / "q").iterdir())


def test_a_negative_cap_is_refused_at_construction(tmp_path):
    with pytest.raises(ValueError, match="negative"):
        BatchQuarantine(str(tmp_path / "q"), max_batches=-1)
