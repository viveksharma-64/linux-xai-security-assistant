"""
On-disk quarantine for event batches the database refused.

Why not just drop them
----------------------
A write can fail for reasons that have nothing to do with the events: a full
disk, a database locked by a stuck vacuum, a corrupted page, a schema newer than
this build. In every one of those cases the events themselves are intact and
valid, and the correct outcome is to keep them until the cause is fixed. Dropping
them would convert a recoverable operational fault into permanent evidence loss,
which is the failure this whole subsystem exists to prevent.

Why not retry in place instead
------------------------------
Retrying forever stalls the consumer, and a stalled consumer fills the queue,
which turns one failed batch into total loss under backpressure. Writing the
batch aside is bounded work that lets ingestion continue: the fault costs one
batch of latency rather than the whole stream.

Why bounded, and why oldest-first
---------------------------------
The most likely reason a write fails is that the disk is full, so an unbounded
quarantine directory would make the problem it is responding to worse. The
directory is therefore capped at a file count, and when it is full the *newest*
batch is refused rather than the oldest deleted. That is the opposite of the
queue's policy and deliberate: the first batches after a fault contain the
evidence of what was happening when it started, and by the time the cap is
reached the fault is sustained and later batches are more of the same.

Format
------
One JSON document per batch: a header describing the failure and a list of
canonical event dicts. Self-describing so a replay tool -- or an analyst with
`jq` -- needs nothing from this process to interpret it. Files are 0600 like the
database, because they contain the same command lines and paths.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

LOGGER = logging.getLogger(__name__)

FILE_MODE = 0o600
DIR_MODE = 0o700
FILENAME_PREFIX = "batch-"
FILENAME_SUFFIX = ".json"


class BatchQuarantine:
    """
    A bounded directory of failed batches.

    Thread-safe: the consumer is the only writer today, but the counter and the
    directory listing are guarded so a future second consumer cannot race two
    batches past the cap.
    """

    def __init__(self, directory: str, max_batches: int = 128):
        if max_batches < 0:
            raise ValueError("max_batches must not be negative")
        self.directory = Path(directory)
        self.max_batches = max_batches
        self._lock = threading.Lock()
        self._prepared = False

    def _prepare(self) -> None:
        """
        Create the directory on first use, not at construction.

        Constructing the quarantine is part of normal startup; creating a
        directory is a side effect on the filesystem. Deferring means a service
        that never fails a write never leaves an empty directory behind, and an
        unwritable path surfaces at the moment it is actually needed rather than
        blocking startup for a facility that may never be used.
        """
        if self._prepared:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, DIR_MODE)
        except OSError as error:
            # Not fatal: the files themselves are 0600 regardless. Worth a line
            # because a group-readable directory leaks batch names and timings.
            LOGGER.warning("quarantine_dir_mode_unenforced dir=%s error=%s", self.directory, error)
        self._prepared = True

    def count(self) -> int:
        try:
            return sum(1 for _ in self._existing())
        except OSError:
            return 0

    def _existing(self) -> List[Path]:
        if not self.directory.is_dir():
            return []
        return sorted(
            path
            for path in self.directory.iterdir()
            if path.is_file() and path.name.startswith(FILENAME_PREFIX) and path.name.endswith(FILENAME_SUFFIX)
        )

    def store(self, events: Sequence[Any], reason: str, source: Optional[str] = None) -> bool:
        """
        Write one batch aside. Returns False when the cap refused it.

        Refusal is a return value rather than an exception: the caller is a
        consumer thread handling a write failure, and raising here would replace a
        recoverable fault with a dead consumer -- the exact outcome the quarantine
        exists to avoid.
        """
        if not events or self.max_batches == 0:
            return False
        with self._lock:
            try:
                self._prepare()
                if len(self._existing()) >= self.max_batches:
                    LOGGER.error(
                        "quarantine_full batches=%d max_batches=%d dropped_events=%d reason=%s",
                        self.max_batches,
                        self.max_batches,
                        len(events),
                        reason,
                    )
                    return False
                document = {
                    "quarantined_at": time.time(),
                    "reason": reason,
                    "source": source,
                    "event_count": len(events),
                    "events": [self._encode(event) for event in events],
                }
                self._write_atomically(document)
            except OSError as error:
                LOGGER.error(
                    "quarantine_write_failed dir=%s events=%d error=%s",
                    self.directory,
                    len(events),
                    f"{type(error).__name__}: {error}",
                )
                return False
        return True

    def _write_atomically(self, document: Dict[str, Any]) -> Path:
        """
        Write via a temporary file and rename.

        The likely cause of the original failure is a full disk, which is also the
        most likely way this write is cut short. A partial file under a name a
        replay tool trusts would put a truncated batch into the evidence path;
        rename is atomic, so a reader sees either nothing or a complete batch. The
        mode is set before the rename so the file is never briefly readable.
        """
        handle, temp_name = tempfile.mkstemp(
            prefix=FILENAME_PREFIX, suffix=".partial", dir=str(self.directory)
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(document, stream, sort_keys=True, default=str)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, FILE_MODE)
            final = self.directory / f"{FILENAME_PREFIX}{time.time_ns()}{FILENAME_SUFFIX}"
            temp_path.replace(final)
            return final
        except BaseException:
            temp_path.unlink(missing_ok=True)
            raise

    def load(self, path: Path) -> Dict[str, Any]:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)

    def batches(self) -> List[Path]:
        """Quarantined batch files, oldest first."""
        return self._existing()

    @staticmethod
    def _encode(event: Any) -> Dict[str, Any]:
        """
        Render one event as a plain JSON-ready dict.

        Handles dataclass events, objects exposing `to_dict`, and raw dicts,
        because the quarantine sits on a failure path and must not itself fail on
        a type it did not expect. `default=str` on the dump is the final backstop
        for a value inside a payload that json cannot represent -- a lossy record
        of an event is worth more than an exception that discards it.
        """
        to_dict = getattr(event, "to_dict", None)
        if callable(to_dict):
            try:
                return dict(to_dict())
            except Exception:  # pragma: no cover - defensive
                pass
        if is_dataclass(event) and not isinstance(event, type):
            return asdict(event)
        if isinstance(event, dict):
            return dict(event)
        return {"repr": repr(event)}
