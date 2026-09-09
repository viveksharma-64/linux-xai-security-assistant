#!/usr/bin/env python3
"""
Streaming journald reader with restart-safe cursor persistence.

Why this exists
---------------
Both journald collectors used to run `journalctl --since "10 minutes ago"`,
buffer the whole result, print it, and exit. That is a query, not a monitor, and
it fails the "real time" requirement three separate ways.

* It is not live. To keep telemetry flowing something has to re-run the
  collector, so authentication and service telemetry arrives in batches with a
  detection latency equal to the cadence of whatever does the re-running. Under
  `live_ingestion`, which supervises a long-running child, a collector that
  exits immediately just ends the supervised session.
* The window is a guess in both directions. A fixed `--since` overlapping a
  shorter re-run interval re-reads and re-hashes the same records every cycle;
  a gap longer than the window loses everything in between, with nothing in the
  record to say so. A silent hole in authentication telemetry is precisely the
  shape of an intrusion that was not detected.
* A restart starts over. Nothing recorded where reading had reached, so the
  agent could not resume; it could only re-guess.

journald gives every entry an opaque `__CURSOR`, and `--after-cursor` resumes
strictly after that entry. Persisting the cursor turns "re-guess a window" into
"resume exactly where we stopped", which is the only way a restart can be
neither lossy nor duplicative.

At-least-once, deliberately
---------------------------
The collector prints events on stdout; the supervisor writes them to SQLite. The
collector cannot see the database, so it cannot know which of its events were
durably stored. That leaves two possible failure modes and no third option:
advance the cursor eagerly and risk skipping an event that was printed but never
stored, or let the cursor lag and risk re-reading records already stored.

This chooses to re-read. `SQLiteEventStore` deduplicates on a unique
`event_hash` index and counts what it rejects in `duplicate_count`, so a
duplicate is absorbed and visible. A skipped event is invisible -- it looks
exactly like a quiet host, which is the failure this whole module exists to
remove. The cursor is therefore checkpointed on an interval and again on clean
shutdown, always after the record it refers to has been written and flushed, so
a crash costs at most `checkpoint_interval_seconds` of re-read.

A stored cursor is validated before it is trusted
-------------------------------------------------
journald rotates and vacuums, and a stored cursor can outlive the entry it names.
Handing an unusable cursor straight to `--follow` is not safe, because journalctl
does not report all three failure shapes the same way. Measured against systemd
261:

* An unparseable cursor exits 1 with "Failed to seek to cursor" on stderr and no
  stdout. Loud, and easy to classify.
* A well-formed cursor whose entry has aged out seeks *forward* to the next
  surviving entry and streams normally, exit 0. Safe: it over-reads rather than
  skipping, which is the direction this module deliberately biases toward.
* A well-formed cursor pointing *past* the end of the journal exits 0, writes
  nothing to stdout, and writes nothing to stderr. Silent. Under `--follow` that
  is an indefinite telemetry blackout indistinguishable from a quiet host -- the
  exact failure this module exists to remove. It happens when the journal is
  reset or vacuumed and reissued with lower indices, or when a state file is
  restored from a snapshot taken later than the journal.

So a stored cursor is resolved first with a bounded one-shot
`journalctl --cursor=<c> --lines=1`, which answers all three cases distinctly: an
entry comes back for the resumable and aged-out cases, nothing comes back for the
past-the-end case, and a non-zero exit marks an unparseable one. A cursor that
does not resolve is discarded in favour of the `--since` window, and the
substitution is emitted as a `telemetry_warning` event naming the unusable cursor
and the reason. The gap becomes a durable row in the evidence record rather than a
log line that scrolls away.

What is deliberately not done
-----------------------------
No journalctl-level `--facility`/`--identifier`/match filtering, even though it
would cut the records this process parses by orders of magnitude. Two reasons.
The Python-side predicates in each collector are what was live-verified and are
covered by tests; moving that filtering into an argv match would change which
records are eligible with no test able to see the difference. And a match makes
the cursor advance only on matching entries, so a quiet hour would leave the
cursor an hour behind and turn every restart into an hour of re-read. Reading
everything and filtering in Python keeps both properties.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Sequence, Tuple

# journald cursors look like "s=<hex>;i=<hex>;b=<hex>;m=<hex>;t=<hex>;x=<hex>".
# Validated rather than trusted: the value comes off disk, is passed to a
# subprocess, and a corrupt one must degrade to "no cursor" instead of being
# handed to journalctl. The character class excludes "-" so a truncated file can
# never produce something argv-parseable as an option, and excludes control
# characters so a mangled cursor cannot break the argv or a log line.
_CURSOR_PATTERN = re.compile(r"\A[A-Za-z0-9=;]{16,512}\Z")

# journalctl's message when a cursor is no longer in the journal. Matched
# case-insensitively on a substring because the wording is not a stable API;
# the exit status alone cannot distinguish "cursor aged out", which is
# recoverable by re-reading, from "journal unreadable", which is not.
_SEEK_FAILURE_MARKER = "failed to seek to cursor"

DEFAULT_CHECKPOINT_INTERVAL_SECONDS = 2.0
DEFAULT_SINCE = "10 minutes ago"
DEFAULT_STATE_DIR_ENV = "SECURITY_STATE_DIR"
CURSOR_PROBE_TIMEOUT_SECONDS = 15.0

# Verdicts from resolving a stored cursor against the live journal. Only
# CURSOR_RESUMABLE may be handed to a streaming read; see the module docstring
# for what each case looks like on the wire.
CURSOR_RESUMABLE = "resumable"
CURSOR_UNRESOLVABLE = "unresolvable"
CURSOR_UNREADABLE = "unreadable"

# Anchored to the repository rather than the working directory. A collector
# started from a different cwd would otherwise create a second, empty cursor
# file and silently re-read the journal from the fallback window every time.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def default_state_dir() -> Path:
    configured = os.getenv(DEFAULT_STATE_DIR_ENV, "").strip()
    return Path(configured) if configured else _REPO_ROOT / "state"


def default_cursor_path(name: str) -> Path:
    """Per-collector cursor file. Separate files because the two collectors are
    separate processes reading at independent positions."""
    return default_state_dir() / f"journald-{name}.cursor"


def is_valid_cursor(value: Any) -> bool:
    return isinstance(value, str) and bool(_CURSOR_PATTERN.match(value))


class CursorStore:
    """
    Atomically persisted journald cursor.

    Written to a temporary file in the destination directory, flushed, fsynced,
    and renamed over the target. A cursor is only useful if it is either the old
    value or the new one: a file torn halfway through a write would be rejected
    by `is_valid_cursor` and silently demote the collector to re-reading a
    fallback window, which is the loss this class exists to prevent. `os.replace`
    is atomic within a filesystem, and the fsync before it is what makes the
    content -- not just the rename -- survive a power loss.
    """

    def __init__(self, path: os.PathLike | str):
        self.path = Path(path)

    def load(self) -> Optional[str]:
        """Return the stored cursor, or None if absent, unreadable, or corrupt."""
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return None
        return raw if is_valid_cursor(raw) else None

    def save(self, cursor: str) -> bool:
        """
        Persist a cursor. Returns False rather than raising on failure.

        A collector that cannot checkpoint is still a collector: losing the
        ability to resume cheaply is much less bad than stopping the telemetry
        stream, so this reports and continues.
        """
        if not is_valid_cursor(cursor):
            return False
        try:
            # The cursor records exactly where this host is in its journal, so the
            # state directory and the cursor file are kept owner-only. mode=0o700
            # applies only when mkdir actually creates the directory (exist_ok
            # leaves an existing one, and its permissions, untouched); fchmod sets
            # the file mode absolutely (umask cannot widen it) on the fd that
            # os.replace then renames into place, carrying 0600 with the inode.
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.path.parent),
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            )
            try:
                with handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(cursor)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(handle.name, self.path)
            except BaseException:
                # Do not leave a temp file behind on a failed checkpoint; the
                # directory would fill with them over a long run.
                try:
                    os.unlink(handle.name)
                except OSError:
                    pass
                raise
        except OSError:
            return False
        return True


class JournalReadError(RuntimeError):
    """journalctl failed for a reason re-reading cannot fix."""


class StaleCursorError(JournalReadError):
    """The stored cursor is no longer in the journal; re-reading can recover."""


def build_command(
    journalctl_command: Sequence[str],
    cursor: Optional[str],
    since: str,
    follow: bool,
) -> list[str]:
    """
    Assemble the journalctl argv.

    `--after-cursor=<value>` is deliberately a single argument. Passed as two,
    a cursor that somehow began with "-" would be consumed as an option and the
    next real option consumed as the cursor -- a parse that succeeds and reads
    the wrong thing. `is_valid_cursor` already forbids that character; this makes
    the argv unambiguous regardless.
    """
    command = [*journalctl_command, "--no-pager", "--output=json"]
    if cursor is not None:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since={since}")
    if follow:
        command.append("--follow")
    return command


class JournalStream:
    """
    Yield `(record, cursor)` pairs from a journalctl subprocess.

    Reads stdout line by line rather than buffering the whole result, so a
    `--follow` stream is delivered as it arrives. stderr is drained on a
    background thread into a bounded ring, both to classify a failure after the
    fact and to keep journalctl from blocking on a full stderr pipe.
    """

    def __init__(
        self,
        journalctl_command: Sequence[str] = ("journalctl",),
        stderr_lines: int = 20,
    ):
        self.journalctl_command = tuple(journalctl_command)
        self.process: Optional[subprocess.Popen] = None
        self._stderr_lines: deque[str] = deque(maxlen=stderr_lines)
        self._stderr_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def stderr_detail(self) -> str:
        return " ".join(self._stderr_lines).strip()

    def stop(self) -> None:
        """Ask the stream to end. Safe from a signal handler."""
        self._stop.set()
        self._terminate()

    def resolve_cursor(
        self,
        cursor: str,
        timeout: float = CURSOR_PROBE_TIMEOUT_SECONDS,
    ) -> Tuple[str, str]:
        """
        Decide whether a stored cursor can be resumed from. Returns (verdict, detail).

        Uses `--cursor` rather than `--after-cursor`: seeking *to* the entry asks
        "does this position exist in the journal", and the answer separates the
        three cases in the module docstring. `--after-cursor` cannot, because it
        answers "is there anything newer", which is legitimately empty on a caught
        up host and empty for a cursor past the end of the journal alike.

        One-shot and bounded. A hang here would delay startup indefinitely, so a
        timeout is treated the same as an unreadable journal: fall back to the
        window rather than block.
        """
        command = [
            *self.journalctl_command,
            "--no-pager",
            "--output=json",
            f"--cursor={cursor}",
            "--lines=1",
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return CURSOR_UNREADABLE, f"timed out after {timeout}s resolving the stored cursor"
        except OSError as error:
            return CURSOR_UNREADABLE, f"could not start journalctl: {error}"
        if result.returncode != 0:
            detail = result.stderr.strip() or f"journalctl exited with status {result.returncode}"
            return CURSOR_UNREADABLE, detail
        if not result.stdout.strip():
            # Exit 0 and no entry: the cursor names a position the journal does
            # not have. Streaming from it would produce nothing, forever.
            return CURSOR_UNRESOLVABLE, "the journal has no entry at the stored cursor"
        return CURSOR_RESUMABLE, ""

    def read(
        self,
        cursor: Optional[str] = None,
        since: str = DEFAULT_SINCE,
        follow: bool = True,
    ) -> Iterator[Tuple[dict, Optional[str]]]:
        command = build_command(self.journalctl_command, cursor, since, follow)
        self._stderr_lines.clear()
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as error:
            raise JournalReadError(f"could not start journalctl: {error}") from error

        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict):
                    continue
                entry_cursor = record.get("__CURSOR")
                yield record, entry_cursor if is_valid_cursor(entry_cursor) else None
            self._finish(cursor)
        finally:
            self._reap()

    def _finish(self, cursor: Optional[str]) -> None:
        """Classify the child's exit once stdout is exhausted."""
        process = self.process
        if process is None:
            return
        return_code = process.wait()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=1)
        if return_code == 0 or self._stop.is_set():
            return
        detail = self.stderr_detail
        if cursor is not None and _SEEK_FAILURE_MARKER in detail.lower():
            raise StaleCursorError(detail or "journalctl could not seek to the stored cursor")
        raise JournalReadError(detail or f"journalctl exited with status {return_code}")

    def _drain_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        try:
            for line in self.process.stderr:
                line = line.strip()
                if line:
                    self._stderr_lines.append(line)
        except (OSError, ValueError):
            # _reap() closed stderr while this thread was blocked reading it.
            return

    def _terminate(self) -> None:
        process = self.process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def _reap(self) -> None:
        """Stop journalctl if it outlived its reader, then close its pipes."""
        process = self.process
        if process is None:
            return
        self._terminate()
        thread = self._stderr_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass


def _notice(event_type: str, message: str, stream, **fields: Any) -> None:
    record = {"event_type": event_type, "message": message, "timestamp": time.time()}
    record.update(fields)
    print(json.dumps(record, sort_keys=True), file=stream, flush=True)


class JournalCollector:
    """
    The shared collector loop: stream records, normalize, emit, checkpoint.

    Both journald collectors differ only in their `normalize` predicate, so the
    streaming, resumption, checkpointing, and gap-reporting all live here.
    """

    def __init__(
        self,
        name: str,
        normalize: Callable[[dict], Optional[dict]],
        cursor_store: CursorStore,
        stream: Optional[JournalStream] = None,
        output=None,
        checkpoint_interval_seconds: float = DEFAULT_CHECKPOINT_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if checkpoint_interval_seconds < 0:
            raise ValueError("checkpoint_interval_seconds must not be negative")
        self.name = name
        self.normalize = normalize
        self.cursor_store = cursor_store
        self.stream = stream if stream is not None else JournalStream()
        self._output = output
        self.checkpoint_interval_seconds = checkpoint_interval_seconds
        self._clock = clock
        self.emitted_count = 0
        self.record_count = 0
        self.checkpoint_count = 0
        self.discarded_cursor_count = 0
        self._pending_cursor: Optional[str] = None
        self._saved_cursor: Optional[str] = None
        self._last_checkpoint: Optional[float] = None

    @property
    def output(self):
        # Resolved per write rather than captured in __init__, so a reopened
        # stdout is honoured instead of a stale file object.
        return self._output if self._output is not None else sys.stdout

    def stop(self) -> None:
        self.stream.stop()

    def run(self, since: str = DEFAULT_SINCE, follow: bool = True) -> int:
        _notice(
            "telemetry_startup",
            f"journald {self.name} stream starting",
            self.output,
            follow=follow,
            cursor_file=str(self.cursor_store.path),
        )
        cursor = self.cursor_store.load()
        if cursor is None:
            _notice(
                "telemetry_info",
                f"journald {self.name} has no usable stored cursor; reading from "
                f"--since {since!r}. Records older than that window are not read.",
                self.output,
            )
        else:
            cursor = self._resolve_or_discard(cursor, since)
        try:
            self._consume(cursor, since, follow)
        except StaleCursorError as error:
            # The cursor resolved at startup but journalctl could not seek to it
            # when the stream actually opened -- a rotation in the interval
            # between the two. Same recovery as a cursor that never resolved.
            self.discarded_cursor_count += 1
            _notice(
                "telemetry_warning",
                f"journald {self.name} could not resume from its stored cursor "
                f"({error}); falling back to --since {since!r}. Telemetry between "
                f"the stored cursor and that window is unrecoverable.",
                self.output,
                stale_cursor=cursor,
                recovery="since_window",
                reason=CURSOR_UNREADABLE,
            )
            try:
                self._consume(None, since, follow)
            except JournalReadError as retry_error:
                return self._fail(retry_error)
        except JournalReadError as error:
            return self._fail(error)
        finally:
            self._checkpoint(force=True)
        _notice(
            "telemetry_shutdown",
            f"journald {self.name} stream finished",
            self.output,
            records_read=self.record_count,
            events_emitted=self.emitted_count,
        )
        return 0

    def _fail(self, error: Exception) -> int:
        _notice(
            "telemetry_warning",
            f"journald {self.name} stream failed: {error}",
            self.output,
        )
        return 1

    def _resolve_or_discard(self, cursor: str, since: str) -> Optional[str]:
        """
        Return the cursor if the journal can resume from it, otherwise None.

        Discarding is reported as an event rather than a log line because the
        interval between the unusable cursor and the fallback window is telemetry
        that will never be read. An unexplained hole in authentication history is
        the shape of an intrusion nobody noticed, so the hole itself is recorded.
        """
        verdict, detail = self.stream.resolve_cursor(cursor)
        if verdict == CURSOR_RESUMABLE:
            return cursor
        self.discarded_cursor_count += 1
        _notice(
            "telemetry_warning",
            f"journald {self.name} cannot resume from its stored cursor "
            f"({detail}); falling back to --since {since!r}. Telemetry between "
            f"the stored cursor and that window is unrecoverable.",
            self.output,
            stale_cursor=cursor,
            recovery="since_window",
            reason=verdict,
        )
        return None

    def _consume(self, cursor: Optional[str], since: str, follow: bool) -> None:
        for record, entry_cursor in self.stream.read(cursor=cursor, since=since, follow=follow):
            self.record_count += 1
            event = None
            try:
                event = self.normalize(record)
            except Exception as error:  # noqa: BLE001 - one bad record must not end the stream
                _notice(
                    "telemetry_warning",
                    f"journald {self.name} could not normalize a record: "
                    f"{type(error).__name__}",
                    self.output,
                )
            if event is not None:
                print(json.dumps(event, sort_keys=True), file=self.output, flush=True)
                self.emitted_count += 1
            # Advanced only after the event has been written and flushed, so the
            # cursor never claims durability for an event still sitting in a
            # buffer. Advanced for non-matching records too: most of the journal
            # matches neither collector, and a cursor that only moved on matches
            # would sit hours behind during quiet periods and turn every restart
            # into hours of re-read.
            if entry_cursor is not None:
                self._pending_cursor = entry_cursor
            self._checkpoint()

    def _checkpoint(self, force: bool = False) -> None:
        """
        Persist the cursor, at most once per interval.

        Coalesced because a checkpoint is an fsync: journald is quiet most of the
        time, where this is effectively per-record, but an auth burst -- a brute
        force attempt, the case that matters most -- would otherwise pay a
        synchronous disk write per line while the records are still arriving.
        """
        cursor = self._pending_cursor
        if cursor is None or cursor == self._saved_cursor:
            return
        now = self._clock()
        if (
            not force
            and self._last_checkpoint is not None
            and now - self._last_checkpoint < self.checkpoint_interval_seconds
        ):
            return
        if self.cursor_store.save(cursor):
            self._saved_cursor = cursor
            self.checkpoint_count += 1
            self._last_checkpoint = now
            return
        # Reported once per occurrence rather than suppressed: an agent that
        # cannot checkpoint will re-read its fallback window on every restart,
        # and an operator needs to know that before the restart, not after.
        _notice(
            "telemetry_warning",
            f"journald {self.name} could not persist its cursor to "
            f"{self.cursor_store.path}; a restart will resume from the "
            f"--since window instead of this position.",
            self.output,
        )
        self._last_checkpoint = now


def install_signal_handlers(collector: JournalCollector) -> tuple[int, ...]:
    """
    Make SIGTERM and SIGINT end the stream cleanly. Returns the signals handled.

    `live_ingestion` stops a collector with SIGTERM and escalates to SIGKILL five
    seconds later. Python's default SIGTERM disposition kills the interpreter
    outright, so the shutdown checkpoint -- the one that makes a planned restart
    resume exactly where it stopped instead of re-reading the fallback window --
    would never run under the only invocation path that actually matters.

    Handling the signal turns it into an ordinary end of stream: journalctl is
    terminated, the record loop drains, and the `finally` in `run()` forces a
    final checkpoint. All of that happens well inside the supervisor's five-second
    grace period, so the escalation to SIGKILL is never reached in normal use.
    """
    def _handle(signum, _frame):  # pragma: no cover - exercised by signal delivery
        collector.stop()

    handled = []
    for signal_number in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(signal_number, _handle)
        except (OSError, ValueError):
            # Not the main thread, or the platform lacks the signal. A collector
            # that cannot install a handler still collects; it only loses the
            # clean-shutdown checkpoint, and at-least-once reading covers that.
            continue
        handled.append(signal_number)
    return tuple(handled)


def add_stream_arguments(parser, default_since: str = DEFAULT_SINCE) -> None:
    """Register the streaming flags shared by both journald collectors."""
    parser.add_argument(
        "--since",
        default=default_since,
        help="journald --since expression, used only when no cursor is stored",
    )
    follow = parser.add_mutually_exclusive_group()
    follow.add_argument(
        "--follow",
        dest="follow",
        action="store_true",
        default=True,
        help="stream continuously (default; required for real-time detection)",
    )
    follow.add_argument(
        "--no-follow",
        dest="follow",
        action="store_false",
        help="read what is already in the journal, then exit",
    )
    parser.add_argument(
        "--cursor-file",
        default=None,
        help="where to persist the journald cursor (default: state/journald-<name>.cursor)",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=float,
        default=DEFAULT_CHECKPOINT_INTERVAL_SECONDS,
        metavar="SECONDS",
        help="minimum seconds between cursor checkpoints (default: %(default)s)",
    )


def run_collector(
    name: str,
    normalize: Callable[[dict], Optional[dict]],
    args,
) -> int:
    """Build a collector from parsed arguments and run it to completion."""
    cursor_path = Path(args.cursor_file) if args.cursor_file else default_cursor_path(name)
    collector = JournalCollector(
        name=name,
        normalize=normalize,
        cursor_store=CursorStore(cursor_path),
        checkpoint_interval_seconds=args.checkpoint_interval,
    )
    install_signal_handlers(collector)
    return collector.run(since=args.since, follow=args.follow)
