#!/usr/bin/env python3
"""
Synthetic collector for the soak/chaos harness (scripts/soak_chaos.py).

Stands in for an eBPF probe: it prints one JSONL event per tick to stdout and is
designed to be SIGKILLed at any moment and restarted without losing a recorded
event. The invariant it upholds is the one the chaos test checks:

  every sequence number written to emitted.log also reached the database.

To make that checkable across a kill it (1) prints and flushes the event first,
then (2) records the sequence to emitted.log, then (3) advances the resume
counter. A kill between (1) and (2) leaves an event in the database that was
never logged -- harmless, the database is a superset. A kill between (2) and (3)
re-emits one sequence on restart, which the database deduplicates and the checker
counts once. What can never happen is a logged sequence that is absent from the
database; that would be data loss.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, help="directory for pid/seq/emitted files")
    parser.add_argument("--rate", type=float, default=300.0, help="events per second")
    parser.add_argument("--name", default="chaos", help="event source label")
    args = parser.parse_args(argv)

    state = args.state
    os.makedirs(state, exist_ok=True)
    seq_path = os.path.join(state, "seq")
    emitted_path = os.path.join(state, "emitted.log")
    pid_path = os.path.join(state, "probe.pid")

    # Announce this incarnation's pid so the chaos thread can find and kill it.
    with open(pid_path, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
        handle.flush()
        os.fsync(handle.fileno())

    try:
        with open(seq_path, "r", encoding="utf-8") as handle:
            seq = int(handle.read().strip() or "0")
    except (OSError, ValueError):
        seq = 0

    period = 1.0 / args.rate if args.rate > 0 else 0.0
    emitted = open(emitted_path, "a", encoding="utf-8")
    try:
        while True:
            event = {
                "event_type": "process_exec",
                "timestamp": 1_000_000.0 + seq * 0.001,
                "pid": 1000 + (seq % 40000),
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "comm": "soak",
                "filename": "/usr/bin/soak",
                "source": args.name,
                "version": "1.0",
                # seq in the payload keeps every event's content hash unique, so
                # the database's dedupe cannot mask a lost-then-reinserted event.
                "argv": ["soak", "--seq", str(seq)],
            }
            # (1) publish the event, fully flushed into the pipe.
            sys.stdout.write(json.dumps(event) + "\n")
            sys.stdout.flush()
            # (2) record that this sequence was emitted.
            emitted.write(f"{seq}\n")
            emitted.flush()
            os.fsync(emitted.fileno())
            # (3) advance the durable resume point last.
            with open(seq_path, "w", encoding="utf-8") as handle:
                handle.write(str(seq + 1))
                handle.flush()
                os.fsync(handle.fileno())
            seq += 1
            if period:
                time.sleep(period)
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    finally:
        emitted.close()


if __name__ == "__main__":
    raise SystemExit(main())
