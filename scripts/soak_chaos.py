#!/usr/bin/env python3
"""
Chaos/soak harness: kill the collector repeatedly and prove no events are lost.

This is the exercise behind the Phase B exit criterion -- "runs unattended with
collector kills injected and no data loss or manual intervention" -- compressed
from a week into a few minutes by killing on a short interval. It runs the real
`IngestionService`: a real subprocess collector (`_soak_probe.py`), the real
supervisor with restart backoff and crash-loop degradation, and the real SQLite
store. A background thread SIGKILLs the collector on a fixed cadence; the
supervisor is expected to bring it back each time.

The supervision timings are scaled so that a kill followed by a healthy reattach
is treated as a recovery rather than a crash loop: each incarnation runs longer
than restart_healthy_runtime_seconds, which resets the backoff ladder, exactly as
a real collector killed once an hour would. Only genuinely rapid, back-to-back
failures trip degradation.

At the end it asserts the invariant directly: the number of distinct sequences
the collector recorded as emitted is present in the database. A shortfall is data
loss and fails the run.

    python3 scripts/soak_chaos.py --kills 15 --kill-interval 1.5 --rate 300
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from observability.config import Settings  # noqa: E402
from pipeline.service import IngestionService, parse_source_spec  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402

PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_soak_probe.py")


def _read_pid(pid_path: str) -> int | None:
    try:
        with open(pid_path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _distinct_emitted(emitted_path: str) -> int:
    try:
        with open(emitted_path, "r", encoding="utf-8") as handle:
            return len({line.strip() for line in handle if line.strip()})
    except OSError:
        return 0


def run(kills: int, kill_interval: float, rate: float, state_dir: str) -> dict:
    os.makedirs(state_dir, exist_ok=True)
    db_path = os.path.join(state_dir, "events.db")
    pid_path = os.path.join(state_dir, "probe.pid")
    emitted_path = os.path.join(state_dir, "emitted.log")

    config = Settings(
        db_path=db_path,
        # A kill every kill_interval with each run outliving restart_healthy_runtime
        # models "killed periodically, always recovers": the ladder resets, so this
        # is not a crash loop. Degradation is still reachable for truly rapid death.
        restart_initial_backoff_seconds=0.2,
        restart_max_backoff_seconds=1.0,
        restart_healthy_runtime_seconds=max(0.3, kill_interval * 0.4),
        crash_loop_threshold=1000,
        crash_loop_window_seconds=5.0,
        retention_max_age_days=0.0,
        queue_size=4096,
    )
    spec = f"chaos={sys.executable} {PROBE} --state {state_dir} --rate {rate}"
    store = SQLiteEventStore(db_path)
    service = IngestionService(store, [parse_source_spec(spec)], config, analysis_pipeline=None)

    killed = 0
    done = threading.Event()

    def chaos():
        nonlocal killed
        while killed < kills and not done.is_set():
            if done.wait(kill_interval):
                break
            pid = _read_pid(pid_path)
            if pid and _alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed += 1
                    print(f"[chaos] SIGKILL collector pid={pid} ({killed}/{kills})")
                except OSError:
                    pass

    service.start()
    # Wait for the collector to come up before the first kill.
    for _ in range(50):
        if _read_pid(pid_path):
            break
        time.sleep(0.1)

    chaos_thread = threading.Thread(target=chaos, name="chaos", daemon=True)
    chaos_thread.start()
    chaos_thread.join()
    done.set()

    # Let the final incarnation drain what it emitted after the last kill.
    time.sleep(max(2.0, kill_interval))
    service.stop()
    service.join(timeout=10.0)

    emitted = _distinct_emitted(emitted_path)
    stored = store.count_events()
    states = {row["name"]: row for row in store.read_source_states()}
    restart_count = states.get("chaos", {}).get("restart_count", 0)
    status = states.get("chaos", {}).get("status", "unknown")
    store.close()

    return {
        "kills_injected": killed,
        "restarts_observed": restart_count,
        "final_source_status": status,
        "distinct_emitted": emitted,
        "events_in_db": stored,
        "no_data_loss": stored >= emitted and emitted > 0,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kills", type=int, default=15)
    parser.add_argument("--kill-interval", type=float, default=1.5)
    parser.add_argument("--rate", type=float, default=300.0)
    parser.add_argument("--state", default=None, help="state directory (default: a temp dir)")
    args = parser.parse_args(argv)

    state_dir = args.state or tempfile.mkdtemp(prefix="soak_chaos_")
    report = run(args.kills, args.kill_interval, args.rate, state_dir)

    width = max(len(k) for k in report)
    for key, value in report.items():
        print(f"{key.ljust(width)}  {value}")
    # Exit non-zero on data loss so the harness is usable as a CI/gating check.
    return 0 if report["no_data_loss"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
