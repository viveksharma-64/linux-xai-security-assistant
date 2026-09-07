#!/usr/bin/env python3
"""
Ingestion throughput and latency benchmark.

Measures the real hot path the collectors feed: a raw event dict is normalised by
`CanonicalNormalizer` and written to SQLite in batches by `write_events` -- the
same two calls `pipeline/live_ingestion.py` makes on its consumer thread. It does
not go through the bounded queue or subprocesses, because the number an operator
sizing a host needs is how fast the store itself can absorb events; queue and
supervision overhead is measured by the soak test instead.

The published Phase B numbers come from running this; see docs/PHASE_B_RESULTS.md.

    python3 scripts/benchmark_ingest.py --events 50000 --batch-size 50
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

# Runnable as a bare script from anywhere: put the repository root on the path so
# the package imports resolve without a PYTHONPATH incantation.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.event_stream import CanonicalNormalizer  # noqa: E402
from storage.sqlite_store import SQLiteEventStore  # noqa: E402


def _raw_event(seq: int) -> Dict[str, Any]:
    # A process_exec event shaped like the exec probe's output. `seq` keeps the
    # content hash unique so dedupe does not silently absorb the batch and flatter
    # the write rate.
    return {
        "event_type": "process_exec",
        "timestamp": 1_000_000.0 + seq * 0.001,
        "pid": 1000 + (seq % 40000),
        "ppid": 1,
        "uid": 1000,
        "gid": 1000,
        "comm": "proc%d" % (seq % 512),
        "filename": "/usr/bin/tool%d" % (seq % 512),
        "source": "benchmark",
        "version": "1.0",
        "argv": ["tool", "--seq", str(seq)],
    }


def _percentile(sorted_values: List[float], fraction: float) -> float:
    if not sorted_values:
        return float("nan")
    index = min(len(sorted_values) - 1, int(round(fraction * (len(sorted_values) - 1))))
    return sorted_values[index]


def run(events: int, batch_size: int, db_path: str) -> Dict[str, Any]:
    store = SQLiteEventStore(db_path)
    normalizer = CanonicalNormalizer()
    inserted = duplicates = rejected = 0
    batch_latencies_ms: List[float] = []
    normalize_seconds = 0.0

    wall_start = time.perf_counter()
    pending = []
    for seq in range(events):
        norm_start = time.perf_counter()
        event = normalizer.normalize(_raw_event(seq))
        normalize_seconds += time.perf_counter() - norm_start
        if event is None:
            rejected += 1
            continue
        pending.append(event)
        if len(pending) >= batch_size:
            start = time.perf_counter()
            result = store.write_events(pending)
            batch_latencies_ms.append((time.perf_counter() - start) * 1000.0)
            inserted += result.inserted
            duplicates += result.duplicates
            rejected += len(result.rejected)
            pending = []
    if pending:
        start = time.perf_counter()
        result = store.write_events(pending)
        batch_latencies_ms.append((time.perf_counter() - start) * 1000.0)
        inserted += result.inserted
        duplicates += result.duplicates
        rejected += len(result.rejected)

    wall_seconds = time.perf_counter() - wall_start
    db_bytes = store.database_bytes() if hasattr(store, "database_bytes") else os.path.getsize(db_path)
    store.close()

    batch_latencies_ms.sort()
    return {
        "events": events,
        "batch_size": batch_size,
        "inserted": inserted,
        "duplicates": duplicates,
        "rejected": rejected,
        "wall_seconds": round(wall_seconds, 4),
        "throughput_events_per_sec": round(inserted / wall_seconds, 1) if wall_seconds else float("nan"),
        "normalize_us_per_event": round(normalize_seconds / events * 1e6, 2) if events else float("nan"),
        "batch_latency_ms_p50": round(_percentile(batch_latencies_ms, 0.50), 3),
        "batch_latency_ms_p95": round(_percentile(batch_latencies_ms, 0.95), 3),
        "batch_latency_ms_p99": round(_percentile(batch_latencies_ms, 0.99), 3),
        "batch_latency_ms_max": round(batch_latencies_ms[-1], 3) if batch_latencies_ms else float("nan"),
        "per_event_write_us": round(wall_seconds / inserted * 1e6, 2) if inserted else float("nan"),
        "db_bytes": db_bytes,
        "bytes_per_event": round(db_bytes / inserted, 1) if inserted else float("nan"),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--db", default=None, help="database path (default: a fresh temp file)")
    args = parser.parse_args(argv)

    db_path = args.db
    cleanup = False
    if db_path is None:
        handle, db_path = tempfile.mkstemp(prefix="bench_ingest_", suffix=".db")
        os.close(handle)
        os.unlink(db_path)  # let the store create it fresh
        cleanup = True
    try:
        report = run(args.events, args.batch_size, db_path)
    finally:
        if cleanup:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(db_path + suffix)
                except OSError:
                    pass

    width = max(len(k) for k in report)
    for key, value in report.items():
        print(f"{key.ljust(width)}  {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
