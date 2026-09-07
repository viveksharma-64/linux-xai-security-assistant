# Phase B Results

Phase B's exit criterion was: *runs unattended with collector kills injected and
no data loss or manual intervention; published throughput and latency numbers; an
authenticated API; and green CI on a suite that was fixed rather than trimmed.*

This document publishes the throughput/latency numbers and the collector-kill
soak result, with the exact commands to reproduce them. The authenticated API and
the test suite are covered by `docs/THREAT_MODEL.md` and the CI workflow.

## Measurement environment

| | |
|---|---|
| Kernel | Linux 7.1.5+kali-amd64 |
| CPU | 6 vCPU |
| Python | 3.14.6 |
| SQLite | 3.53.4 |
| Store | WAL journal, `synchronous=NORMAL`, single writer thread |

Numbers are machine- and load-dependent; treat them as a capacity *shape*
(how batch size trades throughput against latency), not an absolute SLA. Both
harnesses print a full report, so re-running on the target host is the intended
way to size it. The benchmark and the soak were run in isolation from each other —
running them concurrently contends for CPU and understates both.

## Ingestion throughput and latency

The benchmark drives the real hot path — `CanonicalNormalizer.normalize` then
`SQLiteEventStore.write_events` — the same two calls the live consumer thread
makes. Each event carries a unique payload so store-level dedupe cannot flatter
the write rate. 100,000 events per run:

```
python3 scripts/benchmark_ingest.py --events 100000 --batch-size 200
```

| Batch | Throughput (ev/s) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | bytes/event |
|------:|------------------:|---------:|---------:|---------:|---------:|------------:|
| 1     |            8,940  |    0.071 |    0.178 |    0.544 |    4.932 |       556.8 |
| 50    |           26,679  |    1.304 |    3.245 |    4.592 |    9.883 |       559.5 |
| 200   |           36,403  |    4.061 |    6.567 |    6.925 |    9.614 |       567.3 |
| 500   |           24,856  |   14.977 |   27.155 |   29.745 |   30.925 |       576.1 |

Latency columns are *per batch*, not per event.

**Reading it.** Batching is the dominant lever: one-event-at-a-time writes are
transaction-bound at ~8.9k ev/s, while batching to 200 reaches ~36k ev/s — roughly
27 µs of store time per event. Beyond ~200 the per-batch transaction gets large
enough that throughput falls back while tail latency climbs steeply (batch 500's
p99 is ~30 ms). **Batch 50–200 is the operating range**: 26k–36k ev/s with a p99
under 7 ms. Normalization is ~5–15 µs/event and is not the bottleneck. Storage
cost is ~560–580 bytes/event including indexes, so the default retention byte cap
maps predictably to an event count for disk sizing.

For context, steady-state exec/network/IPC volume on a normal host is
*hundreds* of events per second, with bursts into the low thousands. The store's
tens-of-thousands-per-second headroom means ingestion is not the constraint under
realistic load; the bounded queue exists for pathological bursts, and its drops
are counted rather than silent.

## Collector-kill soak (no-data-loss)

The soak runs the real `IngestionService` — a real subprocess collector, the real
supervisor with backoff and crash-loop degradation, and the real SQLite store —
while a background thread `SIGKILL`s the collector on a fixed cadence. It compresses
the "unattended for a week with kills injected" criterion into minutes by killing
every 1.5 s. The collector records every sequence it emits; the harness then
asserts every emitted sequence is present in the database. A shortfall is data loss
and exits non-zero, so the harness doubles as a gate.

```
python3 scripts/soak_chaos.py --kills 20 --kill-interval 1.5 --rate 300
```

Isolated run:

| Metric | Value |
|---|---|
| Kills injected (`SIGKILL`) | 20 |
| Restarts observed by supervisor | 20 |
| Final source status | stopped (clean shutdown) |
| Distinct events emitted | 4,248 |
| Events in database | 4,248 |
| **Data loss** | **none** |

Every one of the 20 kills was detected and the collector was brought back
automatically, with **no manual intervention** — the supervisor's backoff ladder
reset after each healthy re-attach, so periodic kills are treated as recoveries
rather than a crash loop. The emitted-equals-stored invariant held exactly: the
collector's write-then-record-then-advance ordering means a kill can at worst
re-emit one already-durable sequence (deduplicated by content hash), never drop
one. This is the core of the exit criterion demonstrated end-to-end against real
process kills.

The two guarantees compose: even if a batch write *did* fail (disk error rather
than a collector kill), the quarantine path (`pipeline/quarantine.py`) writes that
batch to disk at `0600` for replay, so the no-loss property extends past the store
boundary as well.

## Status against the exit criterion

| Criterion | Evidence |
|---|---|
| Unattended, collector kills injected, no data loss | Soak above: 20 kills → 20 auto-recoveries → 4,248 == 4,248 |
| Published throughput and latency | Benchmark table above; reproduction command included |
| Authenticated API | `api/auth.py`, on-by-default fail-closed; see `docs/THREAT_MODEL.md` |
| Green CI on a fixed (not trimmed) suite | `.github/workflows/ci.yml`; pytest is the hard gate across 3.11–3.13 |
