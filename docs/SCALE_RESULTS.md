# Phase E — Scale Results

Phase E's guiding rule for the storage layer is **measurement before scale-out**:
SQLite is not replaced on a hunch. Phase B published the *write* path — how fast
the store absorbs events and at what batch size — and the collector-kill soak
proved nothing is lost. Neither answered the question a scale-out decision actually
turns on: as the database grows, which operation goes nonlinear first, and at what
volume?

This document publishes that curve. It is a capacity *shape*, not an SLA. It is
measurement only: it changed no schema, no migration, no engine, and it ran
entirely against throwaway temporary databases — nothing was executed against a
live store.

## Measurement environment

| | |
|---|---|
| Kernel | Linux 7.1.5+kali-amd64 |
| CPU | 6 vCPU |
| Python | 3.14.6 |
| SQLite | 3.53.4 |
| Store | WAL journal, `synchronous=NORMAL`, single writer thread |

Timings are machine- and load-dependent — treat them as a capacity shape, not an
absolute SLA. Re-running on the target host is the intended way to size it. Two
measurement notes that matter for reading the tables:

- `db_bytes` sums the main database file **and its WAL/SHM sidecars**. During
  active writing the WAL holds uncheckpointed pages, so mid-write `bytes/event` is
  inflated at low volume and converges as volume grows; the post-VACUUM retention
  figures reflect the compacted on-disk size.
- Tail percentiles (p95/p99) on the growing queries are volatile under load
  (garbage collection, page-cache misses); the **p50 curve is the reliable
  shape**, and the tables show p99 in parentheses so the volatility is visible
  rather than hidden.

## Reproduction

```
python3 scripts/benchmark_scale.py
```

The harness builds volume through the *real* writers (`write_events`,
`write_detection_finding`, `write_policy_decision`, `write_triage_annotation`,
`write_ml_lifecycle_transition`), so every hash chain is folded exactly as
production folds it. Two independent sweeps, each on its own fresh temp database:
an **event sweep** (write throughput held at volume, bounded read latency, and the
retention/VACUUM cost) and a **finding sweep** (the dashboard page query and all
four chain verifications). Tiers, batch size, and repeat count are flags
(`--event-tiers`, `--finding-tiers`, `--repeats`); `--json` emits the raw report.

The deterministic invariants underneath the timings are gate-able on their own,
and CI runs exactly that — no timing is ever asserted:

```
python3 scripts/benchmark_scale.py --check
```

`--check` asserts, on a tiny fast corpus, that every chain verifies, that event and
finding counts reconcile against what was written and pruned, that an age prune
leaves the coverage floor at or after its cutoff, and that a size cap acts on an
over-budget file rather than growing it. It exits non-zero on any violation.

## Event sweep — write throughput and storage at volume

Each event is written through `CanonicalNormalizer.normalize` then
`SQLiteEventStore.write_events` (batch 200), with a unique payload so dedupe cannot
flatter the row count. Throughput is measured writing *into a table that is already
at the previous tier's size*.

| Events in DB | db_bytes | bytes/event | Write throughput (ev/s) |
|-------------:|---------:|------------:|------------------------:|
|       25,000 |   18,035,328 |   721.4 | 12,684 |
|      100,000 |   56,777,384 |   567.8 | 10,212 |
|      250,000 |  134,364,368 |   537.5 | 10,420 |

Write throughput **holds** as the table grows to a quarter-million events and
~134 MB — no degradation from table size. `bytes/event` converges to ~537,
consistent with Phase B's ~560–580 once the low-volume WAL inflation washes out.

## Event sweep — bounded read latency at volume

p50 ms (p99 in parens), by DB volume:

| Operation | 25k | 100k | 250k |
|---|---:|---:|---:|
| `count_events()`                | 0.020 (0.038) | 1.692 (3.135) | 4.148 (4.549) |
| `get_recent_events(100)`        | 2.862 (4.656) | 2.830 (4.883) | 2.191 (2.770) |
| `read_event_records(100)`       | 2.417 (5.951) | 2.371 (3.780) | 1.738 (2.174) |
| `read_event_records(typed,100)` | 2.198 (4.369) | 2.224 (3.682) | 1.730 (1.892) |

The three `LIMIT 100` reads are **flat** across a 10x volume increase (they even
warm slightly) — an index-ordered bounded scan does not care how large the table
is behind it. `count_events()` is the exception: it is an unindexed `COUNT(*)` and
grows linearly with row count, but only to ~4 ms at 250,000 events — a cost worth
naming, not one worth fixing.

## Event sweep — retention cost at 250,000 events (134 MB)

Measured last, after every non-destructive read, so the reads ran against the full
table. The age prune uses an injected clock so its cutoff lands exactly at the
corpus midpoint; the size cap targets half the post-prune size to force a real
reclaim.

| Operation | Result | Wall time |
|---|---|---:|
| standalone `VACUUM` | full-file rebuild under exclusive lock | 5.53s |
| age prune (1-day cutoff) | 125,000 events deleted | 4.16s |
| size cap → 69,340,580 bytes | 68,750 events deleted; **reached cap** (28,201,136 bytes) | 2.69s |

`VACUUM` is the single most expensive operation and scales with total file size:
~5.5 s of exclusive-lock stall at 134 MB. The size cap reached its target by
deleting the oldest events and reclaiming pages; the byte cap therefore bounds both
the file size and — through it — the VACUUM stall window.

## Finding sweep — page query latency

The dashboard reads through `read_detection_findings_page`, whose CTE runs a
correlated triage-state subquery per finding. The sweep grows findings, triage
annotations, and policy decisions 1:1. p50 ms (p99 in parens), by finding count:

| Query | 1k | 5k | 10k |
|---|---:|---:|---:|
| first page (`offset 0`)              |  5.068 (8.725) |  4.833 (7.506)  |  3.953 (9.269) |
| deep page (`offset total−100`)       | 13.280 (17.307)| 55.415 (206.702)| 100.984 (118.346) |
| filter `severity=HIGH`               |  7.974 (14.179)| 27.799 (36.043) | 49.533 (63.596) |
| filter `disposition=true-positive`   |  6.737 (10.028)| 13.106 (16.865) | 21.048 (26.520) |
| sort by `severity`                   |  7.243 (12.625)|  9.310 (11.703) | 13.800 (18.736) |

The **first page stays flat** (~4–5 ms) at every volume, but the **deep page grows
~linearly with the offset**: ~13 ms at 1k findings, ~101 ms at 10k. The offset
forces the correlated per-row subqueries to be evaluated across every row the page
skips. The `severity` filter grows similarly (~8 → ~50 ms) because its matched set
grows with volume; `disposition` and `severity`-sort grow more gently.

## Finding sweep — chain verification

`verify_*_chain` reads the whole table ordered by `chain_seq` and re-folds every
row from genesis. Wall time (µs/row in parens), by chain length:

| Chain | 1k | 5k | 10k |
|---|---:|---:|---:|
| findings      | 0.061s (60.8) | 0.331s (66.3) | 0.558s (55.8) |
| policy        | 0.038s (38.3) | 0.211s (42.3) | 0.344s (34.4) |
| triage        | 0.030s (29.9) | 0.152s (30.3) | 0.228s (22.8) |
| ml_lifecycle *(fixed 300 rows)* | 0.014s (45.7) | 0.009s (29.0) | 0.010s (32.6) |

Verification is **strictly linear in rows** at a stable per-row cost (~56 µs/row
for the findings chain). At 10,000 findings the full findings chain verifies in
~0.56 s. `ml_lifecycle` is held at a fixed floor because it is a handful of rows per
model in practice, not a stream; its time is a floor, not a curve.

## FACT — what goes nonlinear first, and at what volume

- The first operation to leave flat/linear and become a **latency** concern is
  **deep offset-pagination** in `read_detection_findings_page`. Its p50 rises ~8x
  (13 ms → 101 ms) as findings grow 1k → 10k while the first page stays flat at
  ~4 ms. The growth tracks the offset, not the page size, so it crosses ~100 ms at
  ~10,000 findings and extrapolates to the ~1 s range near ~100,000.
- **Chain verification is O(n) in rows** at ~56 µs/row (findings), ~34 µs/row
  (policy), ~23 µs/row (triage). Benign at the volumes measured — ~0.56 s at 10,000
  findings — and crossing into multiple seconds only in the 100,000+ range.
- On the **event side nothing on the read path goes nonlinear** except
  `count_events()`, an unindexed `COUNT(*)` that reaches ~4 ms at 250,000 events.
  Every `LIMIT 100` read is flat across the full 10x range, and **write throughput
  holds at ~10,000+ ev/s to 250,000 events / 134 MB**.
- The most expensive maintenance operation is **`VACUUM`**, which scales with total
  file size (~5.5 s at 134 MB) and runs under an exclusive lock.

## INTERPRETATION — does this justify an engine or rollup change?

*This section is judgement, kept separate from the measured facts above. It
presumes no decision.*

At the volumes measured — 250,000 events / 134 MB, and 10,000 findings — **nothing
crosses a threshold that would justify replacing SQLite.** The write path holds its
Phase B headroom at volume, bounded reads are flat, and the only steep curve has an
in-engine fix:

- **Deep paging.** The proportionate response is a query-shape change, not a new
  engine: keyset/seek pagination (`WHERE window_start < :cursor … LIMIT 100`) or
  materialising the triage-state columns instead of correlated subqueries would
  both flatten the deep page, and both are within SQLite. This is worth doing *if
  and when* deep paging becomes a real access pattern. It may not: analysts page
  the recent head and filter; paging to offset ~9,900 is not an observed workflow.
  The condition, not the change, is what to watch.
- **Chain verification.** O(n) is inherent to verifying an append-only chain from
  genesis, regardless of engine — the cost is re-folding every row, not the storage
  layer. A signed checkpoint (verify only the tail since a trusted point) would
  bound it, but that trades part of the tamper-evidence model for speed and is not
  warranted by a 0.56 s cost at 10,000 findings. It becomes worth revisiting only
  if verification moves onto a request-hot path rather than a maintenance one.
- **VACUUM.** The stall scales with file size, which is already bounded by the
  retention byte cap. This is a tuning knob (cap vs. stall duration), not an engine
  limitation.
- **`count_events()`.** If the ~4 ms ever matters, a maintained counter removes it;
  at present it does not matter.

Net: the measurement **does not support scale-out.** It supports leaving the engine
alone and holding a single, well-scoped query-shape change (keyset paging /
materialised triage columns) in reserve, gated on evidence that deep paging is a
real workload rather than a benchmark artifact. That is the "measurement before
scale-out" rule doing its job: the curve was measured, and the curve says the
current engine is not the constraint.

## Note on tooling

`ruff` and `mypy` are advisory in CI (the merge gate is the pytest suite). Neither
was installed in the environment where this run was produced, so they were not
executed here; the two new files were written to the configured rules (120-column
lines, `from __future__ import annotations`, fully typed signatures). The scale
tests and the full suite are the enforced gate and are green.
