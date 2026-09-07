# Verified-Normal Corpus Program

The ML anomaly subsystem is held **inactive** behind a fixed activation gate. It
turns on only when a verified-normal corpus proves the scorer is quiet on benign
activity. This document is the *program* for building that corpus: how normal
windows are captured, reviewed, attested, kept independent, and counted toward
the gate — **building data to meet the bar, never moving the bar.**

This is a process document plus two read-only-by-default tools. It changes no
model, no threshold, and no gate constant.

## The gate (fixed — reproduced here, not redefined)

Activation is governed entirely by
[`ml/evaluation.py`](../ml/evaluation.py)`:normal_fpr_acceptance`, whose
constants are the bar:

- `MAX_NORMAL_FPR = 0.05` — observed false-positive rate on verified-normal
  holdout windows must be **≤ 5%**.
- One-sided **95% Wilson upper bound** on that FPR must also be **≤ 5%**
  (`_wilson_upper_bound`) — a small clean sample is not enough; the *interval*
  must clear the bar.
- `MIN_NORMAL_HOLDOUT_WINDOWS = 60` — at least **60 independent** verified-normal
  holdout windows.

```python
from ml.evaluation import normal_fpr_acceptance
normal_fpr_acceptance(false_positives, normal_windows)
# -> {"activation_eligible": bool, "max_normal_fpr": 0.05,
#     "minimum_normal_holdout_windows": 60, "normal_fpr_upper_95": float|None,
#     "reasons": [...]}
```

These values are **not tunable by this program**. The corpus is built up to the
bar; the bar is never lowered to the corpus. Any change to those constants is a
change to the safety gate itself, out of scope here.

## Two corpora, kept separate

There are two distinct labeled datasets in this project and they must never be
conflated:

| Corpus | Purpose | Written by | Contains |
| --- | --- | --- | --- |
| **Efficacy corpus** | Measure the deterministic rule/behaviour detector (precision/recall) | `simulation/corpus.py` (synthetic, seeded) | labeled benign **and** attack windows |
| **Verified-normal corpus** | Gate the ML scorer's activation | `ml/training.py` via the tools below | **only** operator-attested benign windows |

The efficacy harness promotes a *throwaway behaviour baseline* and is guarded by
a contamination test (`tests/test_efficacy.py`) so it can **never** write through
the verified-normal path. This program is the *only* sanctioned way to grow the
verified-normal corpus, and every write goes through
`ml/training.py:create_verified_normal_dataset` /
`add_verified_normal_window`, which reject any window not explicitly attested
`verified_normal=True`.

## What a verified-normal window is

- One **five-minute window** of canonical telemetry (`pipeline/event_stream.py`
  `Event`s) captured on a live, **known-benign** Kali host — routine
  interactive, developer, desktop, and scheduled-maintenance activity.
- Captured in the **current event format** (the schema the running collectors
  emit today), so the extracted features match the live feature schema
  (`ml/feature_schema.py`, `SCHEMA_VERSION`).
- **Reviewed by a human** and attested benign before promotion. The window's
  features and provenance (source event ids) are stored immutably; the raw
  events stay in their capture.

A window is **not** verified-normal merely because "nothing alerted." It is
verified-normal because an operator inspected it and attests it represents
benign baseline activity.

## Capture procedure (live Kali)

1. **Fix the host to a benign state.** Normal user/desktop/dev workload; routine
   maintenance is fine (it is part of "normal") but note it in the review. No
   red-team tooling, no exploit rehearsal, no attack simulation on the box.
2. **Record a five-minute window** through the standard supervised collector
   into a source-capture `SQLiteEventStore` (observation-only, `0600`, exactly
   as in production — this program introduces no new collector).
3. **Note session context**: host, boot/session, wall-clock span, and a one-line
   description of what the machine was doing. This is what makes the later
   review and the independence judgement possible.
4. **Repeat across genuinely different conditions** (see independence, below)
   until the holdout budget is met. Batches of short windows from one idle boot
   do not count as independent.

## Operator review checklist (before attesting)

Inspect the window — `collect_normal_window.py --dry-run` prints a digest
(event count, span, unique event types, unique commands, privileged-event
count) — and confirm **all** of:

- [ ] The host was in a known-benign state for the whole window; no
      attack/red-team activity, deliberate or incidental.
- [ ] Every privileged (uid 0) action is explained by legitimate maintenance you
      can name (updates, package ops, service restarts) — not an unexplained
      root exec.
- [ ] No unexpected external network tooling or data movement.
- [ ] The activity is **representative** of the baseline you want the scorer to
      treat as normal (not a pathological idle-only or a one-off spike you would
      not want generalised).
- [ ] For a **holdout** window: it is independent of the training windows
      (below) and of the other holdout windows.

Only when every box is genuinely checked does the operator attest the window
with `--i-verified-normal`. The tooling **cannot** self-approve this — the flag
is the human's attestation, and `ml/training.py` independently rejects any
window lacking `verified_normal=True`.

## Holdout independence criteria

The 60-window requirement is **60 _independent_ holdout windows**, because a
Wilson bound over 60 correlated slices of one boot is not 60 observations of
"the scorer is quiet." A holdout window qualifies as independent when it differs
from the training set and from other holdout windows in a way that matters:

- **Distinct boot/session** — not consecutive windows carved from one long idle
  capture.
- **Non-overlapping time** — disjoint wall-clock spans; no shared events (the
  stored `event_ids` make overlap auditable).
- **Held out from training** — a window used to build a candidate model is never
  also counted as its holdout. Record the split with the dataset `role`
  (`holdout` vs `training`); the tooling writes and reads that role.
- **Representative spread** — ideally different days / workloads / machines, so
  the holdout exercises the scorer across the range of "normal," not one
  narrow slice.

Independence is a **judgement recorded by the collection program**, not a
property this program's counter can prove. `corpus_status.py` counts holdout
windows and says so plainly; it does not certify that they are independent.

## Tooling

Both tools live in [`scripts/`](../scripts) and add **no new ML path** — they
reuse the existing verified-normal API and the fixed acceptance function.

### `scripts/collect_normal_window.py` — promote one reviewed window

Reads a source capture **read-only** (an operator's raw capture is never
mutated, and older-schema captures are read tolerantly) and appends the selected
window to a candidate dataset store via `create_verified_normal_dataset` /
`add_verified_normal_window`.

```bash
# 1. Inspect a capture without writing anything (no attestation required):
python3 scripts/collect_normal_window.py --source capture.db --dry-run

# 2. Create a holdout dataset and promote this window (operator attests):
python3 scripts/collect_normal_window.py \
    --source capture.db --dataset-db corpus/normal.db \
    --dataset-name "kali-desktop-holdout" --role holdout \
    --operator "$(id -un)" --reason "idle desktop + apt update, logs reviewed" \
    --i-verified-normal

# 3. Add further windows to that dataset:
python3 scripts/collect_normal_window.py \
    --source capture2.db --dataset-db corpus/normal.db \
    --dataset-id verified-normal-... --role holdout \
    --operator "$(id -un)" --reason "..." --i-verified-normal
```

Load-bearing properties:

- **Cannot self-approve.** Writing requires `--i-verified-normal` **and**
  `--operator` **and** `--reason`; without them the tool refuses, and
  `ml/training.py` refuses again. The flag records a human attestation; the
  script never manufactures one.
- **Read-only source.** The source capture is opened `mode=ro`; promotion copies
  features + event-id provenance into the candidate store, never editing the
  source.
- **Records the role** (`holdout` | `training`) on the dataset and each window so
  the holdout budget is countable.
- The candidate dataset store inherits the `0600` file mode.

### `scripts/corpus_status.py` — measure progress (read-only)

Opens the candidate dataset store **read-only** and reports per-dataset and
total verified-normal window counts, the holdout count, and the fixed-gate
assessment via `normal_fpr_acceptance`.

```bash
python3 scripts/corpus_status.py --dataset-db corpus/normal.db
python3 scripts/corpus_status.py --dataset-db corpus/normal.db --json
```

It reports a **best-case count readiness**: because a measured FPR needs a
trained candidate model scoring the holdouts (out of scope here, and unavailable
while scikit-learn is absent), the tool passes `false_positives=0` — the most
favourable case — purely to answer "is the *count* sufficient yet, and what is
the best-possible Wilson ceiling?" A real acceptance run substitutes the model's
measured false positives. The tool states this caveat in its own output and
changes nothing.

## Seed material (honest starting point)

An operator left raw captures at
`/home/virus/linux-xai-ml-captures/20260821-current-format/`:

- **4 holdout captures** (`holdout/holdout-02..05.db`) and **20 training
  captures** (`training/training-01..20.db`).
- The holdout captures hold **64 / 37 / 118 / 151 events** over spans of roughly
  **169 / 292 / 283 / 254 seconds** — i.e. windows of about the right length.
- They are **raw, un-promoted captures**: their `ml_datasets` /
  `ml_training_windows` tables are **empty**, and their `events` tables use an
  **older schema** (missing later columns such as `timestamp_monotonic` /
  `host_id`). `collect_normal_window.py` reads them tolerantly and read-only —
  it never migrates or mutates them.

**What this means for the gate, stated plainly:** these give at most **4**
holdout windows once reviewed and promoted. The gate needs **≥ 60** independent
holdout windows, so **~56+ more independent holdout windows** must still be
captured and attested under this program. The seed material is a credible
*starting point and a worked example of the input format*, not a satisfied gate.
Promotion of even these four still requires the operator review and attestation
above; they are candidates, not pre-approved data.

## Credible path to the gate

1. Capture five-minute benign windows across independent boots/days/workloads
   (procedure above), beginning with — but not limited to — reviewing the seed
   captures.
2. For each, run `--dry-run`, complete the review checklist, and promote with an
   explicit attestation, tagging `--role holdout` or `--role training`.
3. Track progress with `corpus_status.py` until the holdout count reaches 60 and
   the best-case Wilson ceiling clears 5%.
4. When the count is met, a candidate model is trained on the training windows
   and scored against the **held-out** windows; `normal_fpr_acceptance` is
   evaluated on the model's **measured** false positives.
5. Activation happens **only** if that measured assessment returns
   `activation_eligible=True` — against the unchanged 5% / 95%-Wilson / 60-window
   bar.

The corpus grows to meet the bar. The bar does not move.
