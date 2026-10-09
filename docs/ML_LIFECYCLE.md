# ML Model Lifecycle: Artifacts, Drift, and the Log

A model needs a governed life, not just a file on disk. This document describes
the three pieces that give it one — a **code-free artifact** whose bytes are
authenticated before they are parsed, a **drift check** that says when the host
has stopped looking like the host the model was trained on, and an
**append-only, hash-chained lifecycle log** that records how a model got from
trained to trusted and on what evidence.

None of it can activate a model on its own. The activation gate in
[`ml/evaluation.py`](../ml/evaluation.py) is the only door, its thresholds are
unchanged, and the ML subsystem remains **inactive by default**. Drift and the
lifecycle log feed that gate's paperwork; they are not a way around it. And the
gate now shuts something: [`ml/scoring.py`](../ml/scoring.py) refuses to
*construct* a scorer for a model that is not active, so an ungated model has no
scoring path at all rather than one whose output a caller is trusted to discard.
See [docs/NORMAL_CORPUS_PROGRAM.md](NORMAL_CORPUS_PROGRAM.md) for the corpus
program that builds data up to the bar.

## The state path

```text
trained ──▶ evaluated ──▶ eligible ──▶ active ──▶ retired
                    └───▶ ineligible          └▶ drifted ──▶ retired

  (at any point after training, as observations about a model)
        drift_assessed ──▶ retraining_required
```

`LIFECYCLE_PATH` in [`ml/lifecycle.py`](../ml/lifecycle.py) is the ordered path;
`drift_assessed` and `retraining_required` sit outside it deliberately — they are
observations *about* a model, not stages *of* one.

| State | Written by | Means |
|---|---|---|
| `trained` | `record_trained` | An artifact exists, with its schema and training-window provenance. |
| `evaluated` | `record_evaluated` | Held-out measurement was performed; the numbers are in the row. |
| `eligible` / `ineligible` | `record_activation_gate` | The gate was called on raw counts and returned this verdict. |
| `active` | `record_activation` | The gate was satisfied *and* re-checked at the moment of the claim, over a model whose latest state was already `eligible`. Sets `ml_models.active` in the same transaction. |
| `drift_assessed` | `record_drift_assessment` | A drift check ran. Commits to the assessment it wrote. |
| `retraining_required` | `record_drift_assessment` | That check found drift. A separate row, so it reads as its own entry. |
| `drifted` | `record_drifted` | A human's judgment that the model no longer fits its host. Clears `ml_models.active`. |
| `retired` | `record_retired` | The model is out of service. Clears `ml_models.active`. |

The current state of a model is the **latest row**, never an edit of an earlier
one (`current_state`, `lifecycle_report`).

## The log records; the gate decides

This is the load-bearing property of the whole layer, and it is enforced in more
than one place on purpose:

- **One door to `active`, with the gate across it.** No append flips
  `ml_models.active`, changes a threshold, or makes a scorer load.
  `record_activation` does not set the flag itself; it calls
  `storage/sqlite_store.py:activate_ml_model`, the **only** writer of `active = 1`,
  which refuses unless the gate grants eligibility over the raw counts *and* the
  model's own latest recorded state is already `eligible` — so a retired model
  cannot be re-activated by re-asserting its old numbers. The flag and the row
  justifying it are written in one transaction, so a model is never active without
  its justification and never carries the row without the flag.

  This replaces an earlier rule that there was **no store method to activate an
  existing model**. That rule was absence-as-guarantee, and it made the gate
  unreachable: `active` could then only be set when a model row was first written,
  which is before any evaluation could have happened, so the only path to a
  scoring model went around the gate entirely. What holds now is enforcement, not
  absence — an *unguarded* setter still does not exist, and
  `tests/test_ml_lifecycle.py` asserts that it does not.

  The write-time route is closed from the other side, so this stays one door
  rather than two. `train_isolation_forest` no longer accepts an `activate` flag
  — the gate measures a false-positive rate on held-out windows, and that
  measurement cannot exist at the instant training returns — and
  `write_ml_model` **refuses** an active row rather than gating one. Refusal
  rather than a gate because the two doors cannot be given the same lock: at
  INSERT a model has no lifecycle history, so it can never satisfy
  `activate_ml_model`'s requirement that its latest recorded state already be
  `eligible`. A gated INSERT would therefore be gated to a weaker standard than
  the door beside it, and would produce the one thing this log exists to prevent
  — a model influencing findings with an empty history.
- **One exception, and it points the safe way.** Appending `retired` or `drifted`
  *does* stand a model down, clearing `ml_models.active` in the same transaction
  as the row. The failure mode of a retirement that leaves a model scoring is
  strictly worse than the failure mode of one that does not.
- **The gate's verdict cannot be supplied by the caller.** `activation_eligible`
  is set from exactly one thing: a fresh `normal_fpr_acceptance` call made inside
  `record_activation_gate` / `activate_ml_model` from the raw false-positive and
  holdout-window counts, tested with `is True` so no truthy stand-in passes for
  the gate's boolean. Activation re-runs the gate rather than trusting an earlier
  `eligible` row, and **raises** if it refuses.

- **Drift cannot log its way to an activation, and a claim is checked against its
  own numbers.** `storage/sqlite_store.py:write_ml_lifecycle_transition`
  independently refuses an `active` row without a gate verdict, refuses any
  eligibility claim on a drift-reachable state, and — for any row claiming
  eligibility — requires the verdict to say `activation_eligible: True`, requires
  the counts it came from to be recorded beside it, and **re-runs
  `normal_fpr_acceptance` over those counts**, refusing unless it reproduces the
  recorded verdict exactly. A shape check would have accepted `{}`, or the real
  gate output for counts that failed, next to a row asserting eligibility. That
  duplication is intentional: the invariant holds for a writer that bypasses
  `ml/lifecycle.py` entirely. It is not a second gate — whatever
  `normal_fpr_acceptance` returns for those counts is what passes, because a
  reimplemented Wilson bound in the storage layer would drift from the one the ML
  layer gates on.
- An **ineligible** verdict is recorded rather than raised. "This model was
  measured and did not qualify" is the more useful audit record, and it is the
  record that stops the same model being quietly re-proposed later.

`tests/test_ml_lifecycle.py` asserts these at the store boundary, and pins the
gate's constants and outputs as literals, so a change to the 5% ceiling or the
60-window floor fails a test rather than passing silently.

## The gate (unchanged — reproduced, not redefined)

Nothing in this document alters it:

- `MAX_NORMAL_FPR = 0.05` — observed false-positive rate on verified-normal
  holdout windows ≤ **5%**;
- one-sided **95% Wilson upper bound** on that rate ≤ **5%**;
- `MIN_NORMAL_HOLDOUT_WINDOWS = 60` — at least **60 independent** verified-normal
  holdout windows.

The bound, not the point estimate, decides. One false positive in 60 windows is
an observed 1.67% but a **7.13%** upper bound, and is refused. Zero in 60 gives a
**4.31%** bound and clears. Zero in 59 gives 4.38% and is refused on the count.

## Storage: migration 10

Migration **10** (`_apply_ml_lifecycle`) adds two new tables. Migrations 1–9 are
untouched; `LATEST_VERSION = 10`. A released migration is never edited or
renumbered.

| Table | Chained? | Holds |
|---|---|---|
| `ml_drift_assessments` | No | One row per drift check: status, method, alpha, sample sizes, drifted-feature count, out-of-range rate, the per-feature detail as JSON, refusal reasons, actor. |
| `ml_model_lifecycle` | **Yes** | One row per transition: model, from/to state, reason, evidence JSON, `activation_eligible`, actor, plus `chain_seq`/`chain_prev_hash`/`chain_hash`. |

Both are append-only. Both were created **with** their final shape (brand-new
tables ⇒ no backfill), with CHECK constraints pinning the enumerated vocabularies
at the schema: `status` in `{no_drift_detected, drift_detected,
insufficient_data}`, `to_state` in the nine states above, `activation_eligible`
in `{0, 1}`. The DB file mode stays `0600`.

`status` carries an explicit `insufficient_data` value because too little
comparison data is a **refusal with reasons**, not a quiet "no drift".

### Why the drift table is unchained, and how it is still tamper-evident

Drift output is bulk statistics written in batches by an operator-run check; a
second hash chain would add a second verify surface without adding
tamper-evidence. So instead, every drift assessment is **committed to** by the
chained `drift_assessed` lifecycle row written with it — one transaction under
the chain lock — which stores the assessment's id and a `content_hash` of its
core columns (`ML_DRIFT_CORE_COLUMNS`).

**A recorded hash is only tamper-evidence if something recomputes it.**
`verify_ml_lifecycle_chain()` does, in a second pass over the `drift_assessed`
rows, reading the **raw** stored columns — the hash was taken over
`features_json`, so it must stay the JSON text it was hashed as rather than the
list it decodes to. Consequences:

- editing an assessment fails verification, even though the edit is outside the
  chained columns and leaves every lifecycle hash valid;
- deleting one leaves a chained row pointing at a missing id, which also fails;
- rewriting only the per-feature detail — the tamper that changes *which* feature
  drifted while leaving the summary counts alone — fails too.

A broken **link** is reported ahead of any binding: once the sequence itself is
untrustworthy, so is the set of commitments read out of it. `checked` counts
lifecycle links, as in the other chains.

`GET /api/integrity` now reports **four** chains — findings, policy, triage, and
`ml_lifecycle` — and the console's integrity banner raises on any of the four. It
stays silent when all four verify. Its top-level `ok` carries a **fifth term**
that is deliberately *not* a chain — the active model's training-window
verification, below — so `ok` can be false while all four chain verdicts are
true. The dashboard banner still keys off the four chains only; the fifth term is
read from the payload (`active_model_training_windows`) and from
`GET /api/models/{id}`.

### Training-window integrity: the same rule, one layer down

`ml_training_windows.immutable_hash` has been `TEXT NOT NULL UNIQUE` since
migration 10, written per row over the window's identity, its 34 feature values,
its event ids, its schema identity, its collector context, and its verified-normal
attestation. Until now **nothing recomputed it** — which, by the rule stated
above, made it a record rather than evidence: the counterexample sitting in the
same schema as the thing the rule was written about.
`SQLiteEventStore.verify_ml_training_windows()` closes that, and the rule now has
one more example instead of one standing exception.

- **One definition, so the two sides cannot drift.** The write path and the verify
  path both call `_training_window_digest(window)`; neither keeps its own copy of
  the material dict. The hazard that removes is specific and would have been
  silent: the digest is taken over Python values, so a recompute that read the
  columns back naively would hash `verified_normal = 1` and `window_start = 1000.0`
  where the writer hashed `True` and `1000`, and *every* row in the database would
  "fail" verification. The helper normalizes (`bool(...)`, `float(...)`) on both
  sides, and a round-trip test pins it. `created_at` is excluded from the material
  on purpose — a window's content is what is being attested, not when it landed —
  and a test pins that exclusion so it cannot be added back by accident.
- **It reports ids, not a break position, because it is a set and not a chain.**
  Each row's hash covers that row alone, so a mismatch is *attributable* —
  `{"ok", "checked", "mismatched_ids"}` — but a **deleted** row is invisible here
  by construction: nothing links row *n* to row *n+1*. Completeness is a separate
  check that already existed. `MLScorer.__init__` refuses when
  `read_ml_training_windows_by_ids` returns fewer rows than the model's provenance
  names ("provenance is incomplete"), and that message is deliberately distinct
  from the tampering one — a missing row and an edited row are different incidents
  calling for different operator responses, and a generic message would make them
  indistinguishable in a degradation reason.
- **Scoped; never an unbounded scan on a request path.** A digest per row is cheap
  but not free. The two forms used are `window_ids=` (one model's own provenance)
  and `dataset_id=` (one corpus). An empty scope verifies **vacuously ok** — the
  honest answer to "are these windows unedited" when the scope names none — and
  that is the default-install answer at `/api/integrity`, where no active model
  means no training data is influencing any finding.
- **Undecodable JSON counts as a mismatch, not an exception.** A row whose
  `features_json` no longer parses is precisely the tamper this exists to catch;
  raising would convert a verification result into a crash in the caller.

Where it is recomputed:

| Site | Scope | On failure |
|---|---|---|
| `MLScorer.__init__` | the model's `training_window_ids` | `MLScoringError` naming **tampered** provenance, so the scorer never constructs. Enforced even under `allow_inactive=True`: evaluating a model against edited training data would measure a threshold against the edit. |
| `ml/drift.py:assess_drift` | reference = the model's ids; comparison = the foreign dataset | `status = insufficient_data` with a named reason — never `no_drift_detected`. |
| `ml/lifecycle.py:lifecycle_report` | the model's ids | a `training_windows` verdict beside `chain`. |
| `GET /api/integrity` | the **active** model's ids | `active_model_training_windows.ok = false`, and the top-level `ok` with it. |
| `GET /api/models/{id}` | that model's ids | `training_windows.ok = false`, beside a `chain` verdict that is still true. |

The API field is `active_model_training_windows` rather than a fourth chain name
because it is not one: it proves the rows that are present are unedited, and
claims nothing about rows that are not.

## The artifact: `iforest-native.v1`

A model is two files, and neither can carry code.

| File | Contents | Pinned by |
|---|---|---|
| `<model_id>.model.json` | The descriptor: feature-schema identity, threshold and its provenance, calibration block, forest scalars, decision bounds, and the checksum of the array file. `sort_keys=True`, compact separators. | `ml_models.artifact_checksum` (sha256 of these bytes) |
| `<model_id>.arrays.npz` | The numbers: per-tree topology and splits, plus the scaler's mean and scale. Uncompressed `np.savez`. | `arrays_checksum` inside the descriptor |

**One root of trust, one hop.** A single value already in the database commits to
both files, so no schema change was needed to gain the second one. The order is
enforced: **verify, then parse.** The descriptor's checksum is checked before
`json.loads`; the array checksum — read from the now-trusted descriptor — before
`np.load`.

- **No code path.** The descriptor is JSON (data only); the arrays load with
  `allow_pickle=False`, which numpy enforces by refusing object arrays outright.
  Compare the previous format, where the loader was `pickle.loads` and the
  checksum was the *only* thing between a swapped artifact and arbitrary code
  execution. A source-level test asserts no module under `ml/` imports a
  code-executing deserializer and that every `np.load` there disallows pickle.
- **The descriptor names the array file, which makes that name untrusted input.**
  It is constrained to a bare basename resolved in the descriptor's own directory,
  so a descriptor cannot point the loader at `../../etc/anything` even before its
  checksum is known good.
- **Reproducible bytes.** `np.savez` pins its archive timestamps, so identical
  arrays produce byte-identical files: the checksum doubles as a rebuild check —
  retraining from the same data with the same seed reproduces the same digest.
  `pickle` never offered that.
- **Scoring is bitwise-identical to sklearn.** `ml/iforest.py` reimplements
  `score_samples` in numpy, including sklearn's float32 routing cast, so
  `is_anomaly = raw <= threshold` does not change meaning when a model moves from
  the training host to a scoring host. The parity test runs where scikit-learn is
  installed and is the only skip-gated test in this layer.

Training still needs scikit-learn; **scoring no longer does**. The estimator is
reduced to tree arrays once, on the machine that has sklearn, and never has to be
reconstructed to score.

> **Consequence, stated plainly:** the two local `.pkl` experiments (gitignored,
> both inactive — one already failed the gate at 40% FPR) are not loadable in this
> format. Neither was ever active, and neither is activation-eligible, so nothing
> in service was affected; a model to be used again must be retrained through
> `ml/training.py`, which now writes the native format.

## Drift

[`ml/drift.py`](../ml/drift.py) answers one narrow, checkable question: for each
named feature, is the distribution in a newer verified-normal dataset
distinguishable from the distribution the model was trained on? That is a
**FACT**. Whether the model should be retrained is an **INTERPRETATION**, and is
reported as one, labelled, with its limitations.

- **Reference sample** = the model's *own* `ml_training_windows`, by id.
  **Comparison sample** = a newer verified-normal dataset, normally in a different
  database (the corpus store), read through a read-only connection.
- **Method** (`two_sample_ks_holm_bonferroni.v1`): per feature, a two-sample
  two-sided Kolmogorov–Smirnov test, then **Holm–Bonferroni** across the whole
  34-feature family at a family-wise `alpha = 0.01`. The correction is not
  optional — 34 independent tests at 0.01 would call something "drifted" about 30%
  of the time on two samples from the *same* distribution, which is precisely the
  false alarm that trains an operator to ignore the signal.
- **Exact where it can be.** The statistic is integer arithmetic
  (`max |i*m - j*n|`, no float ECDF), and the p-value is the exact lattice-path
  probability while the lattice is small enough to enumerate, falling back to the
  Kolmogorov asymptotic series only at sample sizes where it is accurate. Each
  feature records **which method produced its p-value**. No scipy: it happens to
  be installed here but is not a declared dependency.
- **Companion signal.** The share of comparison values falling outside the range
  the model has ever seen, reported alongside — a feature can move entirely out of
  its training range without KS reaching significance at these sample sizes, and
  an operator should see both.

### Refusing rather than guessing

`status = insufficient_data` with explicit `reasons` — never `no_drift_detected`
— when any of these holds: the model or its training-window provenance is
missing, the schemas disagree, the comparison dataset's own `ml_datasets` row is
absent or does not attest it verified-normal, the comparison dataset contains
unverified windows, **either side's windows fail hash verification**, the
comparison dataset **reuses the model's own training windows**
(comparing a sample against itself is guaranteed to find nothing, which would
look like reassurance), fewer than 10 reference windows, fewer than 30 comparison
windows, or — the arithmetic one — the **smallest attainable** two-sided p-value
exceeds the Holm threshold for the first hypothesis, so no amount of separation
in the data could ever be called drift. Reporting "no drift" from a test that
cannot reject anything would be a lie of omission, so it is refused by name.
`scripts/ml_drift_check.py` exits **2** on a refusal so a scheduled run surfaces
it rather than logging "checked" and moving on.

Two of those are worth separating, because they fail differently. The
**dataset-level attestation** is read from the comparison corpus's `ml_datasets`
row; the per-window `verified_normal` check beside it can never fire for rows the
store wrote (the writer only ever passes `1`), so without the dataset check an
unattested corpus would have sailed through on a backstop that cannot trip. The
backstop is kept anyway, for a hand-built or foreign-written row. The **hash
verification** is scoped on each side — reference by the model's own window ids,
comparison by its dataset id — so a tampered row in some unrelated corpus cannot
refuse a check it has nothing to do with.


### What drift cannot do

It is read-only over the store, runs from an operator or a schedule and **never
on the detection hot path**, and writes nothing itself — `ml/lifecycle.py` appends
the result. It cannot score, activate, deactivate, re-threshold, retrain, or
retire. It can append exactly two states, `drift_assessed` and
`retraining_required`. Drift raises the question; a human answers it by training a
new model and putting it through the same gate.

## Running a drift check

```bash
# What is here to compare (both read-only, nothing written):
python3 scripts/ml_drift_check.py --db events.db --list-models
python3 scripts/ml_drift_check.py --comparison-db corpus/normal.db --list-datasets

# Assess without recording:
python3 scripts/ml_drift_check.py \
    --db events.db --model-id iforest-... \
    --comparison-db corpus/normal.db --comparison-dataset verified-normal-...

# Assess and append to the lifecycle log (operator is required, and chained):
python3 scripts/ml_drift_check.py \
    --db events.db --model-id iforest-... \
    --comparison-db corpus/normal.db --comparison-dataset verified-normal-... \
    --record --operator "$(id -un)"
```

`--record` requires `--operator`: the log records who assessed the model. After
recording, the script re-verifies the lifecycle chain and exits non-zero if it
does not verify.

## Running a train → evaluate → gate workflow

`scripts/ml_train_and_evaluate.py` is the one command that walks the first three
states. It mirrors `ml_drift_check.py`'s posture deliberately — same `--list-*`
discovery, same read-only comparison corpus, same `--record`/`--operator`
requirement, same chain re-verification at the end.

```bash
# What is here to work with (both read-only, nothing written):
python3 scripts/ml_train_and_evaluate.py --db models.db --list-models
python3 scripts/ml_train_and_evaluate.py --holdout-db corpus/normal.db --list-datasets

# Dry run: preflight the comparison and print the best case the holdout could
# support. Trains nothing, writes nothing, leaves no artifact.
python3 scripts/ml_train_and_evaluate.py --db models.db \
    --training-dataset verified-normal-... \
    --holdout-db corpus/normal.db --holdout-dataset verified-normal-...

# The real run: train, score the holdout, and record all three transitions.
python3 scripts/ml_train_and_evaluate.py --db models.db \
    --training-dataset verified-normal-... \
    --holdout-db corpus/normal.db --holdout-dataset verified-normal-... \
    --artifact-dir models/ --contamination 0.01 --record --operator "$(id -un)"

# Activation is a separate invocation, on purpose.
python3 scripts/ml_train_and_evaluate.py --db models.db \
    --activate --model-id iforest-... --operator "$(id -un)"
```

What it appends, in order: `trained` (artifact checksum and provenance),
`evaluated` (the measured per-window scores and false-positive count), and then
`eligible` or `ineligible` carrying the gate's own `acceptance` dict with its
reasons. The gate row also carries `holdout_window_ids`, so the chained log
commits to *which* windows were measured and not merely how many —
`normal_window_count` is derived as `len(set(ids))` rather than supplied
independently of them.

Four conditions are refused **before** training, because they mean the
measurement would not be a measurement:

| Refusal | Why |
|---|---|
| training and holdout name the same dataset | measuring a model against its own training data answers nothing about generalization |
| the holdout reuses training windows byte-for-byte | detected with the same `_window_fingerprint` the drift check uses; a subset reuse is as fatal as a whole one |
| the holdout dataset's `role` is not `holdout` | the corpus program records the split; ignoring it would silently undo it |
| the two datasets' schema hashes disagree | the feature vectors are not comparable, so neither are the scores |

Exit codes are the interface a scheduled run reads: **0** eligible, **2** the gate
refused (either a preflight refusal or an `ineligible` verdict), **1** the
invocation was wrong or the run errored. Usage errors deliberately do not use
argparse's default status of 2, so "you asked wrong" can never be mistaken for
"the model was refused".

**Activation is not reachable from here.** `--activate` cannot be combined with
`--training-dataset` or `--holdout-dataset`; it is rejected as a usage error. It
re-reads `normal_window_count` and `false_positive_count` out of the model's own
chained `eligible` row and hands those to `activate_ml_model`, which re-runs the
gate over them — so there is no flag through which an operator could type a
favourable count, and no single command that takes raw data to an active model.

### Contamination against the gate

The trainer's default is `contamination=0.01`, and the number is chosen against
this gate rather than against a convention. Contamination *is* the Isolation
Forest decision threshold: a forest fitted to treat `c` of its training data as
outlying flags roughly `c` of in-distribution normal windows, while the gate
permits 5% only as a 95% Wilson *upper bound* — which at n=60 means zero observed
false positives (§ *The gate*: 0/60 → 4.31%, 1/60 → 7.13%). The former 0.05
default therefore aimed the model at exactly the ceiling it had to clear: 60
independent draws at p=0.05 land on zero failures about 4.6% of the time, so a
refusal was the expected outcome of every training run. At 0.01 the same
arithmetic gives about 55%. The gate did not move; the model stopped being
pointed at it.

Measured on the test corpus, with the holdout drawn interior to the training grid
(unseen windows that are nonetheless in range in every feature):

| `--contamination` | training windows | false positives / 60 | verdict | deliberate outlier flagged |
|---|---|---|---|---|
| 0.05 | 35 | 5 | ineligible | yes |
| 0.05 | 70 | 3 | ineligible | yes |
| 0.05 | 140 | 4 | ineligible | yes |
| 0.01 (default) | 35 | **0** | **eligible** | **yes** |
| 0.01 | 70 | 2 | ineligible | yes |
| 0.01 | 140 | 0 | eligible | **no** |
| 0.001 | 35 | 0 | eligible | yes |
| 0.001 | 70 | 0 | eligible | yes |
| 0.001 | 140 | 0 | eligible | **no** |

Two readings, and the second matters more. The default makes the gate reachable,
not passable — the 70-window row at 0.01 is still refused, which is the gate
working rather than a setting to tune away. And the last column is the thing the
gate cannot see at all. Eligibility is a false-positive budget and nothing else,
so driving contamination down while growing the training set eventually earns an
eligible verdict by producing a model that flags nothing
at all. The gate is a necessary condition, not a sufficient one; efficacy against
a labelled attack corpus remains a separate question, and
`labels_available: False` in the evaluation report says so in the row itself.

Where a given model's boundary actually landed in its own training distribution
is recorded rather than inferred: `write_artifact` stores
`training_decision_percentiles` (p1/p5/p25/p50/p75/p95/p99 of the training
`decision_function` scores) in the descriptor. For a forest fitted at the 0.01
default, `p1` sits on 0.0 to float error — that is the `contamination`/threshold
coupling made legible instead of left as a docstring claim.

`tests/test_ml_workflow_cli.py` pins the two configurations that matter — the
eligible one, which must still flag the outlier, and the single-false-positive one
that must be refused — so a scikit-learn upgrade that moves these numbers fails a
test rather than drifting unobserved.

### Calibrating the threshold: `--calibrate-threshold`

Contamination sets the boundary at fit time from the *training* distribution. The
principled alternative is to set it from held-out normal data: pick the threshold
whose measured false-positive rate on a verified-normal holdout is as close as
possible to a target without exceeding it. That is what `--calibrate-threshold`
does, and it is **off by default** for the reason below.

```bash
python3 scripts/ml_train_and_evaluate.py --db models.db \
    --model-id iforest-... \
    --holdout-db corpus/normal.db --holdout-dataset verified-normal-... \
    --artifact-dir models/ --calibrate-threshold 0.05 --operator "$(id -un)"
```

It refuses to be combined with `--training-dataset`, `--record`, or `--activate`
— usage errors, exit 1, distinct from the gate's exit 2. The holdout refusals are
the same ones the training path applies: wrong `role`, schema mismatch, empty
dataset, or windows byte-identical to the parent's training data.

What it produces is a **second model**, never an edit. Artifacts are immutable
and checksum-pinned in both directions, so moving a threshold means minting:
`rethreshold_model` writes a new artifact carrying the parent's forest, scaler,
training window ids, `decision_min`/`decision_max`, and
`training_decision_percentiles` verbatim, differing in exactly `threshold`,
`threshold_provenance`, and `calibration`. The new row is inactive, its
`hyperparameters.derived_from` names the parent, and its only lifecycle row is
`trained`. There is no `evaluated` row and no gate verdict, so `activate_ml_model`
— which demands an `eligible` latest state — has nothing here to act on.

**The honest limit, which is why this is scaffolding and not the recommendation.**
A threshold fitted to a holdout and a false-positive rate measured on that same
holdout are one number computed twice. Calibrating at a 5% target and then gating
on the same windows would have the gate recite the target rather than test it, so
the resulting FPR is optimistic by construction. The clean form needs two disjoint
splits — one to calibrate, one to gate — which the normal corpus cannot yet
support at 60 windows per split ([`NORMAL_CORPUS_PROGRAM.md`](NORMAL_CORPUS_PROGRAM.md)).
The provenance string says so in the artifact itself
(`holdout_quantile(n=..., target_fpr=..., quantile=...); in_sample -- ...`),
`calibration.in_sample` is `true`, and the CLI prints the caveat to the operator
rather than leaving it in a docstring.

And calibrating is not the same as improving. Measured in
`tests/test_ml_workflow_cli.py`: on a 60-window holdout an uncalibrated parent at
the 0.01 default flags **zero** windows and is eligible; calibrating that same
model *to* a 5% target **raises** the threshold until it flags three, and at n=60
even one false positive bounds to 7.13% — outside the budget. Targeting 5% when
the gate's effective allowance is zero moves the model away from the gate, not
toward it.

## Reading the recorded state: `/api/models`

The console can now show an analyst *whether the model behind a score is fit for
this host*, not just *why a finding scored*. Two GET routes render already-recorded
state; they re-compute no gate, write no row, and touch no threshold, artifact,
`active` flag, or fusion weight.

```text
GET /api/models       # newest-first list: id, algorithm/version, recorded state,
                      #   activation_eligible, latest drift status
GET /api/models/{id}  # provenance, full transition history, gate verdict, latest
                      #   drift summary, the lifecycle chain verdict, and the
                      #   training-window verification for that model's own rows
```

- **The gate verdict is surfaced verbatim.** `activation_eligible` and the gate's
  `acceptance` evidence are read out of the recorded lifecycle rows — never
  recomputed. The gate stays the only door; this surface is a window onto the
  witness log, not a control on it.
- **Two verdicts, about two different things.** `chain` says the *decisions* about
  this model were not rewritten. `training_windows` says the *data those decisions
  were made on* was not edited — a set of recomputed digests, reporting
  `mismatched_ids`, scoped to this model's own provenance. They fail
  independently: an edited training row leaves every lifecycle hash valid, which
  is exactly why the second verdict exists.
- **`artifact_checksum`, never `artifact_path`.** The checksum is the identifying
  evidence the lifecycle log already commits to; the raw path is withheld so the
  read surface does not leak host filesystem layout.
- **Empty is the honest default.** On a default install `/api/models` returns `[]`,
  because detection runs deterministically until a model passes the gate. The
  dashboard's "ML models" panel says so rather than implying a model is missing.
- Both routes are GET-only and behind the same default-deny token middleware as
  every other `/api/` path.

## Trust boundaries

| Boundary | Untrusted input | How it is contained |
|---|---|---|
| Artifact → scorer | Two files on disk that used to be arbitrary pickled objects | Checksum verified before parse; JSON + `allow_pickle=False`; no code path at all. Numbers only. |
| Descriptor → array filename | A filename read out of a not-yet-authenticated document | Bare basename resolved in the descriptor's own directory; traversal is refused before the checksum is known. |
| Drift inputs → drift result | Model metadata, training windows, a foreign corpus database | Read-only throughout; cannot mutate a model, threshold, or activation state; schema/attestation/hash-verification/overlap mismatches are refusals. |
| Training windows → scorer baseline | Rows that are readable, correctly shaped, and still wrong | `immutable_hash` recomputed per row from one shared digest definition. An edit is attributable to ids; `MLScorer.__init__` refuses to construct, naming tampering specifically. Deletion is covered separately by the provenance-length check, because a per-row hash cannot see a missing row. |
| Lifecycle log → activation | An append that would like to be a promotion | **One door, with the gate across it.** `active = 1` is writable only by `activate_ml_model`, which requires a freshly recomputed gate verdict *and* a latest recorded state of `eligible`; `active` is unreachable from drift; an unguarded setter does not exist. The one-directional exception is `retired`/`drifted`, which stand a model *down*. |
| Activation state → scoring | A model that never passed the gate, or one stood down | `ml/scoring.py` refuses to construct a scorer unless `active` is `True`, before it reads the artifact; the detector independently drops any payload not reporting `model_active: True`. Enforced at construction, so a mid-run deactivation applies to scorers built after it. |
| `actor` | A self-reported name (auth has no principal) | Labelled honestly as a claim — and chained, so the claim cannot be altered after the fact. |

## Out of scope here, on purpose

No autonomous or active response of any kind: nothing in this layer terminates,
restarts, blocks, or quarantines anything, on any host. No model is activated by
this track — the currently available holdout material is 4 candidate windows
against a bar of 60. No gate constant, statistical bound, provenance check, or
default-off posture was changed to make any of it fit.
