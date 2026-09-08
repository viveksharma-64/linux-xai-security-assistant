# ML Model Lifecycle: Artifacts, Drift, and the Log

A model needs a governed life, not just a file on disk. This document describes
the three pieces that give it one — a **code-free artifact** whose bytes are
authenticated before they are parsed, a **drift check** that says when the host
has stopped looking like the host the model was trained on, and an
**append-only, hash-chained lifecycle log** that records how a model got from
trained to trusted and on what evidence.

None of it can activate a model. The activation gate in
[`ml/evaluation.py`](../ml/evaluation.py) is the only door, it is unchanged, and
the ML subsystem remains **inactive by default**. Drift and the lifecycle log
feed that gate's paperwork; they are not a way around it. See
[docs/NORMAL_CORPUS_PROGRAM.md](NORMAL_CORPUS_PROGRAM.md) for the corpus program
that builds data up to the bar.

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
| `active` | `record_activation` | The gate was satisfied *and* re-checked at the moment of the claim. |
| `drift_assessed` | `record_drift_assessment` | A drift check ran. Commits to the assessment it wrote. |
| `retraining_required` | `record_drift_assessment` | That check found drift. A separate row, so it reads as its own entry. |
| `drifted` | `record_drifted` | A human's judgment that the model no longer fits its host. |
| `retired` | `record_retired` | The model is out of service. |

The current state of a model is the **latest row**, never an edit of an earlier
one (`current_state`, `lifecycle_report`).

## The log records; it does not decide

This is the load-bearing property of the whole layer, and it is enforced in more
than one place on purpose:

- **Writing a row causes nothing.** No append flips `ml_models.active`, changes a
  threshold, or makes a scorer load. There is deliberately **no store method to
  activate an existing model** — `active` can only be set when a model row is
  first written — and this track did not add one. The log is a witness, not a
  control surface.
- **The gate's verdict cannot be supplied by the caller.** `activation_eligible`
  is set from exactly one thing: a fresh `normal_fpr_acceptance` call made inside
  `record_activation_gate` / `record_activation` from the raw false-positive and
  holdout-window counts, tested with `is True` so no truthy stand-in passes for
  the gate's boolean. `record_activation` re-runs the gate rather than trusting an
  earlier `eligible` row, and **raises** if it refuses.
- **Drift cannot log its way to an activation.**
  `storage/sqlite_store.py:write_ml_lifecycle_transition` independently refuses an
  `active` row without a gate verdict, and refuses any eligibility claim on a
  drift-reachable state. That duplication is intentional: the invariant holds for
  a writer that bypasses `ml/lifecycle.py` entirely.
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
stays silent when all four verify.

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
missing, the schemas disagree, the comparison dataset contains unverified
windows, the comparison dataset **reuses the model's own training windows**
(comparing a sample against itself is guaranteed to find nothing, which would
look like reassurance), fewer than 10 reference windows, fewer than 30 comparison
windows, or — the arithmetic one — the **smallest attainable** two-sided p-value
exceeds the Holm threshold for the first hypothesis, so no amount of separation
in the data could ever be called drift. Reporting "no drift" from a test that
cannot reject anything would be a lie of omission, so it is refused by name.
`scripts/ml_drift_check.py` exits **2** on a refusal so a scheduled run surfaces
it rather than logging "checked" and moving on.

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

## Trust boundaries

| Boundary | Untrusted input | How it is contained |
|---|---|---|
| Artifact → scorer | Two files on disk that used to be arbitrary pickled objects | Checksum verified before parse; JSON + `allow_pickle=False`; no code path at all. Numbers only. |
| Descriptor → array filename | A filename read out of a not-yet-authenticated document | Bare basename resolved in the descriptor's own directory; traversal is refused before the checksum is known. |
| Drift inputs → drift result | Model metadata, training windows, a foreign corpus database | Read-only throughout; cannot mutate a model, threshold, or activation state; schema/verification/overlap mismatches are refusals. |
| Lifecycle log → activation | An append that would like to be a promotion | **One-way: the log records, never causes.** `active` is unreachable from drift; `activation_eligible` requires a fresh gate verdict; no store method activates an existing model. |
| `actor` | A self-reported name (auth has no principal) | Labelled honestly as a claim — and chained, so the claim cannot be altered after the fact. |

## Out of scope here, on purpose

No autonomous or active response of any kind: nothing in this layer terminates,
restarts, blocks, or quarantines anything, on any host. No model is activated by
this track — the currently available holdout material is 4 candidate windows
against a bar of 60. No gate constant, statistical bound, provenance check, or
default-off posture was changed to make any of it fit.
