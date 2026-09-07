# Phase C Results

Phase C's exit criterion was: *published precision/recall against a documented
corpus; every rule versioned, mapped, and independently tested; a tamper-evident
evidence chain; and a corpus on a credible path to satisfying the ML gate on its
existing terms.*

Phase C makes **detection quality** meet the standard the ML activation gate
already sets: numbers a reviewer can reproduce rather than asserted ones, rules
that are versioned artifacts rather than hardcoded constants, evidence that is
ordered and tamper-evident rather than individually hashed, and a written path
to the verified-normal corpus that never moves the ML bar.

This document is the roll-up. The full efficacy numbers and corpus manifest are
generated into [`docs/DETECTION_EFFICACY.md`](DETECTION_EFFICACY.md); the corpus
process lives in [`docs/NORMAL_CORPUS_PROGRAM.md`](NORMAL_CORPUS_PROGRAM.md).
This doc restates the headline, publishes the evidence-chain and migration
verifications that are not documented elsewhere, and states the measured suite
count — each with its reproduction command.

## Measurement environment

| | |
|---|---|
| Kernel | Linux 7.1.5+kali-amd64 |
| Python | 3.14.6 |
| SQLite | 3.53.4 |
| pytest | 9.1.1 |
| scikit-learn | absent (ML subsystem inactive; 4 integration tests skip) |

The efficacy corpus is fully determined by its seed, so its numbers are
reproducible on any host. The chain and migration results below are structural,
not load-dependent.

## 1. Published precision/recall against a documented corpus

The deterministic behaviour+rule detector is measured against a committed,
seeded, labeled corpus of synthesized canonical `Event`s (`simulation/corpus.py`)
— **read-only simulation**: nothing is executed on the host, the "attack" lives
entirely in the shape of the telemetry, matching the observation-only boundary.
`docs/DETECTION_EFFICACY.md` is generated from that run and is verified in sync.

Corpus: **55 windows** at 300 s each (seed `1337`) — 5 attack windows and 50
benign (48 clean, 2 known-false-positive). The throwaway behaviour baseline (600
synthesized normal execs) is promoted only via
`BehaviorAnalyzer.learn_normal(..., verified_normal=True)`, **never** through the
`ml/training.py` verified-normal path — enforced by a contamination guard in
`tests/test_efficacy.py`.

| Metric | Value |
| --- | --- |
| Precision | 0.7143 |
| Recall | 1.0000 |
| F1 | 0.8333 |
| True / False positives | 5 / 2 |
| True negatives / False negatives | 48 / 0 |
| False-positive rate (per benign window) | 0.0400 |
| FPR, one-sided 95% Wilson upper | 0.1139 |
| Projected false positives/day (288 windows/day) | 11.52 |
| FP/day, 95% upper ceiling | 32.80 |

Precision is **not** 1.0 and the corpus does not pretend it is: the two false
positives are legitimate root maintenance (`apt-get`, `dpkg`) running outside the
conservative allowlist, which trips `privileged_unusual_execution` **by design**.
Clean benign activity peaks at fused score 0.0000 while the lowest attack scores
0.5079 — a separation gap of **0.5079**. A band sweep shows MEDIUM (≥ 0.35) is
the only flag band that catches every attack (recall 1.0); raising to HIGH drops
real detections without removing either FP (both score 0.7912). The false
positives are therefore a rule-semantics cost whose correct remedy is operator
**suppression**, not a higher gate — so the fusion weights (`0.50/0.35/0.15`) and
severity bands (CRITICAL ≥ 0.80, HIGH ≥ 0.60, MEDIUM ≥ 0.35) are **retained
unchanged**, justified by the measured separation rather than asserted.

```bash
python3 scripts/run_efficacy.py            # regenerate docs/DETECTION_EFFICACY.md
python3 scripts/run_efficacy.py --check    # verify it is in sync (CI gate)
pytest -q tests/test_efficacy.py           # regression gate + contamination guard
```

## 2. Every rule versioned, MITRE-mapped, independently tested

The four detection rules are externalized to
[`detection/rules_catalog.yaml`](../detection/rules_catalog.yaml) (catalog schema
version 1). Score, behavioural gate, thresholds, and allowlists are the catalog's
— **nothing about a rule is hardcoded in Python**. Each entry carries a per-rule
`version` that must be bumped when its matching semantics, score, or tunables
change, so a persisted finding's rule evidence is traceable to the exact
definition that produced it.

| Rule | Ver | ATT&CK tactic | Technique |
| --- | --- | --- | --- |
| `privileged_unusual_execution` | 1 | TA0002 Execution | T1059 Command and Scripting Interpreter |
| `suspicious_utility_activity` | 1 | TA0011 Command and Control | T1105 Ingress Tool Transfer |
| `execution_burst` | 1 | TA0002 Execution | T1059.004 Unix Shell |
| `multi_uid_activity` | 1 | TA0005 Defense Evasion | T1078 Valid Accounts |

Every rule has a written `mapping_rationale` that states what the evidence does
and does *not* prove (e.g. `privileged_unusual_execution` is mapped to Execution,
not Privilege Escalation, to avoid over-claiming that elevation was newly gained).
Each rule attaches `rule_id`/`version`/`mitre` to its evidence item — additive,
so the explainer's score reconciliation is unaffected.

Integrity is enforced two ways: `detection/rules.py:load_catalog()` fails closed
on a malformed or inconsistent catalog, and the tests pin the contract:

```bash
pytest -q tests/test_rules.py          # per-rule match / no-match / gating
pytest -q tests/test_rule_catalog.py   # versioned, ATT&CK-mapped, ids unique, loader binds all
```

## 3. Finding correlation and suppression

Related findings receive a deterministic `correlation_id` — a 16-hex SHA-256 over
`entity_type|entity_key|anchor`, where the anchor is the first window of a
*contiguous run* of windows for that entity (a window gap starts a new run),
computed in the finding-assembly path of `DetectionEngine.detect()` before
persist. It is a triage-grouping key, not an incident-timeline reconstruction.
Suppression is explicit and
documented — `suppressed` + `suppression_reason` — and is a **disposition only,
never a silent drop**: a suppressed finding is still persisted, still explained,
and still chained, and its four scores are untouched by the disposition (so the
explainer's `1 - Π(1-score)` reconciliation still holds). These are the
migration-8 columns on `detection_findings`, returned automatically by the read
API and asserted in `tests/test_evidence_chain.py` and `tests/test_api_app.py`.

## 4. Tamper-evident evidence chain

`detection_findings` and `policy_decisions` are an append-only hash chain:
`chain_hash = SHA256(chain_prev_hash || serialized_core_columns)`, with the fold
defined once in [`storage/evidence_chain.py`](../storage/evidence_chain.py) and
used by both the runtime writer and the migration-8 backfill (one source of
truth, no drift). The chain extends only on a genuine INSERT — a dedup hit adds
no link — under `BEGIN IMMEDIATE` so the `MAX(chain_seq)+1` read-and-insert is
atomic across threads.

End-to-end demonstration (three findings incl. one suppressed, two policy
decisions), reproducible via the public API:

| Check | Result |
| --- | --- |
| `verify_findings_chain()` intact | `ok=True, checked=3` |
| `verify_policy_chain()` intact | `ok=True, checked=2` |
| Mutate `detection_findings` at `chain_seq=1`, re-verify | `ok=False, break_seq=1, reason="hash mismatch at seq 1 (row mutated, reordered, or removed)"` |
| Applied migrations | `v1..v8` contiguous; v8 = *append-only hash chain over evidence tables plus finding correlation and suppression* |
| `LATEST_VERSION` | 8 (`MIGRATIONS[-1].version`) |
| Reopen store (re-runs migrations) | version stable at 8; chain still verifies — idempotent |
| Database file mode | `0o600` |

Migration 8 is purely additive via `_add_column_if_absent`; versions 1–7 and
their descriptions are untouched (never edited or renumbered). The verifier reads
every row ordered by `chain_seq` and re-folds it, so a mutated, reordered,
deleted, or inserted historical row is detected. It mutates nothing.

```bash
pytest -q tests/test_evidence_chain.py     # continuity, tamper, dedup-no-link, suppressed-chained, backfill==runtime
pytest -q tests/test_schema_migrations.py  # v8 additive columns + idempotent re-run
```

## 5. Verified-normal corpus on a credible path to the ML gate

The ML activation gate is **unchanged and reused, never edited** to pass data:
observed FPR ≤ 5%, one-sided 95% Wilson upper ≤ 5%, over ≥ 60 independent
verified-normal holdout windows (`ml/evaluation.py:normal_fpr_acceptance`,
`MAX_NORMAL_FPR=0.05`, `MIN_NORMAL_HOLDOUT_WINDOWS=60`).

Phase C delivers the **program**, not the 60 windows — live privileged capture
across independent boots is out of a single session's reach, and the exit
criterion asks for a *credible path*:

- [`docs/NORMAL_CORPUS_PROGRAM.md`](NORMAL_CORPUS_PROGRAM.md) — capture procedure,
  operator-review checklist, holdout-independence criteria, and the fixed gate
  reproduced (not redefined).
- `scripts/collect_normal_window.py` — promotes one reviewed window into a
  candidate dataset via the **existing** `ml/training.py` API. It reads the source
  capture read-only (`mode=ro`), tolerates older-schema captures, and **cannot
  self-approve**: writing requires `--i-verified-normal` + `--operator` +
  `--reason`, and `ml/training.py` independently rejects any window not attested
  `verified_normal=True`. Adds no new ML path.
- `scripts/corpus_status.py` — read-only progress reporter against the fixed gate.

Honest starting point: an operator's seed captures provide at most **4** holdout
windows once reviewed and promoted (they are raw, un-promoted, older-schema
captures, read tolerantly and never mutated). The gate needs ≥ 60 independent
holdout windows, so **~56+ more must still be captured and attested** under the
program. This is a credible path and a worked example of the input format, not a
satisfied gate. The efficacy corpus and the verified-normal corpus are kept
strictly separate.

```bash
python3 scripts/collect_normal_window.py --source capture.db --dry-run  # inspect, writes nothing
python3 scripts/corpus_status.py --dataset-db corpus/normal.db          # progress toward the gate
```

## Test suite

```bash
pytest -q     # from repo root
```

**468 passed, 4 skipped.** The 4 skips are `tests/test_ml_integration.py`
(scikit-learn is absent, so the ML integration path cannot run) — they were
already skipped and are **not** newly skipped by Phase C.

The suite was **fixed, not trimmed.** Adding the migration-8 columns surfaced a
real regression: the read-only evidence API's response models use
`extra="forbid"`, so `GET /api/detections` and `/api/policy-decisions` began
raising `ResponseValidationError` (`extra_forbidden`) once the new columns
appeared in `dict(row)`. The fix extended `FindingResponse` and
`PolicyDecisionResponse` additively (new fields `Optional`/defaulted, so a
pre-chain legacy row still serializes), and `tests/test_api_app.py` now asserts
the API actually **surfaces** the chain/disposition fields (genesis `chain_seq=0`,
all-zero `chain_prev_hash`, 64-hex `chain_hash`, `suppressed=False`). No test was
weakened, skipped, or removed to make the run look clean.

## Status against the exit criterion

| Criterion | Evidence |
|---|---|
| Published precision/recall against a documented corpus | `docs/DETECTION_EFFICACY.md` (generated, in sync): Precision 0.7143, Recall 1.0000, F1 0.8333, FP/day 11.52; corpus of 55 seeded windows |
| Every rule versioned, mapped, and independently tested | `detection/rules_catalog.yaml`: 4 rules, each versioned + ATT&CK-mapped with rationale; `tests/test_rules.py` + `tests/test_rule_catalog.py` |
| Tamper-evident evidence chain | Migration 8 hash chain; `verify_findings_chain()`/`verify_policy_chain()` pass intact, detect a mutation at `break_seq=1`; `tests/test_evidence_chain.py` |
| Corpus on a credible path to the ML gate | `docs/NORMAL_CORPUS_PROGRAM.md` + `collect_normal_window.py`/`corpus_status.py`; fixed gate reused unchanged; ~56+ holdout windows still required, path documented |
| Green suite, fixed not trimmed | 468 passed, 4 skipped (sklearn-absent ML tests, pre-existing); API regression fixed additively, not by weakening a test |
