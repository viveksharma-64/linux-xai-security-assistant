# Phase E — ML Anomaly Attribution

This project's promise is that every score is reconstructable from stored evidence,
and that evidence is labelled FACT or INTERPRETATION. The ML signal was the one place
that promise stayed thin. `MLScorer.score()` already surfaces
`contributing_feature_deviations` — the features whose value is furthest from the
training mean by z-score. That is honest but shallow: it describes the *input* ("these
features look unusual on their own"), not *how the Isolation Forest actually isolated
this window*. The explainer says as much, carrying the caveat that those deviations
"are statistical, not causal explanations."

Attribution closes that gap. It decomposes the forest's own scored quantity — the
isolation-path length — by the feature the forest tested at each split, and the
decomposition reconciles to that path length **exactly**. The ML factor now explains
the model, not just the input, while staying advisory: it changes no score, activates
nothing, persists nothing of its own, and is off by default.

It is deliberately additive and opt-in. A scorer must be configured *and* attribution
enabled before a single number changes; the shipped default payload is byte-for-byte
what it was. This is the most conservative reading of the ML invariants — advisory-only,
default-off, off the hot path, deterministic — applied to an explanatory feature.

## Method

The native forest scores a window by
`raw = −2 ** (−depths / denominator) − offset`, where `depths` is summed over trees:

```
depths = Σ_trees ( node_depth(leaf) − 1 )  +  Σ_trees c(n_node_samples[leaf])
```

(`ml/iforest.py`, `decision_function`). `node_depth(leaf) − 1` is exactly the number of
internal splits on the row's root→leaf path in that tree, and **each split tests one
feature**. So the first sum is a count of feature tests, and regrouping those integer
terms by which feature was tested is an exact additive decomposition:

```
depths = total_splits + leaf_correction
       = Σ_features split_count[feature]  +  Σ_trees c(n_node_samples[leaf])
```

`total_splits` is the model-faithful attribution surface: `split_count[feature]` is how
many of the splits on the scored isolation path tested that feature. `leaf_correction`
is the average-path-length residual the forest adds at each leaf for the subtree it did
not build — carried and reported, but not attributed to any feature, because no feature
was tested to produce it. `path-length-split-attribution.v1` is the versioned name of
this decomposition.

The traversal that produces the counts (`NativeIsolationForest.path_length_attribution`)
reuses `decision_function`'s routing **verbatim**: the same shape check, the same
scaler `transform`, and — load-bearing — the same `astype(np.float32).astype(np.float64)`
cast before every `<=` comparison. The attributed path is therefore bitwise the path
that was scored. Skipping the float32 cast and routing in full float64 would send any
value within float32 resolution of a threshold down the other branch — a different leaf,
a different depth, a different score — so the cast is exactly what makes "the path we
explain is the path we scored" true rather than approximately true.

**Rejected alternative — occlusion to the training mean.** Reset each feature to its
scaled-zero (training-mean) value, re-score, and take the change in score. It was
considered because it yields score-space deltas that pair naturally with the existing
counterfactual factor. It was rejected: Isolation Forest is nonlinear, so per-feature
deltas do **not** sum to the score (no reconciliation identity, so no FACT-grade claim),
it is model-agnostic rather than forest-native, and it costs 34× the forest evaluations
per finding. It may return later as a *complementary* INTERPRETATION-space view; it is
not this decomposition.

## Reproduction / how to enable

Attribution is opt-in at scorer construction:

```python
from ml.scoring import MLScorer

scorer = MLScorer(store, model_id, attribute=True)
result = scorer.score(window_events)
result["attribution"]   # present only because attribute=True
```

The `attribution` block travels through the detector — which passes the entire score
payload through as `evidence["ml_anomaly"]["model"]` — into the finding, and the
explainer's `ml_anomaly_evidence` FACT factor surfaces it under `evidence.attribution`.
No detector change and no new evidence signal are involved; a default `MLScorer(store,
model_id)` produces exactly the payload and factor it did before.

The block is bounded and named:

```json
{
  "method": "path-length-split-attribution.v1",
  "features": [{"feature": "network_connection_count", "split_count": 812, "split_share": 0.31}, ...],
  "reported_feature_count": 8,
  "attributed_feature_count": 27,
  "total_splits": 2619,
  "leaf_correction": 41.83,
  "isolation_path_length": 2660.83,
  "baseline_path_length": 5.11,
  "reconciles": true
}
```

`features` is capped to the top 8 by split participation (deterministic tie-break on
feature name); `attributed_feature_count` reports the full breadth so the cap is visible.
`baseline_path_length` is `c(max_samples)`, the expected isolation depth of an
unremarkable point — the yardstick a shorter, more anomalous path is short relative to.

## FACT

*These are the checked, deterministic properties (`tests/test_ml_attribution.py`).
They are proven twice: directly against a hand-built `NativeIsolationForest` — no
scikit-learn, so these run in every environment and pin the **exact** per-feature
split counts against a known-answer path — and end-to-end on a real trained forest
wherever scikit-learn is installed.*

- **Reconciliation.** `total_splits` equals the exact integer sum of the per-feature
  split counts, and `total_splits + leaf_correction` reconstructs the scored
  `isolation_path_length` (to float tolerance; the only slack is one floating-point
  re-association of an exact integer with the residual). The payload carries
  `reconciles: true` as an inline self-check.
- **Routing parity.** The path attributed is bitwise the path `decision_function`
  scored. The test reconstructs the raw score from the attributed depths and demands
  bitwise equality with `decision_function` across the training windows, a 256-row
  seeded sweep of scaled space, and rows placed *exactly* on split thresholds and one
  ULP either side in both float32 and float64 resolution. The sklearn-free forest
  repeats that boundary sweep with thresholds chosen to be non-float32-exact — the
  case where routing in full float64 instead of reusing the cast would take the other
  branch — so the guard fails loudly if the cast is ever dropped.
- **Determinism / order-independence.** A window is a set of events; attribution for a
  window equals attribution for its reversed event list, matching the deterministic-
  scoring guarantee the scorer already holds.
- **Bounded and named.** The reported set is capped to the top-N, every feature name is
  a real schema feature, and the reported shares sum to at most the whole path's splits.

## INTERPRETATION

*This section is judgement about what the numbers mean, kept separate from the facts
above.*

*Split participation is not a causal explanation and not a SHAP-additive share of the
outcome.* It answers one specific, model-faithful question: **on the isolation path this
forest actually placed the window on, which features did it test, and how often?** A
high `split_count` means the forest repeatedly found that feature useful for isolating
this window — which is genuine, model-internal signal — but it does not mean that
feature *caused* the anomaly, that zeroing it would change the score by any particular
amount, or that the per-feature counts can be summed into a decomposition of the score
in the SHAP sense. Isolation Forest is nonlinear; the counts decompose the *path length*
exactly, not the *score* attributably. Read them as "where the model looked," alongside
— not in place of — the deterministic FACTs and the z-score deviations, which answer the
different question of which inputs were unusual on their own.

## Note on tooling

`ruff` and `mypy` are advisory in CI; the enforced merge gate is the pytest suite. The
new files were written to the configured house style (120-column lines,
`from __future__ import annotations` where the module carries it, fully typed
signatures). `AGENTS.md` is left unchanged: by its own rule it is updated only at a major
architectural milestone, and an additive, opt-in explainer feature that touches no gate,
migration, artifact format, lifecycle, or fusion weight is not one.
