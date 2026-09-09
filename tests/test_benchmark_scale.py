"""
Correctness gate for the scale benchmark's invariant checker.

`scripts/benchmark_scale.py` publishes a capacity *shape* -- timings that depend on
the host and its load, and are therefore never asserted. What CAN be asserted is
the deterministic core the harness gates with `--check`: that the synthetic corpus
builds valid hash chains, that event and finding counts reconcile against what was
written and pruned, and that retention honours its age cutoff and byte cap. These
tests exercise that checker on a genuine tiny-tier run and then confirm it actually
*fails* when each invariant is broken -- a checker that always returns "OK" would
gate nothing.

No timings are asserted anywhere here, by design: a test that fails when the CI box
is busy is worse than no test.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

# The harness lives under scripts/, which is not importable by name (pythonpath is
# the repo root only), so load it by file path -- self-contained and independent of
# any path configuration.
_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_scale.py"
_spec = importlib.util.spec_from_file_location("benchmark_scale", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
benchmark_scale = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(benchmark_scale)

# Tiny tiers: enough to build every chain and drive the retention path, small
# enough to run in well under a second.
_EVENT_TIERS = (200,)
_FINDING_TIERS = (50,)
_ML_FLOOR = 20
_REPEATS = 2


@pytest.fixture()
def sweeps(tmp_path):
    """A real (tiny) run of both sweeps, for the checker to read."""
    event_sweep = benchmark_scale.run_event_sweep(
        _EVENT_TIERS, batch=50, repeats=_REPEATS, db_path=str(tmp_path / "events.db")
    )
    finding_sweep = benchmark_scale.run_finding_sweep(
        _FINDING_TIERS, repeats=_REPEATS, ml_floor=_ML_FLOOR,
        db_path=str(tmp_path / "findings.db"),
    )
    return event_sweep, finding_sweep


def test_tiny_run_satisfies_every_invariant(sweeps):
    event_sweep, finding_sweep = sweeps
    assert benchmark_scale.check_invariants(event_sweep, finding_sweep) == []


def test_run_actually_built_the_chains_and_retention_ran(sweeps):
    # Guards against the checker passing vacuously: confirm the run really produced
    # the structures the invariants read, so "no violations" means "all held", not
    # "nothing was measured".
    event_sweep, finding_sweep = sweeps
    assert event_sweep["retention"] is not None
    assert all(tier["facts"]["all_chains_ok"] for tier in finding_sweep["tiers"])
    verify = finding_sweep["tiers"][-1]["verify"]
    assert set(verify) == {"findings", "policy", "triage", "ml_lifecycle"}
    assert all(v["checked"] > 0 for v in verify.values())


def test_check_cli_exits_zero():
    # The gate the doc and CI invoke. Runs its own tiny tiers internally.
    assert benchmark_scale.main(["--check"]) == 0


def test_broken_chain_is_caught(sweeps):
    event_sweep, finding_sweep = sweeps
    broken = copy.deepcopy(finding_sweep)
    broken["tiers"][-1]["verify"]["findings"]["ok"] = False
    broken["tiers"][-1]["facts"]["all_chains_ok"] = False
    violations = benchmark_scale.check_invariants(event_sweep, broken)
    assert any("chain" in v and "findings" in v for v in violations)


def test_event_count_mismatch_is_caught(sweeps):
    event_sweep, finding_sweep = sweeps
    broken = copy.deepcopy(event_sweep)
    broken["tiers"][-1]["facts"]["count_matches_written"] = False
    violations = benchmark_scale.check_invariants(broken, finding_sweep)
    assert any("count_events disagrees" in v for v in violations)


def test_page_total_mismatch_is_caught(sweeps):
    event_sweep, finding_sweep = sweeps
    broken = copy.deepcopy(finding_sweep)
    broken["tiers"][-1]["facts"]["page_total_matches"] = False
    violations = benchmark_scale.check_invariants(event_sweep, broken)
    assert any("page total disagrees" in v for v in violations)


@pytest.mark.parametrize(
    "fact,needle",
    [
        ("oldest_after_ge_cutoff", "age cutoff"),
        ("size_cap_honored", "cap"),
        ("count_consistent", "reconcile"),
    ],
)
def test_retention_regression_is_caught(sweeps, fact, needle):
    event_sweep, finding_sweep = sweeps
    broken = copy.deepcopy(event_sweep)
    broken["retention"]["facts"][fact] = False
    violations = benchmark_scale.check_invariants(broken, finding_sweep)
    assert any(needle in v for v in violations)
