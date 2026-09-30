"""
Guard that the shipped systemd units are actually startable.

A unit file is executable configuration that no test ran before this one, and
its failure mode is total and silent-until-deployed: systemd splits `ExecStart=`
on whitespace, so an unquoted `--source NAME=/path/python probe.py` arrives as
three argv words, argparse rejects the trailing one as an unrecognized argument,
and the ingest service exits 2 on every start and restart. Nothing in the
repository noticed, because every other test constructs the service in-process.

Two properties are pinned here: the command line as shipped parses, and the
collectors it names exist and cover the event types the detectors consume.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import pytest

from pipeline.service import _build_parser, parse_source_spec

ROOT = Path(__file__).resolve().parent.parent
UNITS = ROOT / "deploy" / "systemd"
INGEST_UNIT = UNITS / "linux-xai-ingest.service"
API_UNIT = UNITS / "linux-xai-api.service"

# The install prefix the units assume; stripped to resolve paths in this checkout.
INSTALL_PREFIX = "/opt/linux-xai-security/"


def _exec_start(unit: Path) -> list[str]:
    """The ExecStart command, joined across continuations and split as systemd would."""
    text = unit.read_text()
    # Join backslash continuations first, then take everything after ExecStart=.
    joined = re.sub(r"\\\n\s*", " ", text)
    match = re.search(r"^ExecStart=(.+)$", joined, re.MULTILINE)
    assert match, f"{unit.name} has no ExecStart"
    return shlex.split(match.group(1))


def _source_specs(argv: list[str]) -> list[str]:
    return _build_parser().parse_args(argv[1:]).source


def test_ingest_unit_command_line_parses_as_shipped():
    # The regression this file exists for. `parse_args` raises SystemExit(2) on
    # an unrecognized argument, which is exactly what systemd would surface as a
    # service that never starts.
    argv = _exec_start(INGEST_UNIT)
    try:
        specs = _source_specs(argv)
    except SystemExit as error:  # pragma: no cover - only on a regression
        pytest.fail(f"ExecStart does not parse: argparse exited {error.code}")
    assert specs, "the ingest unit supervises no collectors"


def test_every_supervised_source_spec_is_well_formed():
    # NAME=COMMAND, with a command that survives the split the supervisor does.
    for spec in _source_specs(_exec_start(INGEST_UNIT)):
        source = parse_source_spec(spec)  # raises ValueError on a malformed spec
        assert source.name
        argv = spec.partition("=")[2].split()
        assert len(argv) >= 2, f"{source.name} has no script argument: {spec!r}"


def test_the_availability_detector_has_live_sources_wired():
    # detection/system_failure.py scores system_health and service_state. Both
    # were unwired, which left its disk, memory, CPU and unit-failure rules
    # unreachable on every deployment.
    names = {parse_source_spec(spec).name for spec in _source_specs(_exec_start(INGEST_UNIT))}
    assert "system_health" in names
    assert "service_state" in names
    # The security collectors are still there.
    assert {"process_exec", "network_connect", "network_state", "ipc_pipe"} <= names


def test_every_collector_script_named_by_the_unit_exists():
    # A path typo here is only discoverable on the target host otherwise: the
    # supervisor would restart, fail, and degrade the source forever.
    for spec in _source_specs(_exec_start(INGEST_UNIT)):
        script = spec.partition("=")[2].split()[-1]
        assert (ROOT / script).is_file(), f"{script} does not exist in the repository"


def test_process_exec_is_supervised_exactly_once():
    # telemetry_basic.py also emits process_exec alongside its health samples;
    # wiring it for health would have double-counted every exec and inflated the
    # execution-frequency features the behaviour baseline is built from.
    scripts = [
        spec.partition("=")[2].split()[-1]
        for spec in _source_specs(_exec_start(INGEST_UNIT))
    ]
    assert len(scripts) == len(set(scripts)), f"a collector is supervised twice: {scripts}"


@pytest.mark.parametrize("unit", [INGEST_UNIT, API_UNIT], ids=lambda p: p.name)
def test_unit_entry_point_is_a_declared_console_script(unit):
    # The binary the unit invokes must be something `pip install` actually
    # creates, or the service is unstartable no matter how correct its arguments.
    with (ROOT / "pyproject.toml").open("rb") as handle:
        scripts = set(tomllib.load(handle)["project"]["scripts"])
    executable = _exec_start(unit)[0]
    assert executable.startswith(INSTALL_PREFIX + ".venv/bin/")
    assert executable.rsplit("/", 1)[-1] in scripts


def test_the_journal_reading_collector_has_journal_access():
    # service_monitor.py shells out to journalctl. Without the systemd-journal
    # supplementary group the service user sees only its own records, so the
    # collector would run, stay healthy, and emit nothing.
    assert "SupplementaryGroups=systemd-journal" in INGEST_UNIT.read_text()
