"""
Guard that the shipped example config stays in lockstep with the settings schema.

A drifted example is a specific operational failure: an operator copies it, adds
a key that was renamed or removes one that became required, and the service
either refuses to start or -- worse for a security control -- starts with a
setting they believe is in force and is not. Two properties are pinned: the
example as shipped loads without error, and it names every configurable key so a
new setting cannot be added to the code without being documented here.
"""

from __future__ import annotations

import re
from pathlib import Path

from observability.config import _FIELD_SPECS, load_settings

EXAMPLE = Path(__file__).resolve().parent.parent / "deploy" / "config.example.yaml"
CONFIG_KEYS = {spec[0] for spec in _FIELD_SPECS.values()}
_KEY_LINE = re.compile(r"^#? ?([a-z_]+):")


def _uncomment_every_key(text: str) -> str:
    # The example ships with most keys commented so defaults apply; to exercise
    # them through the real loader we turn "# key: value" back into "key: value".
    lines = []
    for line in text.splitlines():
        match = re.match(r"^# ([a-z_]+):", line)
        lines.append(line[2:] if match and match.group(1) in CONFIG_KEYS else line)
    return "\n".join(lines)


def test_the_example_config_loads_with_every_key_active(tmp_path):
    active = tmp_path / "config.yaml"
    active.write_text(_uncomment_every_key(EXAMPLE.read_text(encoding="utf-8")), encoding="utf-8")
    # environ={} isolates the load from the real process environment.
    settings = load_settings(environ={}, config_path=active)
    # The mode round-trips as octal, which is the whole reason it must be quoted.
    assert settings.db_file_mode == 0o600
    assert settings.api_require_auth is True


def test_the_example_documents_every_configurable_key():
    documented = {
        match.group(1)
        for line in EXAMPLE.read_text(encoding="utf-8").splitlines()
        if (match := _KEY_LINE.match(line))
    }
    missing = CONFIG_KEYS - documented
    assert not missing, f"config.example.yaml is missing keys: {sorted(missing)}"
