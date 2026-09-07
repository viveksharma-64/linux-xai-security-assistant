"""
Catalog integrity and fail-closed loader tests for the externalized rule set.

The bundled detection/rules_catalog.yaml is the single source of every rule's
calibration and ATT&CK mapping. These tests pin the contract the rest of Phase C
relies on: each rule is versioned, ATT&CK-mapped with a written rationale, ids
are unique, every enabled entry is bound to an implementation, and the loader
fails closed -- a malformed or internally inconsistent catalog is an error, never
a silently defaulted rule, matching observability/config.py's posture.
"""

import pytest
import yaml

from detection.rules import (
    _RULE_TYPES,
    RuleCatalogError,
    load_catalog,
    load_rules,
)

_REQUIRED_MITRE = ("tactic", "technique")


def _base_document():
    """A minimal, valid single-rule catalog the negative tests mutate."""
    return {
        "version": 1,
        "rules": [
            {
                "rule_id": "execution_burst",
                "version": 1,
                "enabled": True,
                "score": 0.60,
                "peak_execs_per_second": 5,
                "window_execs": 10,
                "mitre": {"tactic": "TA0002 Execution", "technique": "T1059.004 Unix Shell"},
                "mapping_rationale": "a concentrated burst of process creation is script-driven",
                "description": "execution volume concentrated into a burst",
            }
        ],
    }


def _write(tmp_path, document, name="catalog.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


# --------------------------------------------------- bundled catalog contract


def test_bundled_catalog_binds_every_enabled_rule():
    document = load_catalog()
    enabled = [entry for entry in document["rules"] if entry.get("enabled", True)]
    rules = load_rules()
    assert len(rules) == len(enabled)
    assert {rule.rule_id for rule in rules} == {entry["rule_id"] for entry in enabled}


def test_every_bundled_rule_is_versioned_mapped_and_documented():
    document = load_catalog()
    seen = set()
    for entry in document["rules"]:
        rid = entry["rule_id"]
        assert rid not in seen, f"duplicate rule_id {rid}"
        seen.add(rid)
        assert str(entry["version"]).strip(), f"{rid} has no version"
        assert 0.0 <= float(entry["score"]) <= 1.0
        for field in _REQUIRED_MITRE:
            assert str(entry["mitre"][field]).strip(), f"{rid} missing mitre {field}"
        assert str(entry["mapping_rationale"]).strip(), f"{rid} has no rationale"
        assert str(entry["description"]).strip(), f"{rid} has no description"
        assert rid in _RULE_TYPES, f"{rid} has no implementation"


def test_loaded_rules_carry_version_and_mitre():
    for rule in load_rules():
        assert rule.version
        assert rule.mitre.get("tactic")
        assert rule.mitre.get("technique")


def test_base_document_is_valid(tmp_path):
    # Guards the negative tests below: their starting point must itself be valid,
    # so a failure there indicts the mutation, not a broken fixture.
    rules = load_rules(_write(tmp_path, _base_document()))
    assert [rule.rule_id for rule in rules] == ["execution_burst"]


# ---------------------------------------------------------- fail-closed loader


def test_unreadable_catalog_is_rejected(tmp_path):
    with pytest.raises(RuleCatalogError):
        load_catalog(tmp_path / "does_not_exist.yaml")


def test_non_mapping_document_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(RuleCatalogError):
        load_catalog(path)


def test_unknown_top_level_key_is_rejected(tmp_path):
    document = _base_document()
    document["unexpected"] = True
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_empty_rules_list_is_rejected(tmp_path):
    document = _base_document()
    document["rules"] = []
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_missing_required_field_is_rejected(tmp_path):
    document = _base_document()
    del document["rules"][0]["mapping_rationale"]
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_duplicate_rule_id_is_rejected(tmp_path):
    document = _base_document()
    document["rules"].append(dict(document["rules"][0]))
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_out_of_range_score_is_rejected(tmp_path):
    document = _base_document()
    document["rules"][0]["score"] = 1.5
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_empty_mitre_technique_is_rejected(tmp_path):
    document = _base_document()
    document["rules"][0]["mitre"] = {"tactic": "TA0002 Execution", "technique": "  "}
    with pytest.raises(RuleCatalogError):
        load_catalog(_write(tmp_path, document))


def test_unknown_rule_id_cannot_be_bound(tmp_path):
    document = _base_document()
    document["rules"][0]["rule_id"] = "totally_unknown_rule"
    path = _write(tmp_path, document)
    # The catalog itself is well-formed, so load_catalog accepts it...
    assert load_catalog(path)["rules"][0]["rule_id"] == "totally_unknown_rule"
    # ...but there is no implementation to bind, so load_rules fails closed.
    with pytest.raises(RuleCatalogError):
        load_rules(path)


def test_disabled_entry_is_in_catalog_but_not_bound(tmp_path):
    document = _base_document()
    document["rules"][0]["enabled"] = False
    path = _write(tmp_path, document)
    assert len(load_catalog(path)["rules"]) == 1
    assert load_rules(path) == []


def test_invalid_tunable_fails_at_load_not_detection(tmp_path):
    document = _base_document()
    document["rules"][0]["peak_execs_per_second"] = "not-an-int"
    with pytest.raises(RuleCatalogError):
        load_rules(_write(tmp_path, document))


def test_missing_tunable_fails_closed(tmp_path):
    # A typo'd tunable key leaves the real key absent; from_entry KeyErrors, and
    # the loader surfaces it rather than falling back to a hidden default.
    document = _base_document()
    document["rules"][0].pop("window_execs")
    with pytest.raises(RuleCatalogError):
        load_rules(_write(tmp_path, document))
