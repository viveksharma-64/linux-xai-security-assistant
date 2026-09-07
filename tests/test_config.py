"""
Tests for layered configuration.

The layering itself is the security control: a config file that is silently
ignored, or an environment override that silently loses to a default, means an
operator who set `api_require_auth` believes the API is authenticated when it is
not. These tests assert precedence and fail-closed behaviour rather than the values
of individual defaults.
"""

from __future__ import annotations

import pytest

from observability.config import (
    ConfigError,
    Settings,
    config_file_path,
    load_settings,
    reset_settings_cache,
    settings,
)


def write_config(tmp_path, body: str):
    path = tmp_path / "config.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_apply_when_nothing_is_configured():
    resolved = load_settings(environ={})
    assert resolved.api_require_auth is True
    assert resolved.db_file_mode == 0o600
    assert resolved.db_enforce_mode is True


def test_config_file_overrides_defaults(tmp_path):
    path = write_config(tmp_path, "api_port: 9999\nretention_max_age_days: 7\n")
    resolved = load_settings(environ={"SECURITY_CONFIG_FILE": str(path)})
    assert resolved.api_port == 9999
    assert resolved.retention_max_age_days == 7.0


def test_environment_overrides_the_config_file(tmp_path):
    path = write_config(tmp_path, "api_port: 9999\n")
    resolved = load_settings(
        environ={"SECURITY_CONFIG_FILE": str(path), "SECURITY_API_PORT": "8123"}
    )
    # The environment is the layer a human is holding at the moment they run the
    # process, so it wins. If this inverted, an operator debugging an incident
    # would be silently overridden by a file they are not looking at.
    assert resolved.api_port == 8123


def test_a_named_config_file_that_does_not_exist_is_fatal(tmp_path):
    with pytest.raises(ConfigError) as error:
        config_file_path({"SECURITY_CONFIG_FILE": str(tmp_path / "absent.yaml")})
    assert "not a readable file" in str(error.value)


def test_unparseable_values_are_rejected_rather_than_defaulted(tmp_path):
    with pytest.raises(ConfigError) as error:
        load_settings(environ={"SECURITY_API_PORT": "not-a-port"})
    assert "SECURITY_API_PORT" in str(error.value) or "api_port" in str(error.value)


def test_file_modes_must_be_quoted_in_yaml(tmp_path):
    # YAML 1.1 parses a bare 0600 as octal (384) and a bare 600 as decimal, so the
    # two spellings an operator considers equivalent arrive as different numbers.
    # Refused with the fix in the message rather than guessed at, because guessing
    # wrong applies a permission nobody asked for to the evidence database.
    path = write_config(tmp_path, "db_file_mode: 0600\n")
    with pytest.raises(ConfigError) as error:
        load_settings(environ={"SECURITY_CONFIG_FILE": str(path)})
    assert "quoted" in str(error.value)


def test_quoted_file_modes_agree_across_layers(tmp_path):
    path = write_config(tmp_path, 'db_file_mode: "0600"\n')
    from_file = load_settings(environ={"SECURITY_CONFIG_FILE": str(path)})
    from_env = load_settings(environ={"SECURITY_DB_FILE_MODE": "600"})
    assert from_file.db_file_mode == 0o600
    assert from_env.db_file_mode == 0o600


def test_a_world_readable_database_mode_is_refused():
    # The database holds command lines, file paths, and usernames. A mode that
    # grants group or other access makes every local account a reader of the audit
    # trail, so it is rejected at startup rather than warned about.
    with pytest.raises(ConfigError) as error:
        load_settings(environ={"SECURITY_DB_FILE_MODE": "644"})
    assert "group or other" in str(error.value)


def test_boolean_coercion_accepts_operator_spellings():
    for raw in ("0", "false", "no", "off"):
        assert load_settings(environ={"SECURITY_API_REQUIRE_AUTH": raw}).api_require_auth is False
    for raw in ("1", "true", "yes", "on"):
        assert load_settings(environ={"SECURITY_API_REQUIRE_AUTH": raw}).api_require_auth is True


def test_invalid_boolean_is_rejected_rather_than_read_as_false():
    # The dangerous failure: "maybe" parsed as falsey would disable authentication
    # on a host whose operator asked for it.
    with pytest.raises(ConfigError):
        load_settings(environ={"SECURITY_API_REQUIRE_AUTH": "maybe"})


def test_nonsensical_values_are_rejected_by_validation():
    with pytest.raises(ConfigError):
        load_settings(environ={"SECURITY_QUEUE_SIZE": "0"})
    with pytest.raises(ConfigError):
        load_settings(environ={"SECURITY_INGEST_BATCH_SIZE": "-1"})
    with pytest.raises(ConfigError):
        load_settings(environ={"SECURITY_ALERT_MIN_FREE_DISK_RATIO": "1.5"})
    with pytest.raises(ConfigError):
        # A ceiling below the floor would make the backoff ladder incoherent.
        load_settings(
            environ={
                "SECURITY_RESTART_INITIAL_BACKOFF": "30",
                "SECURITY_RESTART_MAX_BACKOFF": "5",
            }
        )


def test_zero_retention_means_keep_indefinitely_not_delete_everything():
    # The dangerous reading of an unset window is `now - 0`, which would delete the
    # entire evidence record on the first maintenance pass. 0 is a disabled policy.
    resolved = load_settings(environ={"SECURITY_RETENTION_MAX_AGE_DAYS": "0"})
    assert resolved.retention_max_age_days == 0.0


def test_settings_are_cached_and_the_cache_is_resettable(monkeypatch, tmp_path):
    path = write_config(tmp_path, "api_port: 9001\n")
    monkeypatch.setenv("SECURITY_CONFIG_FILE", str(path))
    reset_settings_cache()
    assert settings().api_port == 9001
    assert settings() is settings()

    monkeypatch.setenv("SECURITY_API_PORT", "9002")
    # Still cached: a long-running process must not change its configuration
    # underneath itself because an unrelated environment variable moved.
    assert settings().api_port == 9001
    reset_settings_cache()
    assert settings().api_port == 9002


def test_replace_returns_a_new_settings_without_mutating_the_original():
    base = Settings()
    derived = base.replace(api_port=1234)
    assert derived.api_port == 1234
    assert base.api_port == 8000
    assert derived.db_path == base.db_path
