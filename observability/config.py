"""
Layered runtime configuration: built-in defaults < config file < environment.

Why three layers
----------------
The service has to be configurable in three different situations and they pull
in different directions. A developer wants to change one value for one run, which
is an environment variable. An operator wants a reviewable, package-managed file
that survives reboots and shows up in a diff, which is `/etc/`. And a fresh
checkout has to start with no configuration at all, which is the defaults. Layer
precedence is environment last because that is the layer a human is holding when
something is on fire.

Failing closed
--------------
An unparseable value raises `ConfigError` rather than falling back to the
default. Silently substituting a default would mean a typo in
`retention_max_age_days` quietly keeps events forever, or a typo in
`api_require_auth` quietly serves the API unauthenticated -- both are the exact
opposite of what the operator wrote down. Startup failure is loud, immediate, and
recoverable; a misread security setting is none of those.

`SECURITY_LOG_LEVEL` is deliberately *not* handled this way (see
`observability.configure_logging`): logging is an observation channel, not a
control, so an unreadable level degrades rather than blocks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

# Searched in order; the first readable file wins. `/etc` is the packaged
# location, and the environment override exists so a test or a second instance
# on the same host can point somewhere else without touching system state.
CONFIG_FILE_ENV = "SECURITY_CONFIG_FILE"
DEFAULT_CONFIG_PATHS: Tuple[str, ...] = (
    "/etc/linux-xai-security/config.yaml",
    "/etc/linux-xai-security/config.yml",
)

# Filesystem layout conventions for a packaged install. Held here rather than in
# the systemd units so the Python side and the units cannot drift apart.
DEFAULT_STATE_DIR = "/var/lib/linux-xai-security"
DEFAULT_DB_PATH = "phase2_events.db"


class ConfigError(RuntimeError):
    """Raised when configuration is present but cannot be honoured as written."""


def _as_bool(raw: Any, key: str) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{key}: expected a boolean, got {raw!r}")


def _as_int(raw: Any, key: str) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{key}: expected an integer, got {raw!r}") from error


def _as_float(raw: Any, key: str) -> float:
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{key}: expected a number, got {raw!r}") from error


def _as_str(raw: Any, key: str) -> str:
    if raw is None:
        raise ConfigError(f"{key}: expected a string, got null")
    return str(raw)


def _as_optional_str(raw: Any, key: str) -> Optional[str]:
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


@dataclass(frozen=True)
class Settings:
    """
    The complete set of operator-tunable values, flattened on purpose.

    Flat rather than nested-per-subsystem because every field needs exactly three
    things declared next to it -- a default, a config-file key, and an environment
    variable -- and a nested structure hides which of the three is missing.
    """

    # --- storage -----------------------------------------------------------
    db_path: str = DEFAULT_DB_PATH
    # 0600 by default: the database is the evidence record and holds command
    # lines, file paths, and usernames. Group/other readability would make every
    # local account a reader of the audit trail.
    db_file_mode: int = 0o600
    db_enforce_mode: bool = True

    # --- api ---------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_require_auth: bool = True
    # Comma-separated inline tokens, and/or a file with one token per line. The
    # file is preferred for packaged installs: an environment variable is visible
    # in `/proc/<pid>/environ` and in `systemctl show`, a 0600 file is not.
    api_tokens: Optional[str] = None
    api_token_file: Optional[str] = None

    # --- telemetry freshness ----------------------------------------------
    stale_after_seconds: float = 300.0

    # --- ingestion ---------------------------------------------------------
    queue_size: int = 1024
    backpressure_timeout_seconds: float = 2.0
    health_interval_seconds: float = 1.0
    ingest_batch_size: int = 50

    # --- supervision -------------------------------------------------------
    restart_initial_backoff_seconds: float = 1.0
    restart_max_backoff_seconds: float = 60.0
    # A collector that has run this long is considered to have started
    # successfully, which resets the backoff ladder.
    restart_healthy_runtime_seconds: float = 60.0
    crash_loop_threshold: int = 5
    crash_loop_window_seconds: float = 300.0
    quarantine_dir: Optional[str] = None
    quarantine_max_batches: int = 128

    # --- retention ---------------------------------------------------------
    retention_max_age_days: float = 30.0
    retention_max_db_bytes: int = 2 * 1024 * 1024 * 1024
    retention_interval_seconds: float = 3600.0
    retention_vacuum_interval_seconds: float = 86400.0
    retention_prune_batch: int = 5000

    # --- alerting ----------------------------------------------------------
    alert_min_free_disk_bytes: int = 512 * 1024 * 1024
    alert_min_free_disk_ratio: float = 0.05
    alert_max_queue_fill_ratio: float = 0.8
    alert_collector_silence_seconds: float = 120.0

    # --- system-failure detection -----------------------------------------
    # Availability-impacting host/service conditions surfaced as findings by
    # detection/system_failure.py. Detection only -- these thresholds decide
    # what gets *recorded*, never what gets *done*. Percentages are matched
    # against the collector's system_health payload (cpu/mem/disk _percent);
    # a null field is treated as unknown, never as a breach.
    failure_memory_high_pct: float = 90.0
    failure_memory_medium_pct: float = 80.0
    failure_memory_min_available_mb: int = 128
    failure_cpu_high_pct: float = 95.0
    failure_disk_full_pct: float = 99.0
    # Hysteresis: a sustained condition must breach for this many consecutive
    # 300s windows before a finding is emitted, and must fall below a distinct
    # lower clear threshold (breach * clear_ratio, inverted for "lower is
    # worse") for this many windows before it clears. Discrete events (a unit
    # entering the failed state) bypass hysteresis. The window count -- not the
    # ingestion batch count -- is what advances, so these mean wall-clock time.
    failure_consecutive_windows: int = 2
    failure_clear_windows: int = 2
    failure_clear_ratio: float = 0.9
    # Repeated service failures inside this lookback are labelled a crash loop
    # rather than a single failure. The lookback spans window boundaries.
    failure_crash_loop_threshold: int = 3
    failure_crash_loop_window_seconds: float = 600.0

    def replace(self, **overrides: Any) -> "Settings":
        merged = {f.name: getattr(self, f.name) for f in fields(self)}
        merged.update(overrides)
        return Settings(**merged)


# field name -> (config-file key, environment variable, coercer)
#
# The config-file key is the field name; it is spelled out anyway so a rename in
# Python cannot silently invalidate every deployed `/etc` file.
_FIELD_SPECS: Dict[str, Tuple[str, str, Callable[[Any, str], Any]]] = {
    "db_path": ("db_path", "SECURITY_DB_PATH", _as_str),
    "db_file_mode": ("db_file_mode", "SECURITY_DB_FILE_MODE", lambda raw, key: _as_mode(raw, key)),
    "db_enforce_mode": ("db_enforce_mode", "SECURITY_DB_ENFORCE_MODE", _as_bool),
    "api_host": ("api_host", "SECURITY_API_HOST", _as_str),
    "api_port": ("api_port", "SECURITY_API_PORT", _as_int),
    "api_require_auth": ("api_require_auth", "SECURITY_API_REQUIRE_AUTH", _as_bool),
    "api_tokens": ("api_tokens", "SECURITY_API_TOKENS", _as_optional_str),
    "api_token_file": ("api_token_file", "SECURITY_API_TOKEN_FILE", _as_optional_str),
    "stale_after_seconds": ("stale_after_seconds", "TELEMETRY_STALE_AFTER_SECONDS", _as_float),
    "queue_size": ("queue_size", "SECURITY_QUEUE_SIZE", _as_int),
    "backpressure_timeout_seconds": ("backpressure_timeout_seconds", "SECURITY_BACKPRESSURE_TIMEOUT", _as_float),
    "health_interval_seconds": ("health_interval_seconds", "SECURITY_HEALTH_INTERVAL", _as_float),
    "ingest_batch_size": ("ingest_batch_size", "SECURITY_INGEST_BATCH_SIZE", _as_int),
    "restart_initial_backoff_seconds": ("restart_initial_backoff_seconds", "SECURITY_RESTART_INITIAL_BACKOFF", _as_float),
    "restart_max_backoff_seconds": ("restart_max_backoff_seconds", "SECURITY_RESTART_MAX_BACKOFF", _as_float),
    "restart_healthy_runtime_seconds": ("restart_healthy_runtime_seconds", "SECURITY_RESTART_HEALTHY_RUNTIME", _as_float),
    "crash_loop_threshold": ("crash_loop_threshold", "SECURITY_CRASH_LOOP_THRESHOLD", _as_int),
    "crash_loop_window_seconds": ("crash_loop_window_seconds", "SECURITY_CRASH_LOOP_WINDOW", _as_float),
    "quarantine_dir": ("quarantine_dir", "SECURITY_QUARANTINE_DIR", _as_optional_str),
    "quarantine_max_batches": ("quarantine_max_batches", "SECURITY_QUARANTINE_MAX_BATCHES", _as_int),
    "retention_max_age_days": ("retention_max_age_days", "SECURITY_RETENTION_MAX_AGE_DAYS", _as_float),
    "retention_max_db_bytes": ("retention_max_db_bytes", "SECURITY_RETENTION_MAX_DB_BYTES", _as_int),
    "retention_interval_seconds": ("retention_interval_seconds", "SECURITY_RETENTION_INTERVAL", _as_float),
    "retention_vacuum_interval_seconds": ("retention_vacuum_interval_seconds", "SECURITY_VACUUM_INTERVAL", _as_float),
    "retention_prune_batch": ("retention_prune_batch", "SECURITY_RETENTION_PRUNE_BATCH", _as_int),
    "alert_min_free_disk_bytes": ("alert_min_free_disk_bytes", "SECURITY_ALERT_MIN_FREE_DISK_BYTES", _as_int),
    "alert_min_free_disk_ratio": ("alert_min_free_disk_ratio", "SECURITY_ALERT_MIN_FREE_DISK_RATIO", _as_float),
    "alert_max_queue_fill_ratio": ("alert_max_queue_fill_ratio", "SECURITY_ALERT_MAX_QUEUE_FILL_RATIO", _as_float),
    "alert_collector_silence_seconds": ("alert_collector_silence_seconds", "SECURITY_ALERT_COLLECTOR_SILENCE", _as_float),
    "failure_memory_high_pct": ("failure_memory_high_pct", "SECURITY_FAILURE_MEMORY_HIGH_PCT", _as_float),
    "failure_memory_medium_pct": ("failure_memory_medium_pct", "SECURITY_FAILURE_MEMORY_MEDIUM_PCT", _as_float),
    "failure_memory_min_available_mb": ("failure_memory_min_available_mb", "SECURITY_FAILURE_MEMORY_MIN_AVAILABLE_MB", _as_int),
    "failure_cpu_high_pct": ("failure_cpu_high_pct", "SECURITY_FAILURE_CPU_HIGH_PCT", _as_float),
    "failure_disk_full_pct": ("failure_disk_full_pct", "SECURITY_FAILURE_DISK_FULL_PCT", _as_float),
    "failure_consecutive_windows": ("failure_consecutive_windows", "SECURITY_FAILURE_CONSECUTIVE_WINDOWS", _as_int),
    "failure_clear_windows": ("failure_clear_windows", "SECURITY_FAILURE_CLEAR_WINDOWS", _as_int),
    "failure_clear_ratio": ("failure_clear_ratio", "SECURITY_FAILURE_CLEAR_RATIO", _as_float),
    "failure_crash_loop_threshold": ("failure_crash_loop_threshold", "SECURITY_FAILURE_CRASH_LOOP_THRESHOLD", _as_int),
    "failure_crash_loop_window_seconds": ("failure_crash_loop_window_seconds", "SECURITY_FAILURE_CRASH_LOOP_WINDOW", _as_float),
}


def _as_mode(raw: Any, key: str) -> int:
    """
    Parse a file mode, treating a digit string as octal.

    Modes must be quoted in YAML. This is not pedantry -- YAML 1.1 parses a bare
    `0600` as octal itself (giving 384, which is 0o600) and a bare `600` as decimal
    600, so the two spellings an operator would consider equivalent arrive here as
    different numbers, and there is no way to tell 0o644 written as `0644` (420)
    from a decimal 420 that was meant as 0o420. Guessing would eventually apply a
    mode nobody wrote to the evidence database.

    So an unquoted number is refused with the fix in the message, and `"0600"` /
    `"600"` -- from a quoted YAML value or from the environment, which is always
    strings -- are parsed as octal, matching every other Unix tool.
    """
    if isinstance(raw, bool) or isinstance(raw, (int, float)):
        raise ConfigError(
            f"{key}: file modes must be quoted so YAML cannot reinterpret them, "
            f'got the number {raw!r}; write it as "0600"'
        )
    text = str(raw).strip()
    try:
        if text.lower().startswith(("0o", "0x", "0b")):
            return int(text, 0)
        return int(text, 8)
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{key}: expected an octal file mode, got {raw!r}") from error


def _validate(settings: Settings) -> Settings:
    """
    Reject values that are individually parseable but jointly meaningless.

    Each check names the field, because the caller is an operator reading a
    startup failure in `journalctl`, not a developer with a traceback.
    """
    positive = (
        ("queue_size", settings.queue_size),
        ("health_interval_seconds", settings.health_interval_seconds),
        ("ingest_batch_size", settings.ingest_batch_size),
        ("restart_initial_backoff_seconds", settings.restart_initial_backoff_seconds),
        ("restart_max_backoff_seconds", settings.restart_max_backoff_seconds),
        ("crash_loop_threshold", settings.crash_loop_threshold),
        ("crash_loop_window_seconds", settings.crash_loop_window_seconds),
        ("retention_interval_seconds", settings.retention_interval_seconds),
        ("retention_prune_batch", settings.retention_prune_batch),
        ("stale_after_seconds", settings.stale_after_seconds),
        ("failure_memory_high_pct", settings.failure_memory_high_pct),
        ("failure_memory_medium_pct", settings.failure_memory_medium_pct),
        ("failure_memory_min_available_mb", settings.failure_memory_min_available_mb),
        ("failure_cpu_high_pct", settings.failure_cpu_high_pct),
        ("failure_disk_full_pct", settings.failure_disk_full_pct),
        ("failure_consecutive_windows", settings.failure_consecutive_windows),
        ("failure_clear_windows", settings.failure_clear_windows),
        ("failure_crash_loop_threshold", settings.failure_crash_loop_threshold),
        ("failure_crash_loop_window_seconds", settings.failure_crash_loop_window_seconds),
    )
    for key, value in positive:
        if value <= 0:
            raise ConfigError(f"{key}: must be positive, got {value!r}")

    non_negative = (
        ("backpressure_timeout_seconds", settings.backpressure_timeout_seconds),
        ("retention_max_age_days", settings.retention_max_age_days),
        ("retention_max_db_bytes", settings.retention_max_db_bytes),
        ("retention_vacuum_interval_seconds", settings.retention_vacuum_interval_seconds),
        ("alert_min_free_disk_bytes", settings.alert_min_free_disk_bytes),
        ("quarantine_max_batches", settings.quarantine_max_batches),
        ("alert_collector_silence_seconds", settings.alert_collector_silence_seconds),
    )
    for key, value in non_negative:
        if value < 0:
            raise ConfigError(f"{key}: must not be negative, got {value!r}")

    for key, value in (
        ("alert_min_free_disk_ratio", settings.alert_min_free_disk_ratio),
        ("alert_max_queue_fill_ratio", settings.alert_max_queue_fill_ratio),
    ):
        if not 0.0 <= value <= 1.0:
            raise ConfigError(f"{key}: must be a ratio between 0 and 1, got {value!r}")

    if settings.restart_max_backoff_seconds < settings.restart_initial_backoff_seconds:
        raise ConfigError(
            "restart_max_backoff_seconds must be >= restart_initial_backoff_seconds "
            f"({settings.restart_max_backoff_seconds} < {settings.restart_initial_backoff_seconds})"
        )
    if not 1 <= settings.api_port <= 65535:
        raise ConfigError(f"api_port: must be a valid TCP port, got {settings.api_port}")
    if settings.db_file_mode & 0o077:
        raise ConfigError(
            f"db_file_mode: {settings.db_file_mode:04o} grants group or other access to the "
            "evidence database; use 0600 or 0400"
        )

    # System-failure thresholds are matched against 0-100 percentages, so a
    # threshold above 100 could never fire and almost certainly reflects a typo
    # (e.g. a byte count pasted into a percent field). CPU is intentionally not
    # capped: a collector that sums per-core utilisation can exceed 100.
    for key, value in (
        ("failure_memory_high_pct", settings.failure_memory_high_pct),
        ("failure_memory_medium_pct", settings.failure_memory_medium_pct),
        ("failure_disk_full_pct", settings.failure_disk_full_pct),
    ):
        if value > 100.0:
            raise ConfigError(f"{key}: is a percentage and must be <= 100, got {value!r}")
    if settings.failure_memory_medium_pct >= settings.failure_memory_high_pct:
        raise ConfigError(
            "failure_memory_medium_pct must be below failure_memory_high_pct "
            f"({settings.failure_memory_medium_pct} >= {settings.failure_memory_high_pct})"
        )
    # A clear ratio of 1.0 means no dead-band (a value clears the instant it
    # dips below the breach threshold); above 1.0 the clear threshold would sit
    # above the breach threshold and the condition could never clear.
    if not 0.0 < settings.failure_clear_ratio <= 1.0:
        raise ConfigError(
            f"failure_clear_ratio: must be in (0, 1], got {settings.failure_clear_ratio!r}"
        )
    return settings


def config_file_path(environ: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    """
    The config file that would be read, or None when there is none.

    An explicitly requested file that does not exist is an error rather than a
    silent fall-through to the packaged default: the operator named a file, and
    starting with different settings than the ones they pointed at is worse than
    not starting.
    """
    env = os.environ if environ is None else environ
    requested = env.get(CONFIG_FILE_ENV, "").strip()
    if requested:
        path = Path(requested)
        if not path.is_file():
            raise ConfigError(f"{CONFIG_FILE_ENV} points at {requested!r}, which is not a readable file")
        return path
    for candidate in DEFAULT_CONFIG_PATHS:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def _read_config_file(path: Path) -> Dict[str, Any]:
    import yaml

    try:
        with path.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"cannot read configuration file {path}: {type(error).__name__}: {error}") from error
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ConfigError(f"configuration file {path} must contain a YAML mapping")
    unknown = sorted(set(document) - {spec[0] for spec in _FIELD_SPECS.values()})
    if unknown:
        # Rejected rather than ignored. A typo'd key in a security config is a
        # setting the operator believes is in force and is not.
        raise ConfigError(f"configuration file {path} has unknown keys: {', '.join(unknown)}")
    return document


def load_settings(
    environ: Optional[Mapping[str, str]] = None,
    config_path: Optional[Path] = None,
) -> Settings:
    """
    Resolve defaults, then the config file, then the environment.

    Both inputs are injectable so tests can exercise layering without touching
    the process environment or `/etc`.
    """
    env = os.environ if environ is None else environ
    path = config_path if config_path is not None else config_file_path(env)
    document = _read_config_file(path) if path is not None else {}

    values: Dict[str, Any] = {}
    for name, (file_key, env_key, coerce) in _FIELD_SPECS.items():
        if file_key in document:
            values[name] = coerce(document[file_key], f"{file_key} (from {path})")
        raw_env = env.get(env_key)
        if raw_env is not None and raw_env != "":
            values[name] = coerce(raw_env, env_key)

    return _validate(Settings(**values))


_CACHED: Optional[Settings] = None


def settings() -> Settings:
    """
    Process-wide settings, resolved once.

    Cached because the values are read on request paths and re-reading `/etc` per
    request would make configuration a latency and failure source. Entry points
    that need to re-read call `reset_settings_cache()`.
    """
    global _CACHED
    if _CACHED is None:
        _CACHED = load_settings()
    return _CACHED


def reset_settings_cache() -> None:
    global _CACHED
    _CACHED = None
