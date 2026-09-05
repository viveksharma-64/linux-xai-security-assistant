"""
Identity of the host and agent that observed a telemetry event.

Why events need identity
------------------------
Every canonical `Event` used to describe only what happened -- a pid, a comm, a
timestamp -- and nothing about where it was seen or by which collector run. That
is survivable while a database holds one host's telemetry and nothing else, and
wrong the moment it does not: two hosts that both ran `pid 1412 / bash` at the
same second produce byte-identical records, so the deduplicating store silently
merges two real events into one and an analyst loses an entire host's evidence
without any indication that it happened.

Identity also makes a monotonic clock reading mean something. `time.monotonic()`
is only comparable within a single boot, so a monotonic timestamp without a boot
identifier is a number that cannot be ordered against any other number. The two
fields are only useful together.

What is exposed, and what is not
--------------------------------
`host_id` is derived from `/etc/machine-id` through a keyed hash rather than
copied. systemd's machine-id(5) documents the raw value as confidential and
states it must not be used directly by applications, because it is a stable
cross-boot fingerprint of the machine; the same manual page describes deriving
an application-specific value instead, which is what `_derive` does. The audit
record therefore never contains a raw machine fingerprint, while still carrying
a value that is stable across reboots and agent restarts -- the property that
makes it safe to deduplicate on.

`boot_id` is kept raw, deliberately, and this is a considered difference rather
than an oversight. It changes at every reboot, so it is not a stable
fingerprint, and keeping it verbatim lets an operator line the agent's record up
against `journalctl --list-boots` when reconstructing an incident. Hashing it
would destroy that correlation to protect a value that is already readable by
anyone who can read `/proc`.

Everything here fails soft. A container with no `/etc/machine-id`, or a kernel
that does not export a boot id, must degrade to "identity unknown" rather than
stop ingestion: losing telemetry is a worse outcome than recording it with an
incomplete provenance field, and a null is honest about what is not known.
"""

import hashlib
import hmac
import logging
import os
import uuid
from functools import lru_cache
from typing import Optional

LOGGER = logging.getLogger(__name__)

MACHINE_ID_PATH = "/etc/machine-id"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

# Domain separator for the derivation. Fixed and versioned so the same machine
# always derives the same host_id across agent versions -- changing this string
# would silently re-identify every host and defeat deduplication against rows
# already stored. Treat it as part of the on-disk format.
_HOST_ID_CONTEXT = b"linux-xai-security-assistant/host-id/v1"

# 128 bits of the digest. Long enough that a collision is not a practical
# concern, short enough to keep the column narrow on a table that grows per
# event.
_HOST_ID_LENGTH = 32

AGENT_ID_ENV = "SECURITY_AGENT_ID"


def _read_first_line(path: str) -> Optional[str]:
    """Return the stripped first line of a file, or None if it cannot be read."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.readline().strip()
    except OSError as error:
        LOGGER.debug("identity_source_unavailable path=%s error=%s", path, error)
        return None
    return value or None


def _derive(raw: str) -> str:
    """Keyed derivation of a confidential source value; see the module docstring."""
    return hmac.new(_HOST_ID_CONTEXT, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:_HOST_ID_LENGTH]


@lru_cache(maxsize=1)
def host_id() -> Optional[str]:
    """
    Stable, non-reversible identifier for this machine.

    Cached because it is read once per event on the ingestion path and the
    underlying file does not change while the process runs. Stability across
    reboots and agent restarts is the point: it is the one identity field the
    deduplication hash can safely include, because a replayed capture must still
    deduplicate against the rows it produced the first time.
    """
    raw = _read_first_line(MACHINE_ID_PATH)
    if raw is None:
        LOGGER.warning(
            "host identity unavailable: %s could not be read; events will be "
            "recorded without a host_id",
            MACHINE_ID_PATH,
        )
        return None
    return _derive(raw)


@lru_cache(maxsize=1)
def boot_id() -> Optional[str]:
    """
    Identifier of the current kernel boot, verbatim.

    This is what makes `Event.timestamp_monotonic` interpretable: monotonic
    readings from two different boots are unrelated numbers, and comparing them
    would produce ordering that looks valid and is not.
    """
    return _read_first_line(BOOT_ID_PATH)


@lru_cache(maxsize=1)
def agent_id() -> str:
    """
    Identifier for this agent process.

    Random per run rather than stable per host, because the question it answers
    is "which collector run recorded this", which is what separates a gap caused
    by an agent restart from a gap caused by a quiet host. `SECURITY_AGENT_ID`
    overrides it for deployments that manage their own agent naming.
    """
    configured = os.getenv(AGENT_ID_ENV, "").strip()
    return configured or str(uuid.uuid4())


def reset_cache() -> None:
    """
    Clear the cached identity.

    Exists for tests, which need to observe the unreadable-source and
    environment-override paths without a fresh interpreter.
    """
    host_id.cache_clear()
    boot_id.cache_clear()
    agent_id.cache_clear()
