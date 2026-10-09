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

`session_id` names the *login session* -- logind's, as `XDG_SESSION_ID` reports
it -- and exists for the verified-normal corpus rather than for incident
reconstruction. The activation gate wants 60 independent holdout windows, and
"independent" has to be decidable from the stored rows; boot_id alone forces one
window per reboot. Login sessions are the finer unit of independence a desktop
actually produces several of per boot. It is only meaningful paired with
boot_id: logind numbers sessions from 1 again after every reboot, so the tuple
`(boot_id, session_id)` is the identity, and `session_id` on its own is not.

Everything here fails soft. A container with no `/etc/machine-id`, a kernel that
does not export a boot id, or a daemon that belongs to no login session must
degrade to "identity unknown" rather than stop ingestion: losing telemetry is a
worse outcome than recording it with an incomplete provenance field, and a null
is honest about what is not known. Callers that *need* identity -- the capture
wrapper, which must not record an unattributable window -- enforce that
themselves; see `scripts/capture_normal_window.sh`.
"""

import hashlib
import hmac
import logging
import os
import re
import uuid
from functools import lru_cache

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

# How a caller declares which login session it is observing, and how
# `scripts/capture_normal_window.sh` hands the session it resolved down into the
# ingestion process it starts.
SESSION_ID_ENV = "SECURITY_SESSION_ID"

# What logind exports into every session's environment. pam_systemd(8) sets it,
# so it is present for an interactive login and absent for a system service --
# which is exactly the distinction this field needs to make.
XDG_SESSION_ID_ENV = "XDG_SESSION_ID"

# logind session ids are short and opaque: "2" for a normal login, "c1" for a
# greeter. Anything outside this shape is a misconfigured environment rather
# than a session, and storing it would be worse than storing nothing --
# `scripts/verify_capture_boot.py` keys holdout independence on this value, so a
# junk id is a false independence claim.
_SESSION_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,32}\Z")


def _read_first_line(path: str) -> str | None:
    """Return the stripped first line of a file, or None if it cannot be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.readline().strip()
    except OSError as error:
        LOGGER.debug("identity_source_unavailable path=%s error=%s", path, error)
        return None
    return value or None


def _derive(raw: str) -> str:
    """Keyed derivation of a confidential source value; see the module docstring."""
    return hmac.new(_HOST_ID_CONTEXT, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:_HOST_ID_LENGTH]


@lru_cache(maxsize=1)
def host_id() -> str | None:
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
def boot_id() -> str | None:
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


def _validate_session_id(raw: str | None, source: str) -> str | None:
    """Accept a session id only if it has logind's shape; see `_SESSION_ID_PATTERN`."""
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if not _SESSION_ID_PATTERN.match(value):
        LOGGER.warning(
            "ignoring malformed login session id from %s: %r; events will be "
            "recorded without a session_id",
            source,
            value[:64],
        )
        return None
    return value


@lru_cache(maxsize=1)
def session_id() -> str | None:
    """
    Identifier of the login session being observed, or None if there is not one.

    Read from the environment and nowhere else, which is the load-bearing
    decision here. logind can be *asked* which session is currently active on a
    seat, and using that would be wrong for the process that stamps most events:
    `linux-xai-ingest.service` is a long-running system service that belongs to
    no login session, so "the active session when I started" is a value that is
    already a guess, goes stale the moment that user logs out, and then
    mislabels every subsequent event for the rest of the service's lifetime.
    Declining to answer is the honest result, and a NULL `session_id` simply
    means the row is not usable as evidence of an independent login session --
    which is true.

    So the two sources are both declarations rather than inferences:
    `SECURITY_SESSION_ID` for a caller that resolved a session deliberately
    (`scripts/capture_normal_window.sh` does, and refuses to capture if it
    cannot), and `XDG_SESSION_ID` for a process that is genuinely running inside
    a login session and inherited it from pam_systemd.

    Only meaningful alongside `boot_id()`: session ids restart at 1 after a
    reboot, so this value is a component of an identity, not an identity.
    """
    override = _validate_session_id(os.getenv(SESSION_ID_ENV), SESSION_ID_ENV)
    if override is not None:
        return override
    return _validate_session_id(os.getenv(XDG_SESSION_ID_ENV), XDG_SESSION_ID_ENV)


def reset_cache() -> None:
    """
    Clear the cached identity.

    Exists for tests, which need to observe the unreadable-source and
    environment-override paths without a fresh interpreter.
    """
    host_id.cache_clear()
    boot_id.cache_clear()
    agent_id.cache_clear()
    session_id.cache_clear()
