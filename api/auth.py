"""
Bearer-token authentication for the read-only API.

Why the read-only API needs authentication at all
-------------------------------------------------
It serves the evidence record: command lines, file paths, usernames, and the
detections derived from them. That is a reconnaissance feed -- an attacker who can
read it learns which of their actions were observed and which were not. "Read-only"
bounds what an attacker can *change* through this surface; it says nothing about
what they can learn.

Why bearer tokens and not sessions or mTLS
------------------------------------------
The consumers are a local dashboard, a curl in a runbook, and a monitoring
scraper. A shared bearer token is the weakest mechanism that actually covers those
three, needs no user database, and survives a service restart. mTLS is the right
answer for a multi-host deployment and is the documented upgrade path; adding a
CA to a single-host install would mostly add a way to lock oneself out.

Constant-time comparison
------------------------
Tokens are compared with `secrets.compare_digest`. A short-circuiting `==` leaks
the length of the matching prefix through response timing, which over enough
requests recovers the token one byte at a time. The comparison is against a hash
of the presented token rather than the token itself so that the timing signal does
not depend on token length either.

Failing closed
--------------
Authentication is required by default. If it is required and no token is
configured, every request is refused with 503 -- not served unauthenticated. An
operator who forgot to install a token file gets an outage they will notice and
fix in a minute; the alternative is an open evidence feed nobody notices for a
month.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

from observability.config import Settings

LOGGER = logging.getLogger(__name__)

# Minimum token length. 16 characters of the recommended `secrets.token_urlsafe`
# output is ~96 bits, which is not brute-forceable over a network in any relevant
# time. Enforced so a placeholder like "changeme" cannot be the control.
MIN_TOKEN_LENGTH = 16


class AuthConfigurationError(RuntimeError):
    """Raised when authentication is required but cannot be configured as written."""


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _read_token_file(path: Path) -> List[str]:
    """
    Read one token per line, ignoring blanks and `#` comments.

    Several tokens per file is deliberate: it is what makes rotation possible
    without an outage -- add the new token, move consumers, remove the old one.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise AuthConfigurationError(
            f"api_token_file {path} could not be read: {type(error).__name__}: {error}"
        ) from error
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:  # pragma: no cover - the read above already succeeded
        mode = 0
    if mode & 0o077:
        # Refused rather than warned: a token file every local account can read is
        # not an access control, and serving as though it were one is the failure
        # this module exists to prevent.
        raise AuthConfigurationError(
            f"api_token_file {path} has mode {mode:04o}; it must not be readable by group or other (use 0600)"
        )
    tokens = []
    for line in raw.splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            tokens.append(candidate)
    return tokens


class TokenAuthenticator:
    """
    The set of accepted tokens, resolved once at startup.

    Holds only SHA-256 digests. The plaintext tokens are not kept, so a heap dump,
    a traceback that renders locals, or a debugger attached to the API process
    cannot hand out a working credential.
    """

    def __init__(self, settings: Settings):
        self.required = settings.api_require_auth
        self._digests: Set[bytes] = set()
        self._sources: List[str] = []

        inline = settings.api_tokens or ""
        candidates: List[str] = [part.strip() for part in inline.split(",") if part.strip()]
        if candidates:
            self._sources.append("api_tokens")
        if settings.api_token_file:
            file_tokens = _read_token_file(Path(settings.api_token_file))
            if file_tokens:
                self._sources.append(f"api_token_file:{settings.api_token_file}")
            candidates.extend(file_tokens)

        short = [token for token in candidates if len(token) < MIN_TOKEN_LENGTH]
        if short:
            raise AuthConfigurationError(
                f"{len(short)} configured API token(s) are shorter than {MIN_TOKEN_LENGTH} characters; "
                "generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        self._digests = {_digest(token) for token in candidates}

        if self.required and not self._digests:
            LOGGER.error(
                "api_auth_unconfigured detail=%r",
                "authentication is required but no tokens are configured; the API will refuse every request",
            )
        if not self.required:
            LOGGER.warning(
                "api_auth_disabled detail=%r",
                "api_require_auth is false; the evidence API is being served without authentication",
            )

    @property
    def configured(self) -> bool:
        return bool(self._digests)

    @property
    def token_count(self) -> int:
        return len(self._digests)

    @property
    def sources(self) -> Sequence[str]:
        return tuple(self._sources)

    def verify(self, presented: Optional[str]) -> bool:
        """
        Whether a presented credential is accepted.

        Every configured digest is compared even after a match so that the number
        of comparisons -- and therefore the response time -- does not reveal which
        token was used or how many are installed.
        """
        if not self.required:
            return True
        if not presented or not self._digests:
            return False
        candidate = _digest(presented)
        matched = False
        for known in self._digests:
            if secrets.compare_digest(candidate, known):
                matched = True
        return matched


def extract_token(authorization: Optional[str], api_key: Optional[str]) -> Optional[str]:
    """
    Pull the credential out of `Authorization: Bearer ...` or `X-API-Key`.

    `X-API-Key` is accepted because the scraper and the dashboard's `fetch` are
    both easier to configure with a plain header, and refusing it would push
    operators towards putting the token in a query string, where it lands in
    access logs and in browser history.
    """
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    if api_key and api_key.strip():
        return api_key.strip()
    return None


def unprotected_paths() -> Iterable[str]:
    """
    Paths served without a token.

    Only liveness. A liveness probe runs from the process manager before any
    credential is available and its answer -- "this process responds" -- discloses
    nothing about the monitored host. Readiness and metrics are *not* here:
    readiness reports data age and degraded collector names, and metrics report
    volumes and coverage windows, all of which are useful reconnaissance.
    """
    return ("/api/health", "/api/health/live")
