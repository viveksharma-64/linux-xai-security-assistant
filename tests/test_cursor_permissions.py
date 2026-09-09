"""Gap B: the journald cursor file and its state directory are owner-only.

The cursor records exactly where this host has read to in its own journal. It is
not secret in the cryptographic sense, but it is host-state that no other local
user has any reason to read, and the atomic-write path is the natural place to
make that explicit and umask-proof. These tests assert the security property
without disturbing the frozen content or the temp-file hygiene the other
CursorStore tests pin.
"""

import os
import stat

import pytest

from telemetry.journald.journal_stream import CursorStore

# A syntactically valid journald cursor per is_valid_cursor: [A-Za-z0-9=;]{16,512}.
VALID_CURSOR = "s=0123456789abcdef;i=1;b=1;m=1;t=1"


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX file modes only")
def test_cursor_file_is_owner_only(tmp_path):
    store = CursorStore(tmp_path / "state" / "auth.cursor")
    assert store.save(VALID_CURSOR) is True
    mode = (tmp_path / "state" / "auth.cursor").stat().st_mode
    # fchmod sets the mode absolutely, so this is exact rather than a floor: the
    # file the write path renames into place carries 0600 with its inode.
    assert stat.S_IMODE(mode) == 0o600


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX file modes only")
def test_state_directory_is_owner_only(tmp_path):
    store = CursorStore(tmp_path / "state" / "auth.cursor")
    assert store.save(VALID_CURSOR) is True
    mode = (tmp_path / "state").stat().st_mode
    # mkdir's mode is masked by umask, so assert the security property (nothing for
    # group or other) rather than an exact 0o700 an unusual umask could narrow.
    assert stat.S_IMODE(mode) & 0o077 == 0


def test_hardening_preserves_exact_cursor_content(tmp_path):
    # The permission work must not alter the byte content: a torn or rewritten
    # cursor would be rejected by is_valid_cursor and demote the collector to the
    # fallback window -- the loss CursorStore exists to prevent.
    store = CursorStore(tmp_path / "auth.cursor")
    assert store.save(VALID_CURSOR) is True
    assert (tmp_path / "auth.cursor").read_text(encoding="utf-8") == VALID_CURSOR


def test_hardening_leaves_no_temporary_files(tmp_path):
    store = CursorStore(tmp_path / "auth.cursor")
    assert store.save(VALID_CURSOR) is True
    assert [p.name for p in tmp_path.iterdir()] == ["auth.cursor"]


def test_save_into_existing_directory_still_writes_owner_only_file(tmp_path):
    # exist_ok leaves an existing directory's permissions untouched (by design, so
    # a readonly state dir is not silently widened), but the file itself is still
    # fchmod'd to 0600 on every save.
    existing = tmp_path / "state"
    existing.mkdir()  # created before the store, so mkdir(mode=0o700) is a no-op
    store = CursorStore(existing / "auth.cursor")
    assert store.save(VALID_CURSOR) is True
    if hasattr(os, "fchmod"):
        mode = (existing / "auth.cursor").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600
