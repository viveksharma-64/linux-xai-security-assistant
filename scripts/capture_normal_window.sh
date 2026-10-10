#!/usr/bin/env bash
#
# capture_normal_window.sh
#
# Records ONE bounded normal-behaviour capture per login session, for the
# verified-normal corpus program (docs/NORMAL_CORPUS_PROGRAM.md). It captures and
# nothing else: it never promotes a window, never writes to the corpus database,
# and never touches the activation gate. Promotion stays a manual, attested step
# (scripts/collect_normal_window.py --i-verified-normal).
#
# Why one capture per login session, keyed on (boot_id, session_id):
#
#   The gate needs 60 *independent* holdout windows, and the existing August
#   2026 corpus failed that test because 25 consecutive captures came from a
#   single 2h17m uptime. A wall-clock timer would reproduce that defect faster:
#   on a host with 30 days of uptime, six fires a day is 180 same-boot captures.
#
#   The unit of independence is therefore a *session of use*, not an interval.
#   One capture per boot is the strictest version of that and prices 60 windows
#   at 60 reboots, which is not a program anyone finishes. A login session is the
#   next-finest unit a desktop genuinely produces several of per boot -- each one
#   is a separate decision to sit down and use the machine -- so this script keys
#   on the pair instead: logind renumbers sessions from 1 after every reboot, so
#   `session_id` alone is not unique and `(boot_id, session_id)` is the identity.
#   That pair is also what gets stamped into every event row (migration 11), so
#   scripts/verify_capture_boot.py checks the claim from the data rather than
#   trusting the filename.
#
#   Same-boot sessions are a *weaker* independence claim than distinct boots --
#   they share the kernel, page cache, and long-running daemons. That trade-off
#   is written down in docs/NORMAL_CORPUS_PROGRAM.md; it is not hidden here.
#
# Refusing rather than guessing:
#
#   A capture whose login session cannot be identified is worthless to the
#   program -- it can never be shown independent of any other window -- so this
#   script exits non-zero instead of recording one. That is the opposite of
#   pipeline/identity.session_id(), which returns None rather than blocking
#   ingestion: losing live telemetry is worse than an incomplete provenance
#   field, but recording an unattributable *corpus candidate* is worse than
#   recording nothing.
#
# Exit status:
#
#   0   a capture was written, or this session already has one (idempotent)
#   75  nothing to capture *right now*: nobody is logged in, or two sessions are
#       live and neither can be chosen. Transient host state rather than a fault,
#       separated out because the timer polls -- a laptop sitting at its login
#       screen would otherwise mark the unit failed on every fire. EX_TEMPFAIL
#       from sysexits(3); the unit maps it to success via SuccessExitStatus=.
#   1   a real refusal: malformed session id, a session logind cannot corroborate,
#       a non-user session, or a capture that failed to run.
#
# The capture lands in $CAPTURE_DIR/pending/ and is written under a `.partial`
# name first. A capture that crashes therefore never claims the session's slot
# and never looks promotable: the August corpus has exactly that casualty
# (training-13.db, a 4 KiB main database whose only data was an unreplayed WAL),
# and the rename-on-success makes that state visible instead of silent.
#
# Usage:
#   sudo scripts/capture_normal_window.sh            # from inside the session to capture
#   sudo CAPTURE_SECONDS=305 CAPTURE_DIR=/srv/caps scripts/capture_normal_window.sh
#
# Environment:
#   CAPTURE_DIR        root for pending/ and promoted/  (default /var/lib/linux-xai-captures)
#   CAPTURE_SECONDS    window length in seconds         (default 305)
#   APP_DIR            repository/install root          (default this script's parent)
#   INGEST_PYTHON      interpreter for live_ingestion   (default $APP_DIR/.venv/bin/python, else python3)
#   COLLECTOR_PYTHON   interpreter for the BCC collector (default python3 -- see below)
#   COLLECTOR          collector module path            (default telemetry/bcc/telemetry_basic.py)
#   SECURITY_SESSION_ID  capture this login session instead of resolving one
#   SESSIONS_DIR       logind session records           (default /run/systemd/sessions)
#
# COLLECTOR_PYTHON defaults to the *system* python3 deliberately: README.md
# documents that privileged BCC collectors must run under the interpreter that
# has python3-bpfcc installed, which is normally not a virtualenv.

set -u

here="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${APP_DIR:-$(cd "$here/.." && pwd)}"

CAPTURE_DIR="${CAPTURE_DIR:-/var/lib/linux-xai-captures}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-305}"
COLLECTOR="${COLLECTOR:-telemetry/bcc/telemetry_basic.py}"
COLLECTOR_PYTHON="${COLLECTOR_PYTHON:-python3}"
BOOT_ID_PATH="${BOOT_ID_PATH:-/proc/sys/kernel/random/boot_id}"
SESSIONS_DIR="${SESSIONS_DIR:-/run/systemd/sessions}"

if [ -z "${INGEST_PYTHON:-}" ]; then
    if [ -x "$APP_DIR/.venv/bin/python" ]; then
        INGEST_PYTHON="$APP_DIR/.venv/bin/python"
    else
        INGEST_PYTHON="python3"
    fi
fi

# --- identify the boot -------------------------------------------------------
#
# This is the same file pipeline/identity.boot_id() reads, so the filename and
# the boot_id stamped into every event row come from one source. That is what
# makes scripts/verify_capture_boot.py able to check the claim afterwards
# instead of trusting the name.

if [ ! -r "$BOOT_ID_PATH" ]; then
    echo "capture_normal_window: cannot read $BOOT_ID_PATH; refusing to capture" >&2
    exit 1
fi
boot_id="$(tr -d '[:space:]' < "$BOOT_ID_PATH")"
if [ -z "$boot_id" ]; then
    echo "capture_normal_window: empty boot id at $BOOT_ID_PATH; refusing to capture" >&2
    exit 1
fi

# --- identify the login session ----------------------------------------------
#
# Three sources, in descending order of how much they are a *declaration* rather
# than an inference. Whichever answers, the id is then checked against logind's
# own record: an id nobody can corroborate is not a verified session, and the
# record is also what the provenance manifest is built from.

# Mirrors pipeline/identity._SESSION_ID_PATTERN. Not cosmetic: this value becomes
# part of a filename, so a shape check is what stops `../../etc/something` from
# being treated as a session id.
_is_session_id() {
    case "$1" in
        "") return 1 ;;
        *[!A-Za-z0-9_-]*) return 1 ;;
    esac
    [ "${#1}" -le 32 ]
}

# logind's session records are documented as private data that should not be
# parsed; the sanctioned reader is `loginctl`, which needs the system bus. A
# hardened oneshot unit may not have one, and a file read cannot fail halfway, so
# this reads the record directly and takes the simple `KEY=value` shape as the
# contract. `loginctl show-session` remains the cross-check for a human.
_session_field() {
    sed -n "s/^$2=//p" "$1" | head -n 1
}

# Candidates for "the session this host is being used from right now": active,
# and a real user login rather than a greeter (CLASS=greeter) or a system
# session. Only consulted when nothing declared a session; a declared session is
# not required to be active, because an operator may well capture from a session
# they have switched away from, and that is still a distinct session of use.
_active_user_sessions() {
    [ -d "$SESSIONS_DIR" ] || return 0
    for path in "$SESSIONS_DIR"/*; do
        [ -f "$path" ] || continue
        candidate="$(basename "$path")"
        _is_session_id "$candidate" || continue
        [ "$(_session_field "$path" STATE)" = "active" ] || continue
        [ "$(_session_field "$path" CLASS)" = "user" ] || continue
        printf '%s\n' "$candidate"
    done
}

session_id="${SECURITY_SESSION_ID:-}"
session_source="SECURITY_SESSION_ID"

if [ -z "$session_id" ]; then
    # Set by pam_systemd for any interactive login, so this is the normal path
    # when an operator runs the script from the session they want captured.
    session_id="${XDG_SESSION_ID:-}"
    session_source="XDG_SESSION_ID"
fi

if [ -z "$session_id" ]; then
    # The unattended path: no login session of our own, so ask which one the
    # host is being used from. Exactly one answer, or decline -- a guess between
    # two live sessions would attribute the window to the wrong one, and a wrong
    # session_id is a false independence claim rather than a missing field.
    # Declining here is exit 75, not 1: "nobody is logged in" is the normal
    # state of an idle host, and the timer polls.
    active="$(_active_user_sessions)"
    active_count="$(printf '%s\n' "$active" | grep -c .)"
    if [ "$active_count" -eq 0 ]; then
        echo "capture_normal_window: no active login session found in $SESSIONS_DIR and" >&2
        echo "  neither SECURITY_SESSION_ID nor XDG_SESSION_ID is set; nothing to capture" >&2
        echo "  right now. Run this from inside the session to capture it." >&2
        exit 75
    fi
    if [ "$active_count" -gt 1 ]; then
        echo "capture_normal_window: $active_count active login sessions; cannot tell which" >&2
        echo "  one to attribute the window to. Set SECURITY_SESSION_ID to choose:" >&2
        # Unquoted on purpose: $active is newline-separated and every entry has
        # already passed _is_session_id, so word splitting cannot produce a
        # surprise and each id gets its own indented line.
        # shellcheck disable=SC2086
        printf '  %s\n' $active >&2
        exit 75
    fi
    session_id="$active"
    session_source="$SESSIONS_DIR"
fi

if ! _is_session_id "$session_id"; then
    echo "capture_normal_window: malformed login session id from $session_source; refusing" >&2
    exit 1
fi

session_record="$SESSIONS_DIR/$session_id"
if [ ! -r "$session_record" ]; then
    echo "capture_normal_window: session $session_id (from $session_source) has no readable" >&2
    echo "  record at $session_record, so it cannot be verified as a login session;" >&2
    echo "  refusing to capture. A stale XDG_SESSION_ID inherited from a logged-out" >&2
    echo "  session looks exactly like this." >&2
    exit 1
fi

session_class="$(_session_field "$session_record" CLASS)"
if [ "$session_class" != "user" ]; then
    echo "capture_normal_window: session $session_id is CLASS=${session_class:-unknown}, not a" >&2
    echo "  user login; refusing to capture it as a normal-behaviour window" >&2
    exit 1
fi

# Every event row gets this stamped by pipeline/identity.session_id(), which
# reads the environment and nothing else -- so this export is the whole link
# between the session resolved here and the provenance stored in the capture.
export SECURITY_SESSION_ID="$session_id"

pending="$CAPTURE_DIR/pending"
promoted="$CAPTURE_DIR/promoted"
name="normal-$boot_id-s$session_id.db"

mkdir -p "$pending" "$promoted" || exit 1
chmod 0700 "$CAPTURE_DIR" "$pending" "$promoted" 2>/dev/null || true

# --- one capture per session -------------------------------------------------
#
# Checked across both directories: a capture the operator has already reviewed
# and moved to promoted/ must not be re-taken, or one session would contribute
# two windows and the independence claim would be false again. Re-running this
# script inside the same session -- or starting the unit by hand after the timer
# already fired -- is therefore a no-op, while a later login produces a new id
# and a new capture, which is the point.

if [ -e "$pending/$name" ] || [ -e "$promoted/$name" ]; then
    echo "capture_normal_window: boot $boot_id session $session_id already has a capture; nothing to do"
    exit 0
fi

# --- snapshot the session's provenance ---------------------------------------
#
# logind deletes its session records at reboot, and the whole independence
# argument rests on them: REALTIME is the login wall-clock, which is what shows
# two same-boot windows came from sessions that did not overlap. Reviewing a
# capture a week later means reviewing this file, so it is written before the
# capture starts -- the session can end while the window is still running, and
# the record would be gone by the time we looked.

manifest="$pending/$name.manifest.json"
manifest_tmp="$manifest.partial"
rm -f "$manifest_tmp"

if ! "$INGEST_PYTHON" - \
        "$session_record" "$session_id" "$boot_id" "$session_source" "$manifest_tmp" <<'PY'
import json
import sys
import time

record_path, session, boot, source, out = sys.argv[1:6]

# Everything here describes the session rather than the user's activity in it.
# REALTIME/MONOTONIC are the login instant (microseconds) and are the fields
# that make non-overlap auditable; UID/USER/SEAT/TYPE/CLASS/SERVICE describe what
# kind of session it was; LEADER is the session leader pid.
KEEP = (
    "UID", "USER", "STATE", "ACTIVE", "CLASS", "TYPE", "ORIGINAL_TYPE",
    "SEAT", "VTNR", "DISPLAY", "SERVICE", "DESKTOP", "SCOPE",
    "LEADER", "REMOTE", "REMOTE_HOST", "REMOTE_USER", "AUDIT",
    "REALTIME", "MONOTONIC",
)

fields: dict[str, str] = {}
with open(record_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        if key in KEEP:
            fields.setdefault(key, value.strip())

manifest = {
    "schema": "normal-capture-session.v1",
    "boot_id": boot,
    "session_id": session,
    "session_id_source": source,
    "session_record": record_path,
    "snapshotted_at": time.time(),
    "logind_session": fields,
}

with open(out, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
then
    echo "capture_normal_window: could not snapshot $session_record; refusing to capture a" >&2
    echo "  window whose session cannot be audited later" >&2
    rm -f "$manifest_tmp"
    exit 1
fi

# --- capture -----------------------------------------------------------------
#
# live_ingestion has no --duration flag: it runs until SIGINT/SIGTERM and shuts
# down cleanly on either, so bounding the window is this wrapper's job. timeout
# exits 124 when it had to signal, which is the *expected* ending for a
# fixed-length window, not a failure. --kill-after is the backstop for a
# collector that ignores SIGTERM.

tmp="$pending/$name.partial"
rm -f "$tmp" "$tmp-wal" "$tmp-shm"

cd "$APP_DIR" || exit 1

echo "capture_normal_window: boot $boot_id session $session_id (via $session_source),"
echo "  ${CAPTURE_SECONDS}s -> $pending/$name"

status=0
timeout --signal=TERM --kill-after=30 "$CAPTURE_SECONDS" \
    "$INGEST_PYTHON" -m pipeline.live_ingestion --db "$tmp" -- \
    "$COLLECTOR_PYTHON" "$COLLECTOR" || status=$?

if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
    echo "capture_normal_window: capture failed (exit $status); leaving $tmp for inspection" >&2
    exit "$status"
fi

if [ ! -s "$tmp" ]; then
    echo "capture_normal_window: $tmp was not written; nothing to finalize" >&2
    exit 1
fi

# --- finalize ----------------------------------------------------------------
#
# Move the WAL and shm sidecars with the main database. Renaming the main file
# alone would orphan a WAL that still held rows -- the training-13 failure mode.
# The manifest is renamed first so that the database's presence always implies
# its provenance is there too; the reverse order could leave a promotable
# capture with no session record behind it.

mv "$manifest_tmp" "$manifest" || exit 1
mv "$tmp" "$pending/$name" || exit 1
for sidecar in wal shm; do
    if [ -e "$tmp-$sidecar" ]; then
        mv "$tmp-$sidecar" "$pending/$name-$sidecar" || exit 1
    fi
done
chmod 0600 "$pending/$name" "$manifest" 2>/dev/null || true

echo "capture_normal_window: wrote $pending/$name"
echo "capture_normal_window: session provenance in $manifest"
echo "capture_normal_window: next, verify independence and review before promoting:"
# sudo, because the capture is 0600 inside a 0700 directory owned by whoever ran
# this -- root under sudo, linux-xai under the unit. Printed without it the
# command fails as "unable to open database file", which reads like a corrupt
# capture rather than the permission denial it actually is.
echo "  sudo $INGEST_PYTHON scripts/verify_capture_boot.py $pending/$name --against $promoted"
