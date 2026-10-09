# Deployment

Two systemd services make up a deployment:

- **`linux-xai-ingest`** — the unattended daemon. Supervises the eBPF collector
  subprocesses (restart-with-backoff, crash-loop degradation, on-disk quarantine),
  writes the evidence database, prunes/size-caps it in-process, and logs alert
  transitions. This is the service the Phase B soak exercises.
- **`linux-xai-api`** — the read-only, authenticated API and dashboard. Runs with
  **no capabilities** and never writes an event.

They share one unprivileged user because the evidence database is mode `0600` and
both processes must open it; `DynamicUser=` would give them different UIDs and the
API could not read what the ingester wrote.

## Filesystem layout

| Path | Owner / mode | Contents |
|------|--------------|----------|
| `/opt/linux-xai-security` | root, `0755` | Application code and the `.venv` virtualenv (read-only to the service) |
| `/etc/linux-xai-security/config.yaml` | `linux-xai`, `0640` | Layered config (see `deploy/config.example.yaml`) |
| `/etc/linux-xai-security/tokens` | `linux-xai`, **`0600`** | API bearer tokens, one per line |
| `/var/lib/linux-xai-security` | `linux-xai`, `0700` | `events.db` (`0600`), WAL sidecars, quarantine dir, collector state |

The API refuses to start if `tokens` is group- or world-readable, and the store
refuses to open a database whose mode is looser than `0600`. Keeping `/opt`
root-owned means the service cannot rewrite its own code.

## Install

```bash
# 1. Create the shared service user and its state directory.
sudo cp deploy/systemd/linux-xai.sysusers.conf /etc/sysusers.d/linux-xai.conf
sudo systemd-sysusers

# 2. Install the code and a virtualenv under /opt.
sudo mkdir -p /opt/linux-xai-security
sudo cp -a . /opt/linux-xai-security/
sudo python3 -m venv /opt/linux-xai-security/.venv
sudo /opt/linux-xai-security/.venv/bin/pip install -e /opt/linux-xai-security

# 3. Configuration.
sudo mkdir -p /etc/linux-xai-security
sudo cp deploy/config.example.yaml /etc/linux-xai-security/config.yaml
sudo chown -R linux-xai:linux-xai /etc/linux-xai-security
sudo chmod 0640 /etc/linux-xai-security/config.yaml

# 4. API tokens: generate a strong one (>= 16 chars) into a 0600 file.
( umask 077; openssl rand -hex 32 | sudo -u linux-xai tee /etc/linux-xai-security/tokens >/dev/null )
sudo chmod 0600 /etc/linux-xai-security/tokens

# 5. Install and start the units.
sudo cp deploy/systemd/linux-xai-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linux-xai-ingest.service linux-xai-api.service
```

`events.db`, the WAL sidecars, and the quarantine directory are created
automatically in the `StateDirectory` on first run.

## Tuning capabilities to your kernel

The ingest unit grants the collectors their kernel rights via **ambient
capabilities** — an unprivileged service handing a child exactly what it needs, no
setuid, no root. The default set is deliberately broad so it works out of the box:

```
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_RESOURCE
```

Trim it to the minimum your kernel accepts and delete the rest — this is the single
highest-value hardening step for the deployment:

- **Kernel ≥ 5.8:** `CAP_BPF` + `CAP_PERFMON` are usually sufficient. Drop
  `CAP_SYS_ADMIN` first and confirm the collectors still attach.
- **Older kernels / some BCC operations:** keep `CAP_SYS_ADMIN` (it is the historic
  catch-all `bpf()` requires there).
- `CAP_SYS_PTRACE`/`CAP_SYS_RESOURCE` cover process introspection and the locked-memory
  limit for BPF maps; drop them if your probes don't need them.

Change **both** `AmbientCapabilities=` and `CapabilityBoundingSet=` together, then
`systemctl daemon-reload && systemctl restart linux-xai-ingest` and check
`journalctl -u linux-xai-ingest` for collector-attach errors.

Several sandbox directives are intentionally *relaxed* on the ingest unit because
eBPF requires it — each is commented in the unit with the reason
(`PrivateDevices=no` for `/sys/kernel/debug`, `MemoryDenyWriteExecute=no` for the
BPF JIT, `@privileged`/`@debug` syscalls for `bpf()`/`perf_event_open()`). Do not
"tighten" these without a kernel to test against. The **API unit** has none of these
exceptions — it runs fully sandboxed with zero capabilities.

## Supervised collectors

Each `--source NAME=COMMAND` in the ingest unit's `ExecStart` is one supervised
collector. **Quote each spec**: systemd splits the command line on whitespace, so
an unquoted spec puts the script path in its own argument and the service exits 2
before it starts. `tests/test_deploy_units.py` parses the shipped unit to keep
that from regressing.

| Source | Needs | Emits |
|--------|-------|-------|
| `process_exec`, `network_connect`, `network_state`, `ipc_pipe` | eBPF capabilities | the security telemetry |
| `system_health` | nothing — reads `/proc` via psutil | CPU, memory, disk samples |
| `service_state` | journal read access | systemd unit lifecycle |

The last two feed the availability detector in `detection/system_failure.py`;
without them its disk, memory, CPU, and unit-failure rules have no input and
cannot fire.

`service_state` reads the journal through `journalctl`, which shows a normal user
only their own records. The unit therefore sets
`SupplementaryGroups=systemd-journal` — without it the collector runs, reports
healthy, and emits nothing. Confirm with:

```bash
sudo -u linux-xai journalctl -n 1 --output=json
```

`system_health` needs no capability at all, so it keeps reporting on a kernel
where BCC cannot attach — which makes it the source to check first when
`/api/telemetry/status` shows the eBPF sources degraded.

## Retention runs in-process

Retention deliberately has **no `.timer` unit.** Age pruning, the byte cap, and the
periodic `VACUUM` all run inside the ingest process on a timer driven by config
(`retention_*` keys). This is one fewer moving part to drift out of sync with the
service, and it means retention keeps running exactly as long as ingestion does.
Setting `retention_max_age_days: 0` keeps events indefinitely (bounded only by the
byte cap, if set).

Retention prunes events and the per-window analytics derived from them. It does
**not** delete from the append-only hash-chained tables (findings, policy
decisions, triage, ML lifecycle): those verify by recomputing a contiguous chain
from its first row, so pruning the oldest rows would make `/api/integrity` report
tampering for the rest of the database's life.

Those tables are therefore **unbounded**, and the byte cap does not change
that: the cap deletes only events, and once it runs out of them it logs
`retention_size_cap_ineffective` and stops, so a database dominated by chained
evidence sits permanently over budget. Findings are rare next to events, so the
growth is slow in practice — but it is growth with no ceiling. If you need a
hard limit, archive the database and start a new chain rather than deleting
rows from it.

## Optional: capturing normal-behaviour windows (one per login session)

This is **not** part of a serving deployment. It is the collection half of
`docs/NORMAL_CORPUS_PROGRAM.md`: the ML activation gate in `ml/evaluation.py`
requires 60 *independent* verified-normal holdout windows, and independent means a
distinct login session — not consecutive slices of one long idle capture. Install it
only on a host whose everyday behaviour you intend to contribute to the corpus.

Two files implement it, plus a read-only verifier:

| File | Role |
|------|------|
| `deploy/systemd/linux-xai-normal-capture.timer` | `OnBootSec=15min` + `OnUnitActiveSec=20min` + jitter — **polls** for uncaptured sessions |
| `deploy/systemd/linux-xai-normal-capture.service` | `Type=oneshot`; runs `scripts/capture_normal_window.sh` |
| `scripts/verify_capture_boot.py` | Read-only check that a capture is one login session the corpus has not already used |

Install step 5's `linux-xai-*.service` glob copies the service but **silently does
not match a `.timer`**. Copy both explicitly:

```bash
sudo cp deploy/systemd/linux-xai-normal-capture.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
# Enable the TIMER, not the service: the service has no [Install] section on
# purpose, so the timer is the only thing that activates a capture.
sudo systemctl enable --now linux-xai-normal-capture.timer
sudo systemctl list-timers linux-xai-normal-capture.timer
```

### Why one capture per login session

The unit of independence is a *session of use*, not an interval. A wall-clock timer
on its own guarantees only that windows do not *overlap*: on a host with a month of
uptime, six fires a day is 180 captures from one boot — precisely the defect that
made the August 2026 corpus unusable. One capture per *boot* is the strictest fix,
but it prices 60 windows at 60 reboots, which is not a program anyone finishes.

So the identity is the pair `(boot_id, session_id)`, where `session_id` is the
logind session the host is being used from. logind renumbers sessions from 1 after
every reboot, so the session id alone is not unique. Each capture is named
`normal-<boot_id>-s<session_id>.db`, which makes "already captured this session" a
file-existence check, and the same pair is stamped into every event row (migration
11) so `verify_capture_boot.py` checks the claim from the data rather than from the
filename. The timer can therefore poll: the wrapper refuses to capture a session it
has already captured, so the number of captures cannot exceed the number of logins
however often the unit fires, and a manual `systemctl start` inside an
already-captured session is a no-op. A typical desktop day yields several sessions,
which is why 60 windows now costs roughly 6–9 boots.

Same-boot sessions are a **weaker** independence claim than distinct boots — they
share the kernel, page cache, and long-running daemons. That trade-off, and what to
do about it, is written down in `docs/NORMAL_CORPUS_PROGRAM.md`.

A fire that finds nobody logged in — or two live sessions and no way to tell which
one to attribute the window to — exits **75** (`EX_TEMPFAIL`), and the service maps
that to success with `SuccessExitStatus=75`. Without that, an idle host sitting at
its login screen would mark the unit failed every 20 minutes and bury any real
failure in the noise. Genuine refusals (a malformed session id, a session logind
cannot corroborate, a non-user session, a capture that died) still exit 1 and still
fail the unit, so `systemctl status` remains meaningful.

Two knobs matter if you change the window length: `CAPTURE_SECONDS` in the unit, and
`TimeoutStartSec=`, which for `Type=oneshot` bounds the whole of `ExecStart` and
defaults to **90 s**. Left at the default it would truncate every 305 s window
without reporting a failure. Keep it comfortably above `CAPTURE_SECONDS`.

One sandbox constraint is specific to this unit: the wrapper resolves the session by
reading `/run/systemd/sessions/`, so any directive that hides or empties `/run`
(`PrivateUsers=`, a `RestrictFileSystems=` allowlist, a `TemporaryFileSystem=` over
`/run`) makes every fire exit 75 and the corpus silently stops growing.
`ProtectSystem=strict` is fine: it only makes `/run` read-only.

### Where captures land

`StateDirectory=linux-xai-captures` creates `/var/lib/linux-xai-captures` as
`linux-xai`, `0700`, with `pending/` and `promoted/` beneath it and the databases
themselves `0600`. This is deliberately **not** the ingest service's state
directory: these are candidate corpus captures under review, not evidence, and no
running component reads them.

Do not reconfigure `CAPTURE_DIR` into `/tmp` — the first holdout capture of this
program was lost to exactly that — and not into a home directory either, since
`ProtectHome=yes` makes it unwritable. A capture that crashes leaves a
`normal-<boot_id>-s<session_id>.db.partial` behind and never claims the session's
slot, so a leftover `.partial` is the signal that a window failed; nothing
promotable is produced.

Alongside each database is a `.manifest.json` snapshot of logind's record for that
session — login wall-clock, seat, VT, session type and class. It is written *before*
the capture starts, because logind discards session records at reboot and the
session can end while the window is still running. That file is what makes the
independence claim reviewable a week later; `collect_normal_window.py` folds it into
the promoted window's immutable `collector_context`.

### Reviewing and promoting a capture

Nothing is automatic. The unit captures and stops: it never promotes, never writes
to the corpus database, and never touches the gate. `collect_normal_window.py`
refuses to write without `--i-verified-normal` because `verified_normal` is an
operator attestation of human review, which is what keeps a timer from approving
its own training data.

```bash
cd /opt/linux-xai-security
CAPS=/var/lib/linux-xai-captures

# 1. Independence: one login session, non-empty, and a (boot_id, session_id) pair
#    no promoted capture already used. Pass every pending capture at once so
#    duplicates *within* the batch are caught too, not just against promoted/.
sudo .venv/bin/python scripts/verify_capture_boot.py \
    $CAPS/pending/normal-*.db --against $CAPS/promoted

# 2. Normality: a PASS above says nothing about whether the window is benign.
#    Inspect what the window actually contains before attesting to it.
sudo .venv/bin/python scripts/collect_normal_window.py \
    --source $CAPS/pending/normal-<boot_id>-s<session_id>.db --dry-run

# 3. Promote. --role is a property of the DATASET, so set it on the creation call;
#    passing --role to a later --dataset-id append records context and nothing more.
sudo .venv/bin/python scripts/collect_normal_window.py \
    --source $CAPS/pending/normal-<boot_id>-s<session_id>.db \
    --dataset-db $CAPS/corpus.db \
    --dataset-name "kali-desktop-holdout" --role holdout \
    --operator "$USER" --reason "idle desktop, reviewed" \
    --i-verified-normal

# 4. Record the decision by moving the capture and its manifest together, so the
#    one-per-session guard and the verifier's --against set both stay accurate.
sudo mv $CAPS/pending/normal-<boot_id>-s<session_id>.db* $CAPS/promoted/

# 5. Progress against the gate.
sudo .venv/bin/python scripts/corpus_status.py --dataset-db $CAPS/corpus.db
```

Append every later window to that same dataset with `--dataset-id`; creating a
second holdout dataset splits the count the gate reads. Promotion refuses a
`(boot_id, session_id)` pair already promoted *anywhere in that corpus database*
(exit status 4), whatever role either dataset carries and including on the
`--dataset-name` path that creates a dataset. That rules out re-promoting a
capture, slicing one session into two windows with `--window-start`/`--window-end`,
and promoting one session into both a training and a holdout dataset — the last of
which `scripts/ml_train_and_evaluate.py` cannot catch for you, because it compares
window content byte-for-byte and two differently-bounded windows over one session
do not match. Within a single dataset, training windows may still repeat a session;
they are not counted as independent trials.

The scope is one `--dataset-db` file, which is what the gate counts and what
`corpus_status.py` measures. A deliberately separate corpus — a second experiment,
a re-run from scratch — is a separate file and is not adjudicated against this one.

A capture you decide against should be deleted rather than moved to `promoted/`.
Deleting it frees that session's slot, but the session itself is over, so the next
fire will simply find a different session or nothing at all.

## Verifying a deployment

```bash
# Liveness needs no auth and no database — is the process up? (also /api/health)
curl -fsS http://127.0.0.1:8000/api/health/live

# Readiness, metrics, and the evidence API require a token. Readiness fails if the
# DB is missing, its mode regressed above 0600, or telemetry has gone stale.
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/health/ready
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/metrics
```

The API binds loopback by default; terminate TLS at a reverse proxy in front of it.
The packaged entry point (`linux-xai-api`, i.e. `api/__main__.py`, which is what
both the unit and the commands above run) refuses to start on a non-loopback
address unless `ALLOW_NON_LOOPBACK_API=1` is set, and refuses outright to serve a
non-loopback address without authentication. Those are entry-point checks, not
properties of the ASGI app: invoking `uvicorn api.app:app --host 0.0.0.0`
directly bypasses both. Run the service through its console script.

See `docs/THREAT_MODEL.md` for the security rationale behind these choices and
`docs/PHASE_B_RESULTS.md` for measured throughput/latency and the soak result.
