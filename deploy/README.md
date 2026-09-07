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

## Retention runs in-process

There is deliberately **no `.timer` unit.** Age pruning, the byte cap, and the
periodic `VACUUM` all run inside the ingest process on a timer driven by config
(`retention_*` keys). This is one fewer moving part to drift out of sync with the
service, and it means retention keeps running exactly as long as ingestion does.
Setting `retention_max_age_days: 0` keeps events indefinitely (bounded only by the
byte cap, if set).

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
Binding a non-loopback address requires setting `ALLOW_NON_LOOPBACK_API=1`
explicitly, so it cannot happen by accident.

See `docs/THREAT_MODEL.md` for the security rationale behind these choices and
`docs/PHASE_B_RESULTS.md` for measured throughput/latency and the soak result.
