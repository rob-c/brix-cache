# Configuration Reload Semantics

**Status:** Reference for operators and contributors. Describes what
`nginx -s reload` (SIGHUP) does to this module's settings, how to confirm a
reload took effect, and which settings need a full restart.

---

## The model: standard nginx drain

This module follows nginx's native reload model — there is no custom
"hot-reconfigure the running workers" path, by design.

On `nginx -s reload` the master:

1. Re-reads the config and builds a **fresh cycle**, re-running the module's
   `create/merge_srv_conf` → `postconfiguration` → `init_module` against the new
   config. A config error here (caught by `nginx -t` too) **aborts the reload**
   and the old config keeps serving — there is no partial apply.
2. Forks **new worker processes** that run `init_process` against the new config
   (re-opening the export root fd, re-reading auth material, re-arming timers).
3. Tells the **old workers** to drain: they stop accepting once the new workers
   are up, finish their in-flight connections, then exit.

**Consequence — the contract:** a **new** connection is served with the new
settings; an **in-flight** connection finishes on the old worker with the old
settings. This is exactly what "reload" means here.

```text
   nginx -s reload (SIGHUP)
        │
   ─────┼──────────────── time ────────────────────────────────────▶
        │
  master│ nginx -t passes → fork NEW workers ──────────▶ exit when old gone
        │                      │
   OLD  ████████████████████░░░│░░░░░░░░░ (draining) ──┘
   wkrs │ accepting           ╎ stop accepting, finish in-flight conns
        │                     ╎
   NEW  │              ┌──────████████████████████████████████████████▶
   wkrs │              │ accepting with NEW config
        │              │
        │         ┌────┴───── DRAIN WINDOW ─────┐
        │         │ BOTH accept on shared socket │ ← a new conn may briefly
        │         │ (bound by                    │   land on an OLD worker
        │         │  worker_shutdown_timeout)    │   = old per-worker config
        │         └──────────────────────────────┘
        │
   SHM  │ config_generation flips INSTANTLY for every worker (not drained)
        ▼ a bad config aborts the reload → old config keeps serving (no partial apply)
```

### Eventual consistency during the drain window

During the drain window **both** old and new workers are accepting on the shared
listen socket, so a brand-new connection may briefly land on an *old* worker
still holding the *old* per-worker config. Per-worker settings (auth mode, ACLs,
paths, the `xrootd_metrics`/`xrootd_health` location flags, …) therefore become
fully live only once the old workers have exited — bound this with
`worker_shutdown_timeout`. Shared-memory state is **not** subject to this: the
`config_generation` counter (below) lives in SHM and flips for every worker the
instant the master processes the reload.

---

## Confirming a reload took effect

Every config load publishes two values into the metrics shared memory (the
master writes them in `init_module`, before forking new workers):

- **`config_generation`** — increments by one on **every** config load (1 at
  first start, +1 per `nginx -s reload`). This is the **authoritative** "a
  reload happened" signal.
- **`config_version`** — a 16-hex-digit FNV-1a fingerprint of the **main config
  file**. It changes when the file content changes and is stable across a no-op
  reload, so it answers "did the config actually change?".

Surfaces:

| Surface | Field / metric |
|---|---|
| `GET /healthz` (and `?verbose`) | `"config_generation"`, `"config_version"` JSON fields |
| `GET /metrics` | `xrootd_config_generation` gauge |
| `error.log` (NOTICE, per load) | `xrootd: config generation N live (pid P, version HEX)` |

```console
$ curl -s localhost:9100/healthz
{"status":"ok","service":"nginx-xrootd","config_generation":4,"config_version":"8b52b73417c41027"}
```

Operational recipe: run `nginx -t` first (it runs the full module
postconfiguration, so it rejects a bad config before you reload), then
`nginx -s reload`, then confirm `config_generation` advanced.

> **Caveat:** `config_version` fingerprints the **top-level** config file only —
> `include`d files are **not** folded in. Use `config_generation` (always
> accurate) as the "reload happened" signal; treat `config_version` as a
> best-effort "main file changed" hint.

---

## Per-directive reload behaviour

| Class | Behaviour on reload | Examples |
|---|---|---|
| **(a) Reloadable for new connections** (the default majority) | New workers pick up the new value; new connections honour it after the drain window. | scalars/flags/timeouts, `xrootd_root`, `xrootd_auth`, `xrootd_allow_write`, ACL/policy rules (`xrootd_authdb`, `xrootd_require_vo`, `xrootd_inherit_parent_group`), `xrootd_manager_map`, cache/proxy/TPC settings, the `xrootd_metrics`/`xrootd_health` location flags |
| **(b) Hot-reloaded by a timer** (no reload needed at all) | A per-worker mtime-polling timer reloads the file in place and atomically swaps it; a reload also re-reads it. | CRL (`xrootd_crl` + `xrootd_crl_reload`), JWKS (`xrootd_token_jwks` + refresh interval), XrdAcc authdb (`xrootd_authdb_format xrdacc`) |
| **(c) Re-read on reload** (rotation needs a reload, not a restart) | Loaded once per cycle in postconfiguration/init_process; a reload re-reads from disk for new workers. No in-place hot-reload timer. | GSI server cert/key (`xrootd_certificate`, `xrootd_certificate_key`), trust store, SSS keytab, Kerberos keytab, in-protocol and upstream TLS contexts |
| **(d) State reset on resize** | nginx cannot grow a live SHM zone, so changing a slot-count allocates a **fresh** zone — the live table's contents are dropped for new connections (in-flight ones drain on the old workers). The module logs a **WARN** so this is not silent. | `xrootd_session_slots`, `xrootd_registry_slots` |

Notes:

- **Class (c) rotation:** to rotate a server certificate/key or an SSS/Kerberos
  keytab, replace the files and `nginx -s reload`. New connections use the new
  material; existing TLS sessions finish on the old workers. A full restart is
  **not** required.
- **Class (d) resize:** changing a slot count is safe but transiently empties the
  table. To avoid even the transient reset (e.g. for the cross-process session
  or server registry), do a full restart in a maintenance window instead of a
  reload. Watch for: `xrootd_<directive> changed across reload (shared zone …)`.
- **Proxy upstream pools** are per-worker: after an upstream-address change, old
  pooled connections drain with the old workers and new workers build fresh
  pools — no stale sockets survive, consistent with the drain model.

---

## Logs and SHM across reload

- **Log files** (`xrootd_access_log`, `xrootd_proxy_audit_log`) are registered
  with nginx (`cycle->open_files`), so the master owns their lifecycle: they are
  reopened on `nginx -s reopen`/USR1 (via `dup2` onto the same fd number) and
  closed cleanly across reload — no leaked fds, and log rotation works.
- **Metrics and dashboard SHM** re-attach across reload, so counters and
  in-flight transfer rows **survive** a reload (they are not reset).

---

## Implementation pointers

- Drain/teardown: self-rearming background timers are `!ngx_exiting`-guarded (or
  `cancelable`) so draining workers exit promptly — see `src/core/config/process.c`,
  `src/auth/token/refresh.c`, `src/auth/authz/acc/config.c`, `src/net/cms/connect.c`.
- Config version/generation: published in `xrootd_config_version_publish()`
  (`src/observability/metrics/config.c`), called from the module's `init_module` hook
  (`src/auth/impersonate/lifecycle.c`); read by `/healthz` (`src/observability/metrics/health.c`).
- SHM resize warning: `xrootd_shm_zone_warn_on_resize()` (`src/core/compat/shm_slots.c`),
  called from the registry declarations (`src/session/registry.c`,
  `src/net/manager/registry.c`).
- Tests: `tests/test_reload.py` (self-contained; success + robustness +
  security-neg).
