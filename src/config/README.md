# config — directive lifecycle, startup validation, and per-worker resource init

## Overview

This subsystem is the nginx configuration **plumbing** for the XRootD stream
module and the shared preamble that the WebDAV/S3 HTTP modules build on top of.
It does not handle any client traffic; it runs entirely during nginx's parse →
merge → postconfiguration → init_process startup sequence. Its job is to turn
directives in `nginx.conf` (`xrootd on;`, `xrootd_root`, `xrootd_auth`,
`xrootd_cache*`, `xrootd_manager_map`, `xrootd_require_vo`, the proxy/CMS/mirror
knobs, etc.) into a fully-validated, fully-merged `ngx_stream_xrootd_srv_conf_t`,
and then to allocate every runtime resource that the request handlers assume
already exists.

The four callbacks here are wired into the stream module descriptor in
`../stream/module_definition.c`: `ngx_stream_xrootd_create_srv_conf` (allocate
with `NGX_CONF_UNSET` sentinels), `ngx_stream_xrootd_merge_srv_conf`
(parent→child inheritance + defaults), `ngx_stream_xrootd_postconfiguration`
(one-time master-process setup: auth/TLS/policy validation, shared-memory zones,
thread pools), and `ngx_stream_xrootd_init_process` (per-worker setup after
fork: open the confinement rootfd, start CMS/health-check/CRL/JWKS timers, warm
crypto pools). The `xrootd on;` directive setter (`ngx_stream_xrootd_enable`)
lives here too — it is the switch that swaps the stream core's connection
handler for `ngx_stream_xrootd_handler`.

Because all three protocol surfaces (`root://`, WebDAV, S3) project the same
on-disk export root and share auth/path-confinement, this subsystem also owns
the **cross-protocol shared config preamble** (`shared_conf.h`,
`ngx_http_xrootd_shared_conf_t`) and the helpers that validate and canonicalize
an export root identically everywhere (`root_prepare.c`) and open the per-export
`O_PATH` confinement rootfd that `../path/beneath.c` anchors `openat2(...,
RESOLVE_BENEATH)` on (`http_rootfd.c` for HTTP, `process.c` for stream).

Critically, this is the **fail-fast gate**: nearly every validation failure here
is emitted at `NGX_LOG_EMERG` so that `nginx -t` and `nginx -s reload` reject a
bad config before any connection is ever accepted. Misconfigured roots, missing
VOMS/JWKS/SSS material, cache prerequisites, and out-of-range ports are all
caught at startup rather than under load.

## Files

| File | Responsibility |
|---|---|
| `config.h` | Internal header: `xrootd_path_kind_t` enum and prototypes for every config helper (`xrootd_validate_path`, `xrootd_config_prepare_server`, `xrootd_configure_{gsi,tls,token_auth,sss_auth,krb5_auth,metrics,session_registry,dashboard,thread_pools}`, `xrootd_srv_configure_registry`, `xrootd_pending_configure`, `xrootd_config_finalize_policy`, …). The contract surface for the whole subsystem. |
| `server_conf.c` | The three core srv-conf callbacks: `create_srv_conf` (zero-init + set ~120 fields to `NGX_CONF_UNSET*`/NULL sentinels), `merge_srv_conf` (parent→child inheritance, hard defaults, array merges, range checks), and `ngx_stream_xrootd_enable` (the `xrootd on|off;` setter that installs the stream handler). |
| `postconfiguration.c` | One-time master-process init: load VOMS (`dlopen`), per-server auth/TLS/token/SSS/krb5 setup, policy finalization, then create shared-memory zones (session registry, server registry, redirect-collapse cache, pending-sigver, TPC key + transfer registries, metrics, dashboard) sized to the max slots across enabled blocks, then thread pools. |
| `process.c` | Per-worker init/exit after fork: `init_process` (crypto init, openat2 availability probe, proxy pool init, open `rootfd` for data servers, checkpoint recovery, start CMS/health-check/CRL/JWKS timers, warm GSI DH key pool) and `exit_process` (close rootfds, optional LSan check, crypto cleanup). Hosts the static `xrootd_crl_reload_handler` timer callback. |
| `runtime_server.c` | `xrootd_config_prepare_server`: per-server runtime preparation — validate/canonicalize export root (skipped for proxy/manager/supervisor blocks), enforce cache prerequisites (read-only, origin host, cache_root dir, lock-timeout/eviction-threshold ranges), open access + proxy-audit log fds, build proxy/upstream TLS `SSL_CTX`s. |
| `policy.c` | Directive setters for the access-policy rules — `xrootd_conf_set_authdb`, `xrootd_conf_set_require_vo`, `xrootd_conf_set_inherit_parent_group` — and `xrootd_config_finalize_policy`, which validates VO rules need GSI/token auth + VOMS lib + vomsdir/voms_cert_dir, then finalizes vo/authdb/group rule lookup structures (delegated to `../path/`). |
| `manager_map.c` | `xrootd_conf_set_manager_map`: parses `xrootd_manager_map <prefix> <host:port>` into prefix→backend entries for CMS manager mode, handling IPv4/hostname and IPv6 `[addr]:port` literals with port-range validation. |
| `helpers.c` | Two reusable startup helpers: `xrootd_validate_path` (stat existence + kind check (file/dir/either) + `access()` permission check, all at `EMERG`) and `xrootd_copy_conf_string` (safe `ngx_str_t` → NUL-terminated pool buffer). |
| `root_prepare.c` / `root_prepare.h` | `xrootd_prepare_export_root` + `xrootd_export_root_opts_t`: the single shared export-root preparation used by all three protocols — length guard, `xrootd_validate_path` (dir + R/W/X per policy), and `realpath(3)` to strip symlinks from the confinement boundary. |
| `http_rootfd.c` / `http_rootfd.h` | `xrootd_http_open_rootfd`: opens the persistent `O_PATH` `common->rootfd` for WebDAV/S3 locations at config time (inherited by workers via fork), with a `cf->pool` cleanup so reloads don't leak one fd per export root. Mirrors the stream-side rootfd opened in `process.c`. |
| `shared_conf.h` | `ngx_http_xrootd_shared_conf_t` — the common preamble (`enable`, `root`, `root_canon[PATH_MAX]`, `allow_write`, `thread_pool*`, `rootfd`) embedded as the **first member** of every protocol config struct, plus inline `ngx_http_xrootd_shared_init`/`ngx_http_xrootd_shared_merge`. |
| `merge_macros.h` | Three merge macros for patterns nginx's built-in `ngx_conf_merge_*` doesn't cover: `XROOTD_MERGE_PTR` (NULL-sentinel pointer), `XROOTD_MERGE_HOSTPORT` (paired host+port), `XROOTD_MERGE_ENUM` (custom enum with explicit UNSET). |
| `addr_parse.c` / `addr_parse.h` | `xrootd_parse_address`: shared `host:port` parser with optional `root://`/`roots://`/`https://` scheme prefixes and IPv6 bracket support, returning host/port and a TLS flag — consolidates parsing duplicated across cache/tpc/upstream directives. |

## Key types & data structures

- **`ngx_stream_xrootd_srv_conf_t`** (defined in `../types/config.h`, populated
  here) — the per-server-block configuration. Its first member is the shared
  `common` preamble; the tail holds stream-only fields: auth mode (`auth`),
  GSI/TLS/token/SSS/krb5 material, cache + write-through config, manager/proxy/
  CMS/mirror/health-check/rate-limit settings, and runtime handles
  (`access_log_fd`, `metrics_slot`, `rootfd`, `crl_timer`, `tls_ctx`, …).
- **`ngx_http_xrootd_shared_conf_t`** (`shared_conf.h`) — the cross-protocol
  preamble. `enable`/`root`/`allow_write`/`thread_pool_name` are merged; the
  three trailing fields (`root_canon`, `thread_pool`, `rootfd`) are runtime-only
  and never merged. Embedding it first keeps `offsetof()` into the
  protocol-specific tail valid after merge.
- **`xrootd_path_kind_t`** (`config.h`) — `REGULAR_FILE` / `DIRECTORY` /
  `FILE_OR_DIRECTORY`; selects which `S_IS*` check `xrootd_validate_path` runs.
- **`xrootd_export_root_opts_t`** (`root_prepare.h`) — caller policy for root
  prep: directive name (for errors), `allow_write` (adds `W_OK`), `required`
  (empty root → hard error), `canon_size` (target buffer size, must be ≥
  `PATH_MAX`).
- **Policy rule structs** (`xrootd_vo_rule_t`, `xrootd_authdb_rule_t`,
  `xrootd_group_rule_t`, `xrootd_manager_map_t`) — accumulated into `ngx_array_t`s
  by the `policy.c`/`manager_map.c` setters, merged with `xrootd_merge_arrays`,
  and finalized into runtime lookup structures by `../path/` finalizers.

## Control & data flow

Execution enters here only from nginx's config machinery, in strict order:

1. **Parse** — per server block, the stream core calls
   `ngx_stream_xrootd_create_srv_conf` (sentinel init). As directives are read,
   their setters run: the `xrootd on;` setter `ngx_stream_xrootd_enable`
   installs `ngx_stream_xrootd_handler` (see `../connection/handler.c` /
   `../handshake/dispatch.c`); policy/manager-map setters push rule entries.
2. **Merge** — `ngx_stream_xrootd_merge_srv_conf` applies parent→child
   inheritance and hard defaults, validates a few ranges (e.g. cache slice size
   must be a positive multiple of 1 MiB), and wires the write-through decision
   callback (`wt_decision`, implemented in `../cache/`).
3. **Postconfiguration** — `ngx_stream_xrootd_postconfiguration` runs once in
   the master: VOMS dlopen, then per-enabled-server
   `xrootd_config_prepare_server` (`runtime_server.c`) → `xrootd_configure_gsi`/
   `tls`/`token_auth`/`sss_auth`/`krb5_auth` (implemented in `../gsi/`,
   `../token/`, `../sss/`, `../krb5/`), then `xrootd_config_finalize_policy`
   (`policy.c` → `../path/`), then shared-memory zone creation (`../session/`,
   `../manager/`, `../tpc/`, `../metrics/`, `../dashboard/`) and thread-pool
   resolution (`../aio/`).
4. **init_process** — `ngx_stream_xrootd_init_process` (`process.c`) runs once
   per worker after fork: opens the per-worker confinement `rootfd` that
   `../path/beneath.c` requires, recovers in-flight checkpoints (`../write/`),
   starts the CMS heartbeat client (`../cms/`), active health checks
   (`../manager/`), CRL-reload and JWKS-refresh timers, and warms the GSI DH key
   pool (`../gsi/`).

This subsystem **calls out to** essentially every other subsystem's
`*_configure`/`*_finalize`/`*_start` entry point; it is **called from** only
`../stream/module_definition.c`. The HTTP side mirrors this flow through
`../webdav/config.c` and `../s3/module.c`, which reuse `shared_conf.h`,
`root_prepare.c`, `http_rootfd.c`, and `merge_macros.h`.

## Invariants, security & gotchas

- **`NGX_CONF_UNSET` discipline is load-bearing.** `create_srv_conf` must set
  every mergeable field to the matching sentinel
  (`NGX_CONF_UNSET`/`_UINT`/`_MSEC`/`_SIZE`, `XROOTD_WT_MODE_UNSET`, or NULL).
  nginx's merge macros act *only* on UNSET values; a forgotten sentinel silently
  breaks parent→child inheritance. `server_conf.c:73-211` and
  `merge_srv_conf` (`:230-494`) must stay field-for-field in sync.
- **Export root is canonicalized through `realpath(3)` before it becomes a
  confinement boundary** (`root_prepare.c:65`). Symlinks are stripped at config
  time so the kernel `RESOLVE_BENEATH` anchor (`rootfd`) cannot be aimed outside
  the intended tree. Never feed a non-canonical root to the path layer.
- **rootfd is opened, never merged.** It is runtime-only: stream opens it
  per-worker in `process.c:146-156` (only when `root_canon` is non-empty — proxy/
  manager/supervisor blocks have no local export and stay `rootfd = -1`); HTTP
  opens it at config time in `http_rootfd.c` with a pool cleanup to avoid fd
  leaks across reloads. `exit_process` closes the stream copies
  (`process.c:243-246`).
- **Fail-closed at startup.** Path/auth/policy failures are emitted at
  `NGX_LOG_EMERG` and return `NGX_ERROR`/`NGX_CONF_ERROR`, aborting startup.
  `xrootd_validate_path` treats NULL/empty paths as *optional* (returns
  `NGX_OK`), so `required` enforcement lives in the caller
  (`root_prepare.c:33`, `runtime_server.c`).
- **Auth ordering matters.** `postconfiguration.c` configures auth subsystems
  *before* finalizing policy, because VO/authdb rules depend on the merged auth
  mode and VOMS availability. `xrootd_require_vo` is rejected unless auth is
  GSI/token/both AND `libvomsapi.so.1` loaded AND vomsdir/voms_cert_dir exist
  (`policy.c:199-232`).
- **Cache is read-only.** `xrootd_cache on` requires `allow_write off`, a
  configured origin, an existing writable cache_root, and a valid lock-timeout/
  eviction-threshold (`runtime_server.c:50-96`). These are hard `EMERG` errors.
- **Single shared-memory zone, max-slots sizing.** Session registry, server
  registry, and redirect-collapse cache are each one zone for the whole
  instance; `postconfiguration.c` walks all enabled blocks and sizes each to the
  largest requested slot count, so operators can set the slot directive on any
  one block.
- **openat2 degradation is announced, not fatal.** If `openat2(2)` is
  unavailable (kernel < 5.6), `init_process` logs a persistent `WARN`
  (`process.c:119-126`) — confinement falls back to an O_NOFOLLOW walk with a
  narrow TOCTOU window, but startup proceeds.
- **Timers and crypto are per-worker.** CRL/JWKS/CMS/health-check timers and the
  GSI key pool are created in `init_process` because each worker has its own
  event loop and config-pointer copy; never start them in the master/postconfig.
- **IPv6 + port parsing has two implementations.** `manager_map.c` parses
  inline; everything else should use the shared `xrootd_parse_address`
  (`addr_parse.c`) — both validate port range 1–65535 and reject malformed
  brackets.

## Entry points / extending

- **New config directive:** add the field to `ngx_stream_xrootd_srv_conf_t`
  (`../types/config.h`); set its sentinel in `create_srv_conf`
  (`server_conf.c`); add the `ngx_command_t` entry to the live directives table
  `ngx_stream_xrootd_commands[]` in `../stream/module.c` (note:
  `module_core_directives.c` is a stale, uncompiled copy — do not edit it); add the
  `ngx_conf_merge_*` (or one of `merge_macros.h`'s `XROOTD_MERGE_*`) call in
  `merge_srv_conf`. Only re-run `./configure` if you add a new `.c` file.
- **New validated path/cache/log resource:** add the check to
  `xrootd_config_prepare_server` (`runtime_server.c`) using
  `xrootd_validate_path`; emit `NGX_LOG_EMERG` on failure.
- **New shared-memory zone:** add an `xrootd_<x>_configure(cf, ...)` declaration
  to `config.h`, implement it in the owning subsystem, and call it from
  `ngx_stream_xrootd_postconfiguration` (max-slots over enabled blocks if
  per-server-sized).
- **New per-worker timer/runtime resource:** start it in
  `ngx_stream_xrootd_init_process` (`process.c`), guarded by `xcf->common.enable`
  and the relevant feature flag; tear down in `xrootd_exit_process` if it owns
  an fd or allocation.
- **New policy rule type:** add a setter in `policy.c` (accumulate into an
  `ngx_array_t`), merge it via `xrootd_merge_arrays` in `merge_srv_conf`, and
  finalize it in `xrootd_config_finalize_policy` (delegating the lookup-table
  build to `../path/`).
- **New HTTP protocol surface:** embed `ngx_http_xrootd_shared_conf_t` first,
  call `ngx_http_xrootd_shared_init`/`_merge`, then `xrootd_prepare_export_root`
  + `xrootd_http_open_rootfd` from your `merge_loc_conf` (see `../webdav/config.c`,
  `../s3/module.c`).

## See also

- `../README.md` — master subsystem index
- `../stream/README.md` — stream module descriptor that registers these callbacks and the directives table
- `../path/README.md` — `RESOLVE_BENEATH` confinement and the policy/authdb/group rule finalizers this subsystem feeds
- `../webdav/README.md`, `../s3/README.md` — HTTP surfaces that reuse `shared_conf.h`, `root_prepare.c`, and `http_rootfd.c`
- `../gsi/README.md`, `../token/README.md` — auth subsystems configured from `postconfiguration.c`
- `../manager/README.md`, `../cms/README.md` — manager-map / CMS cluster features configured and started here
- `../aio/README.md` — thread pools resolved by `xrootd_configure_thread_pools`
- `../metrics/README.md`, `../dashboard/README.md` — shared-memory zones created in postconfiguration
