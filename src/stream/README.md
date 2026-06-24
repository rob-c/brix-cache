# stream — `ngx_stream_xrootd_module` descriptor & directive table

## Overview

This subsystem is the **nginx stream-module glue** for the XRootD native
(`root://` / `roots://`) protocol. It contains *no* protocol logic, no I/O, and no
per-request state. Its entire job is to make a stock nginx build aware of the module:
declare the static `ngx_module_t` descriptor, register the full
`ngx_stream_xrootd_commands[]` directive table that nginx parses inside
`stream { server { … } }` blocks, and define the small enum lookup tables
(`xrootd_auth_modes`, `xrootd_security_levels`, `xrootd_hc_types`) that map config
keywords onto internal constants. Everything substantive is delegated to callbacks
declared in `../ngx_xrootd_module.h` and implemented under `../config/`.

It sits at the very top of the `root://` request lifecycle — *before any connection
exists*. When nginx parses a `stream` block and sees the `xrootd` flag, the custom
setter `ngx_stream_xrootd_enable` (in `../config/server_conf.c`) swaps the stream-core
server handler for `ngx_stream_xrootd_handler`. From that point on, every TCP
connection on the listen port enters the module via `../connection/handler.c` →
`../handshake/dispatch.c`. None of that dispatch code lives here; this directory only
wires the module into nginx so the handler gets installed and so the per-server
`ngx_stream_xrootd_srv_conf_t` is populated from `nginx.conf`.

The module context (`ngx_stream_xrootd_module_ctx`) deliberately registers **no
main-conf callbacks** (`create_main_conf`/`init_main_conf` are `NULL`): each stream
`server {}` block owns its configuration independently — there is no stream-wide
aggregation. It *does* register `create_srv_conf`, `merge_srv_conf` (parent→child
inheritance), `postconfiguration` (final validation / resource setup),
`init_process` (per-worker startup: opens the `RESOLVE_BENEATH` root fd; arms the
CMS / health-check / CRL / JWKS timers), and `exit_process` (worker teardown). All
five implementations live under `../config/`.

The directive table is the canonical, single-source list of every `xrootd_*`
directive the module accepts for the `root://` stream protocol. Because the list is
large it appears, in part, across three `.c` files — but only **`module.c`** and
**`module_definition.c`** are actually compiled (`config:236-237`). The other two
files (`module_core_directives.c`, `module_cache_proxy_directives.c`) are *not* in
`NGX_ADDON_SRCS` and never reach the linker; they are stale partial copies kept in
the tree. Treat `module.c` as ground truth.

## Files

| File | Responsibility |
|------|----------------|
| `module.c` | **Authoritative — compiled.** Defines the live `ngx_stream_xrootd_commands[]`: the complete directive table (core + auth + TLS/OCSP + native TPC + manager/CMS + read-through cache + write-through + transparent proxy + Phase 20 KV/rate-limit + Phase 22 health-check + Phase 24 mirror + Phase 25/26/29/31 tuning), terminated by `ngx_null_command`. Also defines the `xrootd_auth_modes[]`, `xrootd_security_levels[]`, and `xrootd_hc_types[]` enum tables. |
| `module_definition.c` | **Compiled.** Declares the static module wiring: `ngx_stream_xrootd_module_ctx` (`ngx_stream_module_t` lifecycle hooks — `postconfiguration`, `create_srv_conf`, `merge_srv_conf`; main-conf slots `NULL`) and the `ngx_module_t ngx_stream_xrootd_module` descriptor (`NGX_STREAM_MODULE`, with `init_process` = `ngx_stream_xrootd_init_process` and `exit_process` = `xrootd_exit_process`). Holds an `extern` reference to `ngx_stream_xrootd_commands[]`. |
| `module_core_directives.c` | **NOT compiled** (absent from `NGX_ADDON_SRCS` in `config`). Stale partial copy of the core + auth + manager directive block; it *also* defines a `ngx_stream_xrootd_commands[]` symbol, but the file never reaches the linker. Reference only — `module.c` supersedes it. |
| `module_cache_proxy_directives.c` | **NOT compiled** (same reason). Stale tail fragment of the cache / write-through / CMS / proxy directive block that closes a directive array. Reference only — `module.c` supersedes it. |

> **Maintainer warning:** the three `module*` directive files overlap. Only
> `module.c`'s `ngx_stream_xrootd_commands[]` links into the binary. Editing
> `module_core_directives.c` or `module_cache_proxy_directives.c` has **zero**
> runtime effect. When you touch a directive, change `module.c` and grep all four
> files to avoid leaving misleading duplicates.

## Key types & data structures

This subsystem defines no runtime structs of its own — it only references them. The
ones a reviewer must know:

- **`ngx_command_t ngx_stream_xrootd_commands[]`** — nginx's directive descriptor
  array. Each entry is `{ name, scope|argcount flags, setter, conf-target, offset,
  post }`. Most entries use stock nginx setters (`ngx_conf_set_str_slot`,
  `ngx_conf_set_flag_slot`, `ngx_conf_set_num_slot`, `ngx_conf_set_sec_slot`,
  `ngx_conf_set_msec_slot`, `ngx_conf_set_size_slot`, `ngx_conf_set_off_slot`,
  `ngx_conf_set_enum_slot`) writing straight into the per-server config via
  `offsetof(...)`. The rest use custom setters declared in `../ngx_xrootd_module.h`
  or in the owning subsystem header (e.g. `xrootd_conf_set_cache_origin`,
  `xrootd_conf_set_proxy_upstream`, `xrootd_rl_zone_directive`,
  `xrootd_stream_mirror_set_url`, `xrootd_kv_zone_directive`,
  `xrootd_token_cache_directive`). Terminated by `ngx_null_command`.
- **`ngx_stream_module_t ngx_stream_xrootd_module_ctx`** — the six-slot stream-module
  callback table. Only `postconfiguration`, `create_srv_conf`, and `merge_srv_conf`
  are non-`NULL` here.
- **`ngx_module_t ngx_stream_xrootd_module`** — the global descriptor nginx discovers
  at startup; carries `init_process` (`ngx_stream_xrootd_init_process`) and
  `exit_process` (`xrootd_exit_process`).
- **`ngx_conf_enum_t` tables** —
  `xrootd_auth_modes` (`none|gsi|token|both|sss|unix|krb5` → `XROOTD_AUTH_*`),
  `xrootd_security_levels` (`none|compatible|standard|intense|pedantic` → `0..4`, the
  kXR_sigver enforcement level), and `xrootd_hc_types` (`ping|stat` →
  `XROOTD_HC_TYPE_*`). Each is NUL-terminated with `{ ngx_null_string, 0 }`.
- **`ngx_stream_xrootd_srv_conf_t`** — the per-server config struct every directive
  writes into. Defined in `../config/config.h`, allocated by
  `ngx_stream_xrootd_create_srv_conf` (`../config/server_conf.c`). This subsystem
  references its field offsets only; it does not declare it.

### Directive groups (authoritative `module.c` set)

| Group | Directives (representative) |
|-------|------------------------------|
| Enable / export / write | `xrootd`, `xrootd_root`, `xrootd_allow_write`, `xrootd_listen_port`, `xrootd_access_log` |
| Auth mode & GSI/x509 | `xrootd_auth`, `xrootd_certificate`, `xrootd_certificate_key`, `xrootd_trusted_ca`, `xrootd_vomsdir`, `xrootd_voms_cert_dir`, `xrootd_crl`, `xrootd_crl_reload`, `xrootd_require_vo`, `xrootd_authdb`, `xrootd_inherit_parent_group`, `xrootd_security_level` |
| Bearer / SSS / krb5 / unix | `xrootd_token_jwks`(+`_refresh_interval`), `xrootd_token_issuer`, `xrootd_token_audience`, `xrootd_macaroon_secret`(`_old`), `xrootd_sss_keytab`, `xrootd_krb5_principal`/`_keytab`/`_ip_check`, `xrootd_unix_trust_remote` |
| TLS / OCSP | `xrootd_tls`, `xrootd_ktls`, `xrootd_ocsp_enable`, `xrootd_ocsp_soft_fail`, `xrootd_ocsp_stapling` |
| Native TPC | `xrootd_tpc_allow_local`/`_private`, `xrootd_tpc_key_ttl`, `xrootd_tpc_outbound_bearer_file`, `xrootd_tpc_outbound_token_endpoint`/`_client_id`/`_client_secret`/`_scope` |
| Manager / redirector | `xrootd_manager_map`, `xrootd_manager_mode`, `xrootd_metadata_only`, `xrootd_supervisor`, `xrootd_virtual_redirector`, `xrootd_collapse_redir`(`_ttl`), `xrootd_registry_slots`, `xrootd_session_slots`, `xrootd_redir_cache_slots`, `xrootd_recover_writes` |
| Upstream redirector | `xrootd_upstream`, `xrootd_upstream_tls`(`_ca`/`_name`), `xrootd_upstream_token_file` |
| CMS cluster | `xrootd_cms_manager`, `xrootd_cms_paths`, `xrootd_cms_interval`, `xrootd_cms_locate_timeout` |
| Read-through cache | `xrootd_cache`(`_root`/`_origin`/`_origin_tls`/`_lock_timeout`/`_eviction_threshold`/`_max_file_size`/`_include_regex`/`_slice`) |
| Write-through | `xrootd_write_through`, `xrootd_wt_mode`/`_origin`/`_deny_prefix`/`_allow_prefix` |
| Transparent proxy | `xrootd_proxy`, `xrootd_proxy_upstream`(`_tls`/`_tls_ca`/`_tls_name`), `xrootd_proxy_auth`, `xrootd_proxy_login_user`, `xrootd_proxy_audit_log`, `xrootd_proxy_reconnect_attempts`, `xrootd_proxy_connect_timeout`/`_read_timeout`/`_keepalive_interval`, `xrootd_proxy_path_rewrite` |
| Health checks (Phase 22) | `xrootd_health_check`(`_interval`/`_timeout`/`_threshold`/`_blacklist`/`_type`) |
| Traffic mirror (Phase 24) | `xrootd_stream_mirror_url`, `xrootd_mirror_opcodes`/`_exclude_opcodes`/`_sample`/`_strip_auth`/`_writes`/`_log_diverge`/`_timeout` |
| KV / cache / rate-limit (Phase 20/25) | `xrootd_kv_zone`, `xrootd_token_cache`, `xrootd_auth_cache`, `xrootd_rate_limit`(+`_zone`/`_rule`), `xrootd_bandwidth_limit`, `xrootd_concurrency_limit` |
| Tuning / misc | `xrootd_thread_pool`, `xrootd_memory_budget`, `xrootd_readv_segment_size` (per-`kXR_readv`-element cap = official `maxReadv_ior`; default 2 MiB−16, advertised via Qconfig `readv_ior_max`), `xrootd_ckscan_depth`/`_max_files`, `xrootd_prepare_command` |

## Control & data flow

**Config-parse time (single-threaded master).** nginx discovers
`ngx_stream_xrootd_module` (via `module_definition.c`), reads `stream {}`, and for each
directive in `ngx_stream_xrootd_commands[]` invokes its setter, which writes into the
`ngx_stream_xrootd_srv_conf_t` produced by `ngx_stream_xrootd_create_srv_conf`
(`../config/server_conf.c`). The `xrootd` flag's setter `ngx_stream_xrootd_enable`
additionally fetches the stream-core srv conf and sets
`cscf->handler = ngx_stream_xrootd_handler`. After all blocks parse,
`ngx_stream_xrootd_postconfiguration` (`../config/postconfiguration.c`) runs final
validation / resource setup. Parent→child inheritance is resolved by
`ngx_stream_xrootd_merge_srv_conf` (`NGX_CONF_UNSET*` sentinels distinguish unset from
explicit).

**Worker startup.** `ngx_stream_xrootd_init_process` (`../config/process.c`) runs once
per worker: opens the per-worker `O_PATH` export-root fd used for `RESOLVE_BENEATH`
confinement (see `../path/README.md`), initialises the proxy pool, and arms the CMS
heartbeat client (`../cms/README.md`), active health-check probes
(`../manager/health_check.h`), the CRL-reload timer, and the JWKS hot-refresh timer
where configured.

**Request time — this subsystem is not on the path.** Once installed,
`ngx_stream_xrootd_handler` is the entry; it lives in `../connection/README.md` and
routes to `../handshake/README.md` → `../session/README.md` (login/auth) → opcode
handlers (`../read/README.md`, `../write/README.md`, `../dirlist/README.md`,
`../query/README.md`). Cache / proxy / manager / mirror behaviour is driven entirely
by the config fields populated here but executed in `../cache/`, `../proxy/`,
`../manager/`, `../mirror/`, `../ratelimit/`.

## Invariants, security & gotchas

- **`module.c` owns the live directive array; the two `*_directives.c` copies are
  dead.** Only `module.c` and `module_definition.c` appear in `NGX_ADDON_SRCS`
  (`config:236-237`); `module_core_directives.c` and `module_cache_proxy_directives.c`
  are never compiled. Editing them has no runtime effect — always change `module.c`.
- **Adding a new source file or a new top-level directive block requires
  `./configure`.** A plain `make` will not pick up a new `.c` file (it must be added to
  `NGX_ADDON_SRCS` in `config`) nor a new `NGX_STREAM_MAIN_CONF` block. Plain scalar
  `NGX_STREAM_SRV_CONF` additions only need a rebuild.
- **Directive scope flags are load-bearing.** Most directives are
  `NGX_STREAM_SRV_CONF`. The KV-zone and rate-limit-zone directives
  (`xrootd_kv_zone` at `module.c:960`, `xrootd_rate_limit_zone` at `module.c:587`) are
  `NGX_STREAM_MAIN_CONF` because SHM zones are process-global, not per-server.
  Misclassifying scope breaks SHM allocation.
- **Fail-closed auth is *configured* here but *enforced* downstream.** `xrootd_auth`
  only selects the advertised login flow; `xrootd_allow_write` (`module.c:382`) only
  enables the write feature — write handlers still re-check auth/scope per op, and
  `allow_write` is verified globally before token scope. S3 SigV4 and WLCG tokens are
  separate auth domains and never share setters. Setting a flag here does not, by
  itself, grant access.
- **`xrootd_security_level`** maps text → integer `0..4` (kXR_secNone…kXR_secPedantic);
  this is the kXR_sigver (HMAC-SHA256 request-signing) enforcement floor consumed by
  `../handshake/`. Raising it can reject legacy unsigned clients.
- **`xrootd_thread_pool`** only takes effect when nginx itself was built
  `--with-threads`; it names the pool `../aio/` uses to offload blocking
  `pread`/`pwrite` off the single-threaded event loop.
- **Mirror write replay is opt-in and dangerous.** `xrootd_mirror_writes`
  (`module.c:565`) gates replay of mutating opcodes to the shadow target; the shadow
  MUST be an isolated namespace (a separate server/root), never the primary's backing
  store. Default off.
- **Enum tables must stay NUL-terminated.** Each `ngx_conf_enum_t[]` ends with
  `{ ngx_null_string, 0 }`; nginx's enum setter walks until that sentinel. Dropping it
  causes an out-of-bounds scan.
- **No main-conf callbacks by design.** `create_main_conf` / `init_main_conf` are
  `NULL` in `module_definition.c` — each server block self-manages. Do not add
  cross-server aggregation here; process-wide state belongs in SHM (`../shm/`,
  `../manager/`) initialised from `init_process`.

## Entry points / extending

**Add a new `xrootd_*` directive:**
1. Add the destination field to `ngx_stream_xrootd_srv_conf_t` in `../types/config.h`
   (initialise to `NGX_CONF_UNSET*` / `NULL` in `create_srv_conf`, and merge in
   `merge_srv_conf` — both in `../config/server_conf.c`).
2. Add an `ngx_command_t` entry to **`ngx_stream_xrootd_commands[]` in `module.c`**
   (the live array): pick the correct scope (`NGX_STREAM_SRV_CONF` vs
   `NGX_STREAM_MAIN_CONF`) and `NGX_CONF_TAKE*` arg count; use a stock
   `ngx_conf_set_*_slot` setter for simple scalars, or a custom setter declared in the
   owning subsystem header for multi-arg/validated parsing.
3. If the directive needs an enum, add a `ngx_conf_enum_t[]` table here and pass it as
   the entry's `post` field (with `ngx_conf_set_enum_slot`).
4. A new top-level block or new `.c` file → register in `config` (`NGX_ADDON_SRCS`)
   and re-run `./configure`; otherwise `make -j$(nproc)` suffices.
5. Document it (this README's `Directive groups` table) and add tests
   (success + error + security-negative).

**Add a new lifecycle hook** (e.g. a new per-worker timer): wire the callback slot in
`ngx_stream_xrootd_module_ctx` / `ngx_module_t` in `module_definition.c`, but implement
the body under `../config/` — keep this directory glue-only.

## See also

- `../config/README.md` — the lifecycle callbacks (`create/merge_srv_conf`,
  `postconfiguration`, `init_process`, `exit_process`) this descriptor points at.
  The `ngx_stream_xrootd_srv_conf_t` struct itself is defined in `../types/config.h`.
- `../connection/README.md` — `ngx_stream_xrootd_handler`, the request entry installed
  by `xrootd on;`.
- `../handshake/README.md` — opcode dispatch consuming `xrootd_auth` /
  `xrootd_security_level`.
- `../session/README.md`, `../path/README.md`, `../aio/README.md`,
  `../cache/README.md`, `../proxy/README.md`, `../manager/README.md`,
  `../cms/README.md`, `../mirror/README.md`, `../ratelimit/README.md` — the subsystems
  whose behaviour these directives configure.
- `../README.md` — master subsystem index.
