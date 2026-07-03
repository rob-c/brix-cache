# stream — `ngx_stream_brix_module` descriptor & directive table

## Overview

This subsystem is the **nginx stream-module glue** for the XRootD native
(`root://` / `roots://`) protocol. It contains *no* protocol logic, no I/O, and no
per-request state. Its entire job is to make a stock nginx build aware of the module:
declare the static `ngx_module_t` descriptor, register the full
`ngx_stream_brix_commands[]` directive table that nginx parses inside
`stream { server { … } }` blocks, and define the small enum lookup tables
(`brix_auth_modes`, `brix_security_levels`, `brix_hc_types`) that map config
keywords onto internal constants. Everything substantive is delegated to callbacks
declared in `../ngx_brix_module.h` and implemented under `../config/`.

It sits at the very top of the `root://` request lifecycle — *before any connection
exists*. When nginx parses a `stream` block and sees the `xrootd` flag, the custom
setter `ngx_stream_brix_enable` (in `../config/server_conf.c`) swaps the stream-core
server handler for `ngx_stream_brix_handler`. From that point on, every TCP
connection on the listen port enters the module via `../connection/handler.c` →
`../handshake/dispatch.c`. None of that dispatch code lives here; this directory only
wires the module into nginx so the handler gets installed and so the per-server
`ngx_stream_brix_srv_conf_t` is populated from `nginx.conf`.

The module context (`ngx_stream_brix_module_ctx`) deliberately registers **no
main-conf callbacks** (`create_main_conf`/`init_main_conf` are `NULL`): each stream
`server {}` block owns its configuration independently — there is no stream-wide
aggregation. It *does* register `create_srv_conf`, `merge_srv_conf` (parent→child
inheritance), `postconfiguration` (final validation / resource setup),
`init_process` (per-worker startup: opens the `RESOLVE_BENEATH` root fd; arms the
CMS / health-check / CRL / JWKS timers), and `exit_process` (worker teardown). All
five implementations live under `../config/`.

The directive table is the canonical, single-source list of every `brix_*`
directive the module accepts for the `root://` stream protocol. It lives entirely
in **`module.c`**, with the module wiring in **`module_definition.c`** — both
compiled via `NGX_ADDON_SRCS` (`config:236-237`). Treat `module.c` as ground truth.

## Files

| File | Responsibility |
|------|----------------|
| `module.c` | **Authoritative — compiled.** Defines the live `ngx_stream_brix_commands[]`: the complete directive table (core + auth + TLS/OCSP + native TPC + manager/CMS + read-through cache + write-through + transparent proxy + Phase 20 KV/rate-limit + Phase 22 health-check + Phase 24 mirror + Phase 25/26/29/31 tuning), terminated by `ngx_null_command`. Also defines the `brix_auth_modes[]`, `brix_security_levels[]`, and `brix_hc_types[]` enum tables. |
| `module_definition.c` | **Compiled.** Declares the static module wiring: `ngx_stream_brix_module_ctx` (`ngx_stream_module_t` lifecycle hooks — `postconfiguration`, `create_srv_conf`, `merge_srv_conf`; main-conf slots `NULL`) and the `ngx_module_t ngx_stream_brix_module` descriptor (`NGX_STREAM_MODULE`, with `init_process` = `ngx_stream_brix_init_process` and `exit_process` = `brix_exit_process`). Holds an `extern` reference to `ngx_stream_brix_commands[]`. |

## Key types & data structures

This subsystem defines no runtime structs of its own — it only references them. The
ones a reviewer must know:

- **`ngx_command_t ngx_stream_brix_commands[]`** — nginx's directive descriptor
  array. Each entry is `{ name, scope|argcount flags, setter, conf-target, offset,
  post }`. Most entries use stock nginx setters (`ngx_conf_set_str_slot`,
  `ngx_conf_set_flag_slot`, `ngx_conf_set_num_slot`, `ngx_conf_set_sec_slot`,
  `ngx_conf_set_msec_slot`, `ngx_conf_set_size_slot`, `ngx_conf_set_off_slot`,
  `ngx_conf_set_enum_slot`) writing straight into the per-server config via
  `offsetof(...)`. The rest use custom setters declared in `../ngx_brix_module.h`
  or in the owning subsystem header (e.g. `brix_conf_set_cache_origin`,
  `brix_conf_set_proxy_upstream`, `brix_rl_zone_directive`,
  `brix_stream_mirror_set_url`, `brix_kv_zone_directive`,
  `brix_token_cache_directive`). Terminated by `ngx_null_command`.
- **`ngx_stream_module_t ngx_stream_brix_module_ctx`** — the six-slot stream-module
  callback table. Only `postconfiguration`, `create_srv_conf`, and `merge_srv_conf`
  are non-`NULL` here.
- **`ngx_module_t ngx_stream_brix_module`** — the global descriptor nginx discovers
  at startup; carries `init_process` (`ngx_stream_brix_init_process`) and
  `exit_process` (`brix_exit_process`).
- **`ngx_conf_enum_t` tables** —
  `brix_auth_modes` (`none|gsi|token|both|sss|unix|krb5` → `BRIX_AUTH_*`),
  `brix_security_levels` (`none|compatible|standard|intense|pedantic` → `0..4`, the
  kXR_sigver enforcement level), and `brix_hc_types` (`ping|stat` →
  `BRIX_HC_TYPE_*`). Each is NUL-terminated with `{ ngx_null_string, 0 }`.
- **`ngx_stream_brix_srv_conf_t`** — the per-server config struct every directive
  writes into. Defined in `../config/config.h`, allocated by
  `ngx_stream_brix_create_srv_conf` (`../config/server_conf.c`). This subsystem
  references its field offsets only; it does not declare it.

### Directive groups (authoritative `module.c` set)

| Group | Directives (representative) |
|-------|------------------------------|
| Enable / export / write | `xrootd`, `brix_root`, `brix_allow_write`, `brix_listen_port`, `brix_access_log` |
| Auth mode & GSI/x509 | `brix_auth`, `brix_certificate`, `brix_certificate_key`, `brix_trusted_ca`, `brix_vomsdir`, `brix_voms_cert_dir`, `brix_crl`, `brix_crl_reload`, `brix_require_vo`, `brix_authdb`, `brix_inherit_parent_group`, `brix_security_level` |
| Bearer / SSS / krb5 / unix | `brix_token_jwks`(+`_refresh_interval`), `brix_token_issuer`, `brix_token_audience`, `brix_macaroon_secret`(`_old`), `brix_sss_keytab`, `brix_krb5_principal`/`_keytab`/`_ip_check`, `brix_unix_trust_remote` |
| TLS / OCSP | `brix_tls`, `brix_ktls`, `brix_ocsp_enable`, `brix_ocsp_soft_fail`, `brix_ocsp_stapling` |
| Native TPC | `brix_tpc_allow_local`/`_private`, `brix_tpc_key_ttl`, `brix_tpc_outbound_bearer_file`, `brix_tpc_outbound_token_endpoint`/`_client_id`/`_client_secret`/`_scope` |
| Manager / redirector | `brix_manager_map`, `brix_manager_mode`, `brix_metadata_only`, `brix_supervisor`, `brix_virtual_redirector`, `brix_collapse_redir`(`_ttl`), `brix_registry_slots`, `brix_session_slots`, `brix_redir_cache_slots`, `brix_recover_writes` |
| Upstream redirector | `brix_upstream`, `brix_upstream_tls`(`_ca`/`_name`), `brix_upstream_token_file` |
| CMS cluster | `brix_cms_manager`, `brix_cms_paths`, `brix_cms_interval`, `brix_cms_locate_timeout` |
| Read-through cache | `brix_cache`(`_root`/`_origin`/`_origin_tls`/`_lock_timeout`/`_eviction_threshold`/`_max_file_size`/`_include_regex`/`_slice`) |
| Write-through | `brix_write_through`, `brix_wt_mode`/`_origin`/`_deny_prefix`/`_allow_prefix` |
| Transparent proxy | `brix_proxy`, `brix_proxy_upstream`(`_tls`/`_tls_ca`/`_tls_name`), `brix_proxy_auth`, `brix_proxy_login_user`, `brix_proxy_audit_log`, `brix_proxy_reconnect_attempts`, `brix_proxy_connect_timeout`/`_read_timeout`/`_keepalive_interval`, `brix_proxy_path_rewrite` |
| Health checks (Phase 22) | `brix_health_check`(`_interval`/`_timeout`/`_threshold`/`_blacklist`/`_type`) |
| Traffic mirror (Phase 24) | `brix_stream_mirror_url`, `brix_mirror_opcodes`/`_exclude_opcodes`/`_sample`/`_strip_auth`/`_writes`/`_log_diverge`/`_timeout` |
| KV / cache / rate-limit (Phase 20/25) | `brix_kv_zone`, `brix_token_cache`, `brix_auth_cache`, `brix_rate_limit`(+`_zone`/`_rule`), `brix_bandwidth_limit`, `brix_concurrency_limit` |
| Tuning / misc | `brix_thread_pool`, `brix_memory_budget`, `brix_readv_segment_size` (per-`kXR_readv`-element cap = official `maxReadv_ior`; default 2 MiB−16, advertised via Qconfig `readv_ior_max`), `brix_ckscan_depth`/`_max_files`, `brix_prepare_command` |

## Control & data flow

**Config-parse time (single-threaded master).** nginx discovers
`ngx_stream_brix_module` (via `module_definition.c`), reads `stream {}`, and for each
directive in `ngx_stream_brix_commands[]` invokes its setter, which writes into the
`ngx_stream_brix_srv_conf_t` produced by `ngx_stream_brix_create_srv_conf`
(`../config/server_conf.c`). The `xrootd` flag's setter `ngx_stream_brix_enable`
additionally fetches the stream-core srv conf and sets
`cscf->handler = ngx_stream_brix_handler`. After all blocks parse,
`ngx_stream_brix_postconfiguration` (`../config/postconfiguration.c`) runs final
validation / resource setup. Parent→child inheritance is resolved by
`ngx_stream_brix_merge_srv_conf` (`NGX_CONF_UNSET*` sentinels distinguish unset from
explicit).

**Worker startup.** `ngx_stream_brix_init_process` (`../config/process.c`) runs once
per worker: opens the per-worker `O_PATH` export-root fd used for `RESOLVE_BENEATH`
confinement (see `../path/README.md`), initialises the proxy pool, and arms the CMS
heartbeat client (`../cms/README.md`), active health-check probes
(`../manager/health_check.h`), the CRL-reload timer, and the JWKS hot-refresh timer
where configured.

**Request time — this subsystem is not on the path.** Once installed,
`ngx_stream_brix_handler` is the entry; it lives in `../connection/README.md` and
routes to `../handshake/README.md` → `../session/README.md` (login/auth) → opcode
handlers (`../read/README.md`, `../write/README.md`, `../dirlist/README.md`,
`../query/README.md`). Cache / proxy / manager / mirror behaviour is driven entirely
by the config fields populated here but executed in `../cache/`, `../proxy/`,
`../manager/`, `../mirror/`, `../ratelimit/`.

## Invariants, security & gotchas

- **`module.c` owns the live directive array.** `module.c` and
  `module_definition.c` are the only directive sources in `NGX_ADDON_SRCS`
  (`config:236-237`); always add or change directives in `module.c`'s
  `ngx_stream_brix_commands[]`.
- **Adding a new source file or a new top-level directive block requires
  `./configure`.** A plain `make` will not pick up a new `.c` file (it must be added to
  `NGX_ADDON_SRCS` in `config`) nor a new `NGX_STREAM_MAIN_CONF` block. Plain scalar
  `NGX_STREAM_SRV_CONF` additions only need a rebuild.
- **Directive scope flags are load-bearing.** Most directives are
  `NGX_STREAM_SRV_CONF`. The KV-zone and rate-limit-zone directives
  (`brix_kv_zone` at `module.c:960`, `brix_rate_limit_zone` at `module.c:587`) are
  `NGX_STREAM_MAIN_CONF` because SHM zones are process-global, not per-server.
  Misclassifying scope breaks SHM allocation.
- **Fail-closed auth is *configured* here but *enforced* downstream.** `brix_auth`
  only selects the advertised login flow; `brix_allow_write` (`module.c:382`) only
  enables the write feature — write handlers still re-check auth/scope per op, and
  `allow_write` is verified globally before token scope. S3 SigV4 and WLCG tokens are
  separate auth domains and never share setters. Setting a flag here does not, by
  itself, grant access.
- **`brix_security_level`** maps text → integer `0..4` (kXR_secNone…kXR_secPedantic);
  this is the kXR_sigver (HMAC-SHA256 request-signing) enforcement floor consumed by
  `../handshake/`. Raising it can reject legacy unsigned clients.
- **`brix_thread_pool`** only takes effect when nginx itself was built
  `--with-threads`; it names the pool `../aio/` uses to offload blocking
  `pread`/`pwrite` off the single-threaded event loop.
- **Mirror write replay is opt-in and dangerous.** `brix_mirror_writes`
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

**Add a new `brix_*` directive:**
1. Add the destination field to `ngx_stream_brix_srv_conf_t` in `../types/config.h`
   (initialise to `NGX_CONF_UNSET*` / `NULL` in `create_srv_conf`, and merge in
   `merge_srv_conf` — both in `../config/server_conf.c`).
2. Add an `ngx_command_t` entry to **`ngx_stream_brix_commands[]` in `module.c`**
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
`ngx_stream_brix_module_ctx` / `ngx_module_t` in `module_definition.c`, but implement
the body under `../config/` — keep this directory glue-only.

## See also

- `../config/README.md` — the lifecycle callbacks (`create/merge_srv_conf`,
  `postconfiguration`, `init_process`, `exit_process`) this descriptor points at.
  The `ngx_stream_brix_srv_conf_t` struct itself is defined in `../types/config.h`.
- `../connection/README.md` — `ngx_stream_brix_handler`, the request entry installed
  by `xrootd on;`.
- `../handshake/README.md` — opcode dispatch consuming `brix_auth` /
  `brix_security_level`.
- `../session/README.md`, `../path/README.md`, `../aio/README.md`,
  `../cache/README.md`, `../proxy/README.md`, `../manager/README.md`,
  `../cms/README.md`, `../mirror/README.md`, `../ratelimit/README.md` — the subsystems
  whose behaviour these directives configure.
- `../README.md` — master subsystem index.
