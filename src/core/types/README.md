# src/core/types — Core type definitions, tunables, and the canonical identity object

## Overview

`src/core/types/` is the **type vocabulary of the entire module**. It holds the per-connection
context (`xrootd_ctx_t`), the per-server configuration block
(`ngx_stream_xrootd_srv_conf_t`), the per-open-file slot (`xrootd_file_t`), the
connection state-machine enum (`xrootd_state_t`), the compile-time tunables and metric
macros, and the one piece of behaviour that lives here: the protocol-agnostic
authenticated principal (`xrootd_identity_t`, with `identity.c`). Almost every other
subsystem includes one of these headers — they are the shared data shapes that the
stream handlers, HTTP handlers, auth code, cache, cluster, and metrics all read and write.
(`grep` confirms ~30+ subsystems include `types/*.h`, directly or via the umbrella header.)

These files began life as focused sub-headers carved out of the umbrella header
`src/core/ngx_xrootd_module.h` so a contributor can read exactly one concept without wading
through the whole module. The umbrella header includes them **in a fixed dependency
order** (`tunables.h → identity.h → state.h → file.h → context.h → config.h`, see
`src/core/ngx_xrootd_module.h:105`), each after the nginx, OpenSSL, `protocol/`, `metrics/`,
and `token/` prerequisites they depend on. **None of these headers are self-contained** —
do not include them directly before those prerequisites are in scope; include the umbrella
header instead.

Where they sit in the request lifecycle: a `root://` TCP accept allocates one
`xrootd_ctx_t` from the connection pool (`ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t))` in
`../connection/handler.c:33`) and zero-fills it; the handler then marks every file slot
free (`files[i].fd = -1`, `handler.c:73`), generates the 16-byte session ID, and points
`ctx->metrics` at the SHM slot (`handler.c:95-102`). That struct then carries *all* session
state — input accumulation, auth identity, the open-file table, the pipelined output ring,
AIO tasks, GSI/sigver crypto, bind/proxy/CMS state — across every handshake, dispatch,
async I/O, and send phase until disconnect. The matching `ngx_stream_xrootd_srv_conf_t`
(one per `server {}` block) is the immutable, merged config the handlers consult on each
request. This subsystem contains almost no logic; it defines the contracts everything
else obeys.

This directory is **stream-plane-centric** (the `root://` protocol). The HTTP plane
(WebDAV, S3) keeps its own per-request structs in `../webdav/` and `../s3/`, but shares
the tunables, the auth-mode constants, and the `xrootd_identity_t` principal defined here.

## Files

| File | Responsibility |
|---|---|
| `tunables.h` | Compile-time size/count limits (`XROOTD_READ_MAX`/`_CHUNK_MAX`/`_REQUEST_MAX`, `XROOTD_READ_WINDOW` + `_SCRATCH_TRIM_THRESHOLD` + `_CONN_XFER_HEAP_MAX` memory-budget streaming, `XROOTD_PIPELINE_MAX`/`_SLOT_HDR_MAX` pipelining, `XROOTD_MAX_FILES`, `XROOTD_MAX_WALK_DEPTH`, `XROOTD_MAX_CONN_POOL_BYTES`, write/prepare/auth payload caps, `XROOTD_GSI_KEYPOOL_*`, `XROOTD_RL_RULE_CACHE_MAX`), auth-mode constants (`XROOTD_AUTH_NONE/GSI/TOKEN/BOTH/SSS/UNIX/KRB5`), SSS sizing + opt flags, JWT clock-skew, and the metric/response-collapse macros (`XROOTD_OP_OK/OP_ERR`, `XROOTD_RETURN_OK/ERR/REDIR`, `XROOTD_BAIL_ERR`). Includes `../compat/path.h`. |
| `state.h` | `xrootd_state_t` — the per-connection state-machine enum that drives the read/write event callbacks (`XRD_ST_HANDSHAKE → REQ_HEADER → REQ_PAYLOAD`, plus `SENDING`, `AIO`, `TLS_HANDSHAKE`, `UPSTREAM`, `PROXY`, `WAITING_CMS`); plus opaque forward decls for `xrootd_upstream_t`, `xrootd_proxy_ctx_t`, `ngx_xrootd_cms_ctx_t` so `context.h` can hold pointers without pulling those headers. |
| `file.h` | `xrootd_file_t` — one slot per open XRootD file handle (**array index = the 4-byte handle the client echoes back**); also `xrootd_wrts_entry_t` + `XROOTD_WRTS_JOURNAL_SLOTS` (the per-handle write-recovery ring). Tracks `fd`, resolved `path`, byte counters, immutable open-time `device`/`inode`/`is_regular`/`cached_size`, read-ahead hints, slice-cache state, `kXR_chkpoint`, `kXR_posc`, native-TPC-destination, write-through dirty state + async-flush task, the `wrts_journal[]` replay ring, and the dashboard/SHM-handle slot hints. |
| `context.h` | `xrootd_ctx_t` — the per-TCP-connection session context (everything below); plus the two helper structs it embeds: `xrootd_resp_slot_t` (one output-ring slot: flat-buffer tail OR chain tail + reusable one-chunk read-response chain structs + per-slot `hdr_bytes[XROOTD_SLOT_HDR_MAX]`) and `xrootd_read_slot_t` (one concurrent-AIO read pool entry: raw buffer + thread task + in-use bit). |
| `config.h` | `ngx_stream_xrootd_srv_conf_t` — the per-`server {}` config block, with every field annotated by the `[nginx.conf directive]` that populates it; plus its helper types: `xrootd_sss_key_t`, `xrootd_auth_type_t` + `XROOTD_AUTH_*` priv bits, `xrootd_authdb_rule_t`, `xrootd_vo_rule_t`, `xrootd_group_rule_t`, `xrootd_manager_map_t`, `xrootd_proxy_upstream_t`. Pulls in `../mirror/mirror.h`, `../cache/writethrough_decision.h`, `../config/shared_conf.h`, `../shm/kv.h`, `../path/auth_cache.h`, `../shm/rate_limit.h`. |
| `identity.h` | `xrootd_identity_t` — the **canonical, protocol-agnostic authenticated principal** (DN/subject/issuer, VO list, OAuth scopes, `XROOTD_AUTHN_*` method bitmask, `is_authenticated/is_admin/has_write_scope/has_read_scope` flags) plus its accessor/builder API. The one shape policy and audit code reason about regardless of which wire auth produced it. |
| `identity.c` | The only `.c` here: implements the `xrootd_identity_*` builders/accessors — `_alloc`, `_set_dn`/`_set_subject`/`_set_vos_csv`/`_set_token_claims`, CSV/space splitters, `_check_token_scope` (delegates to `xrootd_token_check_read/write`), `_method_name`, and `_describe`. All allocation is pool-based (`ngx_pcalloc`/`ngx_pnalloc`). Registered for build in the top-level `config` file (`NGX_ADDON_SRCS`, `config:268`), **not** in `src/core/config/config.h`. |

## Key types & data structures

- **`xrootd_ctx_t` (`context.h`)** — one per TCP connection, allocated from
  `c->pool`. The state machine runs single-threaded on one nginx worker; only one
  request is logically "in flight" at a time (XRootD multiplexes via streamid on the
  *client* side, the server serialises responses). Notable sections:
  - *Input accumulation:* `hdr_buf[24]`/`hdr_pos`, parsed `cur_streamid`/`cur_reqid`/
    `cur_body`/`cur_dlen`, then payload into a reusable, explicitly-owned `payload_buf`.
  - *Session/auth:* `sessid`, `logged_in`/`auth_done`, `login_user[9]`/`login_pid`, capped
    `auth_fail_count` and `pool_bytes_used`; legacy identity views
    `dn`/`primary_vo`/`vo_list`/`peer_ip` **and** the canonical `identity` pointer
    (`xrootd_identity_t *`).
  - *Open-file table:* `files[XROOTD_MAX_FILES]` (index = handle).
  - *Output pipelining (Phase 29+):* `out_ring[XROOTD_PIPELINE_MAX]` of
    `xrootd_resp_slot_t` with `out_head`/`out_tail`/`out_count`, plus `recv_deferred`
    (drain barrier for non-pipelinable opcodes) and `resp_pipelinable` (only single-chunk
    sendfile reads may pipeline).
  - *Read pipeline / windowing (Phase 31/32):* `rd_pool[]` of `xrootd_read_slot_t`,
    `rd_inflight`/`rd_backpressured`, the windowed-read continuation fields (`rd_win_*`),
    reusable scratch buffers and cached AIO tasks
    (`read_scratch`/`read_hdr_scratch`/`write_scratch`,
    `read_aio_task`/`pgread_aio_task`/`readv_aio_task`), and `budget_charged` for the
    SHM-global transfer-heap accounting.
  - *Crypto/security:* `gsi_dh_key` (DH key, valid only between `kXGS_cert` and the secret
    derive at `kXGC_cert`), the `signing_*`/`sigver_*` kXR_sigver request-signing lifecycle
    (HMAC-SHA256 over each request, `last_seqno` replay guard, cached `EVP_MAC`/`EVP_MAC_CTX`),
    and `token_*` bearer-scope state.
  - *Cluster/proxy/bind:* `tls_pending`, `upstream`, `proxy`, raw `bearer_token[4096]`
    (forwarded upstream when `xrootd_proxy_auth forward`), `is_bound`/`pathid`/`bound_sessid`
    (parallel-stream secondary), `cms_wait_streamid`.
  - *Cross-cutting:* `metrics` SHM pointer, `destroyed` AIO guard, session byte totals
    (split IPv4/IPv6 tx/rx for the access log), `wmirror`, rate-limit
    charge/concurrency/key-cache fields, `write_rc` (auth-gate `NGX_DONE` return value), and
    read-only `protocol_label[8]`/`ip_version`.
- **`xrootd_resp_slot_t` / `xrootd_read_slot_t` (`context.h`)** — per-in-flight-response
  and per-in-flight-read state, bundled per slot so multiple responses/reads can be
  outstanding without aliasing each other's chain/header/buffer memory.
- **`xrootd_file_t` + `xrootd_wrts_entry_t` (`file.h`)** — handle bookkeeping; the
  `device`/`inode` captured at open are the validation key for bound-secondary reopens,
  and `wrts_journal[]` makes write replay idempotent (`xrootd_wrts_is_replay()`).
- **`ngx_stream_xrootd_srv_conf_t` + helpers (`config.h`)** — the merged, read-only
  server config. Covers: auth mode + GSI/x509 (cert/key/trust store, VOMS, CRL timer),
  token/JWKS (with grace-period macaroon-secret rotation + mtime hot-refresh), SSS, krb5,
  unix; VO/authdb/group ACL arrays + `manager_map`; access log + metrics slot; read-through
  cache (incl. slice-granular `cache_slice_size`) + write-through; upstream redirector +
  TPC SSRF policy + OAuth2 delegation; CMS heartbeat (`cms_*`, `listen_port`,
  `cms_suspended`) + registry/session/redir-cache slot counts; node-role flags
  (`manager_mode`, `supervisor`, `virtual_redirector`, `metadata_only`,
  `collapse_redir`, `recover_writes`); active health checks (`hc_*`); transparent proxy
  mode; OCSP; mirror; rate-limit. Each ACL helper struct carries a pre-`resolved[PATH_MAX]`
  path so the hot path never re-`realpath`s a rule.
- **`xrootd_identity_t` (`identity.h`)** — DN/subject/issuer + VO/scope arrays + the
  `XROOTD_AUTHN_*` method bitmask; the deliberate bridge that lets one policy/audit code
  path serve GSI, token, SSS, krb5, unix, and S3-SigV4 sessions alike. Keeps both
  structured arrays (`vo_list`, `scopes`) and flat "compatibility views" (`vo_csv`,
  `scope_raw`, `token_scopes[]`) in sync so hot paths can migrate incrementally.
- **`xrootd_state_t` (`state.h`)** — the enum the connection event handlers switch on; the
  comment block documents which read/write events are armed in each state.

## Control & data flow

Nothing "runs" in `src/core/types/` except the `identity.c` helpers — these headers are
**included, not called**. The flow is:

1. `../connection/handler.c` allocates and zero-fills `xrootd_ctx_t` per TCP accept,
   sets every `files[i].fd = -1`, copies `protocol_label`/`peer_ip`/`ip_version`, builds the
   session ID, and points `ctx->metrics` at the SHM slot.
2. `../handshake/` and `../session/` advance `ctx->state` (`state.h`) and fill the auth
   fields; auth code (`../gsi/`, `../token/`, `../sss/`, `../krb5/`) verifies wire
   credentials and then calls the `identity.c` builders to populate `ctx->identity`
   (`xrootd_identity_set_dn` / `_set_subject` / `_set_token_claims` / `_set_vos_csv`).
3. Protocol handlers (`../read/`, `../write/`, `../dirlist/`, `../query/`, …) read the
   per-server config out of `ngx_stream_xrootd_srv_conf_t`, allocate/free `files[]` slots
   (free via `xrootd_free_fhandle()` in `../connection/fd_table.c`), and stage responses
   into the `out_ring` slots.
4. Blocking file I/O detours through `../aio/` using the cached thread tasks on the ctx;
   the completion callback checks `ctx->destroyed` before touching anything.
5. `identity.c`'s `xrootd_identity_check_token_scope` delegates to `../token/`
   (`xrootd_token_check_read/write`); `xrootd_identity_set_token_claims` consumes a
   `xrootd_token_claims_t` produced there.

Sibling subsystems that consume these types most directly: `../connection/README.md`
(allocates/drives the ctx), `../config/README.md` (creates and merges the srv_conf),
`../read/README.md` and `../write/README.md` (use `files[]`, scratch buffers, AIO tasks),
`../path/README.md` (resolves the ACL rules), `../token/README.md` and `../gsi/README.md`
(produce the identity), and `../metrics/README.md` (the SHM struct `ctx->metrics` points at).

## Invariants, security & gotchas

- **Array index *is* the handle.** `ctx->files[i]` is addressed directly by the 4-byte
  XRootD file handle (`file.h`). A slot is free iff `fd < 0`; the handler frees via
  `xrootd_free_fhandle()` (resets to `-1`). Never assume handles are dense or stable
  across reuse.
- **Bound-secondary reopens validate device/inode.** nginx workers cannot safely share
  post-fork fd integers, so a `kXR_bind` secondary lazily reopens the primary's canonical
  path in its *own* worker and must match the `device`/`inode` captured at open
  (`file.h`) before serving — caching only the SHM slot hint (`shared_handle_slot_hint`),
  never the fd. See `context.h` `is_bound`/`pathid`/`bound_sessid`.
- **`identity.c` is fail-closed and pool-bounded.** Every setter rejects a NULL `id`,
  treats empty input as "unset" (`ngx_str_null`), and copies into NUL-terminated pool
  allocations (`ngx_pnalloc(pool, len+1)`); `token_scope_count` is clamped to
  `XROOTD_MAX_TOKEN_SCOPES` (`identity.c:323-324`). `xrootd_identity_check_token_scope`
  returns `NGX_OK` for non-token sessions (scopes only gate token auth) — callers must
  still enforce GSI/ACL separately, and `conf->allow_write` is checked *before* scope.
- **Auth domains never share logic.** `XROOTD_AUTHN_*` (`identity.h`, the *verified*
  principal bitmask) and the wire-auth `XROOTD_AUTH_*` modes (`tunables.h`, the configured
  requirement) are distinct namespaces; S3 SigV4 and WLCG tokens are different auth surfaces
  and must not cross-pollinate.
- **The metric macros are conditional.** `XROOTD_OP_OK/OP_ERR` and the `XROOTD_RETURN_*`
  collapse macros (`tunables.h`) are no-ops when `ctx->metrics == NULL` (metrics zone not
  configured) — never assume the SHM pointer is non-NULL. Keep metric labels
  low-cardinality (no paths/DNs/UUIDs).
- **`XROOTD_RETURN_OK/REDIR` are for *no-body* responses only.** They call
  `xrootd_send_ok(ctx, c, NULL, 0)` / `xrootd_send_redirect`; handlers returning a body
  (read data, query results, pgwrite status) must keep the log/metric/send lines explicit
  (`tunables.h:218`). `XROOTD_BAIL_ERR` is the variant for helper functions that report
  failure via an out-parameter and `return 0`.
- **Size caps are security backstops, not just sizing.** `XROOTD_MAX_WALK_DEPTH` (32)
  rejects deep symlink chains *before* expensive `realpath`/`lstat`;
  `XROOTD_MAX_CONN_POOL_BYTES` (64 MB) closes a connection with `kXR_NoMemory` rather than
  let a dirlist flood exhaust the worker heap; `XROOTD_MAX_AUTH_ATTEMPTS` (10) caps
  GSI/token/SSS CPU-amplification. `XROOTD_READ_WINDOW`/`_CONN_XFER_HEAP_MAX` bound the
  resident heap a single read / a single connection may hold (large TLS reads stream in
  windows rather than buffering whole). Treat these as invariants, not knobs to bump
  casually.
- **`destroyed` guard prevents use-after-free.** `xrootd_on_disconnect()` sets
  `ctx->destroyed = 1`; any thread-pool callback that fires after close must check it
  before writing into the (freed) ctx (`context.h`).
- **Several fields are `void*` on purpose** (`wmirror`, `rl_bw_rule`, `rl_conc_rule`) to
  keep `mirror`/`ratelimit` headers out of this very widely-included header — cast at the
  use site, don't add the include here. Likewise `state.h` uses opaque forward decls for
  the upstream/proxy/CMS contexts.
- **Legacy/anchor naming.** Phase numbers in the comments (Phase 29/31/32/33) are
  historical markers; the `wbuf`/`wchain`/`read_fast_*` send state now lives *per slot* in
  `xrootd_resp_slot_t`, not as connection singletons. Read the struct, not the phase label.

## Entry points / extending

- **Add a config directive →** add the field to `ngx_stream_xrootd_srv_conf_t`
  (`config.h`, init to `NGX_CONF_UNSET*`), annotate it with its `[directive]`, declare the
  `ngx_command_t` and merge it in `../config/`. No `./configure` re-run unless it's a new
  top-level block. (See the build-governance note in `CLAUDE.md`.)
- **Add a tunable / metric macro →** define it in `tunables.h` with a WHAT/WHY comment;
  if it's a per-op metric, also wire the enum/field per the `../metrics/README.md` recipe.
- **Add per-connection state →** add the field to `xrootd_ctx_t` (`context.h`); it is
  zero-initialised by the `ngx_pcalloc` in `../connection/handler.c`, so document the
  meaning of zero. Prefer a `void*` + cast over adding a heavy include to this header.
- **Add per-handle state →** add to `xrootd_file_t` (`file.h`) and ensure
  `xrootd_free_fhandle()` (`../connection/fd_table.c`) resets/frees it on close.
- **Add an auth method →** add an `XROOTD_AUTHN_*` bit (`identity.h`), teach
  `xrootd_identity_method_name()` (`identity.c`) about it, and have the verifier call the
  appropriate `xrootd_identity_set_*` builder. If it's a wire mode, also add an
  `XROOTD_AUTH_*` constant in `tunables.h`. **Remember:** new `.c` files must be
  registered in the top-level `config` (`NGX_ADDON_SRCS`) — that is where `identity.c`
  lives (`config:268`), not `src/core/config/config.h`.

## See also

- `../README.md` — master source-tree index
- `../connection/README.md` — allocates and drives `xrootd_ctx_t`; owns `xrootd_free_fhandle()`
- `../config/README.md` — creates and merges `ngx_stream_xrootd_srv_conf_t`
- `../read/README.md`, `../write/README.md` — primary consumers of `files[]`, scratch buffers, AIO tasks
- `../aio/README.md` — thread-pool tasks cached on the ctx
- `../token/README.md`, `../gsi/README.md` — produce `xrootd_identity_t`
- `../path/README.md` — consumes the `config.h` ACL/VO/group rule structs
- `../metrics/README.md` — the SHM struct `ctx->metrics` and the `op_ok`/`op_err` arrays
- `src/core/ngx_xrootd_module.h` — the umbrella header that includes these in dependency order
