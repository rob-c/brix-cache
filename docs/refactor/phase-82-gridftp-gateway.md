# Phase-82 — GridFTP gateway protocol (gsiftp:// front-end over the VFS)

**Goal:** add a GridFTP server front-end as a fourth protocol under
`src/protocols/gridftp/`, following the `root://` stream-module pattern:
line-based FTP control channel, GSSAPI/GSI control-channel auth (RFC 2228
`AUTH`/`ADAT`), dynamic passive-mode data channels, MODE E parallel streams,
all storage through the existing `brix_vfs_*` seam (INVARIANT 12).
Target interop clients: `globus-url-copy`, gfal2 (gfal-copy/gfal-ls),
UberFTP, FTS gsiftp lanes.

**Provenance:** three architecture surveys anchored **2026-07-16 against
`bff6bf92`**. Every `file:line` and signature below was read from the tree
by those surveys (exceptions are flagged `UNVERIFIED:`). Re-verify anchors
at the start of each phase and mark drift `DRIFT:` inline (phase-80
convention).

**Strategic gate (decide before P82.3):** GridFTP is legacy — Globus
Toolkit is EOL and WLCG TPC moved to HTTP. The ARC-CE httpg front proxy
(`docs/05-operations/arc-ce-httpg-front-proxy.md`) already covers most
"gridftp-era" middleware via davs://. P82.1–P82.2 are cheap and de-risk the
design; **do not start P82.3 (GSSAPI) without a named client population
that can only speak gsiftp.** Otherwise park after P82.2 as a dormant
plain-FTP lab export.

**Size calibration:** s3 ≈ 16.5k LOC, root ≈ 36k. Full plan ≈ 15–25k LOC
across P82.1–P82.5.

---

## 0. Scope and non-goals

**In scope:** RFC 959 core verbs; RFC 2228 (`AUTH GSSAPI`, `ADAT`, `PBSZ`,
`PROT`, `MIC`/`ENC`/`CONF`); RFC 3659 (`SIZE MDTM MLST MLSD REST`);
GridFTP v1 (GFD.020/.021): `SPAS SPOR ESTO ERET SBUF DCAU CKSM`,
`OPTS RETR`, MODE E + restart/perf markers; two-control-channel server-side
TPC. IPv6 via `EPRT`/`EPSV`.

**Non-goals:** striped multi-node GridFTP; GridFTP-v2 `GET`/`PUT`/X-mode;
SRM; Kerberos mech (GSI mech only); `USER`/`PASS` as a production lane
(test-only directive, default off — §7); `LPRT`/`LPSV`.

---

## 1. Architecture (verified anchors)

### 1.1 Module layer — nginx STREAM module, sibling of root://

| Piece | Mirror of (anchor) | New symbol |
|---|---|---|
| module descriptor | `src/protocols/root/stream/module_definition.c:14-29` — `ngx_stream_module_t` ctx `{NULL, postconf, NULL, NULL, create_srv, merge_srv}`, `NGX_STREAM_MODULE` | `ngx_stream_brix_ftp_module` |
| enable setter | `ngx_stream_brix_enable`, `src/core/config/server_conf.c:324` (decl `src/core/ngx_brix_module.h:127`) — flag slot, then `ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module)` → `cscf->handler = …` | `ngx_stream_brix_ftp_enable` → installs `ngx_stream_brix_ftp_handler` |
| create/merge conf | `ngx_stream_brix_create_srv_conf` `server_conf.c:259` / `_merge_srv_conf` `:299` (`NGX_CONF_UNSET*` idiom) | `ngx_stream_brix_ftp_create_srv_conf` / `_merge_srv_conf` |
| directive table | `ngx_stream_brix_commands[]` `src/protocols/root/stream/module.c:153`; example row `module.c:164-171` | `ngx_stream_brix_ftp_commands[]` |

**Srv conf:** own struct `ngx_stream_brix_ftp_srv_conf_t`, first member the
shared preamble `ngx_http_brix_shared_conf_t common;`
(`src/core/config/shared_conf.h:46-218` — fields used here:
`common.enable` :47, `common.root` :48, `common.root_canon[PATH_MAX]` :49,
`common.allow_write` :181, `common.read_only` :182, `common.thread_pool`,
credential fields `common.storage_credential*` :59-94,
`common.backend_delegation` :95). Gsiftp-specific tail in §2.1. ABI note:
struct edits ⇒ clean rebuild (struct_field_abi_clean_rebuild).

**Proto enum:** `brix_proto_t` is X-macro-generated from `BRIX_PROTO_LIST`
in `src/core/types/proto_list.h:58-62` (rows ROOT/"stream", WEBDAV, S3,
CVMFS). Add one row: `X(GRIDFTP, "gridftp")` → `BRIX_PROTO_GRIDFTP` flows
into metrics automatically (`unified.h:32-37`).

### 1.2 Connection lifecycle

Entry `ngx_stream_brix_ftp_handler(ngx_stream_session_t *s)` mirrors
`ngx_stream_brix_handler` (`src/protocols/root/connection/handler.c:475`):

1. `ftp_conn_init_ctx(s, c)` — mirror `conn_init_ctx` (`handler.c:115-143`):
   `ctx = ngx_pcalloc(c->pool, sizeof(brix_ftp_ctx_t))`; `ctx->session = s`;
   `ctx->identity = brix_identity_alloc(c->pool)`
   (`src/core/types/identity.c:176`, decl `identity.h:70`);
   `ngx_pool_cleanup_add(c->pool, 0)` → `brix_ftp_conn_cleanup`;
   `ngx_stream_set_ctx(s, ctx, ngx_stream_brix_ftp_module)`.
2. `ftp_conn_apply_srv_conf(ctx, conf)` — copy deadline ms, caps.
3. Emit `220 brix GridFTP server ready` via `brix_ftp_send_reply`, state →
   `FTP_ST_PREAUTH`.
4. Pump install — mirror `conn_pump` (`handler.c:456-461`):
   `c->read->handler = brix_ftp_recv; c->write->handler = brix_ftp_send;`
   then `brix_ftp_recv(c->read)`. Handler signatures mirror
   `src/protocols/root/connection/handler.h:10-11`
   (`void ngx_stream_brix_recv(ngx_event_t *rev)` /
   `…send(ngx_event_t *wev)`).

Read deadlines mirror `brix_arm_read_deadline`
(`src/protocols/root/connection/deadline.h:49`, disarm `:77`): pre-auth uses
a handshake budget (analog of `handshake_timeout_ms`, `deadline.h:64`),
post-auth a partial-line budget (analog of `read_timeout_ms`,
`deadline.h:62`). Idle keepalive at a fresh-line boundary is NOT armed
(root's deliberate choice — keep it).

### 1.3 Identity

Unlike root (which fills the legacy `ctx->login.*` — see
`gsi_cert_capture_dn`, `src/auth/gsi/auth.c:437-450`), gridftp fills
`brix_identity_t` directly (`src/core/types/identity.h:27-63`), like the
HTTP lanes, because `brix_vfs_ctx_init` consumes it. After chain verify:
set `identity->dn` (pool-copied from `brix_gsi_verify_result_t.dn_buf`,
`gsi_verify.h:26-28`), `identity->auth_method = BRIX_AUTHN_GSI`
(`identity.h:17-25`), `identity->is_authenticated = 1`; VOMS best-effort
via `brix_extract_voms_info` (root precedent `auth.c:462-488`, gated on
vomsdir conf).

### 1.4 Path resolution (INVARIANT 4)

There is no bare `resolve_path()`; every protocol owns a wrapper over the
confined core resolver. Gridftp adds
`brix_ftp_resolve_path(brix_ftp_ctx_t *ctx, const char *root_canon,
ngx_str_t *arg, char *out, size_t outsz)` in `ftp_path.c`, modeled on
`ngx_http_brix_webdav_resolve_path`
(`src/protocols/webdav/webdav_path.h:20`, call-site pattern
`src/protocols/webdav/get.c:509`) over `brix_http_resolve_path`
(`src/core/compat/path.h:62`, def `src/core/compat/path.c:22`); root's
stream-side analog is `src/protocols/root/path/op_path.c`. Semantics:
resolve `arg` relative to `ctx->cwd` (logical path —
beneath_api_logical_path), reject escapes, output physical confined path.
**Every** verb that touches the namespace calls it before any VFS ctx init.

### 1.5 Storage plane (no new backend code)

VFS ctx build per op — mirror `mv_bind_vfs`
(`src/protocols/root/write/mv.c:148-159`):

```c
brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_GRIDFTP,
                  conf->common.root_canon, NULL,
                  conf->common.allow_write, is_tls,
                  ctx->identity, resolved);              /* vfs.h:136 */
brix_vfs_ctx_bind_backend_cred(vctx, &cred_dir, deny);   /* vfs.h:145 */
brix_vfs_deleg_bind(c->pool, vctx, mode, NULL, &proxy_pem); /* vfs.h:190 */
```

`brix_vfs_deleg_bind` full signature (`vfs.h:190`, def `vfs_deleg.c:156`):
`ngx_int_t brix_vfs_deleg_bind(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
enum brix_cred_mode mode, const ngx_str_t *bearer, const ngx_str_t
*proxy_pem);` — no-op returning NGX_OK when `mode==BRIX_CRED_SELECT`.
It populates a `brix_deleg_live_t` (`src/fs/vfs/vfs_internal.h:58-72`:
`have_proxy_pem, proxy_pem, bearer, mode, tx, tx_audience`).

`brix_vfs_file_t` is opaque (`vfs.h:47`; private def
`vfs_internal.h:74`). Open flags (`vfs.h:38-45`, verbatim):

```c
#define BRIX_VFS_O_READ      0x01   #define BRIX_VFS_O_TRUNC     0x10
#define BRIX_VFS_O_WRITE     0x02   #define BRIX_VFS_O_APPEND    0x20
#define BRIX_VFS_O_CREATE    0x04   #define BRIX_VFS_O_MKDIRPATH 0x40
#define BRIX_VFS_O_EXCL      0x08   #define BRIX_VFS_O_NOCACHE   0x80
```

Op → VFS mapping (anchors):

| FTP op | Call chain |
|---|---|
| RETR open | `brix_vfs_open(vctx, BRIX_VFS_O_READ, &err)` vfs.h:218; size/mtime via `brix_vfs_file_size`/`_mtime` (accessors vfs.h:227-294) |
| RETR cleartext+posix | `brix_vfs_file_can_sendfile` → `brix_vfs_file_sendfile_fd` (vfs.h:269) — **only when `sec.prot==FTP_PROT_C`** (INVARIANT 2) |
| RETR PROT P / non-sendfile | `brix_vfs_job_read_init(job, fd, off, len, dst, cap, 0)` vfs_io_core.h:115 + `brix_vfs_io_execute` :247 on thread pool (§1.7) — there is NO handle-level `brix_vfs_read` |
| STOR (random-write) | `brix_vfs_open(vctx, BRIX_VFS_O_WRITE\|BRIX_VFS_O_CREATE[\|_TRUNC], …)`; per-block write via **`brix_vfs_file_pwrite(fh, …)`** (P82.6 — driver-routed, NOT the fd-keyed `brix_vfs_pwrite_full`, which wraps the fd in the POSIX driver and so bypasses an object backend's block layout + catalog-size bookkeeping); read-back via `brix_vfs_file_pread(fh, …)` |
| STOR (object store) | staged seam `brix_vfs_staged_open/write/commit/abort` vfs_ops.h:167-188 (phase-80 route) |
| APPE | open with `BRIX_VFS_O_WRITE\|_APPEND` |
| SIZE/MDTM/MLST | `brix_vfs_stat(vctx, &st)` vfs.h:299 (`brix_vfs_stat_t` vfs.h:71-83) |
| LIST/NLST/MLSD | `brix_vfs_opendir` :333 / `brix_vfs_readdir(dh, &name, &st)` :343 / `brix_vfs_closedir` :367 |
| DELE | `brix_vfs_unlink_path` vfs_ops.h:98 |
| MKD | `brix_vfs_mkdir(vctx, 0755, 0)` ~vfs.h:428 |
| RMD | `brix_vfs_rmdir(vctx, 0)` vfs.h:382 |
| RNFR/RNTO | `brix_vfs_rename` ~vfs.h:394 (`_rename_path` :398 has `overwrite`, `was_dir_out`) |
| REST 0 + STOR | `brix_vfs_truncate(fh, 0)` vfs.h:432 |
| CKSM | `brix_checksum_parse(name, len, &alg, norm, sizeof norm)` checksum.h:38; digest is **driver-routed** (P82.7): `brix_vfs_file_sd_obj(fh, &obj)` then `brix_cksm_digest_obj` / `brix_cksm_u32_obj` walk every byte through `obj->driver` (multi-block aware — NOT the fd-keyed `brix_cksm_*_fd`, which see block 0 only on an object backend); hex at edge `brix_checksum_hex_encode` (INVARIANT 9) |

### 1.6 Error/logging triplet (coding-standards §4 — always together, in order)

1. `brix_ftp_log_access(...)` — gridftp clone of `brix_log_access`
   (`src/fs/path/path.h:305`: `void brix_log_access(brix_ctx_t*,
   ngx_connection_t*, const char *verb, const char *path, const char
   *detail, ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg,
   size_t bytes)`) — same field order, `brix_ftp_ctx_t` first arg.
2. `BRIX_OP_ERR(ctx, op)` — reuse verbatim
   (`src/core/types/tunables.h:266-269`, atomic op_err bump; `BRIX_OP_OK`
   :261) — requires `ctx->metrics` pointer on `brix_ftp_ctx_t`, same as
   root.
3. `brix_ftp_send_reply(ctx, c, code, fmt, ...)` — the FTP analog of
   `brix_send_error` (`src/protocols/root/response/response.h:16`).

Reply code from errno via `brix_ftp_errno_to_reply` (§4.2).

### 1.7 Thread-pool offload (blocking I/O off the event loop)

Idiom (verified): `ngx_thread_task_alloc(tp, sizeof(job_wrapper_t))` →
`brix_task_bind(task, thread_fn, done_fn)`
(`src/core/aio/aio.h:34-42`: sets `task->handler`, `task->event.handler`,
`task->event.data = task`) → `ngx_thread_task_post(pool, task)`. Complete
reference example: `src/fs/xfer/stage_engine_scheduler.c:233,250,252`,
completion cb `stage_flush_done(ngx_event_t *ev)` `:200`
(`task = ev->data; t = task->ctx;`). Pool handle:
`conf->common.thread_pool` populated by
`ngx_thread_pool_get(cf->cycle, name)` (`src/core/aio/config.c:47`);
runtime fallback `ngx_thread_pool_get((ngx_cycle_t*)ngx_cycle, &name)`
name `"default"` (`stage_engine_scheduler.c:261-268`). Rules
(coding-standards §5/§12): never `ngx_alloc` inside `thread_fn`; check
`ctx->destroyed` first thing in every `done_fn`.

### 1.8 Data channels

- **Active (`PORT`/`EPRT`/`SPOR`) = SSRF primitive.** Every connect passes
  `brix_net_target_check_addr(sa, &policy, …)`
  (`src/core/compat/net_target.h:82`). Policy struct (verbatim,
  `net_target.h:49-56`):

  ```c
  typedef struct {
      ngx_flag_t require_https;      ngx_flag_t allow_root_scheme;
      ngx_flag_t allow_local;        ngx_flag_t allow_private;
      uint16_t   default_https_port; uint16_t   default_root_port;
  } brix_net_target_policy_t;
  ```

  Build per-candidate on the stack exactly like
  `src/tpc/outbound/connect.c:49-56` (`ngx_memzero`, set only
  `allow_local`/`allow_private` from conf, check, connect). Additional
  gridftp rule: peer IP must equal control-channel peer IP unless
  `DCAU A` authenticated a TPC partner. Deny ⇒ reply `500` + access log.
- **fd adoption** mirrors `pc_open_socket`
  (`src/net/proxy/connect_upstream.c:419-463`): `ngx_get_connection(fd,
  log)` → `ngx_create_pool` → install recv/send vtable + handlers;
  nonblocking connect with `EINPROGRESS` + write-event + timer per
  `connect_upstream.c:521+`.
- **Passive (`PASV`/`EPSV`/`SPAS`) = NET-NEW.** No event-loop listener
  utility exists (`src/auth/impersonate/lifecycle_broker.c:59` is a
  blocking AF_UNIX socket in a forked broker — not a model). Design in
  §2.6 `pasv_listener.c`.
- **Pump** follows the four-handler cross-wired window-buffer model of
  `src/protocols/root/handoff/handoff.c:229-310` (per-direction fixed
  buffers, no unbounded queues). If splice is used for cleartext
  file→socket, port the WSL2 writable-EAGAIN under-drain fix
  (`src/net/proxy/events_splice.c:224-231, 374-402`; postmortem
  `docs/09-developer-guide/postmortem-proxy-splice-underdrain-stall.md`).

### 1.9 GSSAPI strategy (P82.3) — hand-rolled GSI mech over mem-BIO TLS

Verified: zero `gss_*` and zero `SSL_set_bio` mem-BIO TLS in the tree. The
xrdsecgsi driver (`src/auth/gsi/auth.c:596`, step read at `:631`) is
xrootd-framing-specific (XrdSutBuffer) and implements a different protocol
(DH/RSA) — NOT the ADAT engine. Reusable: `brix_gsi_verify_chain`
(`src/auth/crypto/gsi_verify.h:63`, result `dn_buf[1024]` :26-28,
`client_purpose=1`), proxy-request kernels (`src/auth/gsi/proxy_req*.c`),
delegation flow (`delegation.h:23` → `ctx->gsi.deleg_proxy_pem`), OpenSSL
cleanup guards (`src/auth/crypto/scoped.h`), and the ngx-free kernel
layering of `gsi_core.h`.

New mech `src/auth/gssapi/gsi_mech.c`: server-side
`SSL_set_bio(ssl, rbio_mem, wbio_mem)` accept loop — decoded ADAT token →
read BIO → `SSL_accept` → drain write BIO → `335 ADAT=` out; on completion
verify peer chain, run delegation sub-exchange ('D' flag → proxy CSR out →
signed proxy in, via `proxy_req*.c`), then `wrap = SSL_write→wbio` /
`unwrap = rbio→SSL_read`. Token iface (§2.8) is mech-agnostic so the
timeboxed fallback (link `libglobus_gssapi_gsi` behind an adapter; assess
hardening_cflags_global_constraint first) swaps underneath.

### 1.10 TPC rendezvous (P82.4) — new SHM zone

Xrootd's rendezvous (`tpc.key` CGI; `src/tpc/engine/key_registry.h:32-66`
fixed-slot+TTL register/validate/consume) is protocol-specific but the
right template. Clone as `brix_ftp_data_token` zone using the slab-safe
table API (`src/core/compat/shm_slots.h`):

```c
void  *brix_shm_table_alloc(ngx_shm_zone_t *zn, void *data,
                            size_t table_bytes, ngx_shmtx_t *mtx,
                            ngx_flag_t *fresh);            /* :76 */
size_t brix_shm_zone_size(size_t table_bytes);             /* :79 */
void   brix_shm_zone_warn_on_resize(ngx_conf_t*, ngx_shm_zone_t*,
                                    const char *directive); /* :90 */
```

plus inline `brix_shm_slot_expired` :24 / `brix_shm_remember_free_slot`
:40. Usage model: `src/net/manager/registry.c:65` (init-zone fn, sizing
`sizeof(table) + nslots*sizeof(entry)`, init non-lock fields only when
`fresh`). INVARIANT 10: never bare `ngx_shmtx_create`; spin+yield only.
Monitoring parity: register transfers in the shared transfer registry
(`src/tpc/common/registry.h:47-104` — `_configure/_add/_update/_remove/
_find/_snapshot/_reap_stale/_request_cancel`).

---

## 2. Source tree — per-file function rosters

Naming (coding-standards §2): types `brix_ftp_*_t`; verb handlers
`brix_ftp_handle_*`; replies `brix_ftp_send_*`; dispatch
`brix_ftp_dispatch_*`; nginx event callbacks `brix_ftp_on_*` or
`ngx_stream_brix_ftp_*` (module-visible). NO `goto`; ≤~500 lines/file;
`#pragma once`; WHAT/WHY/HOW doc block on every function; README.md per
dir. Static helpers get file-local `ftp_` prefix (root precedent:
`conn_*`, `gsi_*` statics).

### 2.1 `stream/` — module registration (P82.1)

**`module_definition.c`** (~60 LOC)
- `ngx_stream_module_t ngx_stream_brix_ftp_module_ctx` — `{NULL,
  ngx_stream_brix_ftp_postconfiguration, NULL, NULL,
  ngx_stream_brix_ftp_create_srv_conf, ngx_stream_brix_ftp_merge_srv_conf}`.
- `ngx_module_t ngx_stream_brix_ftp_module`.

**`module.c`** (~300 LOC)
- `ngx_command_t ngx_stream_brix_ftp_commands[]` — full table §7.
- `static char *ftp_conf_set_pasv_range(ngx_conf_t*, ngx_command_t*,
  void*)` — parses `lo-hi`, validates `1023 < lo < hi ≤ 65535`.
- `static char *ftp_conf_set_auth_mode(ngx_conf_t*, …)` — enum
  `gssapi|cleartext-test` (pattern: `brix_ssi_executor_enum`,
  `src/protocols/root/stream/module.c:38` +
  `directives_tpc.inc:69`).
- `ngx_int_t ngx_stream_brix_ftp_postconfiguration(ngx_conf_t *cf)` —
  SHM zone hookup (P82.4), metrics registration.

**`server_conf.c`** (~250 LOC)
- `typedef struct { ngx_http_brix_shared_conf_t common; /* §1.1 */
  ngx_uint_t pasv_port_lo, pasv_port_hi; ngx_uint_t pasv_max;
  ngx_str_t pasv_addr; ngx_uint_t max_parallel; ngx_msec_t
  marker_interval_ms; ngx_msec_t idle_timeout_ms; ngx_msec_t
  data_idle_timeout_ms; ngx_uint_t auth_mode; ngx_str_t cred_dir;
  ngx_ssl_t *tls_ctx; X509_STORE *ca_store; ngx_flag_t cleartext_test; }
  ngx_stream_brix_ftp_srv_conf_t;`
- `void *ngx_stream_brix_ftp_create_srv_conf(ngx_conf_t *cf)` —
  `NGX_CONF_UNSET*` defaults (mirror `server_conf.c:259`).
- `char *ngx_stream_brix_ftp_merge_srv_conf(ngx_conf_t*, void*, void*)` —
  defaults per §7; canonicalize `common.root` → `common.root_canon`.
- `char *ngx_stream_brix_ftp_enable(ngx_conf_t*, ngx_command_t*, void*)` —
  §1.1 (may live beside `ngx_stream_brix_enable` in
  `src/core/config/server_conf.c` if conf layering requires — decide at
  wiring time).

### 2.2 `ftp_ctx.h` — core types (P82.1, ~200 LOC)

```c
typedef enum {                       /* §5 transition table */
    FTP_ST_GREETING = 0, FTP_ST_PREAUTH, FTP_ST_ADAT,
    FTP_ST_AUTHED, FTP_ST_XFER, FTP_ST_RENAME_WAIT, FTP_ST_CLOSING,
} brix_ftp_state_e;

typedef struct {                     /* line accumulator */
    u_char      buf[BRIX_FTP_LINE_MAX];   /* 4096 */
    size_t      used;
    unsigned    overlong:1;          /* discarding until CRLF */
} brix_ftp_line_t;

typedef enum { FTP_PROT_C = 0, FTP_PROT_P } brix_ftp_prot_e;
typedef enum { FTP_DCAU_N = 0, FTP_DCAU_S, FTP_DCAU_A } brix_ftp_dcau_e;

typedef struct {                     /* security state */
    brix_gssapi_srv_t  *gss;         /* §2.8; NULL pre-P82.3 */
    brix_ftp_prot_e     prot;        /* PROT C|P, default C */
    brix_ftp_dcau_e     dcau;        /* default S once authed */
    size_t              pbsz;        /* 0 = streaming (TLS) */
    unsigned            ctrl_wrapped:1;  /* post-235: MIC/ENC framing */
} brix_ftp_sec_t;

typedef struct {                     /* negotiated transfer params */
    unsigned    type_image:1;        /* TYPE I (A accepted, ignored) */
    unsigned    mode_e:1;            /* MODE S|E */
    off_t       rest_offset;         /* REST n (stream mode) */
    ngx_uint_t  parallelism;         /* OPTS RETR, clamp max_parallel */
    size_t      sbuf;                /* SBUF, 0 = kernel default */
} brix_ftp_xfer_params_t;

typedef struct {
    ngx_stream_session_t          *session;
    ngx_stream_brix_ftp_srv_conf_t *conf;
    brix_metrics_shm_t            *metrics;   /* for BRIX_OP_ERR/OK */
    brix_ftp_state_e               state;
    brix_ftp_line_t                recv;
    brix_identity_t               *identity;  /* identity.h:27-63 */
    brix_ftp_sec_t                 sec;
    brix_ftp_xfer_params_t         xp;
    ngx_str_t                      cwd;       /* logical, starts "/" */
    ngx_str_t                      rnfr_path; /* resolved RNFR source */
    ngx_str_t                      deleg_proxy_pem; /* captured cred */
    brix_ftp_data_t               *data;      /* §2.6, NULL when idle */
    brix_ftp_deadline_t            deadline;  /* handshake_ms/read_ms */
    unsigned                       logged_in:1;
    unsigned                       auth_done:1;  /* SECURITY: gate on
                                       this, never logged_in — root
                                       precedent handshake/dispatch.c:60-70 */
    unsigned                       destroyed:1;  /* AIO done-cb guard */
} brix_ftp_ctx_t;
```

### 2.3 `connection/` — pump + replies (P82.1)

**`handler.c`** (~350 LOC)
- `void ngx_stream_brix_ftp_handler(ngx_stream_session_t *s)` — §1.2.
- `static brix_ftp_ctx_t *ftp_conn_init_ctx(ngx_stream_session_t*,
  ngx_connection_t*)`.
- `static void ftp_conn_apply_srv_conf(brix_ftp_ctx_t*,
  ngx_stream_brix_ftp_srv_conf_t*)`.
- `static void brix_ftp_conn_cleanup(void *data)` — pool-cleanup: abort
  data channels, free GSS ctx, `destroyed = 1`.
- `void brix_ftp_finalize(brix_ftp_ctx_t*, ngx_connection_t*, ngx_uint_t
  reply /*421|221|0*/)` — single teardown path.

**`recv_line.c`** (~300 LOC) — clone of the
`brix_recv_read_frame`/`brix_recv_process_frame` split
(`recv_frame.c:187-239`, `recv_process.c:422`), with the
CONTINUE/NEXT/RETURN/BREAK step-code loop:
- `void brix_ftp_recv(ngx_event_t *rev)` — driver; one `c->recv()` per
  pass; `NGX_AGAIN` → `ngx_handle_read_event` + arm deadline + return.
- `static brix_ftp_step_e ftp_recv_accumulate(brix_ftp_ctx_t*,
  ngx_connection_t*)` — append into `recv.buf`; caps enforced BEFORE any
  processing (mirror `recv_process.c:261-268`): pre-auth
  `BRIX_FTP_LINE_MAX_PREAUTH` 512, post-auth 4096; overflow → 421 +
  BREAK; strip telnet IAC (0xFF pairs); accept bare LF.
- `static brix_ftp_step_e ftp_recv_dispatch_line(brix_ftp_ctx_t*,
  ngx_connection_t*)` — split verb/arg (verb uppercased in place); if
  `sec.ctrl_wrapped`: `MIC|ENC|CONF <b64>` → `brix_gssapi_unwrap` →
  recurse on inner line; any other verb (except QUIT) ⇒ 533.
- `static void ftp_arm_read_deadline(ngx_connection_t*, brix_ftp_ctx_t*)`
  — mirror `deadline.h:49-77` (pre-auth handshake_ms, else read_ms).

**`send_reply.c`** (~300 LOC)
- `ngx_int_t brix_ftp_send_reply(brix_ftp_ctx_t*, ngx_connection_t*,
  ngx_uint_t code, const char *fmt, ...)` — formats
  `"%03ui %s\r\n"`; when `sec.ctrl_wrapped`: format → `brix_gssapi_wrap`
  → base64 → `"631 %s\r\n"` (632 when ENC-level). Short-write queueing via
  a small out-chain drained by `brix_ftp_send`.
- `ngx_int_t brix_ftp_send_multiline(… code, ngx_array_t *lines)` —
  `"211-…\r\n … 211 End\r\n"` framing (FEAT, MLST, SPAS 229-).
- `void brix_ftp_send(ngx_event_t *wev)` — write-event handler; drains
  out-chain then re-enters `brix_ftp_recv` (mirror `send.c:22` role).
- `ngx_int_t brix_ftp_send_err_vfs(brix_ftp_ctx_t*, ngx_connection_t*,
  const char *verb, const char *path, int vfs_errno)` — the triplet
  combiner: `brix_ftp_log_access` → `BRIX_OP_ERR` →
  `brix_ftp_send_reply(brix_ftp_errno_to_reply(vfs_errno), …)`
  (analog of `BRIX_RETURN_ERR`, tunables.h:277-303).

### 2.4 `commands/` — dispatch + verb handlers

**`dispatch.c`** (~250 LOC, P82.1)

```c
typedef ngx_int_t (*brix_ftp_cmd_pt)(brix_ftp_ctx_t *ctx,
    ngx_connection_t *c, ngx_str_t *arg);
typedef struct {
    const char       *verb;       /* uppercase */
    brix_ftp_state_e  min_state;  /* FTP_ST_PREAUTH | FTP_ST_AUTHED */
    unsigned          needs_write:1;   /* through require_write */
    unsigned          needs_arg:1;     /* 501 if missing */
    unsigned          feat_line:1;     /* advertised in FEAT (R9) */
    brix_ftp_cmd_pt   handler;
} brix_ftp_cmd_t;
extern const brix_ftp_cmd_t brix_ftp_cmd_table[];
```

- `ngx_int_t brix_ftp_dispatch(brix_ftp_ctx_t*, ngx_connection_t*,
  ngx_str_t *verb, ngx_str_t *arg)` — linear/bsearch lookup; unknown ⇒
  500; state gate ⇒ 530 (pre-auth) / 503 (sequencing);
  `needs_write && !conf->common.allow_write` ⇒ 550 (INVARIANT 3 — check
  precedes ANY scope/mapping logic, clone of `brix_dispatch_require_write`
  `src/protocols/root/session/policy.c:65`).
- `static ngx_int_t ftp_require_auth(brix_ftp_ctx_t*)` /
  `ftp_require_write(…)` — clones of `policy.c:43-65` semantics.
- `ngx_int_t brix_ftp_handle_feat(…)` — generated FROM the table
  (`feat_line` rows only) — FEAT can never overpromise (risk R9).

**`cmd_session.c`** (~400 LOC, P82.1): `brix_ftp_handle_syst` (215),
`_type` (TYPE I→200, TYPE A→200 accepted/ignored, else 504), `_mode`
(S; E once P82.4), `_stru` (F only), `_noop`, `_quit` (221 + finalize),
`_stat` (no-arg: 211 session facts; with-arg: 213 stat; during XFER: 213-
markers, P82.4), `_abor` (426 on data reply + teardown + 226), `_allo`
(202), `_rest` (350; stream form `n`; `0-n` MODE E form P82.4), `_help`.

**`cmd_namespace.c`** (~500 LOC, P82.1): `brix_ftp_handle_pwd` (257
quoted logical cwd), `_cwd`/`_cdup` (resolve → `brix_vfs_stat` must be
dir → update logical `ctx->cwd`), `_mkd` (§1.5), `_rmd`, `_dele`,
`_rnfr` (resolve + stat-exists → save `rnfr_path`, 350, state
RENAME_WAIT), `_rnto` (503 unless RENAME_WAIT; `brix_vfs_rename`; state
back to AUTHED), `_size` (213, regular files only — 550 on dir), `_mdtm`
(213 `YYYYMMDDHHMMSS` UTC from `st.mtime`).

**`cmd_list.c`** (~500 LOC, P82.1): `brix_ftp_handle_list` / `_nlst` /
`_mlsd` (open data channel → readdir loop → format → 226), `_mlst`
(control-channel 250- single entry). Shared:
- `static ngx_int_t ftp_list_run(brix_ftp_ctx_t*, ngx_connection_t*,
  ngx_str_t *arg, brix_ftp_list_fmt_e fmt)` — one engine, three
  formatters.
- `static size_t ftp_fmt_mlsx(char *out, size_t cap, const ngx_str_t
  *name, const brix_vfs_stat_t *st)` — facts
  `type=;size=;modify=;perm=;unique=;` from `brix_vfs_stat_t`
  (vfs.h:71-83); `perm` derived from `allow_write` + mode bits
  (`el` for dirs, `rwadf` subset for files).
- `static size_t ftp_fmt_ls_long(...)` — `ls -l`-style for LIST (fixed
  locale-free format; clients only eyeball it).
Directory listing itself goes to the thread pool when the backend driver
is remote (job model `brix_vfs_job_opendir_init`, vfs_io_core.h:226).

**`cmd_xfer.c`** (~600 LOC, P82.1): `brix_ftp_handle_retr`, `_stor`,
`_appe`. Common skeleton:
1. `ftp_require_write` for STOR/APPE.
2. `brix_ftp_resolve_path` (§1.4).
3. VFS ctx + open per §1.5 table (STOR chooses staged seam when driver
   lacks CAP_RANDOM_WRITE — same probe the stream plane uses).
4. `brix_ftp_data_ensure(ctx)` — data channel(s) up (connect for
   PORT-mode, await-accept for PASV-mode); 425 on failure.
5. `150 Opening BINARY mode data connection` reply.
6. Hand off to pump (§2.6): `brix_ftp_pump_start(ctx, c, fh, dir)`;
   state → FTP_ST_XFER.
7. Pump completion cb: `226 Transfer complete` (or 426/451), metrics
   `brix_metric_op_done(BRIX_PROTO_GRIDFTP, BRIX_METRIC_OP_READ|WRITE, …)`
   (unified.h:125; op enum :39-51) + `brix_metric_backend_bytes`
   (:135), `brix_ftp_log_access` with byte count.

**`cmd_port.c`** (~400 LOC, P82.1-2): `brix_ftp_handle_port` / `_eprt`
(parse h1,h2,…/`|2|::1|port|`; SSRF policy §1.8; store target),
`_pasv` / `_epsv` (P82.2: `brix_ftp_pasv_open` → 227
`(h1,h2,h3,h4,p1,p2)` from `conf->pasv_addr`, / 229 `(|||port|)`),
`_spor` / `_spas` (P82.4: N targets / 229- multiline).

**`cmd_sec.c`** (~500 LOC, P82.3): `brix_ftp_handle_auth` (arg
`GSSAPI` ⇒ 334, else 504; allocate `sec.gss` via
`brix_gssapi_srv_create` §2.8; state ADAT), `_adat` (b64-decode →
`brix_gssapi_srv_step` → 335 `ADAT=…` loop | 235 done | 535 fail; on
done: §1.3 identity fill + `sec.ctrl_wrapped = 1`, `auth_done = 1`,
230 after wrapped USER exchange — globus sends `USER :globus-mapped:`),
`_pbsz` (200, echo 0), `_prot` (`C`/`P` ⇒ 200, else 536), `_dcau`,
`_mic`/`_enc`/`_conf` handled in `recv_line.c` (§2.3).

**`cmd_gridftp.c`** (~450 LOC, P82.4): `brix_ftp_handle_sbuf`
(setsockopt SO_SNDBUF/SO_RCVBUF on data fds), `_opts`
(`RETR Parallelism=n,…;` clamp to `conf->max_parallel`), `_esto`
(`A <off>` adjusted STOR), `_eret` (`P <off> <len>` partial RETR),
`_cksm` (§1.5 CKSM row; whole-file on `0 -1`, else partial via job-read
+ streaming digest).

### 2.5 `ftp_path.c` (P82.1, ~150 LOC)
- `ngx_int_t brix_ftp_resolve_path(brix_ftp_ctx_t*, const char
  *root_canon, ngx_str_t *arg, char *out, size_t outsz)` — §1.4.
- `ngx_int_t brix_ftp_logical_join(ngx_pool_t*, const ngx_str_t *cwd,
  const ngx_str_t *arg, ngx_str_t *out)` — pure logical normalization
  (`.`/`..` folding, no FS access) for CWD/PWD bookkeeping.

### 2.6 `data/` — channels, pumps, listeners

**`data_channel.c`** (~500 LOC, P82.1)

```c
typedef enum { FTP_DC_IDLE=0, FTP_DC_CONNECTING, FTP_DC_LISTENING,
               FTP_DC_OPEN, FTP_DC_DRAINING, FTP_DC_CLOSED } brix_ftp_dc_e;
typedef struct {                       /* one TCP stream */
    ngx_connection_t *conn;
    brix_ftp_dc_e     st;
    off_t             stripe_next;     /* sender-side MODE E cursor */
    unsigned          eod_sent:1, eod_seen:1;
    u_char            hdr[17]; size_t hdr_used;   /* MODE E partial hdr */
    off_t             blk_off;  size_t blk_left;  /* current block */
} brix_ftp_stream_t;
typedef struct {                       /* the per-transfer set */
    brix_ftp_ctx_t     *owner;
    brix_ftp_stream_t   s[BRIX_FTP_MAX_STREAMS];  /* 16 */
    ngx_uint_t          nstreams, nopen, neod;
    struct sockaddr_storage peer;      /* PORT target */
    brix_ftp_pasv_t    *pasv;          /* owning listener, or NULL */
    brix_vfs_file_t    *fh;            /* open transfer handle */
    brix_vfs_staged_t  *staged;        /* or staged handle */
    off_t               bytes_done;
    unsigned            dir_send:1;    /* RETR=1 / STOR=0 */
    unsigned            failed:1;
} brix_ftp_data_t;
```

- `ngx_int_t brix_ftp_data_ensure(brix_ftp_ctx_t *ctx)` — connect-out
  (`ftp_dc_connect` per §1.8 adoption pattern) or arm pasv accept wait.
- `static ngx_int_t ftp_dc_connect(brix_ftp_data_t*, ngx_uint_t idx)` —
  socket/nonblock/policy-check/connect (`connect_upstream.c:521+`
  idiom); `PROT P` ⇒ TLS client-less server-side wrap (§P82.3 step 4).
- `void brix_ftp_data_abort(brix_ftp_data_t*, ngx_uint_t send_426)`.
- `void brix_ftp_data_close_stream(brix_ftp_data_t*, brix_ftp_stream_t*)`
  — refcount `nopen`; last close + all EODs ⇒ completion cb.

**`pump_stream.c`** (~500 LOC, P82.1) — MODE S single-stream pump,
four-handler cross-wired per `handoff.c:229-310`:
- `ngx_int_t brix_ftp_pump_start(brix_ftp_ctx_t*, ngx_connection_t
  *ctrl, brix_ftp_data_t*)`.
- `static void ftp_pump_data_write(ngx_event_t*)` — RETR: refill window
  buffer via thread-pool job read (§1.7; `brix_vfs_job_read_init`
  vfs_io_core.h:115) or sendfile fast path when
  `brix_vfs_file_can_sendfile && sec.prot==FTP_PROT_C` (INVARIANT 2
  gate lives HERE and only here — risk R5).
- `static void ftp_pump_data_read(ngx_event_t*)` — STOR: window buffer
  → job write / `brix_vfs_staged_write`.
- `static void ftp_pump_done(brix_ftp_data_t*, ngx_int_t rc)` — commit
  staged (`brix_vfs_staged_commit`, excl per `STOR` vs `APPE`), close
  fh (`brix_vfs_close` vfs.h:223), 226/426/451, metrics+access log,
  state back to FTP_ST_AUTHED.

**`pasv_listener.c`** (~600 LOC, P82.2) — NET-NEW:

```c
typedef struct {
    ngx_connection_t *lc;              /* adopted listening fd */
    in_port_t         port;
    brix_ftp_data_t  *waiter;          /* transfer awaiting accept */
    ngx_uint_t        accepts_left;    /* = expected streams */
    ngx_msec_t        deadline;
} brix_ftp_pasv_t;
```

- `ngx_int_t brix_ftp_pasv_open(brix_ftp_ctx_t*, brix_ftp_pasv_t**)` —
  socket(AF, SOCK_STREAM|SOCK_NONBLOCK) → walk
  `conf->pasv_port_lo..hi` binding (EADDRINUSE ⇒ next; start point
  rotated per worker to cut collisions) → `listen(fd, 8)` →
  `ngx_get_connection(fd, log)` → `lc->read->handler =
  ftp_pasv_on_accept` → `ngx_handle_read_event` → arm deadline timer.
  Per-worker live count vs `conf->pasv_max` ⇒ 425 when exhausted.
- `static void ftp_pasv_on_accept(ngx_event_t *ev)` — `accept4()` loop;
  peer-IP filter (== control peer unless DCAU A token matches, P82.4);
  adopt fd (§1.8), attach as next `brix_ftp_stream_t`;
  `--accepts_left == 0` ⇒ `brix_ftp_pasv_close`.
- `void brix_ftp_pasv_close(brix_ftp_pasv_t*)` — close lfd, release
  `ngx_connection_t`, decrement worker gauge.
- `static void ftp_pasv_on_deadline(ngx_event_t*)` — idle teardown +
  425 to waiter.
- Worker shutdown: pool-cleanup on the control connection owns the
  listener — no listener survives its session; `ngx_exiting` audit test
  in P82.2 exit criteria.
- Gauge metric `gridftp_pasv_listeners` (count only — INVARIANT 8, no
  per-port labels).

**`mode_e.c`** (~800 LOC, P82.4)
- `ngx_int_t brix_ftp_eblk_decode(brix_ftp_stream_t*, u_char *in,
  size_t n, brix_ftp_eblk_cb cb, void *ud)` — incremental 17-byte
  header + payload slicing; per-block cb(off, buf, len, flags).
- `size_t brix_ftp_eblk_encode_hdr(u_char out[17], uint8_t desc,
  uint64_t count, uint64_t off)`.
- `ngx_int_t brix_ftp_eblk_recv_block(brix_ftp_data_t*, off_t off,
  const u_char *buf, size_t len)` — overlap check vs committed range
  set → `brix_vfs_pwrite_full(fd, buf, len, off)` (vfs_ops.h:123);
  reject `off + len` overflow (security tests).
- `ngx_int_t brix_ftp_eblk_track_eod(brix_ftp_data_t*,
  brix_ftp_stream_t*, uint64_t eof_count_if_any)` — completion = EOF
  count satisfied ∧ all streams EOD ∧ closed.
- Sender: `static void ftp_eblk_fill(brix_ftp_stream_t*)` — stripe
  partition, one EOD per stream, EOF (count = nstreams) on stream 0.

**`markers.c`** (~250 LOC, P82.4)
- `void brix_ftp_markers_arm(brix_ftp_ctx_t*)` — repeating
  `ngx_event_t` timer at `conf->marker_interval_ms`.
- `static void ftp_marker_fire(ngx_event_t*)` — `111 Range Marker
  a-b[,c-d…]` (from committed-range set) + `112 Perf Marker` (bytes,
  stripe count) on the control channel; also feeds
  `brix_tpc_registry_update` (registry.h:61) for dashboard parity.

**`data_token.c`** (~350 LOC, P82.4) — §1.10 SHM zone:
- `ngx_int_t brix_ftp_data_token_configure(ngx_conf_t*, ssize_t size)`
  (zone `"brix_ftp_data_tokens"`).
- `ngx_int_t brix_ftp_data_token_register(const u_char subj_hash[32],
  ngx_msec_t ttl, uint64_t *token_out)`.
- `ngx_int_t brix_ftp_data_token_consume(uint64_t token, u_char
  subj_hash_out[32])`.
- init-zone + slot walk per `src/net/manager/registry.c:65` model,
  expiry via `brix_shm_slot_expired` (shm_slots.h:24).

### 2.7 `error_mapping.c` addition (P82.1, +60 LOC)

`int brix_ftp_errno_to_reply(int err)` beside `brix_http_errno_to_status`
(`src/core/compat/error_mapping.c:194`, decl `error_mapping.h:38`); add
the fourth domain row to the file-header table (`error_mapping.c:4-11`).
Mapping table §4.2.

### 2.8 `src/auth/gssapi/` — GSI mech (P82.3)

**`gsi_mech.h`** (~100 LOC) — mech-agnostic token iface (fallback
adapter swaps under it):

```c
typedef struct brix_gssapi_srv_s brix_gssapi_srv_t;   /* opaque */
typedef enum { BRIX_GSS_CONTINUE, BRIX_GSS_COMPLETE,
               BRIX_GSS_FAILED } brix_gss_status_e;
brix_gssapi_srv_t *brix_gssapi_srv_create(ngx_pool_t*, ngx_log_t*,
    ngx_ssl_t *tls_ctx, X509_STORE *ca_store, unsigned accept_deleg);
brix_gss_status_e  brix_gssapi_srv_step(brix_gssapi_srv_t*,
    const ngx_str_t *tok_in, ngx_str_t *tok_out /*pool-alloc*/);
ngx_int_t brix_gssapi_srv_peer(brix_gssapi_srv_t*, ngx_str_t *dn_out,
    ngx_str_t *deleg_proxy_pem_out /*empty if none*/);
ngx_int_t brix_gssapi_wrap  (brix_gssapi_srv_t*, const ngx_str_t *in,
    ngx_str_t *out);
ngx_int_t brix_gssapi_unwrap(brix_gssapi_srv_t*, const ngx_str_t *in,
    ngx_str_t *out);
void       brix_gssapi_srv_free(brix_gssapi_srv_t*);
```

**`gsi_mech.c`** (~1200 LOC) — the mem-BIO accept engine (§1.9):
- `brix_gssapi_srv_create` — `SSL_new(tls_ctx->ctx)`; `rbio =
  BIO_new(BIO_s_mem())`, `wbio = BIO_new(BIO_s_mem())`;
  `SSL_set_bio(ssl, rbio, wbio)`; `SSL_set_accept_state(ssl)`; stash
  `ca_store`, `accept_deleg`. OpenSSL objects owned via
  `src/auth/crypto/scoped.h` guards (no `goto` cleanup).
- `brix_gssapi_srv_step` — `BIO_write(rbio, tok_in)`; `r = SSL_accept(ssl)`;
  on `WANT_READ` drain `wbio` → `tok_out`, return CONTINUE; on success run
  `gss_verify_peer` then (if delegating) enter the deleg sub-state, return
  COMPLETE when both done; map OpenSSL errors → FAILED (log via
  `ERR_error_string_n`, clear queue — Phase-33 dirty-queue discipline,
  `tls.c:57` precedent).
- `static ngx_int_t gss_verify_peer(brix_gssapi_srv_t*)` —
  `SSL_get_peer_cert_chain` → `brix_gsi_verify_chain(log, ca_store, leaf,
  chain, depth, &res, /*client_purpose=*/1)` (`gsi_verify.h:63`); copy
  `res.dn_buf` → owned `dn`.
- `static ngx_int_t gss_drain(brix_gssapi_srv_t*, ngx_str_t *out)` /
  `gss_feed(...)` — mem-BIO ↔ ngx_str_t plumbing shared by step/wrap/unwrap.
- `brix_gssapi_wrap` / `_unwrap` — `SSL_write`/`SSL_read` over the same
  BIO pair (post-handshake records carry the MIC/ENC protection).

**`gsi_mech_deleg.c`** (~400 LOC) — the delegation sub-exchange:
- `static ngx_int_t gss_deleg_emit_csr(brix_gssapi_srv_t*, ngx_str_t
  *out)` — build+sign a proxy cert request with the existing kernels
  (`src/auth/gsi/proxy_req_assemble.c:62,95`, `proxy_req_sign.c:162,290`).
- `static ngx_int_t gss_deleg_absorb_proxy(brix_gssapi_srv_t*, const
  ngx_str_t *signed_pem)` — assemble the delegated proxy PEM into
  `deleg_proxy_pem` (mirrors `src/auth/gsi/delegation.c:37` flow); later
  read by `brix_gssapi_srv_peer` and bound via `brix_vfs_deleg_bind`
  (§1.5).

### 2.9 `metrics_gridftp.h` (P82.1, ~100 LOC)

Per-proto counter shard beside `metrics_s3.h`/`metrics_webdav.h`. No new
call API — reuse `brix_metric_op_done`/`_backend_bytes`/`_auth`/`_tpc`
(`unified.h:125/135/192/200`) keyed on `BRIX_PROTO_GRIDFTP`. Adds the
gridftp gauge `gridftp_pasv_listeners` (count only — INVARIANT 8).

---

## 3. Build & source-list wiring (build_source_list_location)

New `.c` files go into `ngx_module_srcs` in the **repo-root `./config`**
STREAM block (starts ≈ `config:606`; header section ≈ `config:364`),
backslash-continued `$ngx_addon_dir/...` lines exactly like the s3 block at
`config:1433`. Concretely, append to the STREAM `ngx_module_srcs`:

```
$ngx_addon_dir/src/protocols/gridftp/stream/module.c \
$ngx_addon_dir/src/protocols/gridftp/stream/module_definition.c \
$ngx_addon_dir/src/protocols/gridftp/stream/server_conf.c \
$ngx_addon_dir/src/protocols/gridftp/connection/handler.c \
$ngx_addon_dir/src/protocols/gridftp/connection/recv_line.c \
$ngx_addon_dir/src/protocols/gridftp/connection/send_reply.c \
$ngx_addon_dir/src/protocols/gridftp/connection/tls_ctrl.c \
$ngx_addon_dir/src/protocols/gridftp/commands/dispatch.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_session.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_namespace.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_list.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_xfer.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_port.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_sec.c \
$ngx_addon_dir/src/protocols/gridftp/commands/cmd_gridftp.c \
$ngx_addon_dir/src/protocols/gridftp/ftp_path.c \
$ngx_addon_dir/src/protocols/gridftp/data/data_channel.c \
$ngx_addon_dir/src/protocols/gridftp/data/pump_stream.c \
$ngx_addon_dir/src/protocols/gridftp/data/pasv_listener.c \
$ngx_addon_dir/src/protocols/gridftp/data/mode_e.c \
$ngx_addon_dir/src/protocols/gridftp/data/markers.c \
$ngx_addon_dir/src/protocols/gridftp/data/data_token.c \
$ngx_addon_dir/src/auth/gssapi/gsi_mech.c \
$ngx_addon_dir/src/auth/gssapi/gsi_mech_deleg.c \
```

Headers (`ftp_ctx.h`, `ftp_wire.h`, `ftp_replies.h`, `gsi_mech.h`, per-dir
`README.md`) into the header section. Register the new module in the module
descriptor list. Then re-run `./configure --add-module=$REPO` (adding a
`.c` without re-configure ⇒ silently not compiled — extending.md step ⑥).
Validate `objs/nginx -t` against:

```nginx
stream {
  server { listen 2811; brix_gridftp on; brix_gridftp_export /data;
           brix_gridftp_allow_write on; brix_gridftp_pasv_range 50000-50100; }
}
```

ABI: any edit to `ngx_stream_brix_ftp_srv_conf_t` or `brix_ftp_ctx_t` ⇒
`make clean && make` (struct_field_abi_clean_rebuild); mixed-ABI objects
crash at runtime, not link time.

---

## 4. Wire-level reference

### 4.1 Command → reply matrix (implementation checklist)

Gate: `-` pre-auth OK · `A` require_auth (`auth_done`) · `W`
require_write (`auth_done` + `common.allow_write`).

| Verb | Gate | Phase | Success | Canonical errors |
|---|---|---|---|---|
| AUTH GSSAPI | - | P82.3 | 334 | 504 (mech≠GSSAPI), 431 |
| ADAT `<b64>` | - | P82.3 | 335 `ADAT=…` / 235 | 535 (ctx fail), 503 |
| USER/PASS | - | P82.1* | 331 / 230 | 530 (*cleartext-test only) |
| PBSZ 0 | A | P82.3 | 200 | 503 (before AUTH) |
| PROT C\|P | A | P82.3 | 200 | 536 (level unsupported), 503 |
| DCAU N\|S\|A | A | P82.3 | 200 | 504 |
| MIC/ENC/CONF | A | P82.3 | 63x wrapped | 533, 537 |
| FEAT | - | P82.1 | 211- list | — |
| SYST | - | P82.1 | 215 UNIX Type: L8 | — |
| TYPE I\|A | A | P82.1 | 200 | 504 |
| MODE S\|E | A | P82.1/4 | 200 | 504 |
| STRU F | A | P82.1 | 200 | 504 |
| PWD/CWD/CDUP | A | P82.1 | 257 / 250 | 550 |
| MKD/RMD/DELE | W | P82.1 | 257 / 250 / 250 | 550, 553 |
| RNFR → RNTO | W | P82.1 | 350 → 250 | 550, 503 |
| SIZE/MDTM | A | P82.1 | 213 | 550 |
| MLST | A | P82.1 | 250- facts | 550 |
| LIST/NLST/MLSD | A | P82.1 | 150 → 226 | 425, 450 |
| PORT/EPRT | A | P82.1 | 200 | 501, 522, **500 on SSRF deny** |
| PASV/EPSV | A | P82.2 | 227 / 229 | 425 (range exhausted) |
| SPOR/SPAS | A | P82.4 | 200 / 229- | 501 |
| RETR | A | P82.1 | 150 → 226 | 550, 425, 426, 451 |
| STOR/APPE | W | P82.1 | 150 → 226 | 553, 550, 452, 552 |
| REST n | A | P82.1 | 350 | 501 (MODE E `0-n`: P82.4) |
| ALLO | W | P82.1 | 202 | — |
| SBUF n | A | P82.4 | 200 | 501 |
| OPTS RETR Parallelism=n | A | P82.4 | 200 | 501 |
| ESTO/ERET | W/A | P82.4 | 150 → 226 | 501, 550 |
| CKSM alg off len path | A | P82.4 | 213 `<hex>` | 504 (alg), 550 |
| STAT (during xfer) | A | P82.4 | 213- markers | — |
| NOOP/QUIT | - | P82.1 | 200 / 221 | — |

FEAT advertises exactly the `feat_line` rows registered for the landed
phase (generated from `brix_ftp_cmd_table`, §2.4) — never hand-maintained,
so it can't overpromise to gfal2's feature probe (risk R9).

### 4.2 errno → FTP reply (`brix_ftp_errno_to_reply`, §2.7)

Clone of `brix_http_errno_to_status` (`error_mapping.c:194`), FTP codes:

```
ENOENT, ENOTDIR      → 550    ENOSPC               → 452
EACCES, EPERM        → 550    EDQUOT, EFBIG        → 552
EEXIST (STOR/MKD)    → 553    EBUSY, EAGAIN        → 450
EISDIR               → 550    ENOTEMPTY            → 550
ENAMETOOLONG         → 553    ENOTSUP, ENOSYS      → 502
EROFS                → 550    default              → 451
```

Three tests on the mapper itself (success/error/security-neg), like the
kXR/HTTP tables.

### 4.3 ADAT flow (P82.3)

```
C: AUTH GSSAPI                    S: 334 Using authentication type GSSAPI
C: ADAT <b64 ClientHello…>        S: 335 ADAT=<b64 ServerHello…>
   … n round trips: brix_gssapi_srv_step over mem BIOs (§2.8) …
   [deleg: 'D' ctx → gss_deleg_emit_csr → client returns signed proxy]
C: ADAT <b64 final>              S: 235 ADAT=<b64> GSSAPI authentication ok
→ gss_verify_peer → DN → identity (§1.3);  sec.ctrl_wrapped = 1
→ every later command arrives wrapped:  MIC <b64(wrap("PWD\r\n"))>
   replies leave wrapped:               631 <b64(wrap("257 \"/\"\r\n"))>
   (632 when PROT-privacy negotiated on the control channel)
```

Post-235 unwrapped command (except QUIT) ⇒ 533. Caps: 64 KiB/token, 32
round trips, else hard-close (evil-actor test).

### 4.4 MODE E extended-block framing (P82.4) — **VERIFIED** (landed 2026-07-17)

17-byte header, network byte order, then `count` payload bytes:

```
+--------+----------------+----------------+
| desc:1 |   count:8      |   offset:8     |
+--------+----------------+----------------+
desc bits: 0x40 EOF   0x08 EOD   0x20 suspect-errors   0x10 restart-marker
```

**Critical empirical correction (vs. the original GFD.020-from-memory
sketch):** the EOF block carries **no payload**, its `count` field is **0**,
and the **total EOD count lives in the OFFSET field** — NOT the count field.
globus folds EOF and EOD into a single `desc=0x48` block on the last stream
(e.g. `-p4` PUT → `count=0, offset=4`). Reading the EOD total from `count`
(as the sketch implied) terminates the receive loop early and truncates the
file — this cost a debug cycle; captured via BRIXEB trace logging. There is
no `0x04 close` bit in globus's encoding; a stream ends with its single EOD
followed by a socket close.

Receiver (STOR, `ftp_stor_mode_e`): globus opens all `Parallelism` streams at
once and runs their TLS handshakes concurrently, so the receiver **poll()s
across the listener + every live stream** — accepting/handshaking promptly and
interleaving reads — rather than draining one stream before accepting the next
(a sequential accept+drain times out the un-serviced streams' handshakes →
`Connection reset by peer`). Each block lands via
`brix_vfs_pwrite_full(fd, buf, count, offset)` (no shared cursor); overlap into
a committed range and `offset+count > INT64_MAX` are rejected. The PASV
listener backlog spans the stream cap (`FTP_EB_MAX_CONNS`, was 1 → refused the
extra parallel connects). Complete when the EOF-declared EOD count is met.
Sender (RETR, `ftp_retr_mode_e`): a single framed stream — data blocks at
absolute offsets, then one combined `EOF|EOD` block (`count=0, offset=1`);
globus accepts fewer streams than the `Parallelism` it offered. A missing
source is rejected with `550` **before the 150** (a MODE E client opens its
streams on the 150 and would otherwise hang). Markers: `111 Range Marker`
(coalesced committed ranges, capped) + `112 Perf Marker`, emitted inline each
~1 MiB (no `markers.c` timer in the synchronous model).

---

## 5. Control-channel state machine (§2.2 `brix_ftp_state_e`)

```
FTP_ST_GREETING     → send 220 → FTP_ST_PREAUTH
FTP_ST_PREAUTH      only AUTH ADAT FEAT SYST QUIT NOOP (+USER/PASS if
                    cleartext-test); 512-byte line cap
FTP_ST_ADAT         mem-BIO handshake in flight (P82.3)
FTP_ST_AUTHED       steady state; verbs per §4.1 gates; commands wrapped
                    when sec.ctrl_wrapped
FTP_ST_XFER         data transfer live; control accepts only ABOR/STAT/QUIT
FTP_ST_RENAME_WAIT  RNFR accepted; only RNTO/ABOR legal (else 503)
FTP_ST_CLOSING      421/221 sent → linger-drain → brix_ftp_finalize
```

Transitions in one place — the dispatch gate field (`min_state`, §2.4) plus
explicit `brix_ftp_state_set()` with a debug log line (mirrors how
`ctx->state`/`XRD_ST_*` drives root's pump). Data-channel objects
(`brix_ftp_dc_e`, §2.6) have their own lifecycle
`IDLE→CONNECTING/LISTENING→OPEN→DRAINING→CLOSED`, owned by
`data_channel.c`; the control session holds at most one `brix_ftp_data_t`.

---

## 6. Data-channel & TPC sequencing

**Active (PORT):** client `PORT h1,h2,h3,h4,p1,p2` → parse → SSRF policy
(§1.8) → store `data->peer` → on RETR/STOR `ftp_dc_connect` (nonblocking,
`EINPROGRESS`) → adopt fd → pump.

**Passive (PASV):** `brix_ftp_pasv_open` (§2.6) binds a listener in-range,
replies `227 (h,p)` → client connects → `ftp_pasv_on_accept` adopts fd,
peer-IP filtered → pump. Listener closes after the expected accept count or
idle deadline.

**Server-side TPC (P82.4):** the destination brix issues PASV, returns
`(host,port)` + `DCAU A` subject; the client relays that to the source
brix's `PORT`; the source connects to the destination's listener. The
destination validates the connecting peer's authenticated subject against
its `brix_ftp_data_token` SHM entry (§1.10) — this is why active-mode's
peer-IP pin is relaxed only under `DCAU A`. Both ends register the transfer
in the shared monitoring registry (`registry.h:47-104`) for dashboard
parity with native/HTTP TPC.

---

## 7. Config directives (all net-new; port-range parsing has NO precedent)

4-step recipe each (extending.md §2): field on
`ngx_stream_brix_ftp_srv_conf_t` → `ngx_command_t` row → parser in
`stream/module.c` (or `src/core/config/`) → default in create/merge.

| Directive | Ctx | Default | Notes |
|---|---|---|---|
| `brix_gridftp on\|off` | srv | off | enable setter installs `cscf->handler` (§1.1) |
| `brix_gridftp_export <path>` | srv | — | shares canon/resolve plumbing with `brix_export` |
| `brix_gridftp_allow_write on\|off` | srv | off | INVARIANT 3 gate (`common.allow_write`) |
| `brix_gridftp_pasv_range <lo>-<hi>` | srv | 50000-51000 | new parser `ftp_conf_set_pasv_range`; `1023<lo<hi≤65535` |
| `brix_gridftp_pasv_max <n>` | srv | 64 | per-worker listener cap → 425 when hit |
| `brix_gridftp_pasv_addr <ip>` | srv | ctrl-listener IP | address advertised in 227/229 (NAT) |
| `brix_gridftp_max_parallel <n>` | srv | 8 | clamp on OPTS Parallelism / SPOR streams |
| `brix_gridftp_marker_interval <t>` | srv | 5s | 111/112 markers |
| `brix_gridftp_idle_timeout <t>` | srv | 300s | control channel (data idle fixed 60s) |
| `brix_gridftp_auth gssapi\|cleartext-test` | srv | gssapi | enum `ftp_conf_set_auth_mode`; `cleartext-test` refused unless build/test flag set (pattern: `brix_ssi_cta_executor`, `directives_tpc.inc:69`) |
| `brix_gridftp_cred_dir <path>` | srv | — | feeds `brix_vfs_ctx_bind_backend_cred` (vfs.h:145) |
| `brix_gridftp_data_token_zone <size>` | main | 1m | SHM zone for §1.10 (P82.4) |

---

## 8. Phases & exit criteria

### P82.1 — Skeleton + cleartext control plane (~4.5k LOC)

Module registration (§2.1), `BRIX_PROTO_GRIDFTP` row (§1.1), metrics shard
(§2.9); line pump + replies + dispatch + state machine (§2.2-2.4); session,
namespace, listing verbs (§2.4) — every path through `brix_ftp_resolve_path`
(§1.4); `brix_ftp_errno_to_reply` (§2.7); active-mode data channel + MODE S
pump (§2.6); RETR sendfile fast path (cleartext only) + job-model pump; STOR
via job model with staged-seam fallback; `cleartext-test` auth lane so the
plane is testable pre-GSSAPI; build wiring (§3).

**Exit:** `globus-url-copy ftp://` (cleartext, active) round-trips a 1 GiB
file bit-exact against posix AND an S3 backend (staged seam);
`pytest tests/test_gridftp_core.py -v` green in the `-m "not slow"` lane;
zero fd leak over 1000 connect/QUIT cycles.

### P82.2 — Passive mode: dynamic listeners (~2.5k LOC, highest infra risk)

`pasv_listener.c` (§2.6): range-walk bind, listening-fd adoption via
`ngx_get_connection`, accept handler, peer-IP filter, idle teardown,
per-worker cap, gauge metric; PASV/EPSV replies honoring `pasv_addr`; SPAS
single-address stub; worker-lifecycle audit (`ngx_exiting`).

**Exit:** gfal-ls + gfal-copy passive both directions; kill-mid-transfer,
`nginx -s reload` mid-transfer, and control-drop tests show zero leaked
listeners/fds (extend brutal-teardown lane); port exhaustion → 425 and
recovers.

### P82.3 — GSSAPI/GSI auth + PROT P (~4–8k LOC) — **GATED (header)**

`src/auth/gssapi/gsi_mech.c` mem-BIO accept loop (§2.8), mech-agnostic
token iface; chain verify → DN → identity (§1.3);
`brix_metric_auth(BRIX_PROTO_GRIDFTP, BRIX_AUTHN_GSI, ok)`; delegation
sub-exchange → `deleg_proxy_pem` → `brix_vfs_deleg_bind` (§1.5); `cmd_sec.c`
AUTH/ADAT/PBSZ/PROT/DCAU + MIC/ENC unwrap-rewrap in the line pump; `PROT P`
TLS on data channels (`b->memory=1`, sendfile disabled — INVARIANT 2, the
single gate in `pump_stream.c`); DCAU peer-subject checks. 2-week interop
timebox vs globus-url-copy/gfal2, then Globus-lib fallback (§1.9).

**Exit:** `globus-url-copy gsiftp://` end-to-end with an RFC 3820 proxy,
both PROT C and PROT P, active + passive; security-negatives all land:
expired proxy, broken chain, non-proxy leaf, unmapped DN, write w/o
allow_write, unwrapped post-auth command, ADAT flood/oversize, data connect
from wrong peer IP.

### P82.4 — MODE E, parallelism, GridFTP verbs, TPC (~4.5k LOC)

`mode_e.c` EBLOCK codec (§4.4) + out-of-order STOR reassembly (overlap +
overflow rejection); RETR striping + EOD/EOF bookkeeping; SPOR/SPAS,
OPTS Parallelism, SBUF, ESTO/ERET partial, `REST 0-n`; CKSM (§1.5 row);
`markers.c` (111/112); STAT-during-transfer from the transfer registry;
`data_token.c` SHM zone + DCAU A subject exchange; register transfers for
monitoring parity.

**Exit:** gfal-copy with 4 parallel streams both directions bit-exact;
EBLOCK fuzz corpus (interleaved/duplicate/overlapping/oversize) all safely
rejected; gsiftp↔gsiftp TPC between two brix instances in the k8s lab;
restart marker honored on resume.

### P82.5 — Hardening + lab (test-heavy, ~1k LOC fixtures)

Evil-actor lane (extend `tests/_test_evil_actor_v3_helpers.py`): pre-auth
flood, line-cap abuse, PASV port exhaustion, data-channel hijack (wrong
source IP / right port), MODE E offset attacks, REST beyond EOF,
wrapped-length lies, ABOR races. k8s lab under `k8s-tests/` ONLY
(tests_k8s_folder_split): container with globus-url-copy + gfal2 + VOMS
proxy fixture; matrix posix/pblock/s3 × {PROT C,P} × {MODE S,E} ×
{active,passive} + FTS-style bulk lane. `docs/05-operations/gridftp.md`
cookbook; per-dir README rows. SRR endpoint untouched (HTTP-only —
srr_wlcg_endpoint).

**Landed (2026-07-17) — MODE E offset-attack corpus:** `tests/test_gridftp_mode_e.py`
drives crafted EBLOCK frames over the *cleartext* gateway (PROT C → raw data
socket, no GSSAPI needed; wire framing identical to PROT P). Four tests, green:
a well-formed two-block STOR round-trips byte-identical; an overlapping block
(offset into an already-committed range) → 550; an `offset+count` overflow past
`INT64_MAX` → 550 (rejected at the header, before any pwrite); a short-framed
block (payload shorter than declared count) → 550. These validate the existing
`ftp_eb_recv_block` guards (risk R4) — no source change was required; the guards
already held.

**Finding — `fc->authed` is write-only:** the field is set at the USER/PASS/GSI
sites but never *read*, so file verbs are not gated behind login. Benign on the
cleartext gateway (login is anonymous regardless), but it means a "pre-auth
rejection" evil-actor test has nothing to assert against, and on a GSI-mandated
deployment the gate lives elsewhere (`sec_active` on the security-sensitive
paths), not here. Enforcing `authed` is a behaviour change requiring OP sign-off
before it lands — tracked here, not silently patched.

**Evil-actor lane completed (2026-07-17) — GSI pre-auth abuse corpus +
pre-auth flood:** the RFC 2228 handshake (`AUTH GSSAPI` → `ADAT …`) runs in
*cleartext* on the control channel until the final `235`, so every reject path
in the mem-BIO GSSAPI engine (`gsi_mech.c`) is reachable from a raw socket with
no globus client and no user proxy — only the gateway's host cert + grid CA.
`tests/test_gridftp_gsi_evil.py` (8 green) drives that corpus and pins the codes
against the real handler: `AUTH <badmech>`→504, `ADAT`-before-`AUTH`→503,
double-`AUTH`→534, malformed-b64 `ADAT`→501, bogus-token `ADAT`→535 (session
stays unauthenticated — a following `RETR`→530), `MIC`-pre-auth→503,
`PROT P`-pre-auth→536, oversize `ADAT` line→drop. `tests/test_gridftp_evil.py`
gained `test_preauth_command_flood` (300 gated verbs each 530, gate still opens
on a later login — pre-auth-gate durability). **No source change was required —
the guards already held.** Build/seam unaffected (test-only). Full native
gridftp suite now 60 green.

**N/A on this synchronous/ephemeral-port gateway (recorded, not silently
skipped):** *PASV port-exhaustion reclaim* — `ftp_do_pasv` binds an **ephemeral**
port (`sin_port=0`), there is no configured range or `pasv_max` (the §7
`brix_gridftp_pasv_range/_max` directives belong to the unbuilt event-driven
tree), so there is no range to exhaust; the realistic guard (no fd leak across
repeated PASV) is `test_repeated_pasv_no_fd_leak`. *Data-channel IP-hijack* —
`ftp_data_accept` does `accept(pasv_fd, NULL, NULL)` with no peer-IP filter by
design; the cleartext PASV leg is unauthenticated and the real boundary is the
PROT P GSI **DN pin** on the data-channel TLS handshake, already covered by the
gsiftp suite's untrusted-CA / DN-mismatch path. *ABOR races* — transfers run
inline to completion, so there is no in-flight transfer to interrupt. The
active-mode FTP-bounce negative is `test_gridftp_verbs.py::
test_active_bounce_to_third_party_rejected`.

**Still open:** the k8s interop lab (container + globus-url-copy/gfal2/VOMS, the
posix/pblock/s3 × {C,P} × {S,E} × {active,passive} matrix + FTS bulk lane) +
`docs/05-operations/gridftp.md` cookbook (cookbook drafted; cluster matrix cell
is the remaining container-tier work).

**Exit:** evil-actor suite green; k8s matrix green; ops doc reviewed;
metrics visible in the unified exporter with low-cardinality labels only.

---

## 9. Test contract (3 per change: success + error + security-negative)

| Suite | Phase | Runner notes |
|---|---|---|
| `tests/test_gridftp_core.py` | P82.1 | default lane; no `fast` marker exists — fast lane = `-m "not slow"` (run_suite `--pr`); <30s default timeout |
| `tests/test_gridftp_pasv.py` | P82.2 | `serial` marker (fixed PASV range collides under xdist) |
| `tests/test_gridftp_gsi.py` | P82.3 | `x509conf` + `slow` where proxy gen is involved |
| `tests/test_gridftp_mode_e.py` | P82.4 | MODE E offset-attack corpus (overlap/overflow/short-frame over cleartext PROT C); landed |
| `tests/test_gridftp_evil.py` | P82.5 | control-channel evil-actor lane (pre-auth gate + flood, oversize line, PASV no-leak, REST-beyond-EOF); landed |
| `tests/test_gridftp_gsi_evil.py` | P82.5 | GSI pre-auth abuse corpus over a raw cleartext control socket (bad mech 504, ADAT-before-AUTH 503, double-AUTH 534, malformed-b64 501, bogus-token 535, MIC-pre-auth 503, PROT P-pre-auth 536, oversize ADAT drop); needs host cert + CA, **not** globus; landed |
| `k8s-tests/remote-suite/tests/test_gridftp_interop.py` | P82.5 | container tier only; globus-url-copy/gfal matrix, chart `charts/gridftp-interop`, image `Dockerfiles/gridftp-client`; skips without a cluster |
| `tests/test_gridftp_pblock.py` | P82.6/.7 | pblock backend round-trip: STOR/RETR + MODE E STOR land in the block store (not a posix file under the export); driver-routed CKSM (MD5/CRC32) matches; missing-object 550; traversal confined; landed |
| `tests/test_gridftp_verify_write.py` | P82.7 | `brix_gridftp_verify_write on`, parametrized posix + pblock: verified STOR round-trip, empty STOR, MODE E out-of-order STOR all 226 + byte-identical; landed |
| `tests/c/test_wverify.c` (`wverify` CUnitSpec) | P82.7 | write-verify accumulator unit: in-order == whole-buffer zlib CRC; out-of-order converges; gap/overlap/empty fail closed; landed |
| `tests/test_gridftp_s3.py` | P82.8 | s3 object-store backend via `brix_gridftp_storage_backend s3://` + `brix_gridftp_storage_credential`: STOR/RETR round-trip, whole-object + partial-range CKSM, empty STOR — staged upload + read-back verify; `worker_processes 2` avoids the co-hosted synchronous self-deadlock; landed |

Fixtures reuse `conftest.py` fleet lifecycle (`_test_session_setup`
`conftest.py:735` → `manage_test_servers.sh start-all`),
`registry`/`lifecycle` harnesses (`conftest.py:754/782`); add
`NGINX_GRIDFTP_PORT` to the port map + a gridftp `server{}` to the managed
fleet config. Protocol-level negatives use a raw-socket driver
`tests/gridftp_client.py` (pytest_python39_env_gotcha applies); happy-path
interop uses gfal2 bindings with `pytest.importorskip`. C-unit tests
(EBLOCK codec, errno mapper, line parser) follow the `tests/cmdscripts/*.py`
compile-list convention (c_tests_bash_to_python_port — old `tests/c/*.sh`
runners are gone).

---

## 10. Risks

| # | Risk | Phase | Mitigation |
|---|---|---|---|
| R1 | Hand-rolled GSI-GSSAPI interop failures vs Globus | P82.3 | mech = TLS-in-tokens over mem BIOs; mech-agnostic ADAT iface; 2-week timebox → link `libglobus_gssapi_gsi` behind the adapter |
| R2 | Dynamic listeners leak fds / fight worker lifecycle | P82.2 | per-worker cap + gauge + brutal-teardown + reload tests BEFORE P82.3 stacks on top |
| R3 | PORT verb = SSRF primitive | P82.1 | `brix_net_target_check_addr` per connect + peer-IP pin default; 500 on deny |
| R4 | MODE E reassembly corruption / overlap writes | P82.4 | per-block `brix_vfs_pwrite_full`, committed-range overlap rejection, fuzz corpus |
| R5 | Sendfile on a PROT P channel (INVARIANT 2 breach) | P82.3 | sendfile path structurally unreachable when `sec.prot==FTP_PROT_P` — single gate in `pump_stream.c` + security test |
| R6 | Effort sunk into a dead protocol | all | strategic gate before P82.3; P82.1-2 remain useful as plain-FTP lab export |
| R7 | Conf-struct ABI churn | P82.1 | struct_field_abi_clean_rebuild — `make clean` after conf edits |
| R8 | EBLOCK descriptor bits are from memory, not the tree | P82.4 | verify §4.4 against GFD.020 + a captured globus-url-copy trace before coding |
| R9 | FEAT overpromise breaks gfal2 probing | each | FEAT generated from the dispatch table's per-phase `feat_line` rows |

---

## 11. Status

- **P82.0 (this doc):** plan drafted 2026-07-16; expanded to a
  function-level spec with three surveys' verified anchors the same day. No
  code started; no phase gate passed. Scheduling P82.1 — and the P82.3
  go/no-go — rests with OP.

- **P82.3 event-engine PROT P landed 2026-07-17 (`ftp_ev_tls.c`):** the
  DCAU A / PROT P data channel now runs non-blocking on the event engine,
  reaching parity with the sync `-dcpriv` path. The sync engine's cert logic
  was extracted into the shared `ftp_dc_sec.{c,h}` core and the sync engine
  rewired onto it (its green GSI suite is the extraction oracle); `ftp_ev_tls.c`
  drives the handshake through `ngx_ssl_create_connection` + `ngx_ssl_handshake`
  so the transfer pumps run over TLS unchanged. `globus-url-copy -dcpriv`
  LIST/GET/PUT round-trip against the event gateway
  (`tests/test_gridftp_gsiftp_ev.py`, 5/5 green: 3 success + missing-object
  error + untrusted-CA security-neg). Full detail in §2's "Status (P82.3
  landed)". See the sync-engine note below for the empirically pinned protocol
  facts (unchanged — the wire behaviour is identical, only the I/O model differs).

- **P82.3 sync data-channel security landed 2026-07-17 (`ftp_handler.c`):** the
  gsiftp data channel is now fully GSI-secured end to end, not just the
  control channel. `globus-url-copy -dcpriv` GET and PUT round-trip
  byte-identical against the gateway (`tests/test_gridftp_gsiftp.py`, 7/7
  green). Protocol facts pinned empirically against the real globus client:

  - **DCAU / PROT.** `PROT P` (+ globus's implicit `DCAU A`) makes the data
    connection a **straight TLS 1.2 connection on the data socket** — a raw
    ClientHello, no globus 4-byte token framing. The server does
    `SSL_set_fd`/`SSL_accept`/`SSL_read`/`SSL_write`. `DCAU N`/`PROT C` keep
    the legacy cleartext data leg (still the test default via `-nodcau`).
  - **Server presents the delegated user credential**, not the host cert.
    DCAU authenticates the data channel as the *user* on both ends; globus
    checks the data peer name against the control-channel identity.
    `ftp_data_secure()` loads `fc->deleg_proxy` (the credential delegated over
    the control channel) via `ftp_load_deleg_cred()`, then post-handshake
    re-verifies the client's data-channel proxy against the CA store and
    rejects any DN that differs from the control DN (`fc->ctrl_dn`).
  - **Chain-completion gotcha.** Server-side `SSL_get_peer_cert_chain()`
    *excludes* the peer leaf, so the assembled delegated-credential PEM was
    missing the delegated proxy's direct issuer (the client's control leaf).
    Fixed by exposing that leaf through new
    `brix_gssapi_srv_peer_cert_pem()` (`gsi_mech.c`), capturing it in
    `ftp_gss_finalize()` as `fc->ctrl_leaf_pem`, and prepending it as the
    first chain cert in `ftp_load_deleg_cred()`. Without it globus reports
    "certificate verify failed" on the data channel.
  - **EOF gotcha.** GridFTP stream mode signals end-of-data by closing the
    data connection, and globus closes **without** a TLS `close_notify`.
    OpenSSL 3.x reports that as `SSL_R_UNEXPECTED_EOF_WHILE_READING`
    (`SSL_ERROR_SSL`), which failed a STOR after the final block despite all
    bytes arriving. Fixed with `SSL_OP_IGNORE_UNEXPECTED_EOF` on the data SSL
    so the abrupt close reads as a clean EOF — matching GridFTP stream-mode
    semantics (no data-channel length framing; close = EOF).

- **P82.4 verb-batch + active mode landed 2026-07-17 (`ftp_handler.c`):**
  extended the existing synchronous handler (not the event-driven tree in §2 —
  the on-disk gateway is the compact single-file form) with the self-contained
  RFC 959 / RFC 3659 / GridFTP verbs that do not need the two large subsystems
  (MODE E striping and gsiftp↔gsiftp TPC, both still pending — see below):

  - **Metadata:** `MDTM` (was advertised in FEAT but unimplemented — the FEAT
    lie is now honest), `MLST` (RFC 3659 single-object facts on the control
    channel), `STAT` (session status with no arg; per-path facts with one),
    `CKSM <algo> <off> <len> <path>` (whole-object ADLER32/CRC32/CRC32C/MD5/
    SHA1/SHA256 via the shared `brix_cksum_*_fd` kernels; a partial range is
    declined 504, not answered wrongly).
  - **Transfer parameters:** `MODE S` / `STRU F` accepted, `STRU R` honestly
    `504`; `ALLO` advisory `200`. (`MODE E` now supported — see the MODE E
    landing note below.)
  - **Restart / append:** `REST` offset threaded into the next `RETR`/`STOR`
    (extend-in-place when non-zero); `APPE` extends from EOF. Both routed
    through a widened `ftp_retr_file(...,start)` / `ftp_stor_file(...,start,
    truncate)`.
  - **Rename:** `RNFR`/`RNTO` two-step via `brix_vfs_rename` with a confined
    `brix_path_result_t` destination (mirrors root:// `mv` and WebDAV `MOVE`).
  - **Data channel:** real `EPSV` (RFC 2428 `229 (|||port|)`, previously a
    `502` stub) and **active mode** `PORT`/`EPRT` — parsed, **pinned to the
    control connection's peer IP** (anti-FTP-bounce) and screened through the
    SSRF `brix_net_target_check_addr` policy before `connect()`. Transfers now
    branch on `fc->active` between accept (PASV) and connect-out (PORT).

  Every verb resolves through `brix_http_resolve_path()` / the VFS seam, so the
  confinement guard covers the whole new surface (traversal args rejected).
  Tests: new `tests/test_gridftp_verbs.py` (13 cases, cleartext gateway driven
  by Python `ftplib` via `tests/configs/nginx_gridftp_plain.conf`) — success +
  error + security-negative per verb — plus the 7 GSI cases still green (the
  dcpriv data path shares the refactored transfer code). Build clean under
  `-Werror`; VFS-seam guard clean.

- **gsiftp↔gsiftp server-to-server TPC landed 2026-07-17 (`ftp_handler.c`,
  `ftp_module.c`):** a third-party copy between two brix gateways now moves the
  bytes directly server-to-server over a GSI-secured (DCAU A + PROT P) data
  channel, with nothing flowing through the client. `globus-url-copy -dcpriv
  gsiftp://SRC/f gsiftp://DST/g` round-trips byte-identical
  (`tests/test_gridftp_gsiftp.py::test_third_party_copy_gsiftp_to_gsiftp`).
  In a gsiftp↔gsiftp TPC the destination is passive (its `PASV`/`EPSV` listener
  receives the connection) and the **source server** — not the control-channel
  client — connects out to it; the two servers speak straight TLS 1.2 to each
  other exactly as in the client↔server `-dcpriv` path. What this required:

  - **Active connect-out TLS role.** The source leg needs a TLS *client* on the
    data socket (`SSL_connect`), the mirror of the passive `SSL_accept` role.
    Extracted the common setup into `ftp_dc_ssl_new()` and added
    `ftp_data_secure_connect()` (connect state) alongside `ftp_data_secure()`
    (accept state); `ftp_do_transfer()` picks the role from `fc->active`.
  - **Version-flexible SSL_CTX gotcha.** The data-channel `SSL` is minted from
    the gateway's shared `tls_ctx->ctx`, which was built with
    `TLS_server_method()`. `SSL_connect()` on a server-only context fails with
    OpenSSL `error:0A0C0101 …called a function you should not call`. Switched
    the context to the version-flexible `TLS_method()` (`ftp_module.c`) so the
    one context serves both the accept roles (control channel + passive data)
    and the active data connect.
  - **GSI proxy-delegation DN pin.** The peer on a TPC leg presents a proxy
    *further delegated* from the control identity, so its leaf DN is the control
    DN plus a fresh `/CN=<random>` proxy component per connection — an exact-DN
    pin (correct for the client↔server case, where the data peer is the same
    proxy) rejected it. Replaced the equality check with
    `ftp_dn_matches_identity()`: the peer DN matches when it equals the control
    DN *or* extends it by one-or-more trailing `/CN=` proxy RDNs. Safe because
    the chain is already PKIX-verified as a well-formed RFC-3820 proxy chain, so
    a matched prefix cannot be forged without the control identity's key — this
    is standard GSI identity matching (strip proxy CNs).
  - **Anti-bounce relaxation (already in P82.4).** Because the connecting party
    is the source *server* (a different IP from the control peer), the active
    `PORT`/`EPRT` peer-IP pin is relaxed only under DCAU A, and off-peer legs are
    required to be `PROT P`; the data-channel DN pin above is then the identity
    boundary that authorises the leg (security-negative `test_active_bounce_
    to_third_party_rejected` proves a no-DCAU-A off-peer `PORT` still `500`s).

  The SHM rendezvous zone (§1.10) is **not** needed in this single-worker
  synchronous model — the DN pin already authenticates the connecting subject
  end to end, so a shared registry to pre-authorise the peer address would be
  redundant; deferred unless a future multi-worker/event-driven rewrite needs
  address-based pre-screening.

- **MODE E extended-block + parallel streams landed 2026-07-17
  (`ftp_handler.c`):** `globus-url-copy -p N` now round-trips byte-identical in
  both directions over a GSI-secured data channel
  (`tests/test_gridftp_gsiftp.py::test_{get,put}_mode_e_parallel`, `-p4`; plus a
  missing-object error case). Client sends `TYPE I` + `MODE E` + `OPTS RETR
  Parallelism=N,N,N;` after login, then `PASV` (PUT: server listens, globus
  opens N streams) or `PORT` (GET: server connects out). The framing details,
  the empirical EOF-in-offset correction, the poll()-multiplexed receiver, the
  PASV backlog fix, and the pre-150 missing-source rejection are all documented
  in **§4.4** (now VERIFIED). `111`/`112` markers emit inline each ~1 MiB. The
  `MODE E` accept/reset contract updated `test_gridftp_verbs.py::test_mode_and_
  stru` (bare `MODE E` → `200`, resettable by `MODE S`; `STRU R` still `504`).
  Build clean under `-Werror`; VFS-seam guard clean; both gridftp suites green
  (gsiftp 11/11, verbs 14/14).

  The overlap/overflow security-negatives (a crafted MODE E stream sending a
  block that overwrites a committed range or overflows `offset+count`) are
  guarded in `ftp_eb_recv_block` and belong to the P82.5 evil-actor harness
  (globus won't emit them), tracked next.

  **Still pending (each its own focused pass, per the staged plan):**
  P82.5 hardening (evil-actor MODE E offset attacks) + k8s lab.

  > **Update:** the MODE E offset-attack class is guarded in the event engine —
  > `ftp_ev_mode_e.c` overlap/overflow-checks every accepted block
  > (`ftp_eb_range_overlaps`, transfer aborted on violation), gated by
  > `test_gridftp_mode_e_truncation.py` (interior-hole/out-of-order cases) and
  > the `test_gridftp_evil.py`/`test_gridftp_gsi_evil.py` suites. The **k8s
  > interop lab** (globus-url-copy/gfal2/VOMS container matrix) remains the
  > genuinely-open item.

### P82.6 — pblock storage-backend hook + pre-auth gate (landed 2026-07-17)

Two items, both green, zero new `objs/nginx` growth of note:

1. **Pre-auth reject.** `fc->authed` was write-only (set at USER-when-`sec_active`
   / PASS / GSI-ADAT-complete, never read) — so file/namespace verbs reached the
   VFS on an unauthenticated cleartext session. `ftp_dispatch` now gates every
   verb behind login except a fixed pre-auth whitelist (`USER PASS AUTH ADAT PBSZ
   PROT MIC CONF ENC QUIT FEAT SYST NOOP HELP OPTS`), replying `530` otherwise.
   Transparent to every existing test (all log in first). Covered by
   `test_gridftp_evil.py::test_file_verb_before_login_rejected` (RETR/LIST/MDTM
   pre-login → 530; post-login MDTM → 213/550, proving the gate opens).

2. **pblock backend hook.** `brix_gridftp_storage_backend <name>` (default `""` =
   posix) registers the export's backend at config-merge time via
   `brix_vfs_backend_config_str(cf, root_canon, &sb, 0, BRIX_AF_AUTO)`
   (`ftp_module.c`), so `ftp_vfs_ctx()` on that root resolves to the pblock
   driver — no data-path branch needed, the module only registers the choice.
   (Directive named `brix_gridftp_storage_backend`, not the stream module's own
   `brix_storage_backend`, to avoid the context clash.)

   **The subtle bug this exposed:** the transfer paths wrote/read the object
   through the fd-keyed `brix_vfs_pwrite_full`/`brix_vfs_pread_full`, which
   *wrap the raw fd in the POSIX storage driver* — fine for posix, but for pblock
   they hit block-0's kernel fd directly, bypassing `sd_pblock_pwrite`'s block
   routing and the `os->meta.size`/`dirty` bookkeeping that `sd_pblock_close`
   flushes to the catalog. Result: STOR landed bytes in block 0 but the catalog
   recorded size 0, so RETR read the object back empty. Fix: a new driver-routed
   handle write `brix_vfs_file_pwrite(fh, …)` (`vfs_open_handle.c`, the write twin
   of the existing `brix_vfs_file_pread`) that dispatches to `fh->obj.driver->
   pwrite`; STOR, RETR, and both MODE E paths now use the handle-based calls.
   Posix is unaffected (its driver's pread/pwrite slots are the same syscalls).

   Covered by `tests/test_gridftp_pblock.py` (4 green): STOR/RETR round-trip and
   MODE E parallel STOR both land in the block store (asserted NOT present as a
   plain posix file under the export), missing-object → 550, traversal confined.
   Full native gridftp suite stays green (33 posix + 4 pblock = 37); VFS-seam
   guard clean; `-Werror` build clean.

   s3 backend is likewise still untried through the gateway (the interop matrix
   xfails it).

### P82.7 — backend-agnostic CKSM + self-computed write-verify (landed 2026-07-17)

Two follow-ups to P82.6, both making the gateway trust the storage *driver* for
integrity rather than a raw kernel fd (the class of bug that made pblock STOR
read back empty):

1. **Driver-routed CKSM.** `ftp_cmd_cksm` no longer digests
   `brix_vfs_file_fd(fh)` via `brix_cksum_*_fd` (which POSIX-wraps a bare fd and
   so sees block 0 only on an object backend). It obtains the storage object with
   `brix_vfs_file_sd_obj(fh, &obj)` and calls `brix_cksm_digest_obj` /
   `brix_cksm_u32_obj`, which walk every byte through `obj->driver` — multi-block
   aware, so the whole pblock/rados object is hashed. Posix is unaffected (its
   driver reads the same bytes). Covered by
   `tests/test_gridftp_pblock.py::test_cksm_via_pblock_is_driver_routed` (MD5 +
   CRC32 over a 50 000-byte pblock object match locally-computed values), plus
   missing-object → 550 and traversal-confined negatives.

2. **`brix_gridftp_verify_write on` — self-computed write-verify.** After a STOR
   the gateway re-reads the object through the driver and CRC-checks it against
   the bytes it wrote, so a 226 means the driver *persisted* the content, not
   merely that the write calls returned success. Backend-agnostic: the read-back
   runs `brix_cksum_u32_obj` over whatever driver backs the export.

   - **Reusable VFS-seam facility.** A protocol-neutral accumulator lives in
     `src/core/compat/wverify.{c,h}` (ngx-free: libc + zlib): each written extent
     `[off,off+len)` is CRC-32'd and folded into an offset-sorted list, adjacent
     extents coalesced via `crc32_combine`, so an in-order stream collapses to one
     whole-file CRC and an out-of-order writer (MODE E) converges to the same
     value regardless of arrival order. `brix_wverify_expected()` yields the
     whole-object CRC *only* when the extents cover exactly `[0,total)` — a gap or
     overlap is itself an integrity failure and fails closed. The VFS seam
     `brix_vfs_wverify_check(w, rfh)` (`src/fs/vfs/vfs_wverify.c`) drives the
     read-back compare; it is reusable by webdav PUT / root write / s3 POST, not
     gridftp-specific.
   - **Gateway wiring.** `brix_gridftp_verify_write on|off` (default off — doubles
     read I/O). Both `ftp_stor_file` (stream) and `ftp_stor_mode_e` (parallel)
     feed `brix_wverify_update` from their write loops and call
     `ftp_verify_written` after close; on mismatch the object is unlinked and the
     transfer fails 550, so a corrupt/short write never lingers as a servable
     file. A zero-length object (nothing written, `[0,0)`) skips the read-back.
     Only a fresh offset-0 STOR is verified — REST/APPE writes a partial extent
     and `expected()` would decline, so verify is skipped there.
   - **Tests.** `tests/c/test_wverify.c` (unit: in-order == whole-buffer zlib CRC;
     out-of-order converges to the same; gap/overlap/empty fail closed) via the
     `wverify` `CUnitSpec`. `tests/test_gridftp_verify_write.py` (integration,
     parametrized posix + pblock: verified STOR round-trip, empty STOR, MODE E
     out-of-order STOR all 226 and byte-identical). Full native gridftp suite
     green (35); VFS-seam guard clean; `-Werror` build clean.

   **Still open:** s3 backend untried through the gateway (interop matrix xfails
   it); CKSM partial-range (`off/len` other than `0 -1`) still declined 504.

### P82.8 — s3-through-gateway + CKSM partial-range + unified brix_vfs_writer (landed 2026-07-17)

Closes the two "still open" items above and folds the per-STOR write mechanics
(random-write vs staged/object, plus verify-on-write) behind a single VFS entry
point so every backend gets the same verified write.

1. **Unified `brix_vfs_writer` — one verified-write call for every filesystem**
   (`src/fs/vfs/vfs_writer.c`, API in `vfs_ops.h`). A protocol path opens
   `brix_vfs_writer_open(ctx, flags, verify, &err)`, streams extents with
   `brix_vfs_writer_write(w, buf, len, off)`, and finishes with
   `brix_vfs_writer_commit(w)` / `brix_vfs_writer_abort(w)` — backend dispatch is
   internal. The writer reads `ctx->sd`'s `BRIX_SD_CAP_RANDOM_WRITE` bit
   (`ctx->sd == NULL` ⇒ the POSIX default export ⇒ random-write): a random backend
   (posix, pblock) opens an in-place `O_WRITE` handle and `brix_vfs_file_pwrite`s
   each extent; an object backend (s3/sd_remote — no seekable file, no
   `.pwrite`) opens a `brix_vfs_staged` upload and appends sequentially
   (`off == staged_cursor` enforced; non-sequential ⇒ EINVAL), committed
   atomically. When `verify`, each write folds into a `brix_wverify` accumulator
   and commit re-reads the published object through the driver
   (`brix_vfs_wverify_check`), unlinking on any mismatch. The gridftp STOR paths
   (`ftp_stor_file`, `ftp_stor_mode_e`, `ftp_eb_recv_block`) now hold a single
   `brix_vfs_writer_t *` instead of a raw `brix_vfs_file_t *` + hand-rolled
   `brix_wverify_*`; the old `ftp_verify_written` / `ftp_unlink_object` statics
   are gone. The seam is backend-neutral and reusable by webdav PUT / root write.

2. **s3-through-gateway.** `brix_gridftp_storage_backend s3://host:port/bucket`
   is now a working export. The SigV4 keys arrive through a stream-scope
   `brix_credential <name>` block named by the new
   `brix_gridftp_storage_credential <name>` directive
   (`ftp_gateway.h`/`ftp_module.c`), mapped via the one shared
   `brix_credential_to_backend_cred` (P80.1) onto the export's VFS registry entry.
   Because `brix_vfs_backend_set_credential` runs only at config parse in the
   master and the VFS backend registry is rebuilt per worker, the gridftp module
   gained an `init_process` hook (`brix_ftp_init_process`) that replays the
   credential into each forked worker — mirroring the core stream module's
   `brix_init_server_backend_credential`. Without it a worker holds the s3://
   backend with an empty credential and the first upload fails "no credential set".

   - **Self-deadlock gotcha (test config).** The gateway handler is synchronous
     and the S3 transport (`sd_remote` → `sd_s3`) is a blocking request. A single
     nginx worker that co-hosts both the gateway and the `brix_s3` origin
     deadlocks: the worker parked in the gateway's outbound PUT can't accept the
     inbound S3 connection to itself. `tests/configs/nginx_gridftp_s3.conf` sets
     `worker_processes 2` so a free worker serves the S3 leg. (Production points
     the backend at a separate origin — MinIO — so this only bites the co-hosted
     test.)

3. **CKSM partial-range.** `CKSM <algo> <offset> <length> <path>` with
   `off/len` other than `0 -1` is honoured (was declined 504). The checksum
   kernels grew range variants in `src/core/compat/checksum_core.{c,h}`:
   `brix_cksum_u32_obj_range` / `_u64_obj_range` / `_digest_obj_range`
   (start ≥ 0 first byte; `len < 0` ⇒ to EOF; a range past EOF is clamped;
   `start < 0` ⇒ −1). The whole-object funcs are now thin wrappers over
   `_range(kind, obj, 0, -1, out)`. `ftp_cmd_cksm` validates the range
   (`offset < 0 || length < -1` ⇒ 501) and routes to the range digest, all still
   driver-routed so it works over any backend.

   - **Tests.** `tests/test_gridftp_s3.py` (STOR/RETR round-trip, CKSM
     whole-object + partial range, empty STOR — all through the s3 object store,
     staged upload + read-back verify). `tests/test_gridftp_verbs.py` gained
     `test_cksm_partial_range` (non-trivial extent, MD5 sub-range, past-EOF clamp)
     and `test_cksm_malformed_range_rejected` (`-1 8` and `0 -2` ⇒ 501). The
     interop matrix's `test_nonposix_backend_matrix` xfail placeholder is retired
     (both backends are wired; native suites cover them; the gsiftp cluster cell
     is the remaining container-tier work). Full native gridftp suite green (40);
     VFS-seam guard clean; `-Werror` build clean.

---

## §2 realization — non-blocking event engine (landed 2026-07-17)

The shipped gateway (`ftp_handler.c`) is the **synchronous** engine described as
the POC in §1.2/§5: it blocks in `read()`/`write()` and serves one client per
worker. The §2 event-driven design is now realized as a compact **8-file `ev/`
tree** (`src/protocols/gridftp/ev/`) that reimplements the control plane as a
non-blocking nginx STREAM module, coexisting with the sync engine behind a
feature flag. This is the "modify the gridftp support to be a non-blocking STREAM
module spread across many files" work; it deliberately keeps the sync engine
shipping and green as the parity oracle rather than editing it in place.

**Engine selection.** New directive `brix_gridftp_engine sync|event` (default
`sync`). `ftp_gateway.h` gains `ngx_uint_t engine` + the `BRIX_FTP_ENGINE_*`
enum; `ftp_module.c` installs `brix_ftp_ev_handler` vs `brix_ftp_handler` as the
stream content handler via a shared `brix_ftp_install_handler`, called from both
the enable and the engine setters so the result is independent of directive order
(the engine directive may precede or follow `brix_gridftp on`). Both engines
share `ftp_gateway.h`, the `gsi_mech.c` mem-BIO GSSAPI engine, and the
`brix_vfs_*` seam — the event tree adds no storage or auth code.

**The `ev/` tree (all `src`-rooted includes; the parent `ftp_gateway.h` is
reached as `protocols/gridftp/ftp_gateway.h`, one dir up):**

| File | Role |
|------|------|
| `ftp_ev.h` | per-connection `ftp_ev_t` state machine, buffer geometry, cross-file decls |
| `ftp_ev_io.c` | the engine: content handler, read/write event handlers, buffered flush, command-framing loop (`brix_ftp_ev_process`), idempotent finalize |
| `ftp_ev_reply.c` | reply framing into `->ob` (cleartext or GSS-wrapped), base64 codecs |
| `ftp_ev_path.c` | line split, `brix_http_resolve_path` confinement, VFS ctx build |
| `ftp_ev_dispatch.c` | the dispatcher + one-line stateless verbs; pre-auth gate |
| `ftp_ev_cmd.c` | namespace/metadata verbs (CWD/SIZE/MKD/DELE/RMD/MDTM/MLST/STAT/CKSM/RNFR/RNTO) |
| `ftp_ev_sec.c` | RFC 2228 GSI control handshake (AUTH/ADAT/MIC/CONF/ENC) |
| `ftp_ev_data.c` | data-channel lifecycle (P82.2) — PASV/EPSV/PORT/EPRT setup, non-blocking passive-accept + active-connect bring-up, PROT P → `brix_ftp_ev_dc_start_tls` handoff (P82.3), `data_finish`→SSL shutdown + control resume |
| `ftp_ev_xfer.c` | data-transfer verbs (P82.2) — RETR/STOR/APPE/LIST/NLST/MLSD pumps over the `brix_vfs_*` seam; PROT P via the TLS-swapped vtable (P82.3), MODE E → 502 (P82.4) |
| `ftp_ev_tls.c` | non-blocking PROT P data-channel TLS (P82.3) — `ngx_ssl_create_connection` + `ngx_ssl_handshake` over the shared `ftp_dc_sec` core (deleg cred + policy + post-handshake DN pin); nginx swaps `c->recv/send` so the xfer pumps run over TLS unchanged |

**Engine model.** `brix_ftp_ev_process()` is one loop that (1) drains any queued
reply, (2) frames one CRLF command out of the inbound buffer and dispatches it,
or (3) reads more bytes — running until an op would block (arm the matching event
+ idle timer, return) or the session ends. Commands are processed **lock-step**:
the next command is dispatched only after the current reply fully drains, which
bounds outbound buffering to one reply and mirrors the half-duplex control
channel. Buffer geometry is kept **identical to the sync engine** (128 KiB
inbound to hold a GSI ADAT client-cert flight on one line, 64 KiB outbound) for
behavioural parity — not the doc's aspirational 512/4096 caps, which would break
ADAT. Idle deadline `BRIX_FTP_EV_IO_TIMEO` = 30 s on both read and write.

**GSI is nearly free on the control channel.** `brix_gssapi_srv_step` is
token-driven, not socket-driven — each ADAT command line carries one handshake
token and the reply carries the next — so the control-channel GSI handshake ports
to the event model with no state-machine surgery (`ftp_ev_sec.c` mirrors the sync
`ftp_cmd_auth/adat/protected` + `ftp_gss_finalize`). Only **PROT P data-channel
TLS** was genuinely event-hard; it landed in P82.3 (below) driven through nginx's
own SSL connection layer rather than a hand-rolled WANT_READ/WANT_WRITE loop.

**Status (P82.1 landed).** The full control plane runs non-blocking: login, the
GSI handshake, session/transfer-parameter verbs, navigation, and every
namespace/metadata verb (with live `brix_vfs_*` round trips + INVARIANT-4
confinement). Data verbs (PASV/EPSV/PORT/EPRT/RETR/STOR/APPE/LIST/NLST/MLSD) fail
closed with an honest 502 until the event data-channel pump (P82.2) lands.

**Status (P82.2 landed, 2026-07-17).** Cleartext STREAM-mode data transfers run
fully non-blocking. `ftp_ev_data.c` brings up the data channel both ways:
passive (`ev_do_pasv`/`_epsv` → non-blocking listener bound to the control's
local IP, `ev_accept_handler` on the read event) and active (`ev_do_port`/`_eprt`
→ anti-bounce pin against the control peer + `brix_net_target_check_addr` SSRF
screen, then non-blocking `connect()` confirmed via `ev_connect_handler`
getsockopt SO_ERROR). Immediate connects deliberately defer to the write event so
the data pump never re-enters the control loop from inside itself. The three
pumps in `ftp_ev_xfer.c` — `ev_retr_write` (VFS→socket, refill via
`brix_vfs_file_pread`), `ev_stor_read` (socket→VFS via `brix_vfs_writer_*` with
commit/abort + write-verify), `ev_list_fill`/`_write` (LONG/MLSD/NLST batch
formatting, line-split-safe) — each drives one half-duplex direction, arming its
event + `IO_TIMEO` timer on `NGX_AGAIN`. `brix_ftp_ev_data_finish` closes the VFS
side, tears down the data connection, queues 226/550, and resumes the control
loop from the data-connection event stack (never nested). REST offsets clamp;
RETR stat-validates (550 on missing/dir); the write gate (INVARIANT 3) refuses
STOR/APPE with 550 before any channel opens; path traversal stays confined
(INVARIANT 4). VFS-seam guard clean (data.c uses only NETWORK syscalls — socket/
accept/connect/bind — never file-data POSIX). Coverage:
`tests/test_gridftp_engine_event.py` grows to 15 (9 new: passive+active RETR,
STOR→RETR round trip with on-disk verification, REST partial, LIST+NLST, missing
→550, no-PASV→425, traversal confinement, read-only-export STOR→550). Sync parity
oracle unchanged and green (34: verbs+evil+pblock+verify_write).

**Status (P82.3 landed, 2026-07-17).** The DCAU A / PROT P data channel runs
fully non-blocking. The security-critical cert logic (present the delegated user
credential, PKIX-verify the peer proxy chain, pin its DN to the control identity)
was extracted verbatim from the sync engine into a shared core —
`src/protocols/gridftp/ftp_dc_sec.{c,h}` (`brix_ftp_dc_load_deleg` /
`brix_ftp_dc_apply_policy` / `brix_ftp_dc_gsi_check`) — and the sync engine
(`ftp_handler.c`) was rewired onto it (behaviour-preserving; its green GSI/dcpriv
suite is the extraction's oracle). The new `ftp_ev_tls.c` drives the handshake
non-blocking through nginx's SSL connection layer: the wrapped data connection
gets a per-transfer pool (`dc->dpool`), `ngx_ssl_create_connection` (server on a
passive accept, `NGX_SSL_CLIENT` on an active connect — the TPC leg), the shared
core installs the deleg cred + TLS-1.2/proxy policy, and `ngx_ssl_handshake` arms
the data connection's own read/write events on WANT_READ/WANT_WRITE. On
completion `ev_dc_tls_done` runs the post-handshake DN pin then hands to
`brix_ftp_ev_data_ready`; because nginx has already swapped `c->recv/c->send` to
`ngx_ssl_recv/ngx_ssl_write`, the RETR/STOR/LIST pumps move TLS records with **no
change**. `brix_ftp_ev_data_finish` now `ngx_ssl_shutdown`s the data connection
(synchronous free) before `ngx_close_connection` and destroys `dc->dpool`.
VFS-seam guard clean (tls.c touches only OpenSSL/nginx-SSL, no file-data POSIX).
Coverage: `tests/test_gridftp_gsiftp_ev.py` (5 — PROT P LIST/GET/PUT success,
missing-object error, untrusted-CA security-neg) driven by real `globus-url-copy
-dcpriv` against the `nginx_gridftp_gsiftp_ev.conf` gateway. Sync parity oracle
unchanged and green (40: verbs+gsiftp+pblock+verify_write); event cleartext suite
unchanged (15).

**Build/test.** 8 files added to repo-root `./config` (`ngx_module_srcs`/`_deps`
for `ngx_stream_brix_ftp_module`); reconfigure with the **literal** `--add-module`
path. Configs `nginx_gridftp_plain_ev.conf` / `nginx_gridftp_gsiftp_ev.conf`
mirror the sync templates with `brix_gridftp_engine event`. Coverage:
`tests/test_gridftp_engine_event.py` (7 tests — success control-plane + VFS round
trips, error paths, pre-auth 530 gate, path-traversal 550 confinement, the 502
data-channel boundary). Sync parity oracle unchanged and green
(`test_gridftp_verbs.py` + `test_gridftp_evil.py` = 21). VFS-seam guard clean;
`-Werror` build clean (0 errors, all 7 `ev/` objects compiled).

**Status (P82.4 MODE E landed, 2026-07-17).** MODE E extended-block transfers run
fully non-blocking on the event engine. The wire codec + committed-range overlap
guard were factored into a header-only shared core —
`src/protocols/gridftp/ftp_eblock.h` (`ftp_eb_pack`/`ftp_eb_unpack`,
`ftp_eb_range_overlaps`, `static ngx_inline` so a TU using only the codec compiles
clean under `-Werror`) — so both engines frame identically and cannot drift. The
new `ev/ftp_ev_mode_e.c` implements: (1) **RETR** — `brix_ftp_ev_retr_mode_e_start`
installs a write pump that prepends the 17-byte header to each `brix_vfs_file_pread`
chunk (buffer bumped to `XFER_BUF + FTP_EB_HDR`) and closes with a combined EOF|EOD
trailer (`eb_phase` 0 data → 1 trailer → 2 done); (2) **STOR** — a passive listener
handler `brix_ftp_ev_eb_accept` that (unlike the single-accept `ev_accept_handler`,
selected in `brix_ftp_ev_data_open` by `dc->mode_e && dc->writing`) keeps accepting
every parallel stream globus opens at once, wraps each in a child connection
(`brix_ftp_ev_wrap_conn`, exported from `ftp_ev_data.c`), starts its PROT P
handshake through the shared `brix_ftp_ev_tls_begin`/`_verify` primitives, and arms
a per-stream block reader `ev_eb_child_read` — which accumulates the 17-byte header,
reserves the block's absolute range against the shared overlap table *before*
reading payload, writes via `brix_vfs_writer_write` at that offset, and retires the
stream on EOD; the transfer commits (whole-object read-back verify) once the
EOF-declared EOD count is seen; (3) **markers** — best-effort 111 range (coalesced
committed ranges) + 112 perf every ~1 MiB. **Re-entrancy discipline:** child
readers are kicked via `ngx_post_event` so a transfer that completes on the last
EOD tears the listener down from a *posted* stack, never nested inside the accept
loop; `ngx_close_connection` cancels a child's posted read, so teardown is safe.
INVARIANT-4 confined; VFS-seam guard clean (`mode_e.c` moves data only through
`brix_vfs_*` and the child sockets via NET syscalls). MODE E STOR is passive-only
(504 on active — a single connect cannot carry the fan-in). Coverage:
`tests/test_gridftp_mode_e_event.py` (7 — RETR round-trip, out-of-order STOR,
4-way parallel fan-in, overlap/overflow/short-frame rejection, missing-object
error, all over cleartext raw sockets) **plus** three real-`globus-url-copy -p 4
-dcpriv` cases added to `tests/test_gridftp_gsiftp_ev.py` (MODE E GET/PUT over
parallel PROT P streams + gsiftp↔gsiftp TPC between two event gateways = 8 total).
Full gridftp suite green on both engines: event MODE E 7 + gsiftp_ev 8 + engine_event
15 + sync mode_e 4 + sync gsiftp 11 + verbs/evil/gsi_evil/pblock/verify_write/s3 45.

**Landed (P82.4 final — sync-engine retirement, 2026-07-17).** The event engine is
now the *only* engine; `ftp_handler.c` and the `brix_gridftp_engine` directive are
gone. Sequence executed as planned: (1) flipped the module default to `event`;
(2) ran the full sync suite unchanged (now on event) — 41 green, deterministic
across repeated runs (the one batch-run overlap-test failure was cross-file fleet
contention, not a parity gap: `test_gridftp_mode_e.py` alone passed the overlap
case every time); (3) once green, deleted `ftp_handler.c` (~2200 lines, all 51
helpers static, sole extern `brix_ftp_handler` referenced nowhere), dropped it from
`config`, and removed the engine machinery from the module: the `engine` field +
`BRIX_FTP_ENGINE_*` enum (ftp_gateway.h), the create/merge unset+default, the
`brix_ftp_set_engine` setter, and the `brix_gridftp_engine` command — `brix_ftp_
install_handler` now hardwires `cscf->handler = brix_ftp_ev_handler`. `ftp_dc_sec.
{c,h}` are kept (data-channel GSI security, now event-only). The three `_ev` test
configs dropped their now-invalid `brix_gridftp_engine event;` line (the non-`_ev`
sync-oracle configs already relied on the default). Reconfigured with the literal
`--add-module` path, clean rebuild, VFS seam clean. Full parity sweep on the event
engine: **90 green** — 63 (mode_e + mode_e_event + verbs + evil + pblock +
verify_write + s3 + engine_event) plus 27 (gsiftp + gsiftp_ev + gsi_evil). No
functional reference to the removed engine machinery remains in `src/`, `config`,
or `tests/configs/`. Phase-82 §2 (event-engine realization) is complete: the
gateway ships a single non-blocking STREAM engine.

---

## P82.9 — GSI credential delegation to an xrootd backend (2026-07-17)

**Goal (verbatim OP request).** "Ideally I want a gridftp connection to be able to
fully delegate an x509 client credential to an xrootd backend, the idea being to
provide a legacy gsiftp gateway to an xrootd only storage system." End-to-end GSI
identity forwarding: a gsiftp client delegates an X.509 proxy on the control
channel → the gateway reuses that delegated proxy → it authenticates to an upstream
`root://` xrootd storage server *as the user*.

**Design (OP decisions).** (1) Gating: reuse the `brix_credential` block's mode
field, defaulting to forward. A `mode` field was ADDED to `brix_credential`
(`select|passthrough|exchange|delegate|mint|auto`, `credential_block.{c,h}`,
`brix_credential_mode_token()`); `NGX_CONF_UNSET` ⇒ the consumer's default. (2)
Scope: wiring + a self-contained native loopback E2E test (success + error +
security-neg).

**Naming note.** The OP said "delegate by default", but the codebase reserves
`DELEGATE` for a *fresh* GridSite re-delegation handshake; forwarding a captured
full proxy verbatim is `PASSTHROUGH` (see `op_path.c` — root:// and WebDAV both
bind a captured proxy only under `BRIX_CRED_PASSTHROUGH`). So the gateway's default
*effective* mode is PASSTHROUGH (behaviourally "delegate the client credential"),
overridable per credential block (`mode select` = pin the service identity, never
forward).

**Wiring.**
- `ftp_gateway.h` gains `enum brix_cred_mode deleg_mode`; `ftp_module.c` sets it to
  `BRIX_CRED_PASSTHROUGH` at merge for an enabled export, then lets a named
  credential block's explicit `mode` override it in `install_backend_credential`.
- `vfs_deleg.c`/`vfs.h` add `brix_vfs_backend_accepts_proxy(ctx)` — true only when
  the leaf backend's `cred_accept` carries `BRIX_SD_CRED_PROXY_PEM` (xroot/s3). The
  request-time bind is gated on it, so a posix/pblock export never routes a proxy
  bag through `brix_vfs_deleg_live_cred` (which would DENY, lacking the accept bit)
  — existing gsiftp+posix transfers are untouched.
- `ev/ftp_ev_path.c` `brix_ftp_ev_vfs_ctx()` forwards the delegated proxy: gated
  three ways (a proxy was delegated **and** mode ≠ SELECT **and** the backend
  accepts a proxy), it binds the assembled chain via `brix_vfs_deleg_bind`.

**The chain-assembly bug (the hard part).** The credential captured at GSSAPI
finalize (`fc->deleg_proxy`, from `SSL_get_peer_cert_chain()` server-side) (a) OMITS
the delegated leaf's direct issuer — the peer's own control leaf, which OpenSSL
excludes server-side; the PROT P data channel already compensates with a separately
captured `fc->ctrl_leaf_pem` — (b) carries certs OUT OF ISSUER ORDER, and (c)
includes the self-signed CA. XrdSecgsi walks the presented chain strictly and
rejects all three as **`ErrParseBuffer: certificate chain verification failed:
chain is inconsistent: kXGC_cert`**. Fix: `brix_ftp_ev_forward_pem()` rebuilds a
clean RFC 3820 chain — parse every cert (capture + control leaf), find the leaf by
matching the private key, walk issuer→subject links emitting leaf → … →
end-entity, STOP before the self-signed trust anchor (the upstream trusts the CA
out of band; a forwarded CA breaks the walk), serialize ordered certs + key. The
issuer-walk is bounded by the cert count (a hostile client could delegate a
cross-signed A⇄B pair with no self-signed terminus → worker spin). All OpenSSL
temporaries freed before return; result owned by the connection pool. GOTCHA:
string-splicing the missing issuer before the key block was NOT enough — order and
CA-stripping both matter; only a parse/reorder/filter assembler satisfies XrdCrypto.

**Native loopback E2E** — `tests/test_gridftp_delegate_xrootd.py` (+ config
`tests/configs/nginx_gridftp_gsiftp_ev_xrd.conf`). A stock GSI `xrootd` on the
SHARED test PKI (`$TEST_ROOT/pki`, so the client-minted proxy verifies against the
same CA/host cert the gateway trusts; `-gridmap:none` keeps the raw DN; connect via
`localhost` to match the host cert CN) fronted by an event gsiftp gateway whose
`brix_gridftp_storage_backend root://localhost:<port>` + `brix_gridftp_storage_
credential gsixrd` (block supplies only `ca_dir` for origin verification). Three
cases, all green: (1) **success** — default PASSTHROUGH, `globus-url-copy -dcpriv`
GET round-trips byte-identical AND the upstream log shows `login as
…/CN=Test User/…` (the keystone: identity crossed client → gateway → storage); (2)
**error** — RETR of an absent object → nonzero client rc; (3) **security-neg** —
credential block `mode select` forwards nothing, the upstream (no service cred)
refuses, the transfer fails, and no NEW user-DN login is recorded. GOTCHAS: default
xrootd does NOT log successful GSI logins (need `sec.trace 2` + `xrootd.trace login
auth`); `xrootd -n <inst>` relocates the `-l` logfile into an instance subdir
(dropped `-n` so `log_text()` finds it); nginx clears custom env vars in workers
(`ngx_set_environment`) so a `getenv`-gated debug dump silently no-ops — dump to a
fixed path when instrumenting a worker.

**Verification.** 74 native gridftp tests green (delegate_xrootd 3 + gsiftp_ev 8 +
engine_event 15 + pblock/verify_write 13 + verbs/evil/s3/mode_e/mode_e_event 35);
VFS seam clean (the new OpenSSL cert work is pure crypto — no data syscalls).
BACKENDS reachable through the gateway now: posix + pblock + s3 + **xroot (GSI
identity-forwarding)**.
