# query — XRootD `kXR_query` sub-protocol, `kXR_prepare` staging, and `kXR_set` hints

## Overview

The XRootD wire protocol folds a large family of mostly read-only metadata
operations into a single opcode, `kXR_query`, whose `infotype` field selects a
"sub-protocol": checksums, filesystem space, server capabilities, statistics,
extended attributes, and several opaque/visa plugin hooks. This subsystem
implements that opcode dispatcher plus two adjacent metadata opcodes that share
the same machinery and confinement rules: `kXR_prepare` (storage-staging hints)
and `kXR_set` (advisory client/CMS hints). All three are `root://` / `roots://`
**stream** operations — there is no HTTP/WebDAV or S3 path through this directory.

Execution enters from the handshake opcode router after login/auth completes:
`../handshake/dispatch_read.c` routes `kXR_query` → `brix_handle_query` and
`kXR_prepare` → `brix_handle_prepare`, while `../handshake/dispatch_session.c`
routes `kXR_set` → `brix_handle_set`. `brix_handle_query` (`dispatch.c`) then
fans out by `ntohs(req->infotype)` to one of ~14 handlers declared in
`query_internal.h`, returning `kXR_Unsupported` for any unrecognized infotype.

The two operations that touch real file bytes — `kXR_Qcksum` (checksum one file)
and `kXR_Qckscan` (checksum a file or a whole subtree) — can be expensive, so
they run on the nginx thread pool when one is configured and fall back to a
synchronous event-loop path otherwise. Both variants are written to produce
byte-identical wire responses; the async `_done` callback restores the request
streamid and re-arms the connection exactly like the `../read` data plane.
Everything else (space, fsinfo, config, stats, xattr, prepare-status, the opaque
stubs) is cheap enough to answer inline on the event loop.

This subsystem is heavily compatibility-driven. Response strings, the default
algorithm (`adler32`, the `xrdcp` default), the bare-numeric `tpc` / `QFSinfo`
formats, and the FSctl/fctl "unsupported" shapes are all chosen so the reference
`XrdCl` client parsers accept them. The opaque/visa subtypes deliberately mirror
the reference server's "FSctl/fctl operation not supported" reply because
nginx-xrootd does not embed the `XrdOfs` plugin layer.

## Files

| File | Responsibility |
|---|---|
| `dispatch.c` | `brix_handle_query` — the `kXR_query` dispatcher; switches on `ntohs(req->infotype)` to each sub-handler; `kXR_Qvisa` is rejected with `kXR_ArgInvalid` if `ctx->cur_dlen != 0`; unknown infotypes return `kXR_Unsupported`. |
| `query_internal.h` | Internal header: shared prototypes for every sub-handler, the two AIO context structs (`brix_cksum_aio_t`, `brix_ckscan_aio_t`), the standalone checksum helper prototypes, and the caps `BRIX_CKSCAN_INIT_CAP` (256 KiB) and `BRIX_PREPARE_CMD_MAX_PATHS` (512). |
| `checksum_qcksum.c` | `kXR_Qcksum` (`brix_query_cksum`) — single-file checksum by path (`cksum_path`: full auth chain + confined open + manager/cache-origin redirect) or by open handle (`cksum_handle`); posts a thread task or computes synchronously. Default algo `adler32`. |
| `checksum_qcksum_async.c` | Thread-pool worker + completion for `kXR_Qcksum`: `brix_cksum_aio_thread` computes off-loop via `brix_integrity_get_fd`; `brix_cksum_aio_done` closes any path-opened fd, sends the result, and resumes the connection. |
| `checksum_ckscan_dispatch.c` | `kXR_Qckscan` entry (`brix_query_ckscan`): parses an optional `algo:`/`algo ` prefix, confines the path, runs the auth gate, then posts a thread task or runs the synchronous `brix_ckscan_sync` fallback. |
| `checksum_ckscan_async.c` | Thread-pool worker + completion for `kXR_Qckscan`: `brix_ckscan_aio_thread` stats the target and walks it into a grown buffer; `brix_ckscan_aio_done` sends the buffer and frees it. |
| `checksum_ckscan_common.c` | Shared scan helpers: `brix_ckscan_append` (grow the `"algo <hex>  logical\n"` buffer — `<hex>` is the precomputed checksum, 8 chars for adler32/crc32c, 16 for crc64/crc64nvme, so the line format is width-agnostic), `brix_ckscan_join_logical` (parent+child logical-path join with `/`-root special case), `brix_ckscan_walk` (recursive, depth/file-capped tree walk skipping dot-entries and unreadable files). |
| `space.c` | `kXR_Qspace` (`brix_query_space`, `oss.*` key/value capacity report) and `kXR_QFSinfo` (`brix_query_fsinfo`, compact `wVal freeMB util sVal freeMB util` form used by client redirect logic), both via `brix_fs_usage_stat` / `statvfs`. |
| `config.c` | `kXR_Qconfig` (`brix_query_config`) — best-effort capability query; answers `chksum`, `readv`, `tpc`, `tpcdlg`; unknown keys as `key=0`; `tpc` emits a bare digit for `XrdCl` compatibility. Empty query → `send_ok(NULL, 0)`. |
| `metadata.c` | `kXR_QStats` (`brix_query_stats`, XML server stats), `kXR_Qxattr` (`brix_query_xattr`, `oss.*` attrs + `user.U.*` xattrs — its stat goes through `brix_vfs_probe` and its list/get through the VFS xattr seam, never raw `stat`/`listxattr`), `kXR_QFinfo` (`brix_query_finfo`, placeholder `"0"`), and the `Qvisa`/`Qopaque`/`Qopaquf`/`Qopaqug` FSctl/fctl hooks that validate then return reference-compatible "unsupported". |
| `prepare.c` | `kXR_prepare` (`brix_handle_prepare`) staging-hint handler and `kXR_QPrep` (`brix_query_prep_status`) per-path availability query. FRM-off mode returns legacy `A <path>` / `M <path>` lines and request id `"0"`; FRM-enabled mode delegates durable queue state and request ids to `../frm/`. Includes the `..`/`.` pre-check `brix_prepare_has_forbidden_component`. |
| `prepare_cmd.c` | `brix_prepare_invoke_command` — fire-and-forget **double-fork** + `execv` of the configured `brix_prepare_command` with confined, auth-checked absolute paths; closes all inherited fds ≥ 3 in the grandchild. |
| `set.c` | `kXR_set` (`brix_handle_set`) — accepts advisory hints; parses/logs `appid` `"cms.space <total> <free>"` capacity reports and `clttl` TTL hints; always replies `kXR_ok`. (Includes `ngx_brix_module.h` directly, not `query_internal.h`.) |
| `util.c` | Standalone file/fd checksum helpers (`brix_query_adler32_{fd,file}`, `brix_query_crc32_{fd,file}`, `brix_query_digest_{fd,file}`) wrapping `../compat/checksum`; the `_file` variants use `brix_open_confined` + `brix_sanitize_log_string`. |

## Key types & data structures

- **`ClientQueryRequest`** (wire struct from `../protocol`): carries `infotype`
  (big-endian, needs `ntohs`) and `fhandle[]` (handle index for handle-based
  Qcksum / Qvisa / Qopaqug). Cast directly from `ctx->hdr_buf`.
- **`ClientPrepareRequest`** (`prepare.c`): `options` (`kXR_stage` / `kXR_wmode` /
  `kXR_cancel` / `kXR_noerrs` / `kXR_notify` / `kXR_coloc`) and `optionX`
  (big-endian, `kXR_evict`). **`ClientSetRequest`** (`set.c`): the `modifier`
  byte (`kXR_set_appid` / `kXR_set_clttl`).
- **`brix_cksum_aio_t`** (`query_internal.h`): per-request `kXR_Qcksum` thread
  context. The `close_fd` flag encodes fd ownership — `1` for path-based requests
  (the worker owns the fd; `_done` must close it), `0` for handle-based requests
  (the session keeps ownership). Also holds `streamid`, `algo`, the `resp`/
  `error_*` result fields, and copies of `ctx`/`c`/`conf`.
- **`brix_ckscan_aio_t`** (`query_internal.h`): per-request `kXR_Qckscan`
  thread context. Holds the persistent `rootfd`, the `scan_logical` target,
  `algo`, the `max_depth`/`max_files` caps, and a heap-allocated `resp`/`resp_len`
  the worker grows and `_done` frees.
- **`ctx->prepare_paths` / `prepare_paths_len` / `prepare_reqid[32]`**
  (`../types/context.h`): legacy FRM-off per-session staging state set by a
  `kXR_stage` prepare so a later `kXR_QPrep` with no inline paths can report
  status against the original list. `prepare_paths` is `ngx_alloc`-d and
  freed/replaced on each new stage; in this fallback mode `prepare_reqid` is
  `"0"`. With `brix_frm on`, durable request records and real reqids live in
  `../frm/` and survive disconnect/restart.
- **Response wire shapes** worth remembering: Qcksum = `"algo hexvalue"`;
  Qckscan = newline-delimited `"algo <hex>  logical_path"` lines (hex width per
  algorithm: 8 for adler32/crc32c, 16 for crc64/crc64nvme); Qspace =
  `oss.cgroup=default&oss.space=…&oss.free=…&oss.maxf=…&oss.used=…&oss.quota=-1`;
  QFSinfo = `"wVal freeMB util sVal freeMB util"` (both halves identical, `wVal`/
  `sVal` = `1`); QStats = an `<statistics>…</statistics>` XML document; QPrep =
  FRM-off `"A <path>"` / `"M <path>"` lines or FRM-backed queued/staging/failed/
  available status lines.

## Control & data flow

Entry is always one stream opcode dispatched after auth by `../handshake`
(`dispatch_read.c` for query/prepare, `dispatch_session.c` for set). Inside the
subsystem the handlers call out to:

- **Path confinement** for every client-supplied path: `brix_extract_path`
  parses the wire bytes into a logical path, `brix_beneath_full_path` builds the
  absolute path (for logging/auth), and the confined openers
  `brix_open_beneath` / `brix_stat_beneath` perform the syscall under
  `RESOLVE_BENEATH` — see `../path/README.md`. No raw `open`/`stat` on a wire path.
- **Authorization** uses the shared `brix_auth_gate` (Qcksum / Qckscan / Qxattr
  / Qopaquf) or the explicit `authdb → VO ACL → token scope` triple
  (`brix_check_authdb`, `brix_check_vo_acl_identity`, `brix_check_token_scope`
  in prepare / QPrep), all `BRIX_AUTH_READ`. See `../path/README.md`.
- **Checksum math** is delegated to `../compat/README.md`: `brix_integrity_get_fd`
  (with xattr-cache opts) for Qcksum, `brix_checksum_u32_fd` for the Qckscan
  walk, and `brix_checksum_parse` for algorithm name → enum.
- **Async offload** uses `../aio/README.md`: `ngx_thread_task_alloc`,
  `brix_task_bind`, `brix_aio_post_task` (which falls back to sync if the
  queue is full), `brix_aio_restore_request`, and `brix_aio_resume`.
- **Cluster behavior** (Qcksum, path variant): in `manager_mode` the query is
  bounced like `stat`/`open` — `brix_srv_select` against the SHM registry
  (`../manager/README.md`) yields `BRIX_RETURN_REDIR`; a registry miss triggers
  an async `kYR_locate` to the parent via `../cms/README.md`
  (`ngx_brix_cms_send_locate`, `brix_pending_insert`, `XRD_ST_WAITING_CMS`,
  returning `NGX_AGAIN`). On a data server, a read-through cache miss (`ENOENT`
  with `cache_origin_host` set) redirects to the origin instead of returning
  not-found.
- **Filesystem capacity** (`space.c`) is read via `brix_fs_usage_stat`
  (`../compat/fs_usage.h`).
- **Responses** are framed by `../response/README.md`: `brix_send_ok`,
  `brix_send_error`, and the macros `BRIX_RETURN_OK` / `BRIX_RETURN_ERR` /
  `BRIX_RETURN_REDIR`. `kXR_prepare kXR_notify` builds a combined ok+notify
  buffer with `brix_build_resp_hdr` + `brix_build_attn_asyncms_frame` and
  sends it via `brix_queue_response`.
- **Metrics & access log**: every handler bumps a fixed `BRIX_OP_QUERY_*`
  (or `BRIX_OP_SET`) ok/err slot via `BRIX_OP_OK` / `BRIX_OP_ERR`
  (`../metrics/README.md`) and emits an `brix_log_access` line.

## Invariants, security & gotchas

- **Confine first, always.** Every wire path is run through `brix_extract_path`
  + `brix_open_beneath` / `brix_stat_beneath` (kernel `RESOLVE_BENEATH`)
  before any I/O. `prepare.c` additionally rejects `.` / `..` path components via
  `brix_prepare_has_forbidden_component` as a fast pre-check before resolution.
  The `util.c` helpers use `brix_open_confined` + `brix_sanitize_log_string`.
- **AIO fd ownership is encoded in `close_fd`.** In `checksum_qcksum_async.c`
  the worker-opened (path) fd is closed in `_done` *before* the
  `brix_aio_restore_request` destroy check, so the fd is never leaked even if
  the client disconnected mid-flight. Handle-based requests (`close_fd=0`) must
  never close the session's fd. The Qckscan `_done` frees `t->resp` on both the
  success and the early-return (destroyed-connection) path.
- **Sync and async paths must stay byte-identical.** `brix_ckscan_sync`
  (`checksum_ckscan_dispatch.c`) deliberately mirrors `brix_ckscan_aio_thread`
  (same stat → open → walk → append → caps). Change one, change both. The same
  discipline holds for Qcksum's `brix_query_build_checksum` vs the thread worker.
- **`kXR_Qckscan` is the only client op here that fans out to a whole subtree.**
  It is bounded by `conf->ckscan_max_depth` / `conf->ckscan_max_files`; unreadable
  files and dot-entries are silently skipped, not errored. `brix_ckscan_append`
  returns `0` (skip) when one output line would overflow its `snprintf` buffer.
- **Algorithm rules differ per op.** Qcksum accepts adler32 / crc32 / crc32c /
  crc64 / crc64nvme / md5 / sha1 / sha256 (default adler32); Qckscan accepts
  adler32 / crc32c / crc64 / crc64nvme (`brix_ckscan_algorithm_supported`),
  also defaulting to adler32. (`crc64` = CRC-64/XZ, `crc64nvme` = CRC-64/NVME;
  stock XRootD ships no crc64 calculator, so these are this gateway's de-facto
  convention — 16 lowercase hex over the wire.) The Qckscan algo prefix is only
  parsed up to the first `/` so that paths containing `:` are not misread.
- **`kXR_Qconfig tpc` must be a bare digit.** `XrdCl::Utils::CheckTPCLite` parses
  the first response line with `isdigit()` + `atoi()`; a `tpc=` prefix would make
  the client reject TPC. The `tpc` capability is `allow_write && thread_pool`.
- **Opaque / visa / finfo are intentional stubs.** They validate the request
  (handle index, payload presence, auth) and then return the reference-server
  "FSctl/fctl operation not supported" / placeholder `"0"`. The one special case:
  `kXR_Qopaqug` with payload exactly `"ofs.tpc cancel"` returns `kXR_FSError`
  "tpc operation not found" to match reference TPC-cancel semantics.
- **`kXR_prepare` is fail-closed on writes** (`kXR_wmode` requires `allow_write`,
  else `kXR_fsReadOnly`) and **fail-soft on missing files only under `kXR_noerrs`**
  (a not-yet-staged file is counted in `missing`, not errored; without `noerrs` a
  missing file is `kXR_NotFound` and a directory target is `kXR_isDirectory`).
  In FRM-off mode `kXR_cancel` / `kXR_evict` are accepted as no-ops; with
  `brix_frm on`, `kXR_cancel` removes queued records and `kXR_evict` is treated
  as backend-delegated. See `../frm/README.md`.
- **`kXR_QPrep` treats unauthorized as missing.** Both non-existent and
  auth-denied paths are reported as `M`, matching reference behavior — the auth
  triple and the `S_ISREG` stat must all pass for an `A`.
- **`kXR_prepare kXR_notify` has two modes.** In FRM-off mode it only fires when
  nothing is missing: the handler sends a combined `kXR_ok` +
  `kXR_attn`/`kXR_asyncms` buffer in one write, and omits notification for
  still-missing files. With FRM enabled, durable queue state is the authority for
  completion/progress behavior.
- **Staging exec is double-forked.** `prepare_cmd.c` forks twice so the grandchild
  reparents to init — without this the staging script's `SIGCHLD` would reach the
  nginx worker (whose process table doesn't know the pid) and crash it. The parent
  `waitpid`s only the first child (which exits immediately, so it does not stall
  the event loop). The grandchild closes all fds ≥ 3 (via `/proc/self/fd`, with a
  brute-force fallback) and `execv`s directly (no shell → no injection); paths are
  already confined + auth-checked by the caller. Launch failure is best-effort:
  the client still gets `kXR_ok`.
- **`kXR_set` never rejects.** Per spec it always returns `kXR_ok`; it parses the
  `appid` `"cms.space"` report for logging only (no enforcement) and logs other
  modifiers at debug level.
- **Low-cardinality metrics.** Handlers increment fixed `BRIX_OP_QUERY_*` slots
  (note: several slots are intentionally shared, e.g. `BRIX_OP_QUERY_CKSUM` and
  `BRIX_OP_QUERY_SPACE` both map to slot `17` in `../metrics/metrics.h`); paths,
  algorithms, and reqids are never used as metric labels.

## Entry points / extending

**Add a new `kXR_query` infotype:** declare its handler prototype in
`query_internal.h`, implement it in a new or existing `.c` here, then add one
`if (infotype == kXR_Qfoo) return brix_query_foo(...);` branch in `dispatch.c`
(before the trailing `kXR_Unsupported` fallback). Follow the existing contract:
confine any path (`brix_extract_path` + `brix_*_beneath`), run
`brix_auth_gate` (`BRIX_AUTH_READ`), bump `BRIX_OP_OK`/`_ERR` and
`brix_log_access`, and reply via `brix_send_ok` / `brix_send_error`.
Register the new `.c` in the top-level `config` script (the module's
`ngx_module_srcs` / `NGX_ADDON_SRCS` list) and re-run `./configure`.

**Make a query op async:** copy the `brix_cksum_aio_t` pattern — add a context
struct to `query_internal.h`, write a `_thread` worker (no nginx-event-loop
access; result/error fields only) and a `_done` callback
(`brix_aio_restore_request` → send → `brix_aio_resume`), allocate via
`ngx_thread_task_alloc`, bind with `brix_task_bind`, and post with
`brix_aio_post_task` while keeping a synchronous fallback for the queue-full
case. Always keep the sync and async paths byte-identical.

**Tune scan limits / staging:** caps live in `query_internal.h`
(`BRIX_CKSCAN_INIT_CAP`, `BRIX_PREPARE_CMD_MAX_PATHS`) and in srv-conf
(`ckscan_max_depth`, `ckscan_max_files`, `prepare_command`).

## See also

- `../handshake/README.md` — opcode routing that calls into this subsystem
- `../path/README.md` — path confinement, authdb, VO ACL, token-scope auth gate
- `../compat/README.md` — checksum / digest / integrity-info + fs-usage helpers
- `../aio/README.md` — thread-pool offload, restore/resume contract
- `../response/README.md` — `send_ok`/`send_error` and the attn-frame builders
- `../manager/README.md` and `../cms/README.md` — manager-mode redirect + locate
- `../read/README.md` — sibling stream data plane sharing the same AIO pattern
- `../metrics/README.md` — `BRIX_OP_QUERY_*` / `BRIX_OP_SET` counters
- `../README.md` — master subsystem index
