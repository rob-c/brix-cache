# write — XRootD mutating-opcode handlers (the stream write path)

## Overview

This subsystem implements every **mutating** XRootD operation that arrives over
the `root://`/`roots://` stream protocol: data writes (`kXR_write`,
`kXR_pgwrite`, `kXR_writev`), durability (`kXR_sync`, `kXR_truncate`),
namespace mutation (`kXR_mkdir`, `kXR_rm`, `kXR_rmdir`, `kXR_mv`, `kXR_chmod`),
and transactional checkpointing (`kXR_chkpoint` with its `ckpBegin / ckpCommit /
ckpRollback / ckpQuery / ckpXeq` sub-operations). It is the write-side peer of
[`../read`](../read/README.md); both are reached from the opcode dispatcher
after authentication and confinement.

Execution enters here exclusively from
[`../handshake/dispatch_write.c`](../handshake/README.md):
`brix_dispatch_write_opcode()` switches on `ctx->cur_reqid` and, for **every**
write opcode, first calls `brix_dispatch_require_write()` — a gate stricter
than the read path's `require_auth` because it demands both authentication *and*
the configured `conf->common.allow_write` permission before any handler runs.
Only then does it `DISPATCH_WR(handler)` into one of the functions declared in
[`write.h`](write.h). This enforces invariant #5 (fail-closed write authority,
checked globally before any per-path token scope).

The data-carrying opcodes (`write`/`pgwrite`/`writev`) follow a uniform AIO
fork: when a thread pool is configured they detach the received payload from
`ctx->payload_buf` and post a `pwrite(2)` task to
[`../aio`](../../../core/aio/README.md) (the worker thread + completion callbacks live in
`../aio/write.c`, *not* in this directory), letting the event loop read the next
header while disk I/O proceeds. With no thread pool, or if the task queue is
full, they fall back to an inline synchronous `pwrite(2)` that rebuilds the same
response. Either way, since phase-54 the `pwrite`/writev/pgwrite byte movement runs
through the VFS-owned thread-safe core `brix_vfs_io_execute()`
([`../fs/vfs_io_core.c`](../../../fs/README.md)) rather than a syscall reimplemented here, so
short-write and error handling are shared with the rest of the VFS. Namespace opcodes are
path-based: they resolve the client path beneath
the export root, run the auth gate, and perform a single confined syscall via
[`../compat`](../../../core/compat/README.md)'s `namespace_ops` helpers.

Two reliability features thread through the write path: a per-handle
**write-recovery journal** (`wrts_journal.*`, backing the `kXR_recoverWrts`
protocol flag — replayed writes after a client reconnect are detected and
short-circuited so bytes are never written twice), and **write-through dirty
tracking** (`wt_*` fields, mirroring `XrdPfcFile`, accumulated for close-time
origin flush by [`../cache`](../../../fs/cache/README.md)).

## Files

| File | Responsibility |
|------|----------------|
| `write.h` | Public prototypes for all handlers plus `brix_pgwrite_decode_payload()` and `brix_try_post_write_aio()`. |
| `write.c` | `kXR_write` — validate writable handle, replay-skip check, AIO-or-sync `pwrite(2)` at offset; updates byte/dashboard/rate-limit counters, marks `wt_` dirty state, records the write in the recovery journal. |
| `pgwrite.c` | `kXR_pgwrite` (xrdcp v5+) — defines `brix_pgwrite_decode_payload()` which verifies the interleaved per-page CRC32c and copies into a flat buffer in one pass (`brix_crc32c_copy`); CRC mismatch → `kXR_ChkSumErr`. Response is a `kXR_status` packet carrying the next expected offset, not `kXR_ok`. |
| `writev.c` | `kXR_writev` — scatter-gather write. Discovers segment count `N` by scanning until `N*SEGSIZE + Σwlen == dlen`, validates **all** `fhandle`s before any `pwrite`, then AIO-or-sync writes each segment; optional `kXR_wv_doSync` fsyncs every touched handle. |
| `sync.c` | `kXR_sync` — `fsync(2)` the handle, flush the recovery journal, trigger close-time write-through flush; also drives native-TPC destination arm/flush (first sync arms, second triggers `brix_tpc_start_pull`). |
| `truncate.c` | `kXR_truncate` — two modes: handle-based (`dlen==0`, `ftruncate` the open fd) and path-based (`dlen>0`, resolve + auth-gate + `O_WRONLY` open + `ftruncate` + close). |
| `mkdir.c` | `kXR_mkdir` — single-level or recursive (`kXR_mkdirpath`) via `brix_ns_mkdir`; mode masked to `0777` (default `0755`); `EEXIST`/`BRIX_NS_EXISTS` is success (idempotent); applies parent group policy on fresh single-level create. |
| `mv.c` | `kXR_mv` — atomic rename. Parses the `src ' ' dst` payload (`arg1len` + mandatory space separator), resolves both halves independently beneath the root, auth-gates each, then `brix_ns_rename` (confined `renameat`, closing the realpath/rename TOCTOU). |
| `chmod.c` / `rm.c` / `rmdir.c` | Thin handlers that delegate to the op-descriptor interpreter: `brix_dispatch_op(ctx, c, conf, kXR_<op>)`. |
| `op_table.h` | Declares `brix_op_desc_t` (declarative descriptor: opcode, log verb, metric slot, auth level, write-required, path mode, `exec` callback), `brix_op_exec_t`, and `brix_dispatch_op()`. |
| `op_table.c` | The descriptor table + interpreter for "resolve → auth → one syscall → ok/err" ops. Holds `exec_chmod` (`chmod`), `exec_rm` (`brix_ns_delete`, retries as recursive dir-delete on `EISDIR`), `exec_rmdir` (`brix_ns_delete` with `require_directory`). |
| `common.c` | `brix_try_post_write_aio()` — the shared thread-pool dispatch for `write`/`pgwrite`: allocates an `brix_write_aio_t` task, binds `brix_write_aio_thread`/`brix_write_aio_done` (defined in `../aio/write.c`), posts it; sets `*posted` so callers know whether to fall back to sync. |
| `chkpoint.h` / `chkpoint.c` | `kXR_chkpoint` dispatcher and the begin/commit/rollback/query sub-handlers, plus `brix_chkpoint_recover_root()` — startup scan that rolls back abandoned `<path>.ckp` snapshots left by a crash. |
| `chkpoint_xeq.h` / `chkpoint_xeq.c` | `ckp_xeq()` — parses the inner 24-byte sub-request header and executes a `write`/`pgwrite`/`truncate`/`writev` **under an active checkpoint** (all segments must target the checkpointed handle). |
| `wrts_journal.h` / `wrts_journal.c` | Per-handle fixed-size ring journal for `kXR_recoverWrts`: `open` (arm), `record` (append committed write), `is_replay` (exact offset+length match → skip), `flush` (clear on sync/close). |

## Key types & data structures

- **`brix_op_desc_t`** (`op_table.h`) — declarative row describing a "simple"
  namespace op. Fields: `opcode`, log `name`, `op_id` (metric slot),
  `auth_level` (`BRIX_AUTH_*`), `need_write`, `path_mode`
  (`BRIX_PATH_EXISTING/WRITE/NOEXIST/EITHER`), and an `exec()` syscall
  callback. The static `_ops[]` table in `op_table.c` is the single source of
  truth for `chmod`/`rm`/`rmdir`; `brix_dispatch_op()` is the interpreter that
  runs the shared resolve→auth→exec→reply boilerplate.
- **`brix_op_exec_t`** (`op_table.h`) — per-call context handed to each
  `exec()`: `ctx`, `c`, `conf`, the extracted `reqpath`, and the canonical
  `resolved` path.
- **`brix_write_aio_t`** (defined under `../aio`) — write AIO task: target
  `fd`, `handle_idx`, `offset`, `data`/`len`, `req_offset`, `is_pgwrite`,
  result `nwritten`/`io_errno`, copied `streamid`/`path`, and `payload_to_free`
  (heap buffer the done callback releases, or `NULL` when the data is a
  pool-managed scratch buffer).
- **`brix_writev_aio_t` / `brix_writev_seg_desc_t`** (`writev.c` builds
  them) — the segment-descriptor array plus task carrying `payload_buf`
  ownership and the `do_sync` flag.
- **Recovery-journal state on `brix_file_t`** (`../types/file.h`):
  `wrts_enabled`, `wrts_journal[BRIX_WRTS_JOURNAL_SLOTS]`, `wrts_head`,
  `wrts_count`, `wrts_gen`, each entry an `brix_wrts_entry_t {offset, length,
  gen}`.
- **Checkpoint state on `brix_file_t`**: `ckp_path` (non-NULL ⇒ active
  checkpoint; the heap-allocated `<open-path>.ckp` sibling) and `ckp_size`
  (snapshot length, the rollback target). Freed by `brix_free_fhandle` on
  close/disconnect.
- **`ServerResponseBody_ChkPoint`** — the `kXR_ckpQuery` reply body
  (`maxCkpSize` = `kXR_ckpMinMax`, `useCkpSize` = current `.ckp` size).

## Control & data flow

```
../handshake/dispatch_write.c : brix_dispatch_write_opcode()
    └─ DISPATCH_WR macro → brix_dispatch_require_write()   [auth + allow_write]
       │
       ├ kXR_write    → write.c   : brix_handle_write()
       ├ kXR_pgwrite  → pgwrite.c : brix_handle_pgwrite()  → decode+CRC → kXR_status
       ├ kXR_writev   → writev.c  : brix_handle_writev()
       │     (data ops) → common.c:brix_try_post_write_aio()
       │                    ├ thread pool → ../aio/write.c worker pwrite → done cb sends reply
       │                    └ no pool/queue full → inline pwrite, build reply here
       ├ kXR_sync     → sync.c    : fsync + journal flush + wt-flush / TPC arm→pull
       ├ kXR_truncate → truncate.c: handle- or path-based ftruncate
       ├ kXR_mkdir/mv → mkdir.c/mv.c : resolve→auth_gate→ ../compat namespace_ops
       ├ kXR_chmod/rm/rmdir → op_table.c : brix_dispatch_op() interpreter
       └ kXR_chkpoint → chkpoint.c : begin/commit/rollback/query
                              └ ckpXeq → chkpoint_xeq.c : ckp_xeq()
```

Calls outward to sibling subsystems:

- **[`../path`](../../../fs/path/README.md)** — `brix_resolve_op_path()`,
  `brix_path_resolve_beneath()`, `brix_extract_path()` for confinement, and
  `brix_auth_gate()` for the three-tier (VO ACL / authdb / token-scope) write
  authorization that the gate enforces for path-based ops.
- **[`../aio`](../../../core/aio/README.md)** — thread-pool task plumbing
  (`brix_aio_post_task`, `brix_task_bind`, `BRIX_GET_SCRATCH`); the
  `*_aio_thread`/`*_aio_done` callbacks for both `write` and `writev` live in
  `../aio/write.c`.
- **[`../compat`](../../../core/compat/README.md)** — `brix_ns_mkdir` / `brix_ns_rename`
  / `brix_ns_delete` (confined namespace syscalls), `brix_crc32c_copy`,
  `brix_copy_range`, `brix_staged_*`, and the `brix_kxr_*` errno→kXR
  mappers.
- **[`../cache`](../../../fs/cache/README.md)** — `brix_wt_mark_dirty` /
  `brix_wt_flush_sync_handle` for write-through origin propagation.
- **[`../tpc`](../../../tpc/README.md)** — `brix_tpc_start_pull` driven by the
  second `kXR_sync` on a native-TPC destination handle.
- **`../read`** validation helpers — `brix_validate_write_handle` /
  `brix_validate_file_handle` (defined in `../connection/fd_table.c`,
  also used by `../read/clone.c`).
- **`../response` / `../metrics`** — `brix_send_ok`,
  `brix_send_pgwrite_status`, `brix_send_error`, the `BRIX_RETURN_OK/ERR`
  + `BRIX_OP_OK/ERR` macros, and `brix_log_access`.

## Invariants, security & gotchas

- **Fail-closed write authority.** The dispatcher's
  `brix_dispatch_require_write()` runs before *every* handler and rejects with
  `kXR_NotAuthorized` unless authenticated **and** `conf->common.allow_write` is
  set — checked globally, ahead of per-path token scope (invariant #5).
- **Kernel confinement is mandatory.** Path-based ops never call a raw
  `open`/`rename`/`mkdir` on a client path: they go through
  `brix_resolve_op_path` / `brix_path_resolve_beneath` (RESOLVE_BENEATH) and
  the `../compat` `brix_ns_*` confined-syscall helpers (invariant #1).
  `mv.c` deliberately resolves only for the historical "source not found" 404;
  the *authoritative* confinement is the kernel `renameat` inside
  `brix_ns_rename`, which also closes the realpath→rename TOCTOU
  (`mv.c:110-117`, `141-148`).
- **`mv` wire format is space-separated, length-prefixed.** Payload is
  `src + 0x20 + dst`; `arg1len` (big-endian) gives the source length and the
  byte at `payload[arg1len]` **must** be a space, else `kXR_ArgInvalid`
  (`mv.c:80-90`). Both halves are extracted independently so embedded-NUL and
  traversal checks apply to each.
- **pgwrite framing & response.** Payload layout is *CRC first*:
  `[CRC32c 4B][≤4096B data]` per fragment; first/last fragments may be short on
  unaligned offsets. Decode verifies every CRC before any `pwrite` — mismatch →
  `kXR_ChkSumErr`, malformed → `kXR_ArgInvalid` (`pgwrite.c:98-167`). The
  success reply is `kXR_status` with the next expected offset
  (`brix_send_pgwrite_status`), **not** `kXR_ok` (invariant #2 framing).
- **Replay idempotency is exact-match, not range-coverage.** `wrts_is_replay`
  only skips a write whose offset *and* length exactly equal a journalled entry;
  range coverage was rejected on purpose so a legitimate sub-range overwrite is
  not silently dropped (`wrts_journal.c:84-94`). The journal is flushed on
  `kXR_sync` and `kXR_close` (a new generation begins).
- **Payload-ownership / detach discipline.** On a successful AIO post, `write`
  and `writev` set `ctx->payload = ctx->payload_buf = NULL` and
  `payload_buf_size = 0` so the next request cannot reuse the in-flight buffer;
  the done callback frees it. `pgwrite` instead writes from the pool-managed
  `write_scratch` scratch buffer (`BRIX_GET_SCRATCH`) and passes
  `payload_to_free = NULL` so the callback must **not** free it
  (`pgwrite.c:265-267`). Note: `ctx->write_scratch` is freed explicitly during
  connection teardown in `disconnect.c`.
- **Event loop, no blocking.** Async completions run on the single event-loop
  thread and must rebuild the response identically to the sync path; handlers
  never sleep or block (invariant #3).
- **Short-write = disk-full.** Every sync `pwrite` path treats `nwritten < len`
  as `kXR_IOError "short write (disk full?)"` rather than silently truncating
  client data (`write.c:141`, `pgwrite.c:290`, `writev.c:216`).
- **Checkpoint = `.ckp` sibling + crash recovery.** `ckpBegin` rejects files
  over `kXR_ckpMinMax` (`kXR_overQuota`) and creates the snapshot with
  `O_CREAT|O_EXCL|O_NOFOLLOW`; `ckpXeq` requires `ckp_path != NULL` and that
  *every* sub-write target the checkpointed handle (cross-handle →
  `kXR_InvalidRequest`). `brix_chkpoint_recover_root()` runs under an
  exclusive `flock` on a per-root lockfile, scans (depth-limited, symlink-safe
  `O_NOFOLLOW`) for stale `*.ckp`, and restores via the atomic
  `brix_staged_*` rename so uncommitted writes never survive a restart
  (`chkpoint.c:306-518`).
- **Metric/telemetry consistency.** Error paths must go through
  `BRIX_RETURN_ERR` (not bare `brix_log_access`) so `BRIX_OP_*` counters
  stay correct — a class of bug previously fixed in `chkpoint_xeq.c`. Keep
  metric labels low-cardinality (no paths/UUIDs) per invariant #5.

## Entry points / extending

**Add a "simple" namespace op (resolve → auth → one syscall → ok/err):**
1. Write an `exec_<op>(const brix_op_exec_t *e, int *out_errno)` in
   `op_table.c` that performs the single (confined) syscall.
2. Add a row to the static `_ops[]` table (opcode, log verb, `BRIX_OP_*`
   metric slot, `BRIX_AUTH_*` level, `need_write`, `brix_path_mode_t`).
3. Add a thin `brix_handle_<op>()` (like `chmod.c`) that calls
   `brix_dispatch_op(ctx, c, conf, kXR_<op>)`, declare it in `write.h`, and
   register the case in `../handshake/dispatch_write.c`.

**Add a complex mutating opcode** (non-trivial exec — two-mode, atomic,
streaming, custom response): write a dedicated `brix_handle_<op>()` here
(model on `truncate.c`/`mv.c`), declare it in `write.h`, register it under the
`DISPATCH_WR` switch in `../handshake/dispatch_write.c`, and add a new metric
slot per the project's "New metric" recipe. Always provide 3 tests
(success + error + security-negative).

**Add a `ckpXeq` sub-operation:** add a `ckp_xeq_<op>()` in `chkpoint_xeq.c`
and a `case` in `ckp_xeq()`'s `switch (sub_reqid)`.

## See also

- [`../read/README.md`](../read/README.md) — the read-side opcode peer.
- [`../handshake/README.md`](../handshake/README.md) — the opcode dispatcher and write gate.
- [`../aio/README.md`](../../../core/aio/README.md) — thread-pool offload; the write AIO worker/done callbacks.
- [`../path/README.md`](../../../fs/path/README.md) — confinement and the auth gate.
- [`../compat/README.md`](../../../core/compat/README.md) — confined namespace syscalls, CRC32c, errno→kXR mapping.
- [`../cache/README.md`](../../../fs/cache/README.md) — write-through dirty tracking and origin flush.
- [`../tpc/README.md`](../../../tpc/README.md) — native third-party copy (sync-driven pull).
- [`../types/README.md`](../../../core/types/README.md) — `brix_file_t` (journal + checkpoint state).
- [`../README.md`](../README.md) — subsystem master index.
