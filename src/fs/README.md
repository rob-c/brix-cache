# fs — Unified VFS: the single POSIX-filesystem data plane

## Overview

`src/fs/` is the **Virtual File System (VFS)** layer: one protocol-agnostic API
(`xrootd_vfs_*`) for every byte that touches the local export root. All four
front ends — XRootD `root://` (stream), WebDAV `davs://`/`http://` (HTTP), the
S3 REST subset, and CMS data-server I/O — funnel their open/read/write/stat and
namespace mutations through this layer instead of calling `open`/`pread`/
`rename` directly. That convergence is the point: confinement, metrics, access
logging, page-CRC, and read-through/write-through cache integration are
implemented **once**, here, and inherited by every protocol for free.

The VFS sits between the protocol op handlers and the kernel. A handler builds an
`xrootd_vfs_ctx_t` (the export root, the already-resolved client path, the
caller identity, write permission, TLS flag, cache config) and calls one VFS
entry point. The VFS performs the syscall under kernel-enforced confinement,
records a Prometheus metric and an access-log line, and hands back either an
opaque handle (`xrootd_vfs_file_t` / `xrootd_vfs_dir_t`) or an
`ngx_chain_t`/result struct that the caller frames onto the wire. Callers never
see a raw `fd` except through the accessor `xrootd_vfs_file_fd()`.

Crucially, the VFS does **not** decide *which* path to touch — that is the job of
[`../path/`](../path/README.md), which produces the `xrootd_path_result_t`
embedded in the ctx. The VFS *re-verifies* confinement before every syscall
(`is_confined` must be set and the resolved path non-empty) and then opens via
the kernel `RESOLVE_BENEATH` API in [`../path/beneath.h`](../path/README.md). It
also does not run blocking I/O on the event loop on its own behalf. The blocking
read/write/readv/writev/pgread bodies — on a [`../aio/`](../aio/README.md)
thread-pool worker, on the io_uring inline fallback, or on the event-loop inline
fallback — execute through one VFS-owned, thread-safe core,
`xrootd_vfs_io_execute()` in `vfs_io_core.c` (phase-54). The synchronous
`pread`/`pwrite` helpers here are the bodies that core runs, and the read path is
careful to build the *same* buffer chain whether invoked sync or from an AIO
completion. Workers no longer carry their own copies of these syscalls; a few
zero-copy/fast paths stay beside the core by design (see the two-tier boundary
note below).

Callers today: [`../read/`](../read/README.md) and [`../write/`](../write/README.md)
(XRootD opcodes), [`../shared/file_serve.c`](../shared/README.md),
[`../webdav/`](../webdav/README.md) (`get.c`, `resource.c`; plus the metered
xattr/copy/staged/delete paths in `prop_xattr.c`, `dead_props.c`, `copy.c`,
`put.c`, `namespace.c`), [`../s3/`](../s3/README.md) (`object.c`,
`post_object.c`, `put.c`, `tagging.c`, `checksum.c`, `conditional.c`), and
[`../dirlist/`](../dirlist/README.md).

> **Two VFS tiers — metered (loop-only) vs. raw (thread-safe).** Since phase-54
> the VFS exposes two surfaces, and **all disk byte I/O now goes through the VFS**
> regardless of which thread runs it:
>
> 1. **Public metered entry points** (`xrootd_vfs_open`/`read`/`write`/`stat`/…)
>    allocate from an nginx request `pool` and emit Prometheus metrics +
>    access-log lines — none of which is thread-safe — so they run **only on the
>    event loop**.
> 2. **The worker-safe I/O core** (`xrootd_vfs_io_execute()`, `vfs_io_core.c`) is
>    the thread-safe EXECUTE surface that the offloaded and inline-fallback raw
>    byte ops now funnel through — `kXR_read`, `write`, `readv`, `writev`,
>    `pgread`, and the `dirlist` scan — whether executed on the
>    [`../aio/`](../aio/README.md) thread pool, on the event-loop **inline
>    fallback** (no pool / queue full), or on the io_uring inline fallback. It
>    mutates only a POD job descriptor and caller-owned buffers: **no pool, no
>    metrics, no log, no cache.** This is what removed the old "workers
>    reimplement raw syscalls outside the VFS" boundary — the
>    read/write/readv/pgread bodies are no longer duplicated in `../aio/`, so
>    confinement, CRC, short-I/O, and error behaviour can no longer drift between
>    the worker and the VFS.
>
>    Two categories sit *beside* the core by design, not below it: (a) **zero-copy
>    fast paths** — the cleartext/kTLS `sendfile` read and the
>    `preadv2(RWF_NOWAIT)` warm-cache probe in [`../read/read.c`](../read/README.md)
>    move bytes without a core buffer at all; (b) the **live synchronous
>    `dirlist`** loop in [`../dirlist/handler.c`](../dirlist/README.md) still runs
>    its own confined `fdopendir`/`readdir` (the core's `OPENDIR` op is wired into
>    the `../aio/dirlist.c` worker, which is currently gated off). These are
>    tracked follow-ups, not separate raw-I/O implementations of the offload path.
>
> Namespace **mutation** is the one part still split: the metered
> `xrootd_vfs_unlink`/`rmdir`/`rename`/`mkdir`/`copy` and the staged-write family
> are loop-only, while worker-thread namespace mutation — native TPC pull
> (`../tpc/source.c`), async/multipart S3 PUT assembly, the collection COPY/MOVE
> engines — stays on the `xrootd_ns_*` / `compat/staged_file` tier. Both tiers
> share the same `RESOLVE_BENEATH` confinement; only the VFS's metering/cache
> layer is skipped on the worker tier. (Phase-55 plans to unify even that beneath
> a pluggable storage-driver seam — see
> [`../../docs/refactor/phase-55-storage-backend-abstraction.md`](../../docs/refactor/phase-55-storage-backend-abstraction.md).)

## Files

| File | Responsibility |
|---|---|
| `vfs.h` | Public API. Open flags (`XROOTD_VFS_O_READ/WRITE/CREATE/EXCL/TRUNC/APPEND/MKDIRPATH/NOCACHE`), opaque handle types, the `xrootd_vfs_ctx_t` request descriptor, `xrootd_vfs_stat_t`/`xrootd_vfs_io_result_t`, and every `xrootd_vfs_*` prototype. The only header protocol handlers should include. |
| `vfs_internal.h` | Implementation-private definitions: the real `xrootd_vfs_file_s`/`xrootd_vfs_dir_s` structs, confinement/write guards (`xrootd_vfs_require_confined`, `xrootd_vfs_require_write`), the metrics+access-log observer helpers (`xrootd_vfs_observe_*`), and shared internal prototypes (`pread_full`, `pwrite_full`, `adopt_fd`, `fill_stat`). |
| `vfs_io_core.h` | The **thread-safe** I/O surface: the POD job descriptor `xrootd_vfs_job_t` (IN fields + OUT results), the readv/writev segment descriptors, the per-op `xrootd_vfs_job_*_init` helpers, and the `xrootd_vfs_io_execute()` prototype. The only fs header a thread-pool worker or io_uring fallback may include. |
| `vfs_io_core.c` | The worker-safe EXECUTE core (phase-54). `xrootd_vfs_io_execute()` dispatches one job to a small per-op helper for READ/WRITE/PGREAD/READV/WRITEV/OPENDIR, mutating only the job's OUT fields and caller-owned buffers — **no pool, metrics, log, or cache**. Reuses the pure bodies (`xrootd_vfs_pread_full`/`pwrite_full`, `xrootd_pgread_read_encode_inplace`, `xrootd_readv_read_segments`) and builds the `kXR_dirlist` response from a confined `fdopendir` scan. This is the shared raw-I/O body for every dispatch tier (inline / thread pool / io_uring). |
| `vfs_open.c` | Open/close + handle lifecycle. Maps flags to `O_*`, runs the cache-first / confinement-cascade open logic, `fstat`s into the handle, registers pool cleanup. Also hosts the shared helpers (`fill_stat`, `copy_path`, `register_fd_cleanup`, `adopt_fd`) and the `xrootd_vfs_file_*` accessors. |
| `vfs_read.c` | Read path. `xrootd_vfs_read()` chooses memory-backed chain (TLS or page-CRC wanted) vs file-backed chain (cleartext sendfile via `dup`'d fd), caps length at EOF, computes per-read CRC32c, records cache access. `xrootd_vfs_pread_full()` is the EINTR-safe full-read primitive used everywhere. |
| `vfs_write.c` | Write path. `xrootd_vfs_write()` walks an input `ngx_chain_t` writing in-file and in-memory bufs to the destination offset, extends CRC32c, grows the cached handle size, and consults the write-through cache decision. `xrootd_vfs_pwrite_full()` is the EINTR/short-write-safe primitive. |
| `vfs_dir.c` | Directory enumeration: `opendir`/`readdir`/`closedir`. Skips `.`/`..`, returns each entry name as a pooled `ngx_str_t` plus an optional `lstat` of the child. Returns `NGX_DONE` at end-of-stream. |
| `vfs_stat.c` | `xrootd_vfs_stat()` — `lstat` of the resolved ctx path (no symlink follow), filled into `xrootd_vfs_stat_t`, with metrics/log. |
| `vfs_mkdir.c` | `xrootd_vfs_mkdir()` — delegates to `xrootd_ns_mkdir` (namespace layer) with optional `parents`; write-gated. |
| `vfs_rename.c` | `xrootd_vfs_rename()` — delegates to `xrootd_ns_rename`; requires a confined destination `xrootd_path_result_t`; write-gated. |
| `vfs_unlink.c` | Delete family: shared `xrootd_vfs_delete()` → `xrootd_ns_delete`; `xrootd_vfs_unlink()` (file) and `xrootd_vfs_rmdir()` (recursive or require-empty). Write-gated. |
| `vfs_sync.c` | `xrootd_vfs_truncate()` (`ftruncate` + handle-size update) and `xrootd_vfs_sync()` (`fsync`). |
| `vfs_xattr.c` | Extended-attribute family: `xrootd_vfs_getxattr/listxattr/setxattr/removexattr` over the `user.` namespace (S3 tagging, WebDAV dead-properties, the lock database). Delegates to `xrootd_*xattr_confined_canon`; metered as `OP_XATTR`. set/remove are **not** `allow_write`-gated (the lock DB writes on read-only requests; the protocol layer authorizes). |
| `vfs_copy.c` | `xrootd_vfs_copy()` — single regular-file server-side copy (`copy_file_range`) behind WebDAV COPY / S3 CopyObject. Delegates to `xrootd_ns_local_copy`; write-gated; metered as `OP_COPY` (byte count from the post-copy destination size). |
| `vfs_staged.c` | Atomic staged-write lifecycle (`xrootd_vfs_staged_open` → write the fd → `xrootd_vfs_staged_commit`/`abort`) behind crash-safe S3 PutObject / WebDAV PUT. Wraps `compat/staged_file`; write-gated at open; the commit (atomic publish onto the final path) is metered as `OP_WRITE`. |
| `fd_cache.c` | Reserved slot for future fd-cache unification; currently only a header include + design note. No live code. |

## Key types & data structures

- **`xrootd_vfs_ctx_t`** (`vfs.h`) — the per-operation request descriptor the
  caller fills in: `pool`/`log`, `identity`, `metrics_proto` (stream/webdav/s3),
  `root_canon` + `cache_root_canon`, the persistent per-worker `rootfd`
  (O_PATH, or `-1`), the already-resolved `xrootd_path_result_t resolved`, and
  the `allow_write` / `is_tls` / `want_pgcrc` / `cache_enabled` /
  `cache_writethrough` bitflags. This struct *is* the VFS's view of a request.
- **`xrootd_vfs_file_t`** (opaque; real definition `xrootd_vfs_file_s` in
  `vfs_internal.h`) — an open file handle: `fd`, cached `size`/`mtime`/`ctime`/
  `ino`/`mode`, the pool it lives in, a back-pointer to the originating `ctx`, a
  pooled copy of `path`, and `from_cache`/`is_tls` flags. Cached `size` lets the
  read/write paths bound I/O and the stat path answer without extra syscalls.
- **`xrootd_vfs_dir_t`** — an open directory iterator (`DIR*` + pool + path).
- **`xrootd_vfs_stat_t`** — protocol-neutral stat: `size`, `mtime`/`ctime`,
  `mode`, `ino`, `is_directory`/`is_regular`. Built by `xrootd_vfs_fill_stat()`.
- **`xrootd_vfs_io_result_t`** — per-I/O outcome handed back to the framer:
  `offset`, `length`, `crc32c`, and `from_cache`/`eof` flags. The `crc32c` field
  feeds pgread/pgwrite per-page CRC framing.

## Control & data flow

**Entry.** A protocol op handler resolves the client path via
[`../path/`](../path/README.md), stamps an `xrootd_vfs_ctx_t`, and calls a single
VFS function. There is no dispatcher inside `fs/`; each entry point is called
directly.

**Open (`vfs_open.c`).** `xrootd_vfs_require_confined()` rejects unconfined or
empty paths; a write open additionally requires `allow_write`. Then:
1. `xrootd_cache_open()` ([`../cache/`](../cache/README.md)) gets first refusal —
   a read-through cache hit returns a ready handle and bumps the cache-hit
   metric; `NGX_DECLINED` falls through (and records a miss).
2. Otherwise the **confinement cascade**: `rootfd >= 0` →
   `xrootd_open_beneath()` (the hot path, `openat2(RESOLVE_BENEATH)`);
   else `root_canon` → `xrootd_open_confined_canon()` (same semantics, per-call
   rootfd, for legacy callers); else raw `open()` — *only* reachable for
   server-constructed absolute paths with no export root, never for a client
   path. See the long comment at `vfs_open.c:273-288`.
3. `xrootd_vfs_adopt_fd()` fstats the fd into a handle. Note: the open path does
   **not** register pool-cleanup on the handle fd; the caller owns `close` via
   `xrootd_vfs_close()`. (The read path does register cleanup on the *dup*'d
   sendfile fd — see below.)

**Read (`vfs_read.c`).** Caps `length` to `size - offset` (setting `eof`), then
branches on transport: TLS or `want_pgcrc` → `make_memory_chain()`
(`ngx_pnalloc` + `pread_full`, `b->memory=1`, CRC computed inline); cleartext →
`make_file_chain()` (`dup` the fd, register `ngx_pool_cleanup_file`, emit an
`in_file` buf for sendfile). Cache hits record access into
[`../cache/`](../cache/README.md). The synchronous body here is what
[`../aio/`](../aio/README.md) runs in the thread pool; the AIO completion
rebuilds an identical chain on the event loop.

**Write (`vfs_write.c`).** Iterates the input chain, copying in-file bufs in
`XROOTD_VFS_COPY_CHUNK` (64 KiB) blocks via `pread_full`→`pwrite_full` and
writing in-memory bufs directly, extending the CRC32c and advancing `dst_off`.
On success it grows the handle's cached `size` and asks
[`../cache/`](../cache/README.md) whether the region should be mirrored
write-through.

**Namespace ops (`vfs_mkdir.c`/`vfs_rename.c`/`vfs_unlink.c`).** These do not
syscall directly; they delegate to the `xrootd_ns_*` family in
[`../compat/namespace_ops`](../compat/README.md) (which itself confines via the
beneath API), translating `xrootd_ns_result_t.status`/`.sys_errno` back to
`NGX_OK`/`NGX_ERROR` + `errno`.

**Exit / observability.** Every entry point wraps its result through
`xrootd_vfs_observe_*` (`vfs_internal.h`), which calls `xrootd_metric_op_done()`
([`../metrics/`](../metrics/README.md)) and `xrootd_access_log_emit()`
([`../metrics/access_log`](../metrics/README.md)) with op, byte count, latency,
and an `xrootd_err_class_t` derived from `errno` — then restores `errno` for the
caller. This is why protocol handlers don't (and shouldn't) emit their own
per-op data-plane metrics.

## Invariants, security & gotchas

1. **Confinement is re-checked here, not trusted.** Every entry point calls
   `xrootd_vfs_require_confined()` (`vfs_internal.h:54`): the resolved path must
   be non-empty *and* `resolved.is_confined` must be set, else `EINVAL`. Actual
   filesystem access then goes through `xrootd_open_beneath` /
   `xrootd_open_confined_canon` / `xrootd_ns_*`, all of which use
   `RESOLVE_BENEATH`. An `EXDEV` from those means an escape attempt — callers map
   it to `kXR_NotAuthorized`/403 (see [`../path/beneath.h`](../path/README.md)).
2. **The raw-`open()` branch is not a bypass.** It is only reached when the ctx
   carries *no* root at all (server-constructed absolute path). Client requests
   always set a root and take the confined branches. Do not "simplify" the
   cascade in `vfs_open.c` without preserving this property.
3. **Fail-closed writes.** `xrootd_vfs_require_write()` checks `allow_write`
   *after* confinement and before any mutation; `xrootd_vfs_open()` rejects a
   write open up front with `EACCES`. This is the data-plane backstop behind the
   protocol-layer write gate — both must hold.
4. **TLS vs cleartext buffers never mix.** `vfs_read.c` is the chokepoint:
   `is_tls` (or `want_pgcrc`) → memory-backed buf (`b->memory=1`); cleartext →
   file-backed `in_file` buf for sendfile. Never emit a file-backed buf on a TLS
   connection.
5. **pgread/pgwrite CRC.** `want_pgcrc` makes both read and write compute a
   CRC32c (`xrootd_crc32c_value` / `xrootd_crc32c_extend`) into
   `io_result.crc32c`; the framer turns that into `kXR_status` (4007) per-page
   framing. The VFS computes the checksum but does not frame it.
6. **Event-loop safety.** `pread_full`/`pwrite_full` loop on `EINTR` and short
   writes but are *blocking*. On hot paths they run inside the
   [`../aio/`](../aio/README.md) thread pool, never directly on the event loop.
   Treat new blocking syscalls added here as AIO-offload candidates.
7. **Sendfile fd ownership.** `make_file_chain()` `dup`s the handle fd and
   registers `ngx_pool_cleanup_file`, so the request pool closes the *duplicate*
   independently of `xrootd_vfs_close()`. Don't close the handle out from under
   an in-flight sendfile buf.
8. **`stat` uses `lstat`** (no symlink follow) and `readdir` filters `.`/`..`.
   `xrootd_vfs_file_stat()` answers from the metadata cached at open time when the
   handle's `stat_current` bit is set (phase-45 W2/R1 — `adopt_fd` already
   `fstat`'d the fd, and reads don't change it), avoiding a redundant `fstat` on
   the GET hot path; `xrootd_vfs_write()` clears the bit so a write-then-stat
   still issues a live `fstat`. read/write bound I/O against the *cached*
   `fh->size` for speed — a file grown by another writer won't be seen until reopen.
9. **`errno` discipline.** Helpers set `errno` on failure and the observers
   restore the caller's `errno` after logging; rely on the documented `errno`,
   not on globals surviving the metrics call.
10. **`fd_cache.c` is a placeholder.** No live logic; don't wire callers to it
    until the cache-unification step lands.

## Entry points / extending

- **Add a new VFS operation** (e.g. a new namespace mutation): declare it in
  `vfs.h`, add a focused `vfs_<op>.c`, register the file in the top-level `config`
  script (the module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list) and re-run
  `./configure`, and in the body
  (a) call `xrootd_vfs_require_confined()` / `xrootd_vfs_require_write()` as
  appropriate, (b) prefer delegating to an `xrootd_ns_*` helper or the beneath
  API rather than raw syscalls, and (c) wrap the result in
  `xrootd_vfs_observe_ctx_op()`/`xrootd_vfs_observe_file_op()` with the right
  `XROOTD_METRIC_OP_*`. Then write the 3 tests (success + error + security-neg).
- **Add a new open flag:** define `XROOTD_VFS_O_*` in `vfs.h` and map it in
  `xrootd_vfs_open_flags()` (`vfs_open.c`); cache-affecting flags also belong in
  the cache-eligibility check in `xrootd_vfs_open()`.
- **A new protocol caller** only needs to populate an `xrootd_vfs_ctx_t`
  correctly — set `metrics_proto`, `rootfd`/`root_canon`, the resolved confined
  path, and the `allow_write`/`is_tls`/`want_pgcrc` flags — and call the public
  API; metrics and access logging come for free.

## See also

- [`../path/README.md`](../path/README.md) — produces the confined
  `xrootd_path_result_t` and the `RESOLVE_BENEATH` open primitives this layer relies on.
- [`../cache/README.md`](../cache/README.md) — read-through open + write-through mirroring hooked into open/read/write.
- [`../aio/README.md`](../aio/README.md) — thread-pool offload that runs the VFS read/write bodies off the event loop.
- [`../read/README.md`](../read/README.md), [`../write/README.md`](../write/README.md) — XRootD opcode handlers that frame VFS results onto the stream wire.
- [`../shared/README.md`](../shared/README.md), [`../webdav/README.md`](../webdav/README.md), [`../s3/README.md`](../s3/README.md) — HTTP/S3 file-serving callers.
- [`../dirlist/README.md`](../dirlist/README.md) — consumes `xrootd_vfs_opendir`/`readdir`.
- [`../compat/README.md`](../compat/README.md) — `xrootd_ns_*` namespace mutation helpers and CRC32c.
- [`../metrics/README.md`](../metrics/README.md) — `xrootd_metric_op_done` + access-log emission.
- [`../README.md`](../README.md) — module-wide subsystem index.
