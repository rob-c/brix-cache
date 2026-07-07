# fs — Unified VFS: the single POSIX-filesystem data plane

## Overview

`src/fs/` is the **Virtual File System (VFS)** layer: one protocol-agnostic API
(`brix_vfs_*`) for every byte that touches the local export root. All four
front ends — XRootD `root://` (stream), WebDAV `davs://`/`http://` (HTTP), the
S3 REST subset, and CMS data-server I/O — funnel their open/read/write/stat and
namespace mutations through this layer instead of calling `open`/`pread`/
`rename` directly. That convergence is the point: confinement, metrics, access
logging, page-CRC, and read-through/write-through cache integration are
implemented **once**, here, and inherited by every protocol for free.

The VFS sits between the protocol op handlers and the **storage driver**
([`backend/`](backend/README.md)) — POSIX by default — which performs the actual
syscall over the kernel; the full data path is therefore `proto → VFS → backend`
(POSIX by default), and every byte that touches the export root takes it. A handler builds an
`brix_vfs_ctx_t` (the export root, the already-resolved client path, the
caller identity, write permission, TLS flag, cache config) and calls one VFS
entry point. The VFS calls the storage driver to perform the syscall under
kernel-enforced confinement, records a Prometheus metric and an access-log line,
and hands back either an
opaque handle (`brix_vfs_file_t` / `brix_vfs_dir_t`) or an
`ngx_chain_t`/result struct that the caller frames onto the wire. Callers never
see a raw `fd` except through the accessor `brix_vfs_file_fd()`.

## Shared with the userland clients: `module→vfs_server→vfs→backend`

The byte-I/O **verbs** at the bottom of this layer are shared with the native
clients (`xrdcp`, `xrootdfs`, …), so the full topology is:

```
module ─▶ vfs_server ─▶ vfs ─▶ backend      (this tree: the nginx data plane)
client ──────────────▶ vfs ─▶ backend       (client/lib: the userland tools)
```

- **`backend`** = the storage driver ([`backend/`](backend/README.md), `sd.h` +
  `sd_posix.c`), ngx-free, in `libxrdproto`.
- **`vfs`** = [`core/`](core/README.md) (`vfs_core.c`): the storage-neutral
  `xvfs_pread_full`/`pread_once`/`pwrite_full`/`fsync`/`ftruncate`/`fstat` verbs —
  the EINTR/short-I/O loop policy, single-sourced across both trees.
  `vfs/vfs_read.c` and `vfs/vfs_io_core.c` are thin server wrappers over it.
- **`vfs_server`** = the rest of `src/fs/` (this directory): everything nginx-
  shaped and security-critical that stays server-only — the **export-confined
  open** (`RESOLVE_BENEATH`/`root_canon`), the AIO thread-pool dispatch, sendfile
  chains, metrics, access logging, staged commit, and the confined namespace
  mutations (`mkdir`/`rename`/`unlink`/`xattr`).

Deliberately **not** shared (divergent by design, not duplication): the `open`
(server confined vs client unconfined URL/path), the high-level handle
(`brix_vfs_file_t` is driver-polymorphic + ngx-ctx; the client's
`xrdc_vfs_file` carries a vtable for its non-SD-driver S3 backend), `commit`/
`abort` (export-confined staged-rename vs unconfined temp-rename / MPU), and the
nginx runtime (pool/threadpool/sendfile/metrics). The split keeps the server's
confinement off the client's unconfined paths.

Design: [`docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md`](../../docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md).
Hyper-detailed reference (object model, capability matrix, every data flow, the
S3 transport-vtable trick, the dual-build mechanism, invariants):
[`docs/09-developer-guide/vfs-shared-architecture.md`](../../docs/09-developer-guide/vfs-shared-architecture.md).

Crucially, the VFS does **not** decide *which* path to touch — that is the job of
[`../path/`](path/README.md), which produces the `brix_path_result_t`
embedded in the ctx. The VFS *re-verifies* confinement before every syscall
(`is_confined` must be set and the resolved path non-empty) and then opens via
the kernel `RESOLVE_BENEATH` API in [`../path/beneath.h`](path/README.md). It
also does not run blocking I/O on the event loop on its own behalf. The blocking
read/write/readv/writev/pgread bodies — on a [`../aio/`](../core/aio/README.md)
thread-pool worker, on the io_uring inline fallback, or on the event-loop inline
fallback — execute through one VFS-owned, thread-safe core,
`brix_vfs_io_execute()` in `vfs_io_core.c` (phase-54). The synchronous
`pread`/`pwrite` helpers here are the bodies that core runs, and the read path is
careful to build the *same* buffer chain whether invoked sync or from an AIO
completion. Workers no longer carry their own copies of these syscalls; a few
zero-copy/fast paths stay beside the core by design (see the two-tier boundary
note below).

Callers today: [`../read/`](../protocols/root/read/README.md) and [`../write/`](../protocols/root/write/README.md)
(XRootD opcodes), [`../shared/file_serve.c`](../protocols/shared/README.md),
[`../webdav/`](../protocols/webdav/README.md) (`get.c`, `resource.c`; plus the metered
xattr/copy/staged/delete paths in `prop_xattr.c`, `dead_props.c`, `copy.c`,
`put.c`, `namespace.c`), [`../s3/`](../protocols/s3/README.md) (`object.c`,
`post_object.c`, `put.c`, `tagging.c`, `checksum.c`, `conditional.c`), and
[`../dirlist/`](../protocols/root/dirlist/README.md).

> **Two VFS tiers — metered (loop-only) vs. raw (thread-safe).** Since phase-54
> the VFS exposes two surfaces, and **all disk byte I/O now goes through the VFS**
> regardless of which thread runs it:
>
> 1. **Public metered entry points** (`brix_vfs_open`/`read`/`write`/`stat`/…)
>    allocate from an nginx request `pool` and emit Prometheus metrics +
>    access-log lines — none of which is thread-safe — so they run **only on the
>    event loop**.
> 2. **The worker-safe I/O core** (`brix_vfs_io_execute()`, `vfs_io_core.c`) is
>    the thread-safe EXECUTE surface that the offloaded and inline-fallback raw
>    byte ops now funnel through — `kXR_read`, `write`, `readv`, `writev`,
>    `pgread`, and the `dirlist` scan — whether executed on the
>    [`../aio/`](../core/aio/README.md) thread pool, on the event-loop **inline
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
>    `preadv2(RWF_NOWAIT)` warm-cache probe in [`../read/read.c`](../protocols/root/read/README.md)
>    move bytes without a core buffer at all; (b) the **live synchronous
>    `dirlist`** loop in [`../dirlist/handler.c`](../protocols/root/dirlist/README.md) still runs
>    its own confined `fdopendir`/`readdir` (the core's `OPENDIR` op is wired into
>    the `../aio/dirlist.c` worker, which is currently gated off). These are
>    tracked follow-ups, not separate raw-I/O implementations of the offload path.
>
> Namespace **mutation** has two tiers: the metered
> `brix_vfs_unlink`/`rmdir`/`rename`/`mkdir`/`copy` and the staged-write family
> are loop-only, while worker-thread namespace mutation — native TPC pull
> (`../tpc/source.c`), async/multipart S3 PUT assembly, the collection COPY/MOVE
> engines — uses the thread-safe raw-path primitives
> (`brix_vfs_open_fd`/`_at`, `brix_vfs_unlink_path`/`_at`,
> `brix_vfs_mkdir_path`, `brix_vfs_rename_path`, `brix_vfs_walk`) or the
> `brix_ns_*` / `compat/staged_file` tier beneath them. Both share the same
> `RESOLVE_BENEATH` confinement; only the VFS's metering/cache layer is skipped on
> the worker tier. (Phase-55 landed the pluggable storage-driver seam —
> [`backend/`](backend/README.md) — POSIX default; unifying the worker-tier
> namespace mutation beneath a single metered seam remains the follow-up.)
>
> **Phase-62 closed the namespace/metadata SEAM in handler code.** Beyond the byte
> data plane, *every* protocol handler now reaches `open`/`stat`/`opendir`/
> `unlink`/`rename`/`mkdir`/`truncate`/`chmod`/`xattr` on an export path through
> `brix_vfs_*` — never a raw libc call. The only raw filesystem syscalls left in
> handler code are (a) genuinely non-export resources (config/cert/token, `/tmp`
> creds, `/dev/null`, `/proc` fd-hygiene, sockets) and (b) **separate svc-owned
> storage domains** (the read-through cache, the upload stage dir, the FRM
> control/journal store, S3 multipart staging, the checkpoint journal) that must
> NOT be confined to the export root / impersonation broker — and each of those
> carries an explicit `/* vfs-seam-allow: <reason> */` marker. A third CI guard
> tier enforces this; see "The three guard tiers" below and
> [`../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md`](../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md).

## Files

All of the following live under [`vfs/`](vfs/) — the facade layer, moved off
the `src/fs/` root in phase-67. The sibling concept dirs are `core/` (ngx-free
verb kernel), `backend/` (storage drivers), `path/` (confinement), `cache/`,
`tier/`, `xfer/`, and `scan/`.

| File | Responsibility |
|---|---|
| `vfs.h` | Public API. Open flags (`BRIX_VFS_O_READ/WRITE/CREATE/EXCL/TRUNC/APPEND/MKDIRPATH/NOCACHE`), opaque handle types, the `brix_vfs_ctx_t` request descriptor, `brix_vfs_stat_t`/`brix_vfs_io_result_t`, and every `brix_vfs_*` prototype. The only header protocol handlers should include. |
| `vfs_internal.h` | Implementation-private definitions: the real `brix_vfs_file_s`/`brix_vfs_dir_s` structs, confinement/write guards (`brix_vfs_require_confined`, `brix_vfs_require_write`), the metrics+access-log observer helpers (`brix_vfs_observe_*`), and shared internal prototypes (`pread_full`, `pwrite_full`, `adopt_fd`, `fill_stat`). |
| `vfs_io_core.h` | The **thread-safe** I/O surface: the POD job descriptor `brix_vfs_job_t` (IN fields + OUT results), the readv/writev segment descriptors, the per-op `brix_vfs_job_*_init` helpers, and the `brix_vfs_io_execute()` prototype. The only fs header a thread-pool worker or io_uring fallback may include. |
| `vfs_io_core.c` | The worker-safe EXECUTE core (phase-54). `brix_vfs_io_execute()` dispatches one job to a small per-op helper for READ/WRITE/PGREAD/READV/WRITEV/OPENDIR, mutating only the job's OUT fields and caller-owned buffers — **no pool, metrics, log, or cache**. Reuses the pure bodies (`brix_vfs_pread_full`/`pwrite_full`, `brix_pgread_read_encode_inplace`, `brix_readv_read_segments`) and builds the `kXR_dirlist` response from a confined `fdopendir` scan. This is the shared raw-I/O body for every dispatch tier (inline / thread pool / io_uring). |
| `vfs_open.c` | Open/close + handle lifecycle. Maps flags to `O_*`, runs the cache-first / confinement-cascade open logic, `fstat`s into the handle, registers pool cleanup. Also hosts the shared helpers (`fill_stat`, `copy_path`, `register_fd_cleanup`, `adopt_fd`) and the `brix_vfs_file_*` accessors. |
| `vfs_read.c` | Read path. `brix_vfs_read()` chooses memory-backed chain (TLS or page-CRC wanted) vs file-backed chain (cleartext sendfile via `dup`'d fd), caps length at EOF, computes per-read CRC32c, records cache access. `brix_vfs_pread_full()` is the EINTR-safe full-read primitive used everywhere. |
| `vfs_write.c` | Write path. `brix_vfs_write()` walks an input `ngx_chain_t` writing in-file and in-memory bufs to the destination offset, extends CRC32c, grows the cached handle size, and consults the write-through cache decision. `brix_vfs_pwrite_full()` is the EINTR/short-write-safe primitive. |
| `vfs_dir.c` | Directory enumeration: `opendir`/`readdir`/`closedir`. Skips `.`/`..`, returns each entry name as a pooled `ngx_str_t` plus an optional `lstat` of the child. Returns `NGX_DONE` at end-of-stream. |
| `vfs_stat.c` | `brix_vfs_stat()` (`lstat`, no follow) / `brix_vfs_statf()` (follow in-export symlinks, `RESOLVE_IN_ROOT`) — metered `OP_STAT`, filled into `brix_vfs_stat_t`. `brix_vfs_probe(ctx, nofollow, &vst)` is the **non-metered** existence/type pre-check for op-resolution / ACL gates (routing those pre-stats through the metered stat would log a phantom `OP_STAT` per rm/mkdir/mv). |
| `vfs_mkdir.c` | `brix_vfs_mkdir()` — delegates to `brix_ns_mkdir` (namespace layer) with optional `parents`; write-gated. |
| `vfs_rename.c` | `brix_vfs_rename()` — delegates to `brix_ns_rename`; requires a confined destination `brix_path_result_t`; write-gated. |
| `vfs_unlink.c` | Delete family: shared `brix_vfs_delete()` → `brix_ns_delete`; `brix_vfs_unlink()` (file) and `brix_vfs_rmdir()` (recursive or require-empty). Write-gated. |
| `vfs_sync.c` | `brix_vfs_truncate()` (`ftruncate` + handle-size update) and `brix_vfs_sync()` (`fsync`). |
| `vfs_xattr.c` | Extended-attribute family over the `user.` namespace (S3 tagging, WebDAV dead-properties, the lock database, fattr, checksum-at-rest), metered as `OP_XATTR`, set/remove **not** `allow_write`-gated (the lock DB writes on read-only requests; the protocol layer authorizes). **Path/ctx variants** `brix_vfs_getxattr/listxattr/setxattr/removexattr` delegate to `brix_*xattr_confined_canon` (confined to `ctx->resolved`). **Open-handle (fd) variants** `brix_vfs_fgetxattr/flistxattr/fsetxattr/fremovexattr(ctx_or_NULL, fd, …)` operate on an fd the VFS already opened confined (confinement travels with the descriptor; `ctx` optional, only for the metric) — used by fattr's file-handle mode and `compat/integrity_info`'s checksum cache. |
| `vfs_copy.c` | `brix_vfs_copy()` — single regular-file server-side copy (`copy_file_range`) behind WebDAV COPY / S3 CopyObject. Delegates to `brix_ns_local_copy`; write-gated; metered as `OP_COPY` (byte count from the post-copy destination size). |
| `vfs_staged.c` | Atomic staged-write lifecycle (`brix_vfs_staged_open` → write the fd → `brix_vfs_staged_commit`/`abort`) behind crash-safe S3 PutObject / WebDAV PUT. Wraps `compat/staged_file`; write-gated at open; the commit (atomic publish onto the final path) is metered as `OP_WRITE`. |
| `vfs_walk.c` | The **thread-safe, pool-free confined primitives** for off-loop / bulk consumers (multipart assembly, TPC, recursive scans) that cannot use the metered handle API but must still go through the VFS: `brix_vfs_open_fd`/`open_fd_at` (raw-fd confined open), `brix_vfs_unlink_path`/`unlink_at`, `brix_vfs_mkdir_path`, `brix_vfs_rename_path` (returns errno + `was_dir`), `brix_vfs_walk` (confined tree walk with a per-file callback), and `brix_vfs_copyfile`/`copytree`. Impersonation-aware; no pool, no metric. |
| `vfs_scratch.c` / `.h` | Materialize-to-scratch (`brix_vfs_scratch_*`): capability-gated staging of an object → local POSIX scratch and back via a VFS↔VFS move, for FRM copy-in/out of a non-fd backend. First consumer is the FRM copycmd (`BRIX_FRM_STAGE_DIR`). |
| `fd_cache.c` | Reserved slot for future fd-cache unification; currently only a header include + design note. No live code. |
| `vfs_backend_config.c` | Per-export storage-backend **directive parsing** (phase-67 split): turns the `brix_*_backend` / origin / §14-credential config into `brix_vfs_backend_entry_t` registry entries. |
| `vfs_backend_registry.c` / `vfs_backend_internal.h` | Per-export backend **registry**: the `brix_vfs_backend_entry_t` table, source build + tier/decorator composition, and `brix_vfs_backend_resolve()`. Also exposes `brix_vfs_backend_http_endpoint(root_canon, &host, &port, &tls, &base)` — the HTTP origin of an `http`/`https` backend, for protocol-side **uncached passthroughs** (phase-68 cvmfs geo/manifest) that address the same origin the tier fills from. (phase-67 split the old monolithic `vfs_backend_registry.c` into these two.) |

## Key types & data structures

- **`brix_vfs_ctx_t`** (`vfs.h`) — the per-operation request descriptor the
  caller fills in: `pool`/`log`, `identity`, `metrics_proto` (stream/webdav/s3),
  `root_canon` + `cache_root_canon`, the persistent per-worker `rootfd`
  (O_PATH, or `-1`), the already-resolved `brix_path_result_t resolved`, and
  the `allow_write` / `is_tls` / `want_pgcrc` / `cache_enabled` /
  `cache_writethrough` bitflags. This struct *is* the VFS's view of a request.
- **`brix_vfs_file_t`** (opaque; real definition `brix_vfs_file_s` in
  `vfs_internal.h`) — an open file handle: `fd`, cached `size`/`mtime`/`ctime`/
  `ino`/`mode`, the pool it lives in, a back-pointer to the originating `ctx`, a
  pooled copy of `path`, and `from_cache`/`is_tls` flags. Cached `size` lets the
  read/write paths bound I/O and the stat path answer without extra syscalls.
- **`brix_vfs_dir_t`** — an open directory iterator (`DIR*` + pool + path).
- **`brix_vfs_stat_t`** — protocol-neutral stat: `size`, `mtime`/`ctime`/
  `atime`, `mode`, `ino`, `dev`, `uid`/`gid`, `blocks`, `is_directory`/
  `is_regular`. Built by `brix_vfs_fill_stat()`. (`atime` is consumed by
  `kXR_Qxattr`'s `oss.at`; `dev`+`ino` form the kXR stat id; `uid`/`gid`/`mode`
  derive the readable/writable flags; `blocks` is the statvfs-style size.)
- **`brix_vfs_io_result_t`** — per-I/O outcome handed back to the framer:
  `offset`, `length`, `crc32c`, and `from_cache`/`eof` flags. The `crc32c` field
  feeds pgread/pgwrite per-page CRC framing.

## Control & data flow

**Entry.** A protocol op handler resolves the client path via
[`../path/`](path/README.md), stamps an `brix_vfs_ctx_t`, and calls a single
VFS function. There is no dispatcher inside `fs/`; each entry point is called
directly.

**Open (`vfs_open.c`).** `brix_vfs_require_confined()` rejects unconfined or
empty paths; a write open additionally requires `allow_write`. Then:
1. `brix_cache_open()` ([`../cache/`](cache/README.md)) gets first refusal —
   a read-through cache hit returns a ready handle and bumps the cache-hit
   metric; `NGX_DECLINED` falls through (and records a miss).
2. Otherwise the **confinement cascade**: `rootfd >= 0` →
   `brix_open_beneath()` (the hot path, `openat2(RESOLVE_BENEATH)`);
   else `root_canon` → `brix_open_confined_canon()` (same semantics, per-call
   rootfd, for legacy callers); else raw `open()` — *only* reachable for
   server-constructed absolute paths with no export root, never for a client
   path. See the long comment at `vfs_open.c:273-288`.
3. `brix_vfs_adopt_fd()` fstats the fd into a handle. Note: the open path does
   **not** register pool-cleanup on the handle fd; the caller owns `close` via
   `brix_vfs_close()`. (The read path does register cleanup on the *dup*'d
   sendfile fd — see below.)

**Read (`vfs_read.c`).** Caps `length` to `size - offset` (setting `eof`), then
branches on transport: TLS or `want_pgcrc` → `make_memory_chain()`
(`ngx_pnalloc` + `pread_full`, `b->memory=1`, CRC computed inline); cleartext →
`make_file_chain()` (`dup` the fd, register `ngx_pool_cleanup_file`, emit an
`in_file` buf for sendfile). Cache hits record access into
[`../cache/`](cache/README.md). The synchronous body here is what
[`../aio/`](../core/aio/README.md) runs in the thread pool; the AIO completion
rebuilds an identical chain on the event loop.

**Write (`vfs_write.c`).** Iterates the input chain, copying in-file bufs in
`BRIX_VFS_COPY_CHUNK` (64 KiB) blocks via `pread_full`→`pwrite_full` and
writing in-memory bufs directly, extending the CRC32c and advancing `dst_off`.
On success it grows the handle's cached `size` and asks
[`../cache/`](cache/README.md) whether the region should be mirrored
write-through.

**Namespace ops (`vfs_mkdir.c`/`vfs_rename.c`/`vfs_unlink.c`).** These do not
syscall directly; they delegate to the `brix_ns_*` family in
[`../compat/namespace_ops`](../core/compat/README.md) (which itself confines via the
beneath API), translating `brix_ns_result_t.status`/`.sys_errno` back to
`NGX_OK`/`NGX_ERROR` + `errno`.

**Exit / observability.** Every entry point wraps its result through
`brix_vfs_observe_*` (`vfs_internal.h`), which calls `brix_metric_op_done()`
([`../metrics/`](../observability/metrics/README.md)) and `brix_access_log_emit()`
([`../metrics/access_log`](../observability/metrics/README.md)) with op, byte count, latency,
and an `brix_err_class_t` derived from `errno` — then restores `errno` for the
caller. This is why protocol handlers don't (and shouldn't) emit their own
per-op data-plane metrics.

## Invariants, security & gotchas

1. **Confinement is re-checked here, not trusted.** Every entry point calls
   `brix_vfs_require_confined()` (`vfs_internal.h:54`): the resolved path must
   be non-empty *and* `resolved.is_confined` must be set, else `EINVAL`. Actual
   filesystem access then goes through `brix_open_beneath` /
   `brix_open_confined_canon` / `brix_ns_*`, all of which use
   `RESOLVE_BENEATH`. An `EXDEV` from those means an escape attempt — callers map
   it to `kXR_NotAuthorized`/403 (see [`../path/beneath.h`](path/README.md)).
2. **The raw-`open()` branch is not a bypass.** It is only reached when the ctx
   carries *no* root at all (server-constructed absolute path). Client requests
   always set a root and take the confined branches. Do not "simplify" the
   cascade in `vfs_open.c` without preserving this property.
3. **Fail-closed writes.** `brix_vfs_require_write()` checks `allow_write`
   *after* confinement and before any mutation; `brix_vfs_open()` rejects a
   write open up front with `EACCES`. This is the data-plane backstop behind the
   protocol-layer write gate — both must hold.
4. **TLS vs cleartext buffers never mix.** `vfs_read.c` is the chokepoint:
   `is_tls` (or `want_pgcrc`) → memory-backed buf (`b->memory=1`); cleartext →
   file-backed `in_file` buf for sendfile. Never emit a file-backed buf on a TLS
   connection.
5. **pgread/pgwrite CRC.** `want_pgcrc` makes both read and write compute a
   CRC32c (`brix_crc32c_value` / `brix_crc32c_extend`) into
   `io_result.crc32c`; the framer turns that into `kXR_status` (4007) per-page
   framing. The VFS computes the checksum but does not frame it.
6. **Event-loop safety.** `pread_full`/`pwrite_full` loop on `EINTR` and short
   writes but are *blocking*. On hot paths they run inside the
   [`../aio/`](../core/aio/README.md) thread pool, never directly on the event loop.
   Treat new blocking syscalls added here as AIO-offload candidates.
7. **Sendfile fd ownership.** `make_file_chain()` `dup`s the handle fd and
   registers `ngx_pool_cleanup_file`, so the request pool closes the *duplicate*
   independently of `brix_vfs_close()`. Don't close the handle out from under
   an in-flight sendfile buf.
8. **`stat` uses `lstat`** (no symlink follow) and `readdir` filters `.`/`..`.
   `brix_vfs_file_stat()` answers from the metadata cached at open time when the
   handle's `stat_current` bit is set (phase-45 W2/R1 — `adopt_fd` already
   `fstat`'d the fd), avoiding a redundant `fstat` on the GET hot path. `adopt_fd`
   sets the bit only for **read-only** handles, whose file cannot change through
   them; a writable handle leaves it clear so any stat issues a live `fstat`.
   read/write bound I/O against the *cached*
   `fh->size` for speed — a file grown by another writer won't be seen until reopen.
9. **`errno` discipline.** Helpers set `errno` on failure and the observers
   restore the caller's `errno` after logging; rely on the documented `errno`,
   not on globals surviving the metrics call.
10. **`fd_cache.c` is a placeholder.** No live logic; don't wire callers to it
    until the cache-unification step lands.
11. **Export only — separate domains stay raw (impersonation boundary).** The VFS
    confines to ONE export root and (under impersonation) routes to the broker as
    the mapped user. So the VFS is for **export** paths only. A cache-root, upload-
    stage, FRM-control, S3-multipart-staging, or checkpoint-journal file is a
    *different svc-owned root* — opening it through the VFS would resolve the wrong
    root under the wrong identity. Those are opened raw, as the worker, behind a
    `/* vfs-seam-allow: <reason> */` marker. Do not "fix" a marked raw call by
    routing it through `brix_vfs_*`. When passing a path to the `root_canon`
    primitives (`brix_vfs_open_fd`/`unlink_path`/…) pass the **absolute** path —
    they strip `root_canon` themselves.

## The CI seam guard (three tiers)

`tools/ci/check_vfs_seam.sh` enforces "the VFS is the sole source of storage
truth" and is **green on all three tiers with every backlog at 0**. Run it in CI;
`--regen` re-snapshots the backlogs after a deliberate migration.

| Tier | Catches | Rule | Backlog |
|---|---|---|---|
| **tier-1** | raw positional **byte** ops (`pread`/`pwrite`/`copy_file_range`/`sendfile`) outside `backend/` | HARD (no backlog); `RAW_ALLOW` for documented non-export files | — |
| **tier-2 / 1.5** | a handler calls the confined-helper layer (`*_confined_canon`/`_beneath`, `brix_ns_*`) or the SD vtable directly instead of `brix_vfs_*` | grandfathered | `tools/ci/vfs_seam_backlog.txt` (0) |
| **tier-3** | a handler makes a raw **namespace/metadata** syscall (`open`/`stat`/`opendir`/`unlink`/`rename`/`mkdir`/`truncate`/`chmod`/xattr/…) on storage | grandfathered + per-line marker | `tools/ci/vfs_seam_backlog_ns.txt` (0) |

**The `vfs-seam-allow` marker.** A raw namespace/metadata call that is *correct*
— because it touches a **separate svc-owned storage domain** (cache / upload
stage / FRM control / S3 multipart staging / checkpoint journal) or a
**non-export resource** (config/cert/token, `/tmp` creds, `/dev/null`, `/proc`) —
carries a same-line `/* vfs-seam-allow: <reason> */` comment. The guard greps the
marker on the raw line *before* stripping comments/strings, then matches the
syscall *after* stripping (so an op name in a comment is never a false hit). The
`TIER3_ALLOW` list wholesale-excludes the below-seam layer (`fs/`, `path/`,
`compat/`, `impersonate/`), the separate-domain stores (`cache/`, `dashboard/`,
`frm/`, `write/chkpoint`, `read/slice_read`), and the config/auth readers.

**Why separate domains stay raw — the impersonation boundary.**
`brix_vfs_open_fd`/`probe`/xattr route, underneath, to the impersonation broker,
which resolves under the **export** rootfd as the **mapped user**. That is correct
for export paths but *wrong* for a cache/stage/journal file (a different,
svc-owned root): the broker would open the wrong root as the wrong identity. Those
domains are therefore opened **as the worker** with a raw, marked call — by
design, not omission. See
[`../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md`](../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md) §4.

## Entry points / extending

- **Add a new VFS operation** (e.g. a new namespace mutation): declare it in
  `vfs.h`, add a focused `vfs_<op>.c`, register the file in the top-level `config`
  script (the module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list) and re-run
  `./configure`, and in the body
  (a) call `brix_vfs_require_confined()` / `brix_vfs_require_write()` as
  appropriate, (b) prefer delegating to an `brix_ns_*` helper or the beneath
  API rather than raw syscalls, and (c) wrap the result in
  `brix_vfs_observe_ctx_op()`/`brix_vfs_observe_file_op()` with the right
  `BRIX_METRIC_OP_*`. Then write the 3 tests (success + error + security-neg).
- **In any handler, never raw-syscall an export path.** Use `brix_vfs_*`:
  `brix_vfs_probe` for an existence/type check, `brix_vfs_stat`/`statf` for
  metadata, `brix_vfs_open`/`open_fd`/`open_fd_at` to open, the xattr path/fd
  variants, `brix_vfs_unlink_path`/`unlink_at`/`mkdir_path`/`rename_path` for
  off-loop namespace mutation. A raw call to a separate svc-owned domain or a
  non-export resource is allowed but MUST carry a same-line `vfs-seam-allow`
  marker (see "The CI seam guard"). `tools/ci/check_vfs_seam.sh` rejects an
  unmarked new raw namespace/metadata syscall.
- **Add a new open flag:** define `BRIX_VFS_O_*` in `vfs.h` and map it in
  `brix_vfs_open_flags()` (`vfs_open.c`); cache-affecting flags also belong in
  the cache-eligibility check in `brix_vfs_open()`.
- **A new protocol caller** only needs to populate an `brix_vfs_ctx_t`
  correctly — set `metrics_proto`, `rootfd`/`root_canon`, the resolved confined
  path, and the `allow_write`/`is_tls`/`want_pgcrc` flags — and call the public
  API; metrics and access logging come for free.

## See also

- [`../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md`](../../docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md)
  — the full namespace/metadata seam closure: the three guard tiers, the
  `vfs-seam-allow` marker, the impersonation/separate-domain boundary, and the
  per-cluster migration record. **Read this before adding raw FS access anywhere.**
- [`backend/README.md`](backend/README.md) — the Storage Driver (SD) layer
  directly beneath the VFS: the `brix_sd_driver_t` vtable and the POSIX/block/
  S3/Ceph/pblock drivers + the CSI page-checksum tagstore that issue every raw
  `pread`/`pwrite`/`copy_range`/`fstat`/`open` for this layer.
- [`core/README.md`](core/README.md) — the shared, `ngx`-free I/O verb core
  (`xvfs_*` in `vfs_core.c`): the EINTR/short-I/O loop policy single-sourced
  between this server tree and the native clients (`client/lib`).
- [`xfer/README.md`](xfer/README.md) — the unified durable-transfer engine: one
  state machine + ledger behind normal staging, tape stage-out, proxy
  write-through, and TPC (consumed by `vfs_staged.c`, `cache/writethrough_*`,
  `webdav/tpc*`, `s3/put_finalize.c`, `read/close.c`).
- [`../path/README.md`](path/README.md) — produces the confined
  `brix_path_result_t` and the `RESOLVE_BENEATH` open primitives this layer relies on.
- [`../cache/README.md`](cache/README.md) — read-through open + write-through mirroring hooked into open/read/write.
- [`../aio/README.md`](../core/aio/README.md) — thread-pool offload that runs the VFS read/write bodies off the event loop.
- [`../read/README.md`](../protocols/root/read/README.md), [`../write/README.md`](../protocols/root/write/README.md) — XRootD opcode handlers that frame VFS results onto the stream wire.
- [`../shared/README.md`](../protocols/shared/README.md), [`../webdav/README.md`](../protocols/webdav/README.md), [`../s3/README.md`](../protocols/s3/README.md) — HTTP/S3 file-serving callers.
- [`../dirlist/README.md`](../protocols/root/dirlist/README.md) — consumes `brix_vfs_opendir`/`readdir`.
- [`../compat/README.md`](../core/compat/README.md) — `brix_ns_*` namespace mutation helpers and CRC32c.
- [`../metrics/README.md`](../observability/metrics/README.md) — `brix_metric_op_done` + access-log emission.
- [`../README.md`](../README.md) — module-wide subsystem index.
