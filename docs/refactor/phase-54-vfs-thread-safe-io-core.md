# Phase 54 — Thread-Safe VFS I/O Core (route all disk ops through the VFS layer)

**Status:** PLAN ONLY (not implemented). Authored 2026-06-24.

**Scope chosen:** Full rewire (incremental) — build the thread-safe core AND migrate
every existing AIO worker through it, phase-by-phase with perf gates.

**Definition of done:** every stream worker-thread data-plane operation reaches
disk through a VFS-owned thread-safe primitive; the event loop remains the only
place that allocates from nginx pools, mutates connection/file accounting, emits
metrics/access logs, or touches the read-through/write-through cache. The old raw
worker `pread`/`pwrite`/`open` loops either disappear or become thin wrappers
around the shared core.

**Non-goals for the first landing:** no io_uring redesign, no protocol wire
format changes, no new fd-cache feature, and no attempt to move protocol
framing into `src/fs/`. Protocol code still owns XRootD/WebDAV/S3 response
frames; the VFS owns path confinement, raw I/O execution, cache side effects,
and VFS-level observability.

---

## Context

Today the VFS layer (`src/fs/`) is the single, metered, cache-aware chokepoint for disk I/O — but **only on the nginx event loop**. It is deliberately *not* thread-safe: its entry points allocate handles/buffers from the per-request nginx `pool` (`ngx_pcalloc`/`ngx_pnalloc`), emit Prometheus metrics + access-log lines, and touch the read-through cache — none of which are safe off the event loop (documented in `src/fs/README.md:42-52`).

As a result, every worker-thread disk op in `src/aio/` **bypasses the VFS entirely** and re-implements the raw syscall: `reads.c` (`pread`, pgread `pread`+CRC), `write.c` (`pwrite`, writev `pwrite`+`fsync`), `readv.c` (`preadv`), `dirlist.c` (raw `open`+`fdopendir`+`readdir`+`fstatat` on a path "trusted" as pre-confined). This duplication means confinement, CRC, error-mapping, metrics, and logging each have two implementations that can drift, and the dirlist worker re-opens a directory with a bare `open()` that merely *trusts* a prior confinement check.

**Goal:** make the VFS the single chokepoint for *all* disk I/O, including worker-thread offloads, by splitting each operation into a **PREPARE / EXECUTE / COMPLETE** triad that maps onto the existing `xrootd_aio_post_task` lifecycle. The thread-only EXECUTE phase becomes a small, pure, POD-only "VFS I/O core" that workers call instead of duplicating syscalls — while pool allocation, metrics, logging, and cache mutation stay on the loop. Outcome: one confinement path, one CRC path, one error-mapping path, a closed dirlist confinement gap, and an enforced thread-safety contract — with no data-plane perf regression.

## Current duplication inventory

These are the concrete raw worker paths that Phase 54 collapses into the VFS
core. The inline fallback paths must use the same core call too; otherwise the
thread path and no-thread/queue-full path will keep drifting.

| Path | Current worker body | Current loop completion body | Phase 54 target |
|---|---|---|---|
| `src/aio/reads.c` `xrootd_read_aio_thread` | one raw `pread(t->fd, t->databuf, t->rlen, t->offset)` | bytes counters, `XROOTD_OP_*`, chunked chain, buffer release | `XROOTD_VFS_IO_READ` job; done callback keeps protocol chain and delegates VFS completion/accounting |
| `src/aio/reads.c` `xrootd_pgread_aio_thread` | `xrootd_pgread_read_encode_inplace()` directly | pgread status chain, access log, counters | `XROOTD_VFS_IO_PGREAD` job so pgread CRC framing has one core path |
| `src/aio/readv.c` `xrootd_readv_aio_thread` | `xrootd_readv_read_segments()` directly | response byte count, counters, chain | `XROOTD_VFS_IO_READV` job over the pre-built segment plan |
| `src/aio/write.c` `xrootd_write_aio_thread` | one raw `pwrite(t->fd, t->data, t->len, t->offset)` | short-write mapping, dirty/write-recovery journal, ack | `XROOTD_VFS_IO_WRITE` job; completion owns mutations and ack |
| `src/aio/write.c` `xrootd_writev_write_aio_thread` | per-segment raw `pwrite`, optional per-segment `fsync` | per-segment counters, dirty/journal, access log | `XROOTD_VFS_IO_WRITEV` job over the existing segment descriptors |
| `src/aio/dirlist.c` `xrootd_dirlist_aio_thread` | raw `open(t->resolved)` then `fdopendir`/`readdir`/`fstatat` | access log, queue flat response buffer | `XROOTD_VFS_IO_OPENDIR` job with loop-side beneath-confined `O_PATH` fd |

The stream open/handle layer (`xrootd_file_t` in `ctx->files[]`) remains the
protocol ownership model during this phase. Phase 54 does not require replacing
stream slots with pooled `xrootd_vfs_file_t` handles in one jump. Instead it
adds a narrow adapter: PREPARE snapshots the stream slot fields needed by the
VFS core (`fd`, canonical path, cached size, flags, handle index), EXECUTE sees
only the immutable snapshot, and COMPLETE writes back the event-loop-owned
accounting. That keeps the diff incremental and preserves bound-secondary
handle revalidation in `fd_table.c`.

## Before / after call flow

The target is not "make AIO call the public VFS API from a thread". That would
move the bug, because public VFS functions are intentionally loop-only. The
target is to factor the VFS into loop-only wrappers around a shared thread-safe
execution kernel.

**Before, worker path:**

```text
protocol handler
  -> validate/auth/resolve/open
  -> allocate AIO task and buffers
  -> worker calls raw pread/pwrite/open/readdir
  -> done callback updates counters/logs/builds response
```

**Before, public VFS path:**

```text
protocol HTTP/S3/WebDAV caller
  -> xrootd_vfs_read/write/opendir
       -> pool allocation
       -> raw syscall
       -> cache side effects
       -> VFS metrics/access-log
```

**After, both paths:**

```text
loop PREPARE
  -> validate/resolve/open/allocate/snapshot
EXECUTE
  -> shared POD-only syscall/CRC/scan core
loop COMPLETE
  -> normalize result/cache/metrics/accounting/response
```

The public VFS calls still look synchronous to their callers. Internally they
just run PREPARE, call EXECUTE inline, then run COMPLETE. The AIO path runs the
same EXECUTE body in the thread pool and runs COMPLETE from the existing done
callback.

## Architecture: the three phases

| Phase | Thread | Responsibilities | Owns the non-thread-safe bits |
|---|---|---|---|
| **PREPARE** | event loop | validate handle/capability, re-check confinement where a path is opened, fd resolve/open, allocate handle + I/O buffers, TLS-vs-cleartext decision, snapshot into a POD `xrootd_vfs_job_t` | `ngx_pcalloc`/`ngx_pnalloc`, `xrootd_cache_open`, `xrootd_cache_should_writethrough`, sendfile-vs-memory choice, stream-slot liveness checks |
| **EXECUTE** | worker thread / inline fallback | pure `pread`/`pwrite`/`preadv`/`readdir`/CRC into pre-allocated buffers; results into OUT fields; capture `errno` | **nothing** — this is the thread-safe surface |
| **COMPLETE** | event loop | emit metrics + access-log, `xrootd_cache_record_access`, grow cached sizes/clear stat flags, update `xrootd_file_t` counters, dirty write-through ranges, record write-recovery journal entries, free detached buffers | `xrootd_metric_op_done`, `xrootd_access_log_emit`, `ctx->files[].bytes_*`, `wt_*`, `wrts_*` |

Key reuse: `xrootd_vfs_pread_full` (`vfs_read.c:31`) and `xrootd_vfs_pwrite_full` (`vfs_write.c:32`) are **already** the EXECUTE phase — POD fd + raw buffer, no pool/ctx/metrics. They get re-cast as the canonical core. The synchronous public `xrootd_vfs_read`/`_write` get re-expressed as `prepare → execute (inline) → complete`, so the loop path and the thread path share the exact same three calls.

Two completions exist and must stay separate:
- **VFS completion**: cache access, VFS metrics/access-log, cached VFS handle
  metadata (`fh->size`, `stat_current`), and result normalization.
- **Protocol completion**: XRootD stream counters, write-through dirty ranges,
  write-recovery journal, response frames, send queue ownership, and
  `xrootd_aio_resume()`.

The worker can never call either completion directly. A queue-full/no-thread
fallback still builds the same `xrootd_vfs_job_t`, calls EXECUTE inline, and then
runs the same completion helpers on the event loop before returning.

## The POD job descriptor + core (new, VFS-THREAD-SAFE)

**New header `src/fs/vfs_io_core.h`** — one copyable struct + one dispatcher, no `ngx_pool_t`/`xrootd_vfs_ctx_t`/`ngx_connection_t`:

```c
typedef enum {
    XROOTD_VFS_IO_READ,
    XROOTD_VFS_IO_WRITE,
    XROOTD_VFS_IO_PGREAD,
    XROOTD_VFS_IO_READV,
    XROOTD_VFS_IO_WRITEV,
    XROOTD_VFS_IO_OPENDIR
} xrootd_vfs_io_op_e;

typedef struct {
    /* IN (immutable during flight) */
    xrootd_vfs_io_op_e op;
    ngx_fd_t  fd;          off_t offset;   size_t length;
    u_char   *buf;         size_t buf_cap;  unsigned want_pgcrc:1;
    void     *segs;        size_t nsegs;    unsigned do_sync:1;   /* readv/writev */
    int       rootfd;                                            /* opendir variant */
    /* OUT (written by execute only) */
    ssize_t   nio;         size_t out_size; uint32_t crc32c;     int io_errno;
} xrootd_vfs_job_t;

void xrootd_vfs_io_execute(xrootd_vfs_job_t *job);   /* VFS-THREAD-SAFE */
```

Descriptor rules:
- The job is stack-copyable and contains no `ngx_pool_t`, `ngx_connection_t`,
  `ngx_stream_session_t`, `xrootd_ctx_t`, `xrootd_vfs_ctx_t`, `xrootd_vfs_file_t`,
  `DIR *`, or owned heap pointer whose lifetime is not already pinned by the
  event loop.
- IN fields are immutable after `xrootd_aio_post_task()` succeeds. OUT fields
  are written only by `xrootd_vfs_io_execute`.
- `buf`/`segs` point to event-loop-prepared storage that is exclusively owned by
  this in-flight job until COMPLETE returns or the send path assumes ownership.
- `io_errno` is set to 0 before dispatch and copied from `errno` immediately
  after the failing syscall. COMPLETE must use `job->io_errno`, not ambient
  `errno`.
- Short read and EOF are not errors for READ/PGREAD; short write is an error for
  WRITE/WRITEV because the XRootD write replies are all-or-nothing.
- A zero-length READ/WRITE job is legal. EXECUTE must return success without
  relying on libc behavior for zero-byte syscalls.
- `rootfd` in an OPENDIR job is an already-confined fd prepared on the loop. The
  thread may duplicate it and derive `dirfd(dp)`, but must not re-open by path.

### Job result semantics

All arms should use one result vocabulary so completion callbacks stop carrying
operation-specific syscall folklore:

| Field | READ | WRITE | PGREAD | READV | WRITEV | OPENDIR |
|---|---|---|---|---|---|---|
| `nio` | raw bytes read; 0 = EOF | bytes written; must equal `length` | raw file bytes read | not required, may mirror total | not required, may mirror total | 0 on success |
| `out_size` | same as `nio` unless future transform | same as `nio` | encoded `[crc][data]` bytes | full response bytes | total committed bytes | response bytes |
| `crc32c` | request CRC when wanted | optional write CRC | unused; per-page CRC is embedded | unused | unused | unused |
| `io_errno` | set only on hard error | set on hard/short write | set only on hard error | set on first hard error | set on first hard/short error | set on open/scan/size error |

Recommended normalization:
- Success: `io_errno = 0`, `nio >= 0`, `out_size` meaningful for the op.
- EOF: success for READ/PGREAD, with `nio = 0`, `out_size = 0`.
- Hard syscall error: `nio = -1`, `io_errno = saved errno`.
- Short write: `nio >= 0`, `io_errno = EIO` or `ENOSPC` if the platform exposed
  it; COMPLETE sends the same "short write (disk full?)" text as today.
- Unsupported/malformed job: `nio = -1`, `io_errno = EINVAL`; this should only
  be reachable in tests because PREPARE validates before dispatch.

**New `src/fs/vfs_io_core.c`** — `xrootd_vfs_io_execute` is a pure `switch (job->op)` (no fall-through, no goto), each arm a small static fn delegating to an existing pure primitive:
- READ → `xrootd_vfs_pread_full` (+ optional `xrootd_crc32c_value`)
- WRITE → `xrootd_vfs_pwrite_full`
- PGREAD → `xrootd_pgread_read_encode_inplace` (`src/read/pgread.c` — reuse verbatim)
- READV → `xrootd_readv_read_segments` (`src/read/readv.c` — already pure)
- WRITEV → per-seg `xrootd_vfs_pwrite_full` loop + optional `fsync` (body currently inlined in `write.c:258`)
- OPENDIR → `fdopendir(dup(job->rootfd))` + readdir/fstatat/checksum scan (body moved from `dirlist.c`)

Each arm captures `errno` into `job->io_errno` before returning.

The dispatcher must be boring by design:
- no `goto`
- no allocation
- no logging
- no metrics
- no cache calls
- no protocol response builders
- no mutation outside `job` and caller-provided output buffers
- no path-based filesystem access after PREPARE

**PREPARE/COMPLETE helpers** (VFS-LOOP-ONLY, declared in `vfs_internal.h`), e.g. `xrootd_vfs_read_prepare(fh, off, len, buf, cap, job)` and `xrootd_vfs_read_complete(fh, job, result, start_msec)`; mirror for write/writev/readv/pgread/opendir.

### Suggested helper shape

The public VFS API should remain simple; the triad helpers are internal. The
expected shape is:

```c
ngx_int_t xrootd_vfs_read_prepare(xrootd_vfs_file_t *fh, off_t offset,
    size_t requested, u_char *buf, size_t cap, xrootd_vfs_job_t *job,
    xrootd_vfs_io_result_t *result);

ngx_int_t xrootd_vfs_read_complete(xrootd_vfs_file_t *fh,
    const xrootd_vfs_job_t *job, xrootd_vfs_io_result_t *result,
    ngx_msec_t started);
```

For stream-slot callsites that do not yet own an `xrootd_vfs_file_t`, add a
small loop-only adapter rather than widening the thread contract:

```c
typedef struct {
    int          handle_idx;
    ngx_fd_t     fd;
    const char  *path;
    off_t        cached_size;
    unsigned     from_cache:1;
    unsigned     is_regular:1;
    unsigned     writable:1;
    unsigned     readable:1;
} xrootd_vfs_slot_view_t;
```

The adapter is filled from `ctx->files[idx]` after
`xrootd_validate_{read,write}_handle()` and any bound-secondary refresh. The
worker receives only fields copied into `xrootd_vfs_job_t`; COMPLETE uses the
same slot index to update the live stream table after `xrootd_aio_restore_*`
passes.

### PREPARE return contract

Every PREPARE helper should have the same failure discipline:
- Return `NGX_OK` only when `job` is fully initialized and safe to execute.
- Return `NGX_DECLINED` only for "do not use EXECUTE" alternatives that are not
  errors, such as cleartext sendfile serving from an already-open fd.
- Return `NGX_ERROR` with `errno` set for caller-visible failures.
- Never partially transfer ownership of a buffer on failure. If PREPARE
  allocated a temporary buffer and then fails, it frees or leaves ownership with
  the pool before returning.
- Record `started = ngx_current_msec` on the loop immediately before dispatch,
  not inside EXECUTE; workers should not read nginx time globals.

### COMPLETE return contract

Every COMPLETE helper should:
- Consume a completed `job` and write a protocol-neutral
  `xrootd_vfs_io_result_t`.
- Emit VFS metrics/access-log exactly once for that job.
- Preserve the caller-visible `errno` after observers run.
- Avoid response framing. It may report normalized bytes/CRC/eof/from_cache, but
  XRootD `kXR_ok`, `kXR_status`, and chunk headers stay outside `src/fs/`.
- Be idempotence-hostile by design: callers must not call COMPLETE twice for the
  same job. Debug builds can poison `job->op` or add an executed/completed flag
  if double-complete bugs are hard to track.

### Concrete adapter API sketch

The exact names can change during implementation, but the shape below is the
intended boundary. There are two families: public VFS-handle helpers for
`xrootd_vfs_file_t`, and stream-slot adapters for `ctx->files[]`.

```c
/* VFS-LOOP-ONLY: public VFS handle read path. */
ngx_int_t xrootd_vfs_read_prepare(xrootd_vfs_file_t *fh, off_t offset,
    size_t requested, u_char *dst, size_t dst_cap, xrootd_vfs_job_t *job,
    xrootd_vfs_io_result_t *result, ngx_msec_t *started);

/* VFS-LOOP-ONLY: public VFS handle read completion. */
ngx_int_t xrootd_vfs_read_complete(xrootd_vfs_file_t *fh,
    const xrootd_vfs_job_t *job, xrootd_vfs_io_result_t *result,
    ngx_msec_t started);

/* VFS-LOOP-ONLY: stream-slot adapter, no pooled VFS handle required. */
ngx_int_t xrootd_vfs_slot_read_prepare(const xrootd_vfs_slot_view_t *slot,
    off_t offset, size_t requested, u_char *dst, size_t dst_cap,
    unsigned want_pgcrc, xrootd_vfs_job_t *job);

/* VFS-LOOP-ONLY: applies normalized outcome to stream-owned accounting. */
ngx_int_t xrootd_vfs_slot_read_complete(xrootd_ctx_t *ctx,
    const xrootd_vfs_slot_view_t *slot, const xrootd_vfs_job_t *job,
    xrootd_vfs_io_result_t *result);
```

Write and vector helpers mirror the same pattern. Stream adapters may live in
`src/fs/` only if their declarations do not drag `xrootd_ctx_t` into worker
headers; otherwise keep the protocol-accounting half in `src/aio/` and only use
the VFS core for EXECUTE.

### Example worker rewrites

READ worker after Phase 1 should be this small:

```c
void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;
    xrootd_vfs_job_t   job;

    xrootd_vfs_job_read_init(&job, t->fd, t->offset, t->rlen, t->databuf,
                             t->rlen, 0);
    xrootd_vfs_io_execute(&job);

    t->nread = job.nio;
    t->io_errno = job.io_errno;
}
```

WRITE worker after Phase 2 is symmetric:

```c
void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;
    xrootd_vfs_job_t    job;

    xrootd_vfs_job_write_init(&job, t->fd, t->offset, t->data, t->len);
    xrootd_vfs_io_execute(&job);

    t->nwritten = job.nio;
    t->io_errno = job.io_errno;
}
```

DIRLIST worker after Phase 6 should not know the path-open story:

```c
void
xrootd_dirlist_aio_thread(void *data, ngx_log_t *log)
{
    ngx_thread_task_t    *task = data;
    xrootd_dirlist_aio_t *t = task->ctx;
    xrootd_vfs_job_t      job;

    xrootd_vfs_job_opendir_init(&job, t->dirfd, t->response,
                                t->response_cap, t->want_stat,
                                t->want_cksum);
    xrootd_vfs_io_execute(&job);

    t->response_len = job.out_size;
    t->io_errno = job.io_errno;
}
```

The init helpers are optional, but they make stale-field bugs less likely when
nginx reuses task structs. If plain struct literals are used instead, every
worker must zero the whole job first.

## Rewiring the AIO workers

Each `*_aio_thread` shrinks to: build a stack `xrootd_vfs_job_t` from the task's IN fields → `xrootd_vfs_io_execute(&job)` → copy `nio`/`out_size`/`crc32c`/`io_errno` back to the task. The `*_aio_done` callbacks keep their protocol/chain work and move metering/cache/handle-counter updates into the `_complete` helper (most already live there).

- `src/aio/reads.c` — `xrootd_read_aio_thread` (`:237`), `xrootd_pgread_aio_thread` (`:378`)
- `src/aio/write.c` — `xrootd_write_aio_thread` (`:23`), `xrootd_writev_write_aio_thread` (`:258`)
- `src/aio/readv.c` — `xrootd_readv_aio_thread` (`:34`)
- `src/aio/dirlist.c` — see "dirlist" below

**io_uring is untouched for read/write/readv/writev:** `xrootd_uring_op_for` (`uring_submit.c:101`) keys off the bound thread-fn pointer and the SQE prep reads the *same* `t->fd`/`t->databuf`/`t->offset` IN fields the job reads. The job is a strict superset of the SQE inputs, so io_uring keeps bypassing even the core's `pread`. pgread/dirlist already route to the pool (`XRD_URING_OP_NONE`). No io_uring file changes.

### Per-operation data flow

| Operation | PREPARE inputs | EXECUTE output | COMPLETE checks and side effects |
|---|---|---|---|
| READ | validated read handle, capped length, acquired response buffer, `want_pgcrc`, cache/from-cache bit | `nio`, optional `crc32c`, `io_errno` | if `nio < 0` map error; else update `result.length/eof/crc32c/from_cache`, record cache access for cache hits, update stream bytes, build chunked/window chain |
| PGREAD | validated read handle, encoded-output scratch sized for `rlen + pages*4` | `nio` raw file bytes, `out_size` encoded bytes, `io_errno` | EOF sends empty pgread status; non-empty sends `xrootd_build_pgread_chain`; access-log detail remains `<offset>+<nread>` |
| READV | pre-validated segment list and response layout, all handles/capabilities checked before first byte | total bytes and adjusted per-seg header lengths | reject all-or-nothing on core error; update each handle's bytes by actual segment read length; build chunked chain over final response buffer |
| WRITE | validated writable handle, detached payload, original request offset/path, pgwrite flags | `nio`, `io_errno` | hard error or short write -> `kXR_IOError`; success updates bytes, dirty write-through range, write-recovery journal, and write/pgwrite response |
| WRITEV | pre-validated segment descriptors, detached payload, `do_sync` | `bytes_total`, first error kind/message | all segment validation stays before dispatch; success updates each target handle's counters/dirty/journal; optional sync remains best-effort after successful writes |
| OPENDIR | confined O_PATH/O_DIRECTORY fd, response buffer, stat/checksum flags, display path for logs | response length or `E2BIG`/syscall error | queue the flat response buffer exactly as today; log `DIRLIST`; release buffer on error or after send drain |

### Task field mapping

This table keeps the actual rewrite grounded in existing task structs.

| Task struct | Existing input fields | Job IN fields | Existing output fields | Job OUT source |
|---|---|---|---|---|
| `xrootd_read_aio_t` | `fd`, `offset`, `rlen`, `databuf` | `op=READ`, `fd`, `offset`, `length`, `buf`, `buf_cap` | `nread`, `io_errno` | `nio`, `io_errno` |
| `xrootd_pgread_aio_t` | `fd`, `offset`, `rlen`, `scratch` | `op=PGREAD`, `fd`, `offset`, `length`, `buf`, `buf_cap` | `nread`, `out_size`, `io_errno` | `nio`, `out_size`, `io_errno` |
| `xrootd_readv_aio_t` | `segments`, `segment_count`, `response_buffer` | `op=READV`, `segs`, `nsegs`, optional `buf` | `bytes_read_total`, `response_bytes`, `io_error`, `err_msg` | `out_size`, `io_errno` plus core error message |
| `xrootd_write_aio_t` | `fd`, `offset`, `data`, `len` | `op=WRITE`, `fd`, `offset`, `buf`, `length` | `nwritten`, `io_errno` | `nio`, `io_errno` |
| `xrootd_writev_aio_t` | `segs`, `n_segs`, `do_sync` | `op=WRITEV`, `segs`, `nsegs`, `do_sync` | `bytes_total`, `io_error`, `err_msg` | `out_size`, `io_errno` plus core error message |
| `xrootd_dirlist_aio_t` | `response`, `response_cap`, flags, path | `op=OPENDIR`, prepared `rootfd`, `buf`, `buf_cap`, flags | `response_len`, `io_errno`, `err_msg` | `out_size`, `io_errno` plus core error message |

Keep protocol-only fields out of the job: `c`, `ctx`, `conf`, `streamid`,
`path`, `req_offset`, pgwrite CSE bad-page state, detached payload ownership, and
response queue ownership all stay in task structs and done callbacks.

### Done callback split

Each done callback should read naturally in three blocks:

```text
1. release resources that must be freed even if the connection is stale
2. restore stream/request liveness; return if stale
3. call VFS/protocol completion, build response, queue/release buffers, resume
```

For pipelined writes, block 1 also decrements `wr_inflight` before the liveness
check, matching the current deferred-teardown invariant.

### Inline fallback rule

Every path with a no-thread fallback must call the same EXECUTE arm:
- `xrootd_read_window_pump` queue-full/no-pool window read
- non-windowed kXR_read fallback in `src/read/read.c`
- kXR_pgread fallback in `src/read/pgread.c`
- kXR_write/kXR_pgwrite fallback in `src/write/common.c` callers
- kXR_readv/kXR_writev fallback bodies
- dirlist synchronous fallback only after the OPENDIR core is extracted, so the
  response-building loop is not duplicated

This is the main guard against "fixed in AIO, broken in sync fallback" regressions.

## State and ownership matrix

This phase is mostly about drawing a bright line around ownership. The following
table is the review checklist for every touched function.

| State / object | PREPARE may read | PREPARE may write | EXECUTE may read | EXECUTE may write | COMPLETE may write |
|---|---:|---:|---:|---:|---:|
| `ctx`, `c`, `session`, `pool` | yes | limited | no | no | yes, after restore guard |
| `ctx->files[idx].fd/path/flags` | yes | no, except existing validation refresh | copied fd/path only | no | counters/cache/journal fields only |
| detached write payload | yes | ownership to task | yes | no | free before liveness guard |
| read/pgread/readv response buffer | yes | allocate/assign | yes | payload bytes only | queue or release |
| VFS pooled handle `fh` | yes | size/stat/cache fields | no | no | yes |
| `xrootd_vfs_job_t` | initialize | initialize | all IN fields | OUT fields only | read, then discard |
| metrics/access log | no | no | no | no | yes |
| read-through/write-through cache metadata | yes | open/decision only | no | no | access/dirty side effects |
| response frames/chains | no | maybe allocate buffers | no | no | protocol callback only |

Review rule: if EXECUTE needs a field that is not in `xrootd_vfs_job_t`, either
copy it into the job during PREPARE or move that behavior back to COMPLETE. Do
not punch a pointer through to the live connection state.

## Error mapping contract

The core should report POSIX facts; protocol code maps them. Keep the mapping
centralized and boring:

| Core condition | `job` result | VFS/public caller | XRootD stream caller |
|---|---|---|---|
| bad fd / EBADF | `nio=-1`, `io_errno=EBADF` | `NGX_ERROR`, `errno=EBADF` | normally impossible after handle validation; if hit, `kXR_IOError` |
| permission / EACCES/EPERM | `nio=-1`, `io_errno=EACCES/EPERM` | `NGX_ERROR`, observer class auth | `kXR_NotAuthorized` only when this comes from PREPARE auth/confinement; worker EACCES stays `kXR_IOError` unless existing behavior says otherwise |
| path escape / EXDEV | PREPARE fails before EXECUTE | `NGX_ERROR`, `errno=EXDEV` | `kXR_NotAuthorized` / security-negative test |
| EOF | `nio=0`, `io_errno=0` | success with `eof=1` | empty `kXR_ok` or pgread status |
| short write | `nio < length`, `io_errno=EIO` | `NGX_ERROR` | `kXR_IOError`, same message as today |
| response too large | `io_errno=E2BIG` | `NGX_ERROR` | dirlist `kXR_IOError` with current message |

Important distinction: authorization/confinement errors happen in PREPARE and
keep their security mapping. An unexpected worker syscall failure is an I/O
failure unless the pre-existing handler already maps it more specifically.

## dirlist confinement upgrade (security win)

Today `dirlist.c:117` does raw `open(t->resolved, O_RDONLY|O_DIRECTORY)` on the thread, *trusting* a prior loop-side confinement check. New design:
- **PREPARE (loop):** `dfd = xrootd_open_beneath(ctx->rootfd, path, O_RDONLY|O_DIRECTORY|O_PATH|O_CLOEXEC, 0)` — `openat2(RESOLVE_BENEATH)`, thread-safe AND confined; snapshot into `job->rootfd`; allocate the response buffer as today. If `O_PATH|O_DIRECTORY` is not accepted on a target kernel/filesystem combination, fall back on the loop to a beneath-confined `O_RDONLY|O_DIRECTORY|O_CLOEXEC` fd. The invariant is "opened beneath on the loop", not "must be O_PATH".
- **EXECUTE (thread):** `fdopendir(dup(job->rootfd))` then the existing readdir/skip/`fstatat(AT_SYMLINK_NOFOLLOW)`/checksum/wire-build loop, operating on `dirfd(dp)` (inherently confined, no path re-resolution).
- **COMPLETE:** unchanged (meter, `xrootd_log_access`, queue buffer).

The impersonated synchronous path (`xrootd_opendir_confined_canon`, `vfs_dir.c:27`) is unchanged; only the non-impersonated AIO fast path moves — and it gets *stronger* confinement, closing the "raw open trusts prior check" gap.

Extra dirlist details to preserve:
- Keep filtering `.`/`..`, `.nginx-xrootd*`, and control-byte names.
- Keep `AT_SYMLINK_NOFOLLOW` for stat bodies so symlink entries are described as
  symlinks, not followed.
- Keep chunking semantics: one or more `kXR_oksofar` frames followed by exactly
  one `kXR_ok` frame, including empty-list behavior.
- Keep `E2BIG` behavior for `XROOTD_DIRLIST_AIO_RESPONSE_MAX`; this phase is not
  a streaming-dirlist redesign.
- Checksum code may receive the parent `dirfd` and entry name; any display path
  string is for hash/xattr helper compatibility and logs, never for opening the
  directory itself.

## Thread-safety contract (annotation + enforcement)

Two doc-comment tags on every VFS prototype:
- **`VFS-LOOP-ONLY`** — may pool-alloc, meter, log, mutate cache or `ctx->files`. Never called from a `*_aio_thread`.
- **`VFS-THREAD-SAFE`** — POD-only; may only call other THREAD-SAFE symbols + raw syscalls + `xrootd_crc32c_*` + the beneath API.

Enforcement (no new tooling): (1) CI grep guard — a `*_aio_thread` body referencing a `VFS-LOOP-ONLY` symbol fails; (2) thread TUs include only `vfs_io_core.h`, never `vfs_internal.h` (structural — `vfs_internal.h` pulls in `access_log.h`/`namespace_ops.h`); (3) document the triad + tags in `src/fs/README.md` (replacing the `:42-52` boundary note).

Proposed tag placement:
- Prototype comments in `vfs.h`, `vfs_internal.h`, and `vfs_io_core.h`.
- File-level banner in `vfs_io_core.c`: "VFS-THREAD-SAFE translation unit".
- File-level banner in `vfs_read.c`/`vfs_write.c`/`vfs_dir.c`: "public API is
  VFS-LOOP-ONLY; `pread_full`/`pwrite_full` are VFS-THREAD-SAFE".
- A short "allowed from worker" allowlist in `src/aio/README.md`.

Suggested static checks:

```bash
rg -n "VFS-LOOP-ONLY|xrootd_vfs_(read|write|open|close|opendir|readdir|observe|ctx_init|cache)" src/aio
rg -n "#include .*vfs_internal.h" src/aio src/read src/write
rg -n "ngx_palloc|ngx_pcalloc|ngx_pnalloc|xrootd_log_access|XROOTD_OP_|xrootd_cache_" src/fs/vfs_io_core.c
```

The CI version should be narrower than the exploratory commands above: it should
parse only `*_aio_thread` bodies or maintain an explicit allowlist so done
callbacks can continue to log, meter, and allocate on the event loop.

## Handling each non-thread-safe dependency

- **Pool alloc** → moved to PREPARE; EXECUTE buffer pre-allocated on the loop into `job->buf` (workers already pre-allocate `t->databuf`/`t->scratch`/`t->response`).
- **Access-log + metrics emit** → deferred to COMPLETE (already deferred to `*_done` today). No metric/log from a thread.
- **Read-through cache** → `xrootd_cache_open` stays in PREPARE (loop); `xrootd_cache_record_access` (`vfs_read.c:241`, an LRU `utimensat` side-effect) **moves to COMPLETE** to keep the contract clean rather than auditing the whole cache module. `cache_should_writethrough` is a pure read → PREPARE.
- **`xrootd_file_t` counters** (`bytes_read`/`bytes_written`, `wt_*`, `wrts_*`, single-owner-per-connection, non-atomic) → stay loop-only in COMPLETE; tag the struct VFS-LOOP-ONLY.
- **`fh->size`/`stat_current` mutation** → moved to COMPLETE.
- **TLS-vs-cleartext** → decided in PREPARE; the offload path only ever describes a memory-backed transfer, file-backed sendfile never enters EXECUTE (README invariant #4). Defensive assert in `xrootd_vfs_read_prepare`.

Additional lifecycle rules:
- **Detached payloads** stay owned by the completion callback. WRITE/WRITEV
  completion must keep the existing "free before liveness guard" behavior so a
  disconnect while AIO is in flight cannot leak the detached request body.
- **Read buffers** are released only after chain ownership is clear. READ/READV/
  PGREAD completion keeps the current `xrootd_release_read_buffer()` pattern so
  a draining response owns its backing buffer until the send path finishes.
- **Pipelined writes** keep the current deferred-teardown discipline:
  decrement `wr_inflight` before the liveness check, and run deferred teardown on
  the last completion when `finalize_pending` is set.
- **Bound secondary reads** must refresh the slot before PREPARE by continuing
  to call `xrootd_validate_read_handle()` / `xrootd_ensure_read_handle()`. The
  worker must not consult shared-memory handle state.
- **Write replay / recovery state** remains protocol-owned. The VFS core writes
  bytes; `wrts_record`, pgwrite CSE replies, FOB tracking, and POSC close-time
  behavior stay in stream code.

## Observability contract

The split must not double-count or lose metrics. The rule is one VFS observation
per logical disk operation and one protocol operation result per XRootD request.

| Operation | VFS metric op | Existing protocol metric | Access-log detail to preserve |
|---|---|---|---|
| READ | `XROOTD_METRIC_OP_READ` | `XROOTD_OP_READ` | `<offset>+<bytes>` where currently emitted |
| PGREAD | `XROOTD_METRIC_OP_READ` or pgread-specific if added later | `XROOTD_OP_PGREAD` | `<offset>+<nread>` |
| READV | `XROOTD_METRIC_OP_READ` | `XROOTD_OP_READV` | segment count / existing readv detail |
| WRITE/PGWRITE | `XROOTD_METRIC_OP_WRITE` | `XROOTD_OP_WRITE` | `<req_offset>+<len>` |
| WRITEV | `XROOTD_METRIC_OP_WRITE` | `XROOTD_OP_WRITEV` | `<n>_segs` |
| DIRLIST | `XROOTD_METRIC_OP_READ` or future `OP_DIRLIST` if metric enum exists | `XROOTD_OP_DIRLIST` | `stat`, `dcksm`, or `-` |

If the existing metric enum does not distinguish pgread/readv/writev/dirlist,
do not add new labels in this phase unless a separate metrics migration is
approved. Low-cardinality metric labels remain mandatory: no paths, handles,
streamids, buckets, or UUID-like values.

## Cache and metadata details

Read-through cache behavior after the split:
- `xrootd_cache_open()` stays in loop-side open/PREPARE. A worker never opens a
  cache path by itself.
- `xrootd_cache_record_access()` moves to COMPLETE for successful cache-sourced
  reads with `length > 0`. EOF should not update LRU state unless current VFS
  semantics already do.
- Cache-hit/miss metrics stay where `xrootd_cache_open()` currently emits them;
  Phase 54 should not reinterpret cache eligibility.

Write-through and recovery behavior after the split:
- `xrootd_cache_should_writethrough()` is a loop-side decision made before the
  write is posted.
- `xrootd_wt_mark_dirty()` runs in COMPLETE after success and uses the same
  inclusive end offset as today.
- `xrootd_wrts_record()` runs in COMPLETE after success and must record the
  client-requested offset, not an adjusted internal offset.
- `fh->size` / stream `cached_size` grows only after successful writes; failed
  or short writes do not make metadata optimistic.

Metadata freshness:
- Reads do not clear `stat_current`.
- Writes clear `stat_current` or update cached size exactly as current code
  does.
- Directory scans do not mutate file-handle metadata.

## Incremental migration order (each shippable; 3-tests rule: success + error + security-negative)

- **Phase 0 — scaffolding:** add `vfs_io_core.{h,c}` (READ/WRITE arms delegating to `pread_full`/`pwrite_full`), register in `src/config/config.h`, `./configure`, add annotation tags. Tests: execute==direct pread/pwrite; bad-fd → `io_errno`; link/grep assertion that the core references no pool/metrics symbol.
- **Phase 1 — kXR_read:** rewire `read_aio_thread`; add read prepare/complete; re-express `xrootd_vfs_read`. Tests: windowed+plain read byte/CRC identical; EIO → `kXR_IOError`; confinement still enforced at open.
- **Phase 2 — kXR_write/pgwrite:** rewire `write_aio_thread`. Tests: success; short-write → `kXR_IOError`; `allow_write` off → EACCES.
- **Phase 3 — kXR_readv:** rewire `readv_aio_thread`. Tests: multi-seg success; bad-offset; overflow/escape negative.
- **Phase 4 — kXR_pgread (risk-gated):** add PGREAD arm, rewire `pgread_aio_thread`. Tests: per-page CRC framing intact; EOF/empty; corrupt-page mismatch.
- **Phase 5 — kXR_writev:** add WRITEV arm, rewire `writev_write_aio_thread`. Tests: multi-seg + fsync barrier; short-write; escape negative.
- **Phase 6 — dirlist:** add OPENDIR arm, beneath-confined PREPARE. Tests: large listing; E2BIG truncation; **symlink-to-parent entry not escaped** (now structurally true).
- **Phase 7 — cleanup:** move `xrootd_cache_record_access` to COMPLETE; rewrite README boundary note; flip CI grep guard to enforcing.

Each phase touches one AIO file + its VFS counterpart, keeping io_uring and the thread pool green throughout.

### Phase checklist template

Every phase should land with the same mechanical checklist:

1. Identify the exact worker syscall body and inline fallback body.
2. Add or extend one EXECUTE arm in `vfs_io_core.c`.
3. Add loop-only prepare/complete helpers or a stream-slot adapter for that op.
4. Rewire the worker to construct a job and call `xrootd_vfs_io_execute`.
5. Rewire the inline fallback to use the same job.
6. Preserve done-callback liveness, buffer ownership, and response framing.
7. Add the success/error/security-negative tests for that op.
8. Run the static thread-safety grep and the focused pytest selection.
9. Run the relevant throughput smoke before/after; record any delta in this doc
   or the phase PR notes.

### Detailed per-phase notes

**Phase 0 - scaffolding**
- Register `src/fs/vfs_io_core.c` in `src/config/config.h` `NGX_ADDON_SRCS`.
- Move `xrootd_vfs_pread_full`/`pwrite_full` prototypes to the new public
  thread-safe header or include them through a small internal thread-safe header;
  do not expose loop-only helpers to `src/aio`.
- Add unit-level tests that call the core directly through a tiny C harness or
  existing C test style, including bad fd and zero-length jobs.

**Phase 1 - READ**
- Keep windowed read behavior: each window becomes one READ job.
- Preserve `resp_pipelinable` behavior for single memory-backed reads.
- EOF (`nio == 0`) is a successful empty response, not an IOError.
- Cleartext sendfile reads remain loop-prepared file-backed chains and should
  not be forced through memory buffers unless TLS/page-CRC requires memory.

**Phase 2 - WRITE/PGWRITE**
- Plain writes can be pipelined; pgwrite remains serial.
- Completion must preserve the existing short-write handling and pgwrite status
  semantics (`req_offset`, not `offset + len`).
- The core should not know about pgwrite CSE bad-page replies; it only performs
  the already-decoded flat write.

**Phase 3 - READV**
- Keep "validate all segments before first byte" semantics.
- Reuse `xrootd_readv_read_segments` as the core arm initially; later cleanups
  can move its descriptor type into `src/fs/` if desired.
- Preserve response layout: headers and payloads are already in the final buffer
  before EXECUTE starts.

**Phase 4 - PGREAD**
- Reuse `xrootd_pgread_read_encode_inplace` exactly; this is the CRC-framing
  risk gate.
- EOF/empty remains a header-only pgread status.
- Path-based pgread must either prepare an opened fd on the loop or stay on the
  existing confined open path until its own adapter is added.

**Phase 5 - WRITEV**
- Preserve all-or-nothing reply semantics even though earlier segments may have
  reached disk before a later failure.
- Keep `fsync` best-effort and after all writes succeed.
- If de-duplicating fsync by fd is added, keep it loop-independent and bounded;
  do not allocate in EXECUTE.

**Phase 6 - DIRLIST**
- Land after READ/WRITE/READV so the core contract is already proven.
- The first patch should move only the worker loop behind OPENDIR; a follow-up
  can decide whether the sync dirlist path should share the same exact builder.
- Add a regression test that swaps a directory with a symlink between path
  resolution and worker execution; the new loop-opened fd should keep the worker
  pinned to the confined directory object.

**Phase 7 - cleanup**
- Rewrite `src/fs/README.md` from "VFS is event-loop-only" to "VFS public API is
  loop-only; VFS I/O core is thread-safe".
- Turn the static checks from advisory to CI-enforced.
- Delete any now-unused raw worker helpers after `rg` confirms no callsites.

## Suggested patch slices

Even within a phase, keep the review slices small:

| Slice | Patch contents | Build/test expectation |
|---|---|---|
| 0a | Add `vfs_io_core.h` and READ/WRITE job init helpers, no callsites | compile only after configure |
| 0b | Add `vfs_io_core.c` READ/WRITE execution and tests | core tests pass |
| 0c | Add annotation comments and advisory static guard | guard is allowed to warn only |
| 1a | Rewire non-windowed read worker | focused read tests |
| 1b | Rewire windowed read inline/thread fallback | window boundary tests |
| 1c | Re-express public `xrootd_vfs_read()` through triad | WebDAV/S3 GET smoke |
| 2a | Rewire write worker | root write tests |
| 2b | Rewire pgwrite flat write path | pgwrite tests |
| 2c | Move write metadata/cache completion into helper | stat-after-write tests |
| 3a | Wrap existing readv pure helper in READV job | readv tests |
| 4a | Wrap pgread pure helper in PGREAD job | pgread CRC tests |
| 5a | Move writev segment loop into WRITEV job | writev tests |
| 6a | Prepare confined dir fd on loop | dirlist escape tests |
| 6b | Move dirlist scan/build loop into OPENDIR job | dirlist equivalence tests |
| 7a | README + static guard enforcing | full focused suite |

No slice should mix an operation rewire with broad formatting churn. If a helper
move causes large diffs, land the pure move first and the behavior change second.

## Per-file implementation recipe

Use this as the patch map for the actual implementation. Each bullet is intended
to keep diffs small enough to review.

### `src/fs/vfs_io_core.h`

- Include only the minimum nginx/POSIX types needed for `ngx_fd_t`, `u_char`,
  `off_t`, `size_t`, and `uint32_t`.
- Define `xrootd_vfs_io_op_e`, `xrootd_vfs_job_t`, and any tiny thread-safe
  segment descriptors that cannot stay in `src/aio/aio.h`.
- Add a file banner that states this header is allowed in worker translation
  units.
- Do not include `vfs.h`, `vfs_internal.h`, metrics, cache, access-log, or
  protocol response headers.

### `src/fs/vfs_io_core.c`

- Include `vfs_io_core.h`, the CRC helper header, and the narrow headers for
  pure readv/pgread helpers.
- Implement one static `execute_<op>()` per operation.
- Initialize OUT fields at the top of `xrootd_vfs_io_execute()` so reused task
  structs cannot leak stale results.
- Use early returns for each invalid input or syscall failure.
- Keep per-op helper bodies small. If OPENDIR's response builder is too large,
  split it into pure helpers like `dirlist_emit_entry()` and
  `dirlist_flush_chunk()` inside the same file or a dedicated thread-safe
  dirlist core file.

### `src/fs/vfs_read.c`

- Split current `xrootd_vfs_read()` into:
  - capping/validation PREPARE
  - memory READ job execution
  - file-backed sendfile bypass for cleartext
  - COMPLETE for cache access, result, metrics/log
- Keep `make_file_chain()` loop-only. It duplicates fds and registers pool
  cleanup, so it is not part of EXECUTE.
- Make `xrootd_vfs_pread_full()` visible to the core through the new
  thread-safe header path.

### `src/fs/vfs_write.c`

- Split `xrootd_vfs_write()` so memory buffers can map directly to WRITE jobs.
- Keep file-buffer copying explicit: the source side `pread_full` from
  `b->file->fd` plus destination `pwrite_full` is a thread-safe copy primitive,
  but the chain walk is loop-owned because it sees `ngx_chain_t`.
- Move cached size/stat mutation into COMPLETE.
- Keep `xrootd_cache_should_writethrough()` in PREPARE and write-through dirty
  marking in protocol/VFS completion as appropriate.

### `src/fs/vfs_dir.c`

- Add a loop-only opendir prepare helper that re-checks confinement and opens a
  directory fd beneath `rootfd`.
- Keep public `xrootd_vfs_opendir()` behavior unchanged for existing HTTP/S3
  callers unless a later patch deliberately moves it onto the new core.
- Do not make `xrootd_vfs_dir_t` visible to worker code.

### `src/aio/reads.c`

- Replace raw `pread` in `xrootd_read_aio_thread()` with READ job execution.
- Replace direct `xrootd_pgread_read_encode_inplace()` call with PGREAD job
  execution once Phase 4 lands.
- Keep `xrootd_read_window_emit()` and response chain builders in the done path.
- Preserve every buffer release branch; this file is sensitive to leaks on
  stale-connection returns.

### `src/aio/write.c`

- Replace raw `pwrite` in `xrootd_write_aio_thread()` with WRITE job execution.
- Replace WRITEV loop with WRITEV job execution once Phase 5 lands.
- Preserve the exact ordering around detached payload free, `wr_inflight`
  decrement, `ctx->destroyed`, and deferred teardown.
- Keep write-through dirty marking and `xrootd_wrts_record()` in done callbacks.

### `src/aio/readv.c`

- Keep the response layout builder outside the worker.
- Let the worker execute a READV job over the already-built segment descriptors.
- Keep `ngx_free(t->segments)` and `xrootd_release_read_buffer()` on every early
  return path.

### `src/aio/dirlist.c`

- Remove the worker raw `open(t->resolved, ...)`.
- Add `dirfd` or `rootfd` to the task context only if the existing task cannot
  carry the prepared fd through `xrootd_vfs_job_t`.
- Ensure the prepared directory fd is closed on every done path, including stale
  connection restore failure. If ownership moves into the task, document whether
  EXECUTE closes the duplicated `DIR *` only or COMPLETE also closes the
  original prepared fd.
- Keep `t->resolved` as a display/log/checksum path only.

### `src/aio/aio.h`

- Prefer no large struct churn. Add fields only when a migrated operation needs
  a result that is not currently represented.
- If `xrootd_vfs_job_t` is embedded in task structs, keep it as a value field,
  not a pointer to stack storage.
- Do not move `ctx`, `c`, `streamid`, `payload_buf`, or response ownership into
  `src/fs/`.

### `src/config/config.h`

- Add every new `.c` file to `NGX_ADDON_SRCS` in the module source list.
- Do not edit nginx-generated Makefiles.
- Re-run `./configure` only when adding the new source file or changing config
  structure; ordinary callsite rewires use incremental `make`.

### `src/fs/README.md`

- Replace the current event-loop-only warning with a two-tier contract:
  public VFS APIs are loop-only, `vfs_io_core` is worker-safe.
- Document PREPARE / EXECUTE / COMPLETE in the same vocabulary used here.
- Add a small "worker allowlist" that names `vfs_io_core.h`,
  `xrootd_vfs_io_execute`, `xrootd_vfs_pread_full`, and
  `xrootd_vfs_pwrite_full`.

### `tests/`

- Put the static guard in a test file that can run without starting nginx.
- Prefer protocol-level tests for behavior and a small C/Python harness only for
  direct core semantics that are hard to trigger through XRootD.
- Keep security-negative tests explicit about the expected denial:
  confinement/auth failures should fail before the worker executes.

## Resource cleanup rules

These are the failure branches that should be reviewed explicitly:

- PREPARE fails before posting: caller releases any buffer it acquired during
  PREPARE and sends the existing error response.
- `xrootd_aio_post_task()` returns queue-full: caller executes the same job
  inline, then runs COMPLETE immediately.
- Worker succeeds but connection is stale: done callback frees detached payloads
  and prepared fds/buffers it owns, then returns without touching `ctx` beyond
  the approved restore helper.
- Worker fails: done callback releases response buffers before sending an error
  if the buffer will not be queued.
- Response queue accepts a chain: ownership transfers to the send path; do not
  release the backing buffer unless `ctx->state != XRD_ST_SENDING`.
- Pipelined write completion after disconnect: the last completion owns running
  deferred teardown after `wr_inflight` reaches zero.

## Review checklist

For each phase, reviewers should be able to answer "yes" to all of these:

- Does every path to disk go through PREPARE or an already-confined fd?
- Does EXECUTE compile without including loop-only VFS internals?
- Are all buffers used by EXECUTE already allocated and uniquely owned?
- Are all failure paths preserving the current user-visible error code/message?
- Is response framing byte-for-byte identical for success and EOF cases?
- Are cache, metrics, access-log, `ctx->files`, and journal mutations on the
  event loop only?
- Does no-thread fallback use the same EXECUTE helper as the worker path?
- Does the patch add success, error, and security-negative coverage?
- Did the phase avoid new source files unless `src/config/config.h` was updated
  and `./configure` rerun?

## Risks & guards

1. **Data-plane perf** — triad adds no heap on hot path (reuses cached `t->databuf`; job is a stack value; dispatcher is a `switch`). Gate every data-plane phase on a before/after throughput/latency benchmark.
2. **UAF/teardown** — EXECUTE touches only the job + its buffer (fd by value, immutable in flight); no pointer into `ctx`/connection. COMPLETE keeps every `ctx->destroyed` guard (`reads.c:266`, `write.c:65`) and free-before-guard pattern (`write.c:50`, `readv.c:333`).
3. **pgread CRC framing** — delegate to `xrootd_pgread_read_encode_inplace` unchanged; never re-implement CRC; ship after read/write/readv prove the pattern.
4. **dirlist syscall change** — raw `open` → `xrootd_open_beneath` strengthens confinement; impersonated path unchanged. Mitigation: only the non-impersonated AIO fast path moves.
5. **errno discipline** — every arm captures `errno` into `job->io_errno`; COMPLETE restores via the existing observer.
6. **Partial write ambiguity** — `pwrite_full` loops until full length or error,
   but WRITEV historically reports the first short segment as a hard error.
   Preserve the externally visible behavior per opcode, even if the core shares
   lower-level loops.
7. **Header ownership under pipelining** — READ/READV completion must continue to
   use per-slot headers/buffers where the send path expects them. The core must
   not introduce a shared scratch header.
8. **Path-based compatibility** — handle-based reads/writes are straightforward
   fd snapshots; path-based read/pgread and dirlist need loop-side confined open
   before the worker. Treat every path-based worker open as a security-sensitive
   migration.
9. **Over-broad static guard** — done callbacks legitimately allocate/log/meter.
   A naive grep across all of `src/aio` will create noise; enforce on worker
   bodies or on `vfs_io_core.c` plus an include allowlist.

## Files to modify / create

**New (register in `src/config/config.h` `NGX_ADDON_SRCS`, requires `./configure` per AGENTS.md BUILD GOVERNANCE):**
- `src/fs/vfs_io_core.h` — POD job + `xrootd_vfs_io_execute` (THREAD-SAFE banner)
- `src/fs/vfs_io_core.c` — dispatcher + per-op execute arms

**Modify (make only):**
- `src/fs/vfs.h`, `src/fs/vfs_internal.h` — annotation tags; prepare/complete + `pread_full`/`pwrite_full` tagged THREAD-SAFE
- `src/fs/vfs_read.c`, `vfs_write.c`, `vfs_dir.c` — prepare/complete helpers; beneath-confined opendir prepare
- `src/aio/reads.c`, `write.c`, `readv.c`, `dirlist.c` — rewire `*_aio_thread` to the core
- `src/cache/open.c` — `record_access` call moves to COMPLETE (no signature change)
- `src/fs/README.md` — triad model + contract
- `src/aio/README.md` — document worker allowlist and inline fallback rule
- `tests/` — focused success/error/security-negative tests per phase plus a
  static guard script or pytest

**Explicitly NOT modified:** `src/aio/uring*.c/.h` (same IN fields), `src/path/beneath.*`, `src/compat/namespace_ops.*`, `src/compat/staged_file.*` (already thread-safe, reused), `src/aio/aio.h` task structs (job built *from* them — smaller diff).

If a phase needs task structs to carry one new result field, keep the change
minimal and do not move protocol-only fields (`streamid`, `ctx`, `c`, path copy,
payload ownership) into the VFS job.

## Verification

- **Per phase:** the 3-tests rule (success + error + security-negative) listed above; reuse conformance fixtures.
- **Differential I/O:** byte-for-byte + CRC-for-CRC equality pre/post rewire for read/pgread/readv/write/writev/dirlist on identical fixtures.
- **Backend matrix:** run each phase under (a) thread pool, (b) inline fallback (`thread_pool == NULL`), (c) io_uring build (`XROOTD_HAVE_LIBURING`) — proves the descriptor maps identically across all three tiers.
- **Static contract check:** CI grep — no `*_aio_thread` references a `VFS-LOOP-ONLY` symbol; thread TUs don't include `vfs_internal.h`.
- **Teardown stress:** client drops mid-read/write to exercise `ctx->destroyed` + detached-buffer free on the new path.
- **Perf gate:** throughput/latency benchmark before/after each data-plane phase; block on regression.
- **Build/validate:** `./configure --with-stream ... --add-module=$REPO && make -j$(nproc)` (Phase 0 only); `make -j$(nproc)` thereafter; `objs/nginx -t`; `PYTHONPATH=tests pytest tests/ -k "read or write or readv or pgread or dirlist" -v`.

### Command runbook

Phase 0, after adding `vfs_io_core.c`:

```bash
cd /tmp/nginx-1.28.3
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO
make -j$(nproc)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
PYTHONPATH=$REPO/tests pytest $REPO/tests/ -k "vfs or aio" -v
```

Later phases:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
cd "$REPO"
PYTHONPATH=tests pytest tests/ -k "read or write or readv or pgread or dirlist" -v
```

Thread-pool versus inline fallback:

```bash
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/ -k "read and not http" -v
# Then rerun against a config with no xrootd thread_pool to force inline fallback.
```

io_uring build smoke:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)
cd "$REPO"
PYTHONPATH=tests pytest tests/ -k "read or write or readv or writev" -v
```

The exact test names may differ; the important part is that every phase records
which command proved thread-pool, inline fallback, and io_uring behavior.

### Concrete test ideas

| Phase | Success | Error | Security-negative |
|---|---|---|---|
| 0 core | direct core READ/WRITE matches `pread`/`pwrite` on temp file | bad fd returns `io_errno=EBADF` | static check: core has no pool/log/cache/metric references |
| 1 read | root read and roots/TLS read byte-identical, including window boundary | closed/bad fd maps to `kXR_IOError` | path-based read cannot escape export after symlink swap |
| 2 write | xrdcp upload and pgwrite upload byte-identical | injected short write maps to `kXR_IOError` | `allow_write off` still rejects before EXECUTE |
| 3 readv | multi-handle/multi-segment response matches official server | segment past EOF or invalid offset errors as before | slice-mode/unsupported handle rejected before EXECUTE |
| 4 pgread | per-page CRC output matches pre-change fixture | bad fd or I/O error maps to pgread error | path-form pgread escape attempt rejected before worker |
| 5 writev | multi-segment write with sync flag persists expected bytes | later-segment short write errors and does not ack success | readonly/non-writable handle rejected before first segment writes |
| 6 dirlist | large listing emits same chunk sequence and final `kXR_ok` | listing over 4 MiB returns `E2BIG`/`kXR_IOError` | symlink-to-parent or rename/swap race cannot make worker open outside root |

### Static guard sketch

The guard can start as a pytest that scans source text. It does not need a C
parser on day one, but it should avoid false positives in done callbacks.

```python
WORKER_FUNCS = (
    "xrootd_read_aio_thread",
    "xrootd_pgread_aio_thread",
    "xrootd_readv_aio_thread",
    "xrootd_write_aio_thread",
    "xrootd_writev_write_aio_thread",
    "xrootd_dirlist_aio_thread",
)

FORBIDDEN_IN_WORKER = (
    "ngx_palloc", "ngx_pcalloc", "ngx_pnalloc",
    "xrootd_log_access", "XROOTD_OP_",
    "xrootd_cache_", "xrootd_vfs_observe_",
    "xrootd_vfs_read(", "xrootd_vfs_write(",
    "xrootd_vfs_open(", "xrootd_vfs_opendir(",
)
```

Implementation approach:
- Extract each worker body by matching braces from the function declaration.
- Fail if any forbidden token appears in the extracted body.
- Separately fail if `src/aio/*.c` includes `src/fs/vfs_internal.h`.
- Separately fail if `src/fs/vfs_io_core.c` references pool, metrics, access-log,
  cache, protocol response builders, or connection/session types.

This is intentionally simple and local. If it starts to fight legitimate code,
prefer an explicit allowlist near the guard over weakening the contract in prose.

### Differential fixtures

Keep fixtures small enough to run often but shaped enough to catch framing
regressions:
- READ: empty file, 1 byte, 4 KiB, 4 KiB+1, `XROOTD_READ_WINDOW-1`,
  `XROOTD_READ_WINDOW`, `XROOTD_READ_WINDOW+1`.
- PGREAD: unaligned offset, exactly one page, two pages, EOF mid-page.
- READV: adjacent same-fd segments, gapped same-fd segments, different handles,
  zero-length segment if the parser accepts it.
- WRITE/PGWRITE: empty write, unaligned offset, overwrite existing bytes,
  append past cached size.
- WRITEV: same fd repeated, multiple fds, sync flag on/off.
- DIRLIST: empty directory, unsafe names, `.nginx-xrootd*` hidden entry, large
  chunk boundary, symlink entry.

### Perf gates

Use small, repeatable smoke numbers rather than one giant benchmark:
- `root://` read, write, readv/writev where available, 64 MiB and 1 GiB fixtures.
- TLS read for memory-backed path.
- pgread fixture with page-aligned and unaligned offsets.
- directory listing with 1, 1k, and 50k entries if local disk permits.
- Compare thread-pool path and inline fallback separately.

Acceptable overhead target: no statistically meaningful throughput regression on
the hot path, and no additional heap allocation in EXECUTE. Any intentional
regression must be documented with a security or correctness reason.

### Perf measurement notes

Record at least:
- file size and cache state (cold, warm page cache, read-through cache hit)
- transport (`root://`, `roots://`, WebDAV if public VFS changed)
- execution mode (thread pool, inline fallback, io_uring)
- median throughput over repeated runs
- CPU sample if throughput moves meaningfully

Expected neutral changes:
- READ/WRITE worker dispatch: no measurable regression; extra stack job and
  switch should be lost in syscall cost.
- PGREAD: no CRC regression because the existing in-place encoder is reused.
- READV/WRITEV: no regression if segment descriptor layout stays unchanged.
- DIRLIST: possible tiny overhead from `dup(job->rootfd)` but security win is
  worth it; large directories should be dominated by `readdir`/stat/checksum.

## Acceptance / rollback

Acceptance criteria:
- `rg -n "pread\\(|pwrite\\(|open\\(" src/aio` shows no raw worker data-plane
  syscall that should be owned by `vfs_io_core.c` (allow documented exceptions
  only).
- AIO worker bodies include `vfs_io_core.h` but not `vfs_internal.h`.
- All existing conformance tests for read/write/readv/pgread/writev/dirlist pass
  under thread-pool and no-thread fallback.
- io_uring builds still route READ/WRITE/READV/WRITEV as before.
- `src/fs/README.md` documents the new split so future work knows which symbols
  are loop-only versus thread-safe.

Rollback strategy:
- Each phase is shippable and should be reversible by restoring that one
  operation's worker/fallback to the pre-core body while leaving `vfs_io_core.c`
  in place for earlier phases.
- Do not rollback by removing the shared core after later phases depend on it;
  instead disable the most recent op arm and keep earlier migrated ops intact.
- Keep tests phase-scoped so a regression identifies the operation that needs
  rollback.

## Open questions before implementation

- Should stream `kXR_open` eventually wrap its fd in an `xrootd_vfs_file_t`, or
  is the stream-slot adapter the long-term boundary? The adapter is lower risk
  for Phase 54; full handle unification can be a later refactor.
- Should READV/WRITEV segment descriptor types move from `src/aio/aio.h` into
  `src/fs/vfs_io_core.h`, or should the core accept opaque segment arrays plus
  typed helper callbacks? Start with the smaller move: reuse current descriptors
  and relocate only if include boundaries become tangled.
- Should dirlist's sync fallback be converted in the same patch as AIO dirlist or
  one patch later? Security improvement is the AIO worker open; sharing the sync
  builder is cleanup and can follow if it risks a large diff.
- Should VFS metrics distinguish READV/PGREAD/WRITEV/DIRLIST in a later metrics
  phase? Do not expand metric cardinality in Phase 54, but note any gap exposed
  while moving completion code.
- Should `xrootd_vfs_job_t` carry a fixed-size error string for READV/WRITEV/
  DIRLIST, or should workers keep current task-local `err_msg` fields? Prefer
  task-local strings unless the core needs consistent messages across callers.
- Should the static guard live under `tests/` as pytest or under a dedicated
  developer script? Pytest is easier to enforce in CI; a script is easier to run
  manually during refactors.
