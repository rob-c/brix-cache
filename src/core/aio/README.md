# aio — Thread-pool async file I/O and shared response-chain builders

## Overview

nginx workers run a single thread per process and must never block. A bare
`pread(2)`/`pwrite(2)` on the event-loop thread would freeze every other
connection on that worker for the full duration of the disk I/O — fatal on
spinning or network-backed HEP storage where a single read can stall for tens
to hundreds of milliseconds. This subsystem is the data plane's **blocking-I/O
detour**: the heavy syscalls (`pread`, `pwrite`, `fsync`, `readdir`/`fstatat`,
per-page CRC32C, per-entry checksum) are offloaded to the nginx **thread pool**,
and only the protocol/wire work runs back on the event loop.

Since phase-54 these workers do **not** carry their own copies of the raw
syscalls. Every `_thread` body fills a POD `brix_vfs_job_t` and calls the
VFS-owned, thread-safe I/O core `brix_vfs_io_execute()`
([`../fs/vfs_io_core.c`](../../fs/README.md)); the inline fallbacks (no pool, or
post failed) call the exact same core on the event loop for one bounded unit of
work. So the **offloaded and inline-fallback raw I/O — read/write/readv/writev/
pgread and the dirlist worker's scan — now flows through the VFS layer**, and
confinement, CRC, short-I/O, and error handling live in one place instead of
being duplicated here. This subsystem now owns the *scheduling* (which tier, the
three-phase hand-off, scratch-buffer lifetime), not the raw I/O itself. (The
handler-level zero-copy fast paths — `sendfile` and the `preadv2(RWF_NOWAIT)`
warm-cache probe in [`../read/`](../../protocols/root/read/README.md) — and the still-live
synchronous `dirlist` loop deliberately sit outside this offload path.)

## Optional io_uring backend (Phase 44 — `uring.c` / `uring_submit.c` / `uring_admin.c`)

A third dispatch tier sits **above** the thread pool, making the cascade
**io_uring → thread pool → inline sync**.  It is OFF BY DEFAULT, double-gated
(`pkg-config liburing` at build → `-DBRIX_HAVE_LIBURING`; an authoritative
opcode probe at runtime), and degrades transparently.  The single interposition
point is `brix_aio_post_task()` (`resume.c`): a selector keyed on the task's
bound worker-fn picks io_uring for READ/WRITE and single-contiguous-group
READV/WRITEV(+linked FSYNC); everything else (pgread CRC interleave, dirlist,
multi-fd/gap vectored ops) falls through to the pool unchanged.  The six
`*_aio_t` structs and `*_aio_done` callbacks are reused verbatim — only the
*syscall location* differs.

- `uring.c` — per-worker ring singleton, eventfd→epoll bridge (public-API
  analogue of nginx core's libaio `ngx_epoll_aio_init`/`ngx_epoll_eventfd_handler`),
  the UAF-safe generation-guarded completion-slot table, and the reaper (posts
  to `ngx_posted_events`, never inline).  Brought up in `init_process`, torn
  down in `exit_process`; gated on a NOP self-test.  `register_eventfd` must run
  **before** `register_restrictions`+`enable_rings` (register ops are denied on a
  restricted+enabled ring).
- `uring_submit.c` — `brix_uring_op_for` (worker-fn → op) + `brix_uring_submit`
  (slot acquire → SQE prep → cookie → submit; linked FSYNC for a `do_sync`
  writev via `IOSQE_IO_LINK` + an SQ-space pre-check).
- `uring_admin.c` — the no-reload kill switch: a cross-worker SHM `ngx_atomic_t`
  read lock-free on the submit hot path (`brix_uring_disabled`), flipped by the
  admin endpoint (`POST /xrootd/api/v1/admin/io_uring`) or a watched panic-file
  (`brix_io_uring_panic_file`).
- `§32` fail-fast: `brix_io_uring on` makes `nginx -t` fail (and the master
  refuse to start) if io_uring is not compiled in or the probe fails;
  `auto`/`off` always start.  Containment: the ring runs in the unprivileged
  worker on broker-opened `RESOLVE_BENEATH` fds and is restricted to fd-only data
  opcodes, so it can never open or traverse a path.

See [`docs/refactor/phase-44-io-uring-backend.md`](../../../docs/refactor/phase-44-io-uring-backend.md)
for the full design, the per-workstream status table, and the deferred tiers
(client loop-engine swap CB-W4, O_DIRECT, registered buffers, uring-pgread,
SQPOLL, Prometheus metrics exposition).

## Thread-pool contract

Every offloaded opcode follows the same three-phase contract: a `_thread`
worker function does *only* the blocking I/O via the VFS core
`brix_vfs_io_execute()` (no nginx state, no pools, no `c->log`); nginx posts a
`_done` completion callback back to the single-threaded event loop via
`ngx_post_event`; the `_done` callback builds the XRootD wire response
identically to the synchronous path and re-arms the connection. While a
task is in flight the connection sits in `XRD_ST_AIO` with both read and write
events disarmed, and `ctx->destroyed` is checked in every callback so a task
completing after the client disconnects discards its work safely.

This is the `root://` stream data plane. It serves `kXR_read`, `kXR_readv`,
`kXR_pgread`, `kXR_write`, `kXR_pgwrite`, `kXR_writev`, and `kXR_dirlist`.
The handler bodies live in [`../read/`](../../protocols/root/read/README.md),
[`../write/`](../../protocols/root/write/README.md), and [`../dirlist/`](../../protocols/root/dirlist/README.md);
they validate/auth/resolve the request, populate a per-task context struct, and
post here. If no thread pool is configured (or its queue is full) each call site
falls back to synchronous I/O, so the subsystem is an optimisation, not a
dependency — except for `brix_cache`, which **requires** a working pool
(enforced at config time in `config.c`).

Beyond the offload, this directory owns the **shared response-chain builders**
(`buffers.c`) used by *both* the sync and async read paths, plus the
per-connection scratch-buffer lifecycle. Centralising chain construction here is
what guarantees a response looks bit-identical on the wire regardless of which
path produced it, and why the HTTP/S3 file-serve path
([`../s3/`](../../protocols/s3/README.md)) reuses the same buffers rather than writing to the
send buffer directly.

All code here compiles only under `NGX_THREADS`.

## Files

| File | Responsibility |
|------|----------------|
| `aio.h` | Subsystem header: per-task context structs (`brix_read_aio_t`, `brix_write_aio_t`, `brix_writev_aio_t`, `brix_readv_aio_t`, `brix_pgread_aio_t`, `brix_dirlist_aio_t`), segment descriptors, all `_thread`/`_done` prototypes, the `brix_task_bind()` inline binder, scratch-buffer API, and chain-builder prototypes. |
| `buffers.c` | Shared response-chain builders + scratch lifecycle. `brix_build_chunked_chain` (memory, multi-frame), `brix_build_sendfile_chain` (zero-copy `in_file=1`), `brix_build_window_chain` (one window frame w/ explicit status), and the static single-chunk helpers. Plus `brix_get_pool_scratch` (grow-only reusable buffer), `brix_release_read_buffer`, `brix_trim_scratch`. |
| `reads.c` | `kXR_read` + `kXR_pgread` workers/callbacks. `brix_read_aio_thread`/`_done` (plain read), `brix_pgread_aio_thread`/`_done` (page reads w/ per-4096-byte CRC32C). Also the Phase 31 windowed-read driver `brix_read_window_pump` and its `brix_read_window_emit` helper. |
| `write.c` | `kXR_write`/`kXR_pgwrite`/`kXR_writev` workers/callbacks. `brix_write_aio_thread`/`_done` (single `pwrite`) and `brix_writev_write_aio_thread`/`_done` (multi-segment `pwrite` loop + optional per-fd `fsync`). On success updates byte counters, write-through dirty marking, and the write recovery journal. |
| `readv.c` | `kXR_readv` worker/callback. `brix_readv_aio_thread` fills the pre-laid-out segment payloads via `brix_readv_read_segments` (defined in [`../read/readv.c`](../../protocols/root/read/README.md)); `brix_readv_aio_done` builds the chain and updates per-handle counters. |
| `dirlist.c` | `kXR_dirlist` worker/callback. `brix_dirlist_aio_thread` opens the dir, iterates entries, runs optional `fstatat` + `brix_dirlist_checksum_token`, and builds the *complete* wire response (oksofar chunks + final ok) into one buffer. `brix_dirlist_aio_done` queues it. Caps output at `BRIX_DIRLIST_AIO_RESPONSE_MAX` (4 MiB → `E2BIG`). |
| `resume.c` | Shared completion plumbing. `brix_aio_restore_stream`/`_restore_request` (re-seat streamid / reset to `XRD_ST_REQ_HEADER`, with `destroyed` guard), `brix_aio_post_task` (post to pool, set `XRD_ST_AIO`, fall back to sync on NULL/full pool), `brix_aio_resume` (re-arm write vs read event after a `_done`). |
| `config.c` | `brix_configure_thread_pools`: postconfiguration pass that resolves each XRootD stream server's pool name (or `"default"`) to a concrete `ngx_thread_pool_t`. Hard-fails (`NGX_LOG_EMERG`) if `brix_cache` is enabled without a pool; otherwise just disables async I/O with a notice. |

## Key types & data structures

All per-task structs live in `aio.h`, are heap-allocated (or `ngx_thread_task`
slab) before posting, and carry a private `streamid[2]` copy so the `_done`
callback can restore the originating request's identity even if other requests
ran in between.

- **`brix_read_aio_t`** — `fd`, `offset`, `rlen`, `databuf`, plus result
  `nread`/`io_errno`. The read task is *cached* on the ctx (`ctx->read_aio_task`)
  and reused across windows to avoid re-allocation.
- **`brix_pgread_aio_t`** — single `scratch` allocation split in two:
  `scratch[0..rlen)` holds the flat `pread` data, `scratch[rlen..rlen+out_size)`
  holds the CRC-interleaved wire output. The CRC encoding runs on the worker so
  it never touches the event loop.
- **`brix_readv_aio_t`** / **`brix_readv_seg_desc_t`** — the response buffer
  is laid out *before* I/O as `[seg header][payload][seg header][payload]...`;
  each descriptor's `payload_ptr` points straight into that final buffer so the
  worker `preadv`s directly into place with no post-copy.
- **`brix_write_aio_t`** / **`brix_writev_aio_t`** / **`brix_writev_seg_desc_t`**
  — carry the detached payload (`payload_to_free` / `payload_buf`), the per-write
  `req_offset`, `is_pgwrite`/`do_sync` flags, and a 64-byte `err_msg`. `io_error`
  distinguishes hard failure (1) from short write / disk-full (2).
- **`brix_dirlist_aio_t`** — pre-resolved `resolved[PATH_MAX]` (already
  auth-checked on the main thread), `cksum_algo`, `want_stat`/`want_cksum`, and a
  `c->pool` `response` buffer (`response_cap` = `BRIX_DIRLIST_AIO_RESPONSE_MAX`)
  the worker fills with the entire framed listing.
- **Scratch slots** (in `brix_ctx_t`, `../types/context.h`): `read_scratch`,
  `read_hdr_scratch`, `write_scratch` — long-lived, **raw heap** (`ngx_alloc`)
  grow-only buffers reused across requests and freed once at disconnect. The
  per-slot fast structs (`read_fast_hdr_buf`/`_body_buf`/`_chain`/`_file`,
  `hdr_bytes`) live in the `out_ring` response slots and let the common
  single-chunk response build with zero pool allocation.

## Control & data flow

**Entry (from handler bodies):** a stream handler in
[`../read/`](../../protocols/root/read/README.md) / [`../write/`](../../protocols/root/write/README.md) /
[`../dirlist/`](../../protocols/root/dirlist/README.md) finishes synchronous validation
(handle lookup, offset/length parse, `RESOLVE_BENEATH` path confinement via
[`../path/`](../../fs/path/README.md), auth/scope checks), fills a task struct, binds
it with `brix_task_bind()`, and calls `brix_aio_post_task()`. On success the
connection enters `XRD_ST_AIO`; on a missing/full pool the handler does the I/O
inline and builds the response with the same `buffers.c` helpers.

**Worker thread:** the `_thread` function performs *only* POSIX syscalls + pure
computation (CRC for pgread, dir iteration + checksum for dirlist), storing
results in the task struct. It must not touch `ctx`, `c`, pools, or `c->log`
(stale on a thread) — it uses the thread pool's `log` argument.

**Completion (main thread):** nginx posts `_done`. It calls
`brix_aio_restore_request()` (or `_restore_stream` for the windowed read),
which bails if `ctx->destroyed`. On error it emits the mapped `kXR_*` status via
`brix_send_error`; on success it builds the wire chain (`buffers.c`), updates
`ctx->files[idx].bytes_read/written` + `ctx->session_bytes*`, write-through
dirty marks ([`../cache/`](../../fs/cache/README.md)) and the write recovery journal
([`../write/`](../../protocols/root/write/README.md)), writes the access log
([`../path/`](../../fs/path/README.md) `brix_log_access`), and queues the response.
Finally `brix_aio_resume()` arms the **write** event if the response is still
draining (`XRD_ST_SENDING`) or the **read** event otherwise, so pipelined
requests already in the kernel buffer run before the next `epoll_wait`. The
scheduling hooks themselves live in
[`../connection/`](../../protocols/root/connection/README.md) (`brix_schedule_write_resume` /
`brix_schedule_read_resume`, `event_sched.c`).

**Windowed-read loop (Phase 31):** a memory-backed read (TLS / non-regular file)
larger than `BRIX_READ_WINDOW` is served one window at a time.
`brix_read_window_pump` reads the next window (async if a pool exists, else
inline) and `brix_read_window_emit` frames it as `kXR_oksofar` (or `kXR_ok` on
the final window / short read). The next window is read only after the previous
chunk drains — so `connection/send.c` calls `brix_read_window_pump` again on
send-completion (`send.c:78`) — bounding resident heap to ~one window per stream
regardless of request size.

**Config wiring:** `config.c`'s `brix_configure_thread_pools` runs from
postconfiguration ([`../config/`](../config/README.md)); the resolved
`conf->common.thread_pool` is what every `brix_aio_post_task` consults.

## Invariants, security & gotchas

- **Worker threads touch nothing but the task struct.** No pool alloc, no
  connection/request state, no `c->log` (use the `log` arg). All protocol/state
  mutation happens in the `_done` callback on the single-threaded event loop.
  See the rules block atop `dirlist.c:70`.
- **`ctx->destroyed` is the disconnect guard.** Every `_done` calls
  `brix_aio_restore_*` first (`resume.c`); if the client vanished while I/O was
  in flight the callback frees its detached payload and returns without touching
  freed memory. Detached write payloads (`payload_to_free`/`payload_buf`) are
  freed *before* the destroyed check so they never leak on teardown.
- **Path confinement happens before posting, not on the worker.** The dirlist
  worker calls a bare `open(t->resolved, O_DIRECTORY)` *only because* the path
  was already `RESOLVE_BENEATH`-confined on the main thread
  (`dirlist.c:115`). Never resolve a client path on a worker thread.
- **pgread keeps its own framing.** The encoded `[CRC32C(4)][page(4096)]×N`
  payload must **not** go through `brix_build_chunked_chain` (which would
  prepend a `kXR_ok` header); `brix_pgread_aio_done` builds the
  `ServerStatusResponse_pgRead` header + raw data chain by hand
  (`reads.c:466-485`). Per the project invariant, pgread/pgwrite use `kXR_status`
  (4007) framing with per-page CRC.
- **TLS vs cleartext buffers never mix.** `brix_build_*_memory_chain` set
  `b->memory=1`; `brix_build_*_sendfile_chain` set `b->in_file=1` for kernel
  zero-copy. TLS connections cannot wrap `sendfile`, so callers pick the memory
  builder for TLS and the sendfile builder for cleartext — this layer does not
  re-check; the caller's choice is load-bearing.
- **Scratch buffers are raw heap, deliberately.** `brix_get_pool_scratch`/
  `brix_trim_scratch` use `ngx_alloc`/`ngx_free`, *not* the pool. A previous
  pool-backed version caused a use-after-free: `ngx_pfree`/`ngx_palloc` churned
  nginx's large-allocation list while stale pointers (reused
  `read_aio_task->databuf`) still referenced the freed block on a big read
  followed by a big readv (`buffers.c:37`). The ctx owns these and frees them at
  disconnect (`write_scratch` cleanup added in `connection/disconnect.c`).
- **`brix_release_read_buffer` must skip scratch slots.** It only `ngx_pfree`s
  single-request buffers (e.g. a dirlist response); it is a deliberate no-op for
  `read_scratch`/`read_hdr_scratch`/`write_scratch` (`buffers.c:82`). Freeing a
  scratch slot per response would corrupt the reuse contract.
- **Trim only between requests.** `brix_trim_scratch` may run only in
  `XRD_ST_REQ_HEADER` with nothing buffered, or it will free a buffer an
  in-flight response chain still points into (`buffers.c:93`). Hysteresis at
  `BRIX_SCRATCH_TRIM_THRESHOLD` avoids realloc thrash.
- **`oksofar` frames still set `last_buf`/`last_in_chain`.** Those mark the end
  of *this wire frame* for nginx's output filter, not end-of-response; the client
  keys end-of-response off the `kXR_ok` status (`buffers.c:269`).
- **Multi-chunk sendfile headers live in the slot, not shared scratch.** To allow
  pipelining, per-chunk headers go in `slot->hdr_bytes` (capped by
  `BRIX_SLOT_HDR_MAX`) so a pipelined next read built into another slot can't
  clobber a still-draining response's headers (`buffers.c:562-570`).
- **Cache requires a pool; everything else degrades gracefully.** `config.c`
  fails configuration if `brix_cache` is set without a resolvable thread pool;
  for non-cache servers a missing pool just disables async I/O.
- **Short writes are treated as errors.** `brix_write_aio_done` maps
  `nwritten < len` to `kXR_IOError` "short write (disk full?)" — a partial
  `pwrite` is never silently accepted (`write.c:91`).

## Entry points / extending

**Add a new async opcode** (e.g. a new bulk-I/O op):

1. Define an `brix_<op>_aio_t` task struct in `aio.h` (always include a private
   `streamid[2]` copy and result/`io_errno` fields).
2. Add `void brix_<op>_aio_thread(void *data, ngx_log_t *log)` (blocking
   syscall only) and `void brix_<op>_aio_done(ngx_event_t *ev)` (build chain,
   update counters, resume) in the appropriate file (or a new `.c`).
3. From the handler body: validate + confine path + auth on the main thread,
   fill the struct, `brix_task_bind(task, _thread, _done)`,
   `brix_aio_post_task(...)`; provide a synchronous fallback for the
   no-pool / queue-full case.
4. In `_done`, call `brix_aio_restore_request` first, reuse a `buffers.c`
   builder if the wire format allows, and end with `brix_aio_resume`.
5. If you added a new `.c`, register it in the top-level **`config`** file
   (`ngx_brix_stream_srcs` list — see the existing `src/core/aio/*.c` entries around
   line 494) and re-run `./configure`. Note: per project build governance the
   source list lives in `config`/`config.h`, not in any Makefile.
6. Add the 3 required tests (success + error + a teardown/`destroyed`-race or
   short-I/O negative case).

**Add a new response-chain shape:** put the builder in `buffers.c` alongside the
existing memory/sendfile/window helpers and prototype it in `aio.h`, so both the
sync and async paths can share it.

## See also

- [`../read/README.md`](../../protocols/root/read/README.md) — `kXR_read`/`readv`/`pgread` handler
  bodies; defines `brix_readv_read_segments`.
- [`../write/README.md`](../../protocols/root/write/README.md) — `kXR_write`/`pgwrite`/`writev`
  handlers; write recovery journal (`wrts_journal`).
- [`../dirlist/README.md`](../../protocols/root/dirlist/README.md) — `kXR_dirlist` handler and
  `brix_dirlist_checksum_token` / `dcksm`.
- [`../connection/README.md`](../../protocols/root/connection/README.md) — recv/send loop, event
  scheduling, `XRD_ST_*` state machine, scratch cleanup at disconnect.
- [`../cache/README.md`](../../fs/cache/README.md) — read-through/write-through; why the
  cache requires a thread pool.
- [`../path/README.md`](../../fs/path/README.md) — `RESOLVE_BENEATH` confinement and
  `brix_log_access`.
- [`../response/README.md`](../../protocols/root/response/README.md) — wire framing helpers
  (`brix_build_resp_hdr`, `brix_send_error`, pgread/pgwrite status).
- [`../config/README.md`](../config/README.md) — postconfiguration ordering for
  `brix_configure_thread_pools`.
- [`../README.md`](../README.md) — subsystem master index.
