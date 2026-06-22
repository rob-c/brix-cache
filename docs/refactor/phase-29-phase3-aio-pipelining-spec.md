# Phase 29 — Phase 3: AIO read pipelining (implementation spec)

**Status:** Superseded/partially landed. Phases 1, 2, and 4 are landed; the
Phase 32 WS3 foundation added the concurrent AIO read-buffer/task pool
(`rd_pool`, `rd_inflight`) and documented the architecture. The remaining
recv-state-machine flip for fully concurrent memory-backed AIO reads is deferred
to a benchmark-backed session. Keep this file as the original Phase 3 design
spec, not as a current statement that no AIO-pipeline work exists.

## Why it was deferred (2026-06-13)

Scoping against the real code showed Phase 3 is a multi-file, UAF-sensitive change
whose **disconnect-mid-AIO deferred-teardown path is not exercisable in the current
environment** (the existing `state=AIO` recv-suspend prevents any finalize while a
worker runs, so the new deferral path would ship untested), and a mis-wired
refcount decrement leaks/hangs connections — a gateway-fatal regression the test
suite cannot catch. Value is also marginal post-findings: cleartext already
pipelines (Phase 2 sendfile), TLS isn't the bottleneck (userspace TLS = 309 MB/s),
and kTLS regresses. Real benefit narrows to **pgread/readv-heavy** workloads.

## What's already done (reuse it)

- **Output side is complete.** Phase 2's `out_ring[]` (xrootd_ctx_t) +
  `xrootd_queue_response_chain`/`xrootd_flush_pending` already handle out-of-order
  response *enqueue* + head-first drain. An AIO done callback just calls
  `xrootd_queue_response_chain()` and the ring does the rest. The client demuxes by
  streamid, and per-task `streamid` already exists (`t->streamid`).

## The change (file-by-file)

### 1. `src/types/context.h`
```c
ngx_thread_task_t *read_aio_ring[XROOTD_PIPELINE_MAX]; /* reusable tasks */
u_char            *read_databuf[XROOTD_PIPELINE_MAX];  /* raw-heap, per-slot */
size_t             read_databuf_size[XROOTD_PIPELINE_MAX];
ngx_uint_t         read_aio_next;     /* next ring slot to claim */
ngx_uint_t         outstanding;       /* posted-but-not-completed AIO reads */
ngx_uint_t         inflight_tasks;    /* AIO tasks (read+pgread+readv) live */
unsigned           finalize_deferred:1;
ngx_uint_t         finalize_rc;
```

### 2. UAF guard (the safety core — do FIRST, but it needs a finalize-during-AIO
test harness to validate)
- New helper `xrootd_disconnect_finalize(ctx, c, rc)` replacing the
  `on_disconnect();close_all_files();ngx_stream_finalize_session()` sequence at the
  **7 finalize sites** (recv.c ×3, send.c ×2, resume.c ×2):
  ```c
  if (ctx->inflight_tasks > 0) { ctx->destroyed = 1; ctx->finalize_deferred = 1;
                                 ctx->finalize_rc = rc; return; }
  xrootd_on_disconnect(ctx, c); xrootd_close_all_files(ctx);
  ngx_stream_finalize_session(c->data, rc);
  ```
- Increment `inflight_tasks` at the **read/pgread/readv post sites** only, AFTER
  `posted==1` (NOT inside `xrootd_aio_post_task`, which 14 callers share).
- Each of the 3 done callbacks, at the very end (after resume/queue), calls a
  shared `xrootd_aio_task_complete(ctx, c)`: `if (--ctx->inflight_tasks == 0 &&
  ctx->finalize_deferred) { xrootd_on_disconnect; close_all_files; finalize(rc); }`.
  On the `!restore_stream` (destroyed) early-bail branch it must STILL run
  task_complete (free its databuf slot first).

### 3. Per-slot databuf + reusable task ring (`src/read/read.c` small-memory path,
lines ~298-337)
- Replace the `ctx->read_aio_task` singleton + `databuf=read_scratch` with:
  claim slot `i = ctx->read_aio_next; ctx->read_aio_next = (i+1)%W;` lazily
  alloc `read_aio_ring[i]`; grow `read_databuf[i]` (raw heap) to `rlen`;
  `t->databuf = read_databuf[i]; t->ring_idx = i;`. Add `int ring_idx;` to
  `xrootd_read_aio_t` (`src/aio/aio.h`).
- Slot is free because recv only dispatches while `outstanding < W` (see #4).

### 4. recv decoupling (`src/connection/recv.c`) — mirror Phase 2's out_count
- After dispatching a memory-AIO read: instead of returning on `state==XRD_ST_AIO`,
  if `outstanding < XROOTD_PIPELINE_MAX` set `state=REQ_HEADER` and keep reading;
  else suspend (leave AIO/SENDING). `outstanding++` happens at post.
- `xrootd_read_aio_done` (`src/aio/reads.c`): `outstanding--`; build chunked chain
  from `t->databuf`/`t->nread` with `t->streamid`; `xrootd_queue_response_chain`;
  then re-arm read if `outstanding < W` (so the next buffered read dispatches).
  Drop the `state=REQ_HEADER` reset's assumption of single-flight.
- `xrootd_release_read_buffer`: teach it the `read_databuf[]` slots are retained
  (freed at disconnect), like `read_scratch` today.

### 5. `src/connection/disconnect.c`
- Free `read_databuf[0..W-1]` in `xrootd_release_disconnect_owned_buffers` — but
  ONLY reached when `inflight_tasks==0` (guard in #2 guarantees it).

### 6. Extend to pgread (`src/read/pgread.c` + `xrootd_pgread_aio_done`) and readv
(`src/read/readv.c` + `xrootd_readv_aio_done`): same slot-claim + inflight++/--,
and let them pipeline by removing their drain-barrier deferral for the
`cur_reqid==kXR_pgread/kXR_readv` cases in recv (treat like kXR_read). pgread shares
`read_scratch` with a CRC overlay — it needs the per-slot databuf too.

## Validation (the harness Phase 3 needs)
- Force a thread pool + many async reads on one conn → assert `outstanding` climbs
  (instrument like Phase 2's PIPELINE_DEPTH), byte-exact.
- **Disconnect-mid-AIO**: raw client that opens, fires W reads, then RSTs; assert no
  crash AND `connections_active` returns to baseline (no leak) — this is the test
  that's missing today and is REQUIRED before landing the UAF guard.
- Full integrity suite (70/70) + concurrent (16/16) stay green.
- ASAN build (phase-27 W6) running the disconnect-mid-AIO repro: no UAF.
