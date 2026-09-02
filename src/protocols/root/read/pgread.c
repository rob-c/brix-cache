/*
 * pgread.c — kXR_pgread opcode.  See each function's docblock below.
 */

#include "read.h"
#include "read_internal.h"
#include "pgread_internal.h"  /* run struct + front-half seam */

#include "core/ngx_brix_module.h"
#include "fs/backend/sd.h"   /* phase-55: route preadv through the SD seam */
#include "fs/vfs/vfs_io_core.h"  /* brix_vfs_effective_obj — POSIX-wrap or driver obj */
#include "core/compat/pgio.h"     /* kXR_pgPageSZ / kXR_pgUnitSZ page geometry  */
#include "protocols/root/session/registry.h" /* §1.2 pathid validation (bound-path bitmap) */
#include "protocols/root/session/offload_registry.h" /* §1.1 brix_offload_lookup */
#include "protocols/root/connection/budget.h" /* phase-31 W4 memory-budget admission */



/* Shared task-field init for BOTH pgread post sites (primary slot reuse and
 * §1.1 offload).  Everything except the reply routing: the caller sets the
 * sec_* trio and the §1.2 pool_send eligibility to its own shape after this
 * returns.  The pool-send reporting flags are cleared here so a uring-path
 * error completion (which skips both thread fns) can never see a previous
 * request's stale values in a reused slot task. */
static void
brix_pgread_task_init(brix_pgread_aio_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c, brix_pgread_run_t *run)
{
    t->c = c;
    t->ctx = ctx;
    t->fd = run->fd;
    t->handle_idx = run->idx;
    t->offset = (off_t) run->offset;
    t->rlen = run->rlen;
    t->scratch = run->scratch;
    t->out_size = 0;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->obj = ctx->files[run->idx].sd_obj; /* Layer 3: driver obj (or zeroed) */
    t->start_ns = brix_phase_now_ns();  /* phase-56 D-2 */
    t->counted = 1;                     /* single-shot pgread — the per-slot
                                         * task may still hold a stale 0 from
                                         * a kXR_read windowed post */
    t->pool_sent = 0;
    t->pool_sent_all = 0;
    t->pool_token_held = 0;
    t->pool_send_errno = 0;
    t->pool_chunked = 0;
    t->chunk_error = 0;
    t->pool_image_len = 0;
    t->pool_frames = 0;
}

/*
 * brix_pgread_post_aio - offload the read to the thread pool.
 *
 * WHAT: Fills the connection's reusable pgread AIO task from `run` and posts
 *       it to the configured thread pool.  Returns NGX_OK when posted (the
 *       completion handler sends the response), NGX_DECLINED when the post
 *       failed (caller falls back to the sync path), NGX_ERROR on
 *       allocation failure.
 *
 * WHY: The task-population boilerplate is one nameable step of the handler;
 *      extracting it keeps the orchestrator flat (coding-standards §8).
 *
 * HOW: Uses the rd_pool slot task backing run->scratch (phase-32 WS3
 *      discipline, shared with read_post_aio): each in-flight pgread carries
 *      an independent task struct, so several can run on worker threads at
 *      once without a later post clobbering a task a worker still owns.  A
 *      posted task is counted in rd.aio_inflight (t->counted) so teardown
 *      defers and the recv loop's pipelining/backpressure bounds hold.
 */
static ngx_int_t
brix_pgread_post_aio(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run)
{
    ngx_thread_task_t   *task = NULL;
    brix_pgread_aio_t *t;
    ngx_flag_t           posted;
    ngx_uint_t           i;

    for (i = 0; i < ctx->out.pipeline_depth; i++) {
        if (ctx->rd.pool[i].buf == run->scratch) {
            task = ctx->rd.pool[i].task;
            if (task == NULL) {
                /* Sized for either pipelined read opcode — kXR_read posts
                 * share the per-slot task (see brix_rd_slot_aio_u, aio.h). */
                task = ngx_thread_task_alloc(c->pool,
                                             sizeof(brix_rd_slot_aio_u));
                if (task == NULL) {
                    return NGX_ERROR;
                }
                ctx->rd.pool[i].task = task;
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }
            break;
        }
    }

    /* A scratch that is not a pool slot cannot pipeline safely (no per-slot
     * task to bind); decline so the caller serves synchronously instead. */
    if (task == NULL) {
        return NGX_DECLINED;
    }

    t = task->ctx;
    brix_pgread_task_init(t, ctx, c, run);
    t->sec_c = NULL;                    /* primary-stream reply (a reused slot
                                         * task may hold stale offload fields) */
    t->sec_ctx = NULL;
    t->sec_counted = 0;
    t->pool_send = 0;                   /* §1.2: never pool-send on the
                                         * primary path (reused slot task) */

    brix_task_bind(task, brix_pgread_aio_thread, brix_pgread_aio_done);

    (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                "brix: thread_task_post failed, sync pgread fallback",
                                &posted);

    /* Only a posted task runs on a worker thread, so only then does its
     * completion decrement rd.aio_inflight — count it here so disconnect
     * defers teardown until the worker releases the rd_pool buffer, and so
     * the recv loop's in-flight bounds see this read (mirrors read_post_aio). */
    if (posted) {
        ctx->rd.aio_inflight++;
    }

    return posted ? NGX_OK : NGX_DECLINED;
}

/*
 * brix_pgread_sync_fill - blocking fallback read into the wire buffer.
 *
 * WHAT: Runs the pgread VFS job inline (read directly into the gapped wire
 *       buffer, CRC each page in place — no flat-buffer copy).  On success
 *       fills run->{out_buf, out_size, flat_buf}, updates run->rlen to the
 *       bytes actually read (accounting), and returns 0; on I/O error
 *       returns the job's errno for the caller's error triplet.
 *
 * WHY: Same code path as the AIO worker, kept as a pure produce-or-errno
 *      step so the handler owns the wire error response (side effects at
 *      the edges, coding-standards §8).
 *
 * HOW: Skipped by the caller when the warm-cache fast path already produced
 *      the encoding; runs when no thread pool is configured or the post
 *      failed.
 */
static int
brix_pgread_sync_fill(brix_ctx_t *ctx, brix_pgread_run_t *run)
{
    brix_vfs_job_t job;

    brix_vfs_job_read_init(&job, run->fd, (off_t) run->offset, run->rlen,
                              run->scratch, run->rlen, 0);
    job.op = BRIX_VFS_IO_PGREAD;
    brix_vfs_job_set_obj(&job, &ctx->files[run->idx].sd_obj);
    brix_vfs_io_execute(&job);

    if (job.io_errno != 0) {
        return job.io_errno;
    }

    run->out_size = job.out_size;
    run->flat_buf = run->scratch;
    run->out_buf  = run->scratch;      /* output starts at offset 0 now */
    run->rlen     = (size_t) job.nio;  /* actual bytes read (accounting) */
    return 0;
}

/*
 * brix_pgread_send_response - frame, account, log, and queue the reply.
 *
 * WHAT: Builds the kXR_status(4007) response chain over the produced output,
 *       charges the byte accounting / bandwidth limiter, writes the access
 *       log line, and queues the chain.  Returns the queue rc (NGX_ERROR on
 *       framing failure), releasing the read buffer on any non-send outcome.
 *
 * WHY: Response assembly is the handler's final nameable step; the order of
 *      framing → accounting → log → metric → queue is frozen (byte-identical
 *      wire output and log lines).
 *
 * HOW: run->rlen here is the actual byte count (the sync path overwrote it
 *      with job.nio; the warm path read exactly rlen).  The buffer is kept
 *      only while the send is in flight (state XRD_ST_SENDING).
 */
static ngx_int_t
brix_pgread_send_response(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run)
{
    ngx_chain_t  *rsp_chain;
    char          detail[64];
    ngx_int_t     rc;

    rsp_chain = brix_build_pgread_chain(ctx, c, run->offset, run->out_buf,
                                          (uint32_t) run->out_size);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, run->flat_buf);
        return NGX_ERROR;
    }

    ctx->files[run->idx].bytes_read += run->rlen;
    ctx->totals.bytes += run->rlen;
    brix_rl_charge_ctx(ctx, run->rlen);  /* Phase 25 bandwidth */

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) run->offset, run->rlen);
        brix_log_access(ctx, c, "PGREAD", ctx->files[run->idx].path,
                          detail, 1, 0, NULL, run->rlen);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);

    /* Self-contained frame (per-response palloc'd header, data in this
     * request's own rd_pool slot): if it parks, the next pgread may safely
     * queue behind it while it drains (brix_recv_try_pipeline_read). */
    ctx->out.resp_pipelinable = 1;

    rc = brix_queue_response_chain(ctx, c, rsp_chain, run->flat_buf);
    if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, run->flat_buf);
    }
    return rc;
}

/*
 * brix_pgread_post_aio_offload — post a large pgread to the thread pool with
 * the reply targeted at a bound same-worker SECONDARY channel (§1.1).
 *
 * WHAT: The offload analog of brix_pgread_post_aio: binds the SECONDARY's
 *       per-slot task (fbuf is its rd_pool slot; the encode region starts 32
 *       bytes in, after the pgRead status header the done handler stamps),
 *       fills it from `run`, and posts.  Counted in BOTH connections'
 *       rd.aio_inflight — the primary owns the request/recv state, the
 *       secondary owns the buffer and the out-ring slot the reply will take —
 *       so either side's teardown defers until the completion runs.
 *
 * WHY: One TCP socket tops out well below what a striped -S4 client can
 *      sink; routing each large pgread's reply over the substream the client
 *      asked for (pathid) engages every bound socket in parallel, which is
 *      exactly how XRootD's do_Offload wins multi-stream benchmarks.
 *
 * HOW: Returns NGX_OK when posted (brix_pgread_aio_done routes to the
 *      offload epilogue via t->sec_c) or NGX_DECLINED when no per-slot task
 *      could be bound / the pool refused — the caller releases fbuf and falls
 *      through to the primary producer paths.
 */
static ngx_int_t
brix_pgread_post_aio_offload(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run,
    brix_ctx_t *sec_ctx, ngx_connection_t *sec_c, u_char *fbuf)
{
    ngx_thread_task_t   *task = NULL;
    brix_pgread_aio_t *t;
    ngx_flag_t           posted;
    ngx_uint_t           i;

    for (i = 0; i < sec_ctx->out.pipeline_depth; i++) {
        if (sec_ctx->rd.pool[i].buf == fbuf) {
            task = sec_ctx->rd.pool[i].task;
            if (task == NULL) {
                task = ngx_thread_task_alloc(sec_c->pool,
                                             sizeof(brix_rd_slot_aio_u));
                if (task == NULL) {
                    return NGX_DECLINED;
                }
                sec_ctx->rd.pool[i].task = task;
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }
            break;
        }
    }

    if (task == NULL) {
        return NGX_DECLINED;
    }

    t = task->ctx;
    brix_pgread_task_init(t, ctx, c, run);  /* run->scratch = fbuf + hdr off */
    t->sec_c = sec_c;
    t->sec_ctx = sec_ctx;
    t->sec_counted = 1;

    /* §1.2 pool-send eligibility: any cleartext secondary (a worker thread
     * cannot enter the TLS filter, invariant #2).  Ring state is NOT checked
     * here — the thread's send-time gate (token CAS + send_busy) is the
     * authoritative throttle; a post-time out.count check would cascade (one
     * parked frame routes every task posted during its drain to the event
     * loop, which keeps the ring busy, which extends the cascade). */
    t->pool_send = (sec_c->ssl == NULL) ? 1 : 0;
    if (t->pool_send) {
        sec_ctx->out.pool_send_active = 1;   /* engage the send-token gates */
    }

    brix_task_bind(task, brix_pgread_aio_thread, brix_pgread_aio_done);

    (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                "brix: thread_task_post failed, primary pgread fallback",
                                &posted);

    if (posted) {
        ctx->rd.aio_inflight++;
        sec_ctx->rd.aio_inflight++;
    }

    return posted ? NGX_OK : NGX_DECLINED;
}

/*
 * brix_pgread_try_offload - §1.1 response offloading (do_Offload parity) for
 * kXR_pgread: the pgread analog of brix_read_try_offload (read.c) — see there
 * for the full safety rationale. pgread already VALIDATES its pathid in
 * brix_pgread_parse_validate (§1.2); this routes an eligible response over the
 * bound secondary. The pgread reply is [32B kXR_status frame | CRC-interleaved
 * page data], so it is the same secondary-owned flat-buffer shape as read/readv,
 * only with a 32-byte header built by brix_build_pgread_status instead of 8.
 *
 * When the pathid names a same-worker, quiescent secondary and the encoded reply
 * fits one streaming window: acquire the frame buffer from the SECONDARY's pool
 * (32B header + the gapped [CRC32c][page] encoding), encode the pages straight
 * into buf+32 via the shared brix_pgread_sync_fill, stamp the kXR_status frame
 * (carrying the PRIMARY request's streamid) into buf[0..32), and queue it on the
 * secondary's out-ring — acquire+release both on the secondary's ctx, no cross-
 * connection lifetime tangle. Returns 1 when routed (*rc set), 0 to fall through
 * to the normal primary-stream producer paths (warm / AIO / sync).
 */
static ngx_flag_t
brix_pgread_try_offload(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run, ngx_int_t *rc)
{
    ngx_connection_t *sec_c;
    brix_ctx_t       *sec_ctx;
    size_t            n_pages_max, enc_max, hdr_space;
    u_char           *buf;
    int               io_errno;

    sec_ctx = brix_read_offload_secondary(ctx, c, run->pathid, &sec_c);
    if (sec_ctx == NULL) {
        return 0;
    }

    /* Encoded-reply upper bound — the gapped [CRC32c(4)][page] size, identical
     * to brix_pgread_scratch_size's math. A reply larger than one streaming
     * window belongs on the (thread-pool-capable) primary path. */
    n_pages_max = ((size_t) (run->offset & (kXR_pgPageSZ - 1)) + run->rlen
                   + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
    if (n_pages_max == 0) {
        n_pages_max = 1;
    }
    enc_max = run->rlen + n_pages_max * BRIX_PG_CKSZ;
    if (enc_max > (size_t) BRIX_READ_WINDOW) {
        /* Large reply: too big for the inline sync fill (it would stall the
         * event loop for milliseconds), but exactly what the thread pool is
         * for — post the normal pgread AIO with the response targeted at the
         * SECONDARY (multi-socket parallelism for striped -S clients).  Any
         * ineligibility falls through to the unchanged primary paths. */
        if (rconf->common.thread_pool == NULL) {
            return 0;
        }
        /* §1.3 chunked streaming lays one status header per chunk frame
         * back-to-back in this buffer — size for the worst-case train. */
        hdr_space = sizeof(ServerStatusResponse_pgRead)
                    * (1 + (run->rlen + BRIX_PGREAD_STREAM_CHUNK - 1)
                           / BRIX_PGREAD_STREAM_CHUNK);
        if (!brix_budget_admit(ctx, rconf->memory_budget,
                               hdr_space + enc_max)) {
            return 0;   /* over budget — the primary path issues the kXR_wait */
        }
        buf = brix_acquire_read_buffer(sec_ctx, sec_c, hdr_space + enc_max);
        if (buf == NULL) {
            return 0;   /* secondary pool exhausted — primary path serves it */
        }
        brix_budget_sync(sec_ctx);   /* charge the (possibly grown) slot */
        run->scratch = buf + sizeof(ServerStatusResponse_pgRead);
        if (brix_pgread_post_aio_offload(ctx, c, rconf, run, sec_ctx, sec_c,
                                           buf) != NGX_OK)
        {
            brix_release_read_buffer(sec_ctx, sec_c, buf);
            run->scratch = NULL;
            return 0;
        }
        *rc = NGX_OK;
        return 1;
    }

    /* Frame buffer from the SECONDARY's pool: 32B status frame + encoding. */
    buf = brix_acquire_read_buffer(sec_ctx, sec_c,
                                     sizeof(ServerStatusResponse_pgRead) + enc_max);
    if (buf == NULL) {
        return 0;   /* secondary pool exhausted — fall back rather than fail */
    }

    /* Encode the pages straight into the frame's data region [32 .. 32+enc). */
    run->scratch = buf + sizeof(ServerStatusResponse_pgRead);
    io_errno = brix_pgread_sync_fill(ctx, run);   /* fills out_size + rlen(=nio) */
    if (io_errno != 0) {
        /* I/O failure: the secondary wire is untouched, so the error rides the
         * PRIMARY control stream exactly like the normal path. */
        brix_release_read_buffer(sec_ctx, sec_c, buf);
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        *rc = brix_send_error(ctx, c, kXR_IOError, strerror(io_errno));
        return 1;
    }

    /* Accounting stays on the PRIMARY ctx (the request's owner). */
    ctx->files[run->idx].bytes_read += run->rlen;
    ctx->totals.bytes += run->rlen;
    brix_rl_charge_ctx(ctx, run->rlen);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) run->offset, run->rlen);
        brix_log_access(ctx, c, "PGREAD", ctx->files[run->idx].path,
                          detail, 1, 0, NULL, run->rlen);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);

    /* Stamp the kXR_status frame (PRIMARY streamid) into the 32-byte header, then
     * queue the contiguous [status|data] frame on the SECONDARY (it owns buf). */
    brix_build_pgread_status(ctx, run->offset, (uint32_t) run->out_size,
                               (ServerStatusResponse_pgRead *) buf);
    *rc = brix_queue_response_base(sec_ctx, sec_c, buf,
                                     sizeof(ServerStatusResponse_pgRead)
                                         + run->out_size, buf);
    if (*rc == NGX_OK) {
        brix_metric_offload(BRIX_PROTO_ROOT);   /* §1.1 observability */
    }

    if (*rc != NGX_OK || sec_ctx->out.count == 0) {
        brix_release_read_buffer(sec_ctx, sec_c, buf);
    }
    return 1;
}

/*
 * brix_handle_pgread - kXR_pgread orchestrator.
 *
 * WHAT: Decodes and validates the request, sizes the wire buffer, then tries
 *       the producer paths in order — warm-cache inline, thread-pool offload,
 *       sync fallback — and frames whatever output was produced.
 *
 * WHY: Flat sequence of named steps per coding-standards §8; the complexity
 *      lives in the helpers above.
 *
 * HOW: run.{out_buf, flat_buf, out_size} start NULL/0 (phase-72.A) and are
 *      set only by a producer; the out_buf==NULL guard before framing makes
 *      the exactly-one-producer invariant enforceable.
 */
ngx_int_t
brix_handle_pgread(brix_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: pgread is ALWAYS plaintext — it never consults
     * ctx->files[idx].read_codec.  Inline read compression is a kXR_read-only
     * handle property; pgread's kXR_status(4007) framing + per-page CRC32c must
     * stay byte-for-byte intact, so compression is deliberately not applied here. */
    brix_pgread_run_t             run;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_int_t                     rc;
    ngx_flag_t                    warm_hit;

    ngx_memzero(&run, sizeof(run));   /* out_buf/flat_buf NULL, out_size 0 */

    if (!brix_pgread_parse_validate(ctx, c, &run, &rc)) {
        return rc;
    }

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    /*
     * §1.1 response offloading: route an eligible pgread reply over the bound
     * secondary channel (the pathid was already validated in parse_validate).
     * Ineligible requests (pathid 0, cross-worker, busy secondary, large) fall
     * through to the normal warm/AIO/sync producer paths below, unchanged.
     */
    if (brix_pgread_try_offload(ctx, c, rconf, &run, &rc)) {
        return rc;
    }

    /*
     * Windowed streaming (pgread_window.c): a primary-path request larger
     * than one window is served as a kXR_PartialResult train produced
     * window-by-window into the hot read_scratch slot instead of a
     * request-sized rd_pool fill — LLC-hot copy destination, one window of
     * memory budget, first frame on the wire after one window.  Offload-
     * eligible requests were consumed above, so everything reaching this
     * gate rides the primary stream.
     */
    if (run.rlen > BRIX_PGREAD_WARM_INLINE_MAX) {
        return brix_pgread_serve_windowed(ctx, c, rconf, &run);
    }

    /* Memory-budget admission (phase-31 W4, parity with read_serve_buffered):
     * this request will hold an rd_pool buffer of the encoded size until its
     * response drains; over budget it is deferred with kXR_wait. */
    if (!brix_budget_admit(ctx, rconf->memory_budget,
                           brix_pgread_scratch_size(&run))) {
        return brix_fsoverload_backoff(ctx, c, rconf);
    }

    /*
     * Per-in-flight gapped wire buffer (pgread pipelining): each outstanding
     * pgread encodes into its OWN rd_pool slot rather than the shared
     * read_scratch, so this response can keep draining while the recv loop
     * admits the next pgread into a different buffer (and a pool thread reads
     * it concurrently).  Released back to the pool when the response's
     * out_ring slot drains, or below on the error paths.
     */
    run.scratch = brix_acquire_read_buffer(ctx, c,
                                             brix_pgread_scratch_size(&run));
    if (run.scratch == NULL) {
        /* Pool exhausted despite the recv-side depth bound — slot accounting
         * has gone wrong upstream.  Never fatal: a bare NGX_ERROR here tears
         * down a healthy pipelined connection (silent RST, client re-login
         * storm); defer the request with the standard overload backoff. */
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: pgread rd_pool exhausted (depth %ui, "
                      "rd_inflight %ui, aio_inflight %ui) — deferring",
                      ctx->out.pipeline_depth, ctx->rd.inflight,
                      ctx->rd.aio_inflight);
        return brix_fsoverload_backoff(ctx, c, rconf);
    }
    brix_budget_sync(ctx);   /* charge the (possibly grown) slot promptly */

    /* Large requests skip the inline warm probe even when resident: posting
     * to the pool overlaps this request's read+CRC with the previous
     * response's socket writes (see BRIX_PGREAD_WARM_INLINE_MAX). */
    warm_hit = run.rlen <= BRIX_PGREAD_WARM_INLINE_MAX
               ? brix_pgread_try_warm(ctx, rconf, &run) : 0;

    if (!warm_hit && rconf->common.thread_pool != NULL) {
        rc = brix_pgread_post_aio(ctx, c, rconf, &run);
        if (rc == NGX_ERROR) {
            brix_release_read_buffer(ctx, c, run.scratch);
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            return NGX_OK;   /* posted; the AIO done handler responds */
        }
        /* NGX_DECLINED: post failed — fall through to the sync path. */
    }

    if (!warm_hit) {
        int io_errno = brix_pgread_sync_fill(ctx, &run);

        if (io_errno != 0) {
            brix_release_read_buffer(ctx, c, run.scratch);
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                              ctx->files[run.idx].path, "-",
                              kXR_IOError, strerror(io_errno));
        }
    }

    /* Invariant: exactly one of the producer paths (warm hit or sync
     * fallback) must have filled the output; the AIO path returned above. */
    if (run.out_buf == NULL) {
        brix_release_read_buffer(ctx, c, run.scratch);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                          ctx->files[run.idx].path, "-",
                          kXR_ServerError, "pgread: no output produced");
    }

    return brix_pgread_send_response(ctx, c, rconf, &run);
}
