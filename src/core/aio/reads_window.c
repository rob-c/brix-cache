#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "protocols/root/read/read.h"

/*
 * reads_window.c — the windowed-read train's forward drive (split from
 * reads.c, round-12 file-size cap).
 *
 * WHAT: a kXR_read / kXR_pgread larger than BRIX_READ_WINDOW is served as a
 *       train of window-sized wire frames (kXR_oksofar chunks for read,
 *       kXR_status partial/final frames for pgread).  This file owns the
 *       pump that reads + emits each window, the per-window thread-pool
 *       post, and the round-12 double-buffered read-ahead machinery.
 *
 * HOW:  brix_read_window_pump drives fill -> drain -> fill; the AIO
 *       completion halves (brix_read_aio_done and the windowed/prefetch
 *       routing) stay in reads.c and re-enter the train through
 *       brix_read_window_emit_step / brix_read_window_park_or_resume /
 *       brix_read_window_pump — the three cross-file entry points.
 */


/*                                                                      */
/* BRIX_READ_WINDOW is served as a sequence of kXR_oksofar wire chunks */

/*
 * brix_read_window_emit — build + queue one window's wire chunk from
 * rd.read_scratch[0..nread), advancing the continuation state.  Status is
 * kXR_oksofar for every window except the last (or a short read at EOF), which
 * is kXR_ok.  Returns NGX_ERROR if the read failed or the chain could not be
 * built (an error response has already been sent); otherwise NGX_OK, with
 * ctx->state == XRD_ST_SENDING if the chunk is still draining and
 * ctx->rd.win_active cleared when this was the final window.
 */
static ngx_int_t
brix_read_window_emit(brix_ctx_t *ctx, ngx_connection_t *c,
    ssize_t nread, int io_errno)
{
    ngx_chain_t *chain;
    uint16_t     status;
    size_t       got;

    if (nread < 0) {
        brix_read_io_failure_log(c->log, "windowed", ctx->rd.win_fd,
                                   ctx->rd.win_offset, ctx->rd.win_remaining,
                                   io_errno);
        ctx->rd.win_active = 0;
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
        BRIX_OP_ERR(ctx, BRIX_OP_READ);
        brix_send_error(ctx, c, kXR_IOError,
                          io_errno ? strerror(io_errno) : "async read error");
        return NGX_ERROR;
    }

    got = (size_t) nread;
    ctx->files[ctx->rd.win_idx].bytes_read += got;
    ctx->totals.bytes += got;

    if (got < ctx->rd.win_remaining) {
        ctx->rd.win_remaining -= got;
        ctx->rd.win_offset += (off_t) got;
    } else {
        ctx->rd.win_remaining = 0;
    }

    /* Last planned window, or a short read (EOF), terminates the response. */
    status = (ctx->rd.win_remaining == 0 || got == 0) ? kXR_ok : kXR_oksofar;

    chain = brix_build_window_chain(ctx, c, ctx->rd.read_scratch, got, status);
    if (chain == NULL) {
        ctx->rd.win_active = 0;
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    if (status == kXR_ok) {
        ctx->rd.win_active = 0;
        BRIX_OP_OK(ctx, BRIX_OP_READ);
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
    brix_queue_response_chain(ctx, c, chain, ctx->rd.read_scratch);
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, ctx->rd.read_scratch);  /* no-op slot */
    }
    return NGX_OK;
}

/*
 * brix_window_emit_dispatch — route a completed window to its opcode's emit.
 * The window pump is shared between kXR_read (kXR_oksofar chunks) and
 * kXR_pgread (kXR_status partial/final frames, pgread_window.c); the state
 * machine carries the opcode in rd.win_pgread.
 */
static ngx_int_t
brix_window_emit_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
    ssize_t nread, size_t out_size, int io_errno)
{
    if (ctx->rd.win_pgread) {
        return brix_pgread_window_emit(ctx, c, nread, out_size, io_errno);
    }
    return brix_read_window_emit(ctx, c, nread, io_errno);
}

/*
 * read_window_sizes — data length and scratch requirement for the next window.
 * pgread windows cut on the absolute 4 KiB page grid (every partial frame
 * carries whole [CRC][page] units) and need frame headroom: [32-byte status
 * header][gapped encoded window]; plain read windows are the raw byte count.
 */
static void
read_window_sizes_at(ngx_flag_t pgread, off_t offset, size_t remaining,
    size_t *want, size_t *scratch_need)
{
    if (pgread) {
        *want = brix_pgread_window_want(offset, remaining);
        *scratch_need = brix_pgread_window_scratch(offset, *want);
        return;
    }
    *want = remaining < (size_t) BRIX_READ_WINDOW
            ? remaining : (size_t) BRIX_READ_WINDOW;
    *scratch_need = *want;
}

static void
read_window_sizes(brix_ctx_t *ctx, size_t *want, size_t *scratch_need)
{
    read_window_sizes_at(ctx->rd.win_pgread, ctx->rd.win_offset,
                           ctx->rd.win_remaining, want, scratch_need);
}

/*
 * read_window_post_aio — post the next window to the pread thread pool.
 * Returns 1 when posted (state XRD_ST_AIO; brix_read_aio_done resumes the
 * pump) and 0 when the window must be read inline instead: no pool
 * configured, a driver-backed handle, or the pool queue is full.
 *
 * Driver-backed (memory-served, fd<0) handles — e.g. a remote root://
 * storage backend — must NOT be posted to the pread thread pool: the
 * driver drives an event-loop-bound origin connection (brix_cache_*),
 * which returns EIO when driven from a worker thread.  Serve such reads
 * inline on the event loop, matching how the ≤window buffered path and
 * the sendfile gate already exclude driver handles.
 */
static ngx_flag_t
read_window_post_aio(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, u_char *datap, size_t want,
    off_t offset)
{
    ngx_thread_task_t *task;
    brix_read_aio_t   *t;
    ngx_flag_t          posted = 0;

    if (rconf->common.thread_pool == NULL
        || ctx->files[ctx->rd.win_idx].sd_obj.driver != NULL)
    {
        return 0;
    }

    /*
     * One task struct is allocated once per stream and cached on
     * ctx->rd.read_aio_task, then reused across every window of this read
     * (and across later reads) to avoid a pool allocation per window.
     * On reuse the task is dirty from its last trip through the pool:
     * task->next must be cleared (the pool threads it onto its run
     * queue) and event.complete reset to 0 (ngx_post_event set it when
     * the previous completion fired) or the next post would be ignored.
     */
    task = ctx->rd.read_aio_task;
    if (task == NULL) {
        task = ngx_thread_task_alloc(c->pool, sizeof(brix_read_aio_t));
        if (task == NULL) {
            return 0;
        }
        ctx->rd.read_aio_task = task;
    } else {
        task->next = NULL;
        task->event.complete = 0;
    }

    t = task->ctx;
    t->c = c;
    t->ctx = ctx;
    t->conf = rconf;
    t->fd = ctx->rd.win_fd;
    t->handle_idx = ctx->rd.win_idx;
    t->offset = offset;
    t->rlen = want;
    t->databuf = datap;
    /*
     * Snapshot the 2-word streamid into the task so the completion
     * callback can verify it still matches the live ctx — by the
     * time the worker finishes, this connection may have been torn
     * down and the slot reused by an unrelated stream.
     */
    t->streamid[0] = ctx->rd.win_streamid[0];
    t->streamid[1] = ctx->rd.win_streamid[1];
    t->nread = 0;
    t->io_errno = 0;
    /*
     * The task struct is shared with the single-shot buffered path
     * (read_post_aio), so csi/obj still hold the LAST read's handle
     * state.  The worker routes the pread through t->obj's driver
     * (which carries its own fd) whenever obj.driver != NULL, so a
     * stale obj sends this window to the previous handle's fd —
     * wrong file if the number was recycled, EBADF if closed or
     * write-only — and a stale csi is a dangling pointer once that
     * handle closed.  Rebind both to the windowed read's own handle
     * on every post.
     */
    /* pgread computes fresh per-page CRC32c from the bytes it just
     * read (classic pgread AIO never binds CSI either); a stale
     * csi under the PGREAD op would be meaningless. */
    t->csi = ctx->rd.win_pgread
             ? NULL : ctx->files[ctx->rd.win_idx].csi;
    t->obj = ctx->files[ctx->rd.win_idx].sd_obj;
    t->pg = ctx->rd.win_pgread;
    t->out_size = 0;
    t->start_ns = brix_phase_now_ns();  /* phase-56 D-2 */
    /* Round 12 (double-buffered windows): every windowed post is counted
     * in rd.aio_inflight.  A read-ahead runs on a worker thread WHILE the
     * previous frame drains on the socket, so a send-error teardown must
     * defer until the worker has left the scratch buffer — the same
     * phase-32 WS3 discipline the pipelined single-shot path uses.  (The
     * pre-round-12 counted=0 relied on recv being suspended AND nothing
     * sending during XRD_ST_AIO; the overlap breaks that assumption.) */
    t->counted = 1;
    brix_task_bind(task, brix_read_aio_thread, brix_read_aio_done);
    (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
        "brix: window task post failed, sync fallback", &posted);
    if (posted) {
        ctx->rd.aio_inflight++;
    }
    return posted;   /* post failed (queue full) → caller reads inline */
}

/*
 * Round 12 — double-buffered windows.
 *
 * WHAT: while window N drains from rd.read_scratch, window N+1 is already
 * being read (and, for pgread, encoded + CRCed) by a worker thread into
 * rd.win_scratch_b; after every emit the two buffers swap roles.
 *
 * WHY: the round-11 train self-serializes — read, encode and send of every
 * window ran strictly in sequence, capping each worker at what one event
 * loop core can do.  Overlapping window N's send with window N+1's read
 * moves the read+CRC+copy off the critical path, which is the per-worker
 * ceiling the 8-client bench hits.
 *
 * HOW: brix_read_window_prefetch posts the NEXT window (offset advanced by
 * the current window's nread) into win_scratch_b BEFORE the current window
 * is emitted — brix_aio_post_task flips ctx->state to XRD_ST_AIO, and the
 * emit that follows overwrites state again, so the pre-emit ordering keeps
 * the state machine consistent.  The completion routes on task identity
 * (task == rd.read_aio_task) + rd.win_prefetch and stashes its result in
 * rd.win_pf_* (win_ready); the frame's drain (send.c → pump) and the
 * completion then meet in the pump, whichever arrives last emits.  The
 * INVARIANT that makes the swap safe: a window is emitted only after the
 * previous frame fully drained (send.c re-enters the pump only when
 * brix_flush_pending reports empty), so the read-ahead always targets a
 * buffer no queued frame references.  Any reason not to read ahead —
 * no pool, driver-backed handle, budget refusal, OOM, full queue — just
 * degrades to the round-11 serial train.
 */
static ngx_flag_t
brix_read_window_prefetch(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, ssize_t nread)
{
    off_t    next_off;
    size_t   next_rem, want, need;
    u_char  *buf, *datap;

    if (nread <= 0 || (size_t) nread >= ctx->rd.win_remaining) {
        return 0;                 /* the window being emitted ends the train */
    }
    if (rconf->common.thread_pool == NULL
        || ctx->files[ctx->rd.win_idx].sd_obj.driver != NULL)
    {
        return 0;                 /* post_aio would refuse — don't grow the
                                   * back buffer for nothing */
    }

    next_off = ctx->rd.win_offset + (off_t) nread;
    next_rem = ctx->rd.win_remaining - (size_t) nread;
    read_window_sizes_at(ctx->rd.win_pgread, next_off, next_rem,
                           &want, &need);

    if (need > ctx->rd.win_scratch_b_size
        && !brix_budget_admit(ctx, rconf->memory_budget, need))
    {
        return 0;                 /* budget refused the second window */
    }
    buf = BRIX_GET_SCRATCH(ctx, c, rd.win_scratch_b, rd.win_scratch_b_size,
                             need);
    if (buf == NULL) {
        return 0;
    }
    brix_budget_sync(ctx);

    datap = ctx->rd.win_pgread
            ? buf + sizeof(ServerStatusResponse_pgRead) : buf;
    if (!read_window_post_aio(ctx, c, rconf, datap, want, next_off)) {
        return 0;
    }
    ctx->rd.win_prefetch = 1;
    return 1;
}

/* Swap the front (emit) and back (read-ahead) window buffers.  Field-level
 * swap only: a still-queued frame and the in-flight task's databuf hold raw
 * pointers into the actual allocations, which don't move. */
static void
brix_read_window_swap_buffers(brix_ctx_t *ctx)
{
    u_char   *p   = ctx->rd.read_scratch;
    size_t    sz  = ctx->rd.read_scratch_size;
    unsigned  hot = ctx->rd.read_scratch_hot;

    ctx->rd.read_scratch       = ctx->rd.win_scratch_b;
    ctx->rd.read_scratch_size  = ctx->rd.win_scratch_b_size;
    ctx->rd.read_scratch_hot   = ctx->rd.win_scratch_b_hot;
    ctx->rd.win_scratch_b      = p;
    ctx->rd.win_scratch_b_size = sz;
    ctx->rd.win_scratch_b_hot  = hot;
}

/* Post the next window's read-ahead, emit the current window from
 * read_scratch, then swap the buffers so the read-ahead target becomes the
 * next emit source.  The prefetch must come FIRST (see the round-12 block
 * comment) and the swap must come LAST (emit reads read_scratch). */
ngx_int_t
brix_read_window_emit_step(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, ssize_t nread, size_t out_size,
    int io_errno)
{
    ngx_flag_t  prefetched;
    ngx_int_t   rc;

    prefetched = brix_read_window_prefetch(ctx, c, rconf, nread);
    rc = brix_window_emit_dispatch(ctx, c, nread, out_size, io_errno);
    if (prefetched && rc == NGX_OK) {
        brix_read_window_swap_buffers(ctx);
    }
    return rc;
}

/* An emit failed and killed the train.  If a read-ahead worker is still
 * writing into win_scratch_b, the request loop must NOT resume yet — park in
 * XRD_ST_AIO until that (counted) completion discards itself and resumes;
 * otherwise resume now. */
void
brix_read_window_park_or_resume(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->rd.win_prefetch) {
        ctx->state = XRD_ST_AIO;
        return;
    }
    brix_aio_resume(c);
}

/* phase-56 D-2 sample for a train whose FINAL window was emitted from a
 * stashed read-ahead: the task that produced it is the cached windowed task,
 * so its start_ns is the sample origin (parity with the direct-completion
 * sample in brix_read_aio_window_done). */
static void
brix_read_window_final_sample(brix_ctx_t *ctx)
{
    brix_read_aio_t *t;

    if (ctx->rd.read_aio_task == NULL) {
        return;
    }
    t = ctx->rd.read_aio_task->ctx;
    brix_aio_metric_done(t->start_ns, BRIX_METRIC_OP_READ);
}

/* Emit a stashed read-ahead window (win_ready).  Returns NGX_AGAIN to keep
 * pumping (the loop top resumes a finished train) and NGX_DONE when the pump
 * must return (frame draining, or parked on an emit error). */
static ngx_int_t
brix_read_window_pump_ready(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf)
{
    ctx->rd.win_ready = 0;
    if (brix_read_window_emit_step(ctx, c, rconf, ctx->rd.win_pf_nread,
                                     ctx->rd.win_pf_osz, ctx->rd.win_pf_errno)
        == NGX_ERROR)
    {
        brix_read_window_park_or_resume(ctx, c);
        return NGX_DONE;
    }
    if (!ctx->rd.win_active) {
        brix_read_window_final_sample(ctx);
    }
    return ctx->state == XRD_ST_SENDING ? NGX_DONE : NGX_AGAIN;
}

/*
 * Inline fallback (no pool configured, or post failed): do the blocking VFS
 * read on the event-loop thread for this one window only, then let the pump
 * loop pick up the next window.  Bounded to a single window so a large read
 * can never monopolise the loop for more than BRIX_READ_WINDOW.  Returns
 * NGX_DONE when the pump must return (emit error, parked), NGX_OK otherwise.
 */
static ngx_int_t
read_window_inline_step(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, u_char *datap, size_t want)
{
    brix_vfs_job_t job;

    brix_vfs_job_read_init(&job, ctx->rd.win_fd,
                              ctx->rd.win_offset, want, datap,
                              want, 0);
    /* Same handle binding as the posted task: verify CSI pages (plain read
     * only — pgread CRCs the fresh bytes itself) and route driver-backed
     * handles through their storage object. */
    if (ctx->rd.win_pgread) {
        job.op = BRIX_VFS_IO_PGREAD;
    } else {
        job.csi = ctx->files[ctx->rd.win_idx].csi;
    }
    brix_vfs_job_set_obj(&job, &ctx->files[ctx->rd.win_idx].sd_obj);
    brix_vfs_io_execute(&job);
    if (brix_read_window_emit_step(ctx, c, rconf, job.nio, job.out_size,
                                     job.io_errno) == NGX_ERROR)
    {
        brix_read_window_park_or_resume(ctx, c);
        return NGX_DONE;
    }
    return NGX_OK;
}

/*
 * brix_read_window_pump — read the next window into rd.read_scratch and emit it,
 * looping while sends complete synchronously.  Posts an AIO task when a thread
 * pool is available (returns with state XRD_ST_AIO; brix_read_aio_done resumes
 * the pump); otherwise reads the window inline (bounded to one window).  When
 * the windowed read finishes it resumes the event loop for the next request.
 */
void
brix_read_window_pump(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf)
{
    for ( ;; ) {
        size_t   want;
        size_t   scratch_need;
        u_char  *databuf;
        u_char  *datap;
        ssize_t  nread;

        if (!ctx->rd.win_active) {
            brix_aio_resume(c);
            return;
        }

        /* Round 12: a read-ahead window is already stashed (emit it) or
         * still on a worker (park until its completion drives the next
         * step — XRD_ST_AIO keeps recv suspended, truthfully: a counted
         * task is in flight). */
        if (ctx->rd.win_ready) {
            if (brix_read_window_pump_ready(ctx, c, rconf) == NGX_DONE) {
                return;
            }
            continue;
        }
        if (ctx->rd.win_prefetch) {
            ctx->state = XRD_ST_AIO;
            return;
        }

        read_window_sizes(ctx, &want, &scratch_need);

        databuf = BRIX_GET_SCRATCH(ctx, c, rd.read_scratch, rd.read_scratch_size,
                                     scratch_need);
        if (databuf == NULL) {
            ctx->rd.win_active = 0;
            ctx->state = XRD_ST_REQ_HEADER;
            brix_send_error(ctx, c, kXR_NoMemory, "read window alloc failed");
            brix_aio_resume(c);
            return;
        }
        brix_budget_sync(ctx);

        /* pgread: the encoded window lands after the 32-byte frame headroom
         * so emit can stamp the status header ahead of it in place. */
        datap = ctx->rd.win_pgread
                ? databuf + sizeof(ServerStatusResponse_pgRead) : databuf;

        /* Warm inline window (pgread only): a page-cache-resident window is
         * read + encoded + CRCed right here on the event loop, skipping the
         * thread-pool round-trip (pure handoff latency for this self-
         * serialized train).  A cold window falls through to the post. */
        if (ctx->rd.win_pgread) {
            size_t warm_osz;

            if (brix_pgread_window_try_warm(ctx, rconf, datap, want,
                                              &nread, &warm_osz))
            {
                if (brix_read_window_emit_step(ctx, c, rconf, nread,
                                                 warm_osz, 0) == NGX_ERROR)
                {
                    brix_read_window_park_or_resume(ctx, c);
                    return;
                }
                if (ctx->state == XRD_ST_SENDING) {
                    return;   /* send.c resumes the pump on drain */
                }
                continue;     /* sync send complete → next window */
            }
        }

        if (read_window_post_aio(ctx, c, rconf, datap, want,
                                   ctx->rd.win_offset)) {
            return;   /* async: done callback resumes the pump */
        }
        /* not posted (no pool / driver handle / queue full): read inline. */
        if (read_window_inline_step(ctx, c, rconf, datap, want) == NGX_DONE) {
            return;
        }
        if (ctx->state == XRD_ST_SENDING) {
            return;   /* async send: send.c resumes the pump on drain */
        }
        /* sync send complete → loop reads the next window */
    }
}
