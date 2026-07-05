#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"

/*
 * reads.c — thread-pool offload for the stream kXR_read / kXR_pgread opcodes.
 *
 * WHAT: Three read paths share this file. (1) Windowed memory read
 *       (brix_read_window_pump / _emit) streams a large memory-backed
 *       (TLS / non-regular) read as fill->drain->fill chunks. (2) Plain
 *       kXR_read AIO (brix_read_aio_thread / _done) offloads a single
 *       file reads to a worker thread and returns one chained response.
 *       (3) pgread AIO (brix_pgread_aio_thread / _done) does the same but
 *       interleaves a per-page CRC32C into the wire output.
 *
 * WHY:  File I/O (and the pgread CRC32C loop) can block; running them on the
 *       nginx event-loop thread would stall every other connection on this
 *       worker. The thread pool absorbs the blocking syscall and CPU-bound
 *       checksum so the event loop stays responsive.
 *
 * HOW:  Each path splits into a *_thread half (runs on a worker thread, may
 *       only touch the task struct — never ctx/connection/pool) and a *_done
 *       half (runs back on the event loop, owns all protocol/state mutation
 *       and chain building). The two halves communicate only through the
 *       brix_{read,pgread}_aio_t task struct carried by ngx_thread_task_t.
 *       Every *_done first re-validates the connection via
 *       brix_aio_restore_stream/_request (the stream may have died while the
 *       task ran) and ends by calling brix_aio_resume() to re-arm events.
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
        u_char  *databuf;
        ssize_t  nread;

        if (!ctx->rd.win_active) {
            brix_aio_resume(c);
            return;
        }

        want = ctx->rd.win_remaining < (size_t) BRIX_READ_WINDOW
               ? ctx->rd.win_remaining : (size_t) BRIX_READ_WINDOW;

        databuf = BRIX_GET_SCRATCH(ctx, c, rd.read_scratch, rd.read_scratch_size,
                                     want);
        if (databuf == NULL) {
            ctx->rd.win_active = 0;
            ctx->state = XRD_ST_REQ_HEADER;
            brix_send_error(ctx, c, kXR_NoMemory, "read window alloc failed");
            brix_aio_resume(c);
            return;
        }
        brix_budget_sync(ctx);

        if (rconf->common.thread_pool != NULL) {
            ngx_thread_task_t *task = ctx->rd.read_aio_task;
            brix_read_aio_t *t;
            ngx_flag_t         posted = 0;

            /*
             * One task struct is allocated once per stream and cached on
             * ctx->rd.read_aio_task, then reused across every window of this read
             * (and across later reads) to avoid a pool allocation per window.
             * On reuse the task is dirty from its last trip through the pool:
             * task->next must be cleared (the pool threads it onto its run
             * queue) and event.complete reset to 0 (ngx_post_event set it when
             * the previous completion fired) or the next post would be ignored.
             */
            if (task == NULL) {
                task = ngx_thread_task_alloc(c->pool,
                                             sizeof(brix_read_aio_t));
                if (task != NULL) {
                    ctx->rd.read_aio_task = task;
                }
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }

            if (task != NULL) {
                t = task->ctx;
                t->c = c;
                t->ctx = ctx;
                t->conf = rconf;
                t->fd = ctx->rd.win_fd;
                t->handle_idx = ctx->rd.win_idx;
                t->offset = ctx->rd.win_offset;
                t->rlen = want;
                t->databuf = databuf;
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
                brix_task_bind(task, brix_read_aio_thread,
                                 brix_read_aio_done);
                (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool,
                    task, "brix: window task post failed, sync fallback",
                    &posted);
                if (posted) {
                    return;   /* async: done callback resumes the pump */
                }
                /* post failed (queue full): fall through to the inline read. */
            }
        }

        /*
         * Inline fallback (no pool configured, or post failed): do the blocking
         * VFS read on the event-loop thread for this one window only, then let
         * the for(;;) loop pick up the next window. Bounded to a single window
         * so a large read can never monopolise the loop for more than
         * BRIX_READ_WINDOW.
         */
        {
            brix_vfs_job_t job;

            brix_vfs_job_read_init(&job, ctx->rd.win_fd,
                                      ctx->rd.win_offset, want, databuf,
                                      want, 0);
            brix_vfs_io_execute(&job);
            nread = job.nio;
            if (brix_read_window_emit(ctx, c, nread, job.io_errno)
                == NGX_ERROR)
            {
                brix_aio_resume(c);
                return;
            }
        }
        if (ctx->state == XRD_ST_SENDING) {
            return;   /* async send: send.c resumes the pump on drain */
        }
        /* sync send complete → loop reads the next window */
    }
}

/*
 * brix_read_aio_thread — thread-pool worker for kXR_read.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.  Only the blocking VFS core
 * syscall belongs here; all protocol work happens in the done callback on the
 * main thread.
 *
 * t->nread: set to pread return value (< 0 on error, 0 on EOF, > 0 on success).
 * t->io_errno: saved errno on failure.
 */
void
brix_read_aio_thread(void *data, ngx_log_t *log)
{
    brix_read_aio_t *t = data;
    brix_vfs_job_t   job;

    /*
     * Worker threads execute the VFS-owned thread-safe core only; all protocol
     * state updates stay on the event-loop side in the completion callback.
     */
    brix_vfs_job_read_init(&job, t->fd, t->offset, t->rlen,
                             t->databuf, t->rlen, 0);
    job.csi = t->csi;                    /* phase-59 W2: verify in the worker */
    brix_vfs_job_set_obj(&job, &t->obj); /* Layer 3: route via driver if bound */
    brix_vfs_io_execute(&job);

    t->nread = job.nio;
    t->io_errno = job.io_errno;          /* CSI mismatch surfaces as EIO here */
}

/*
 * brix_read_aio_done — main-thread completion callback for kXR_read AIO.
 *
 * Called by nginx's event loop after the thread pool posts the result via
 * ngx_post_event.  Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check via restore_stream).
 *   2. On I/O error: send kXR_IOError, release databuf, resume event loop.
 *   3. On success: build a response chain (chunked if > 16 MiB), update per-
 *      handle and session byte counters, queue the chain.
 *   4. Call brix_aio_resume() to re-arm the appropriate event (write or read).
 *
 * NOTE: if the chain send blocks (XRD_ST_SENDING), databuf is kept alive as
 * wchain_base and freed by brix_release_pending_buffer after full drain.
 */
void
brix_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    brix_read_aio_t  *t = task->ctx;
    brix_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c = t->c;
    ngx_chain_t        *rsp_chain;

    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        return;
    }

    if (ctx->rd.win_active) {
        /*
         * Phase 31 W2.1: this completion belongs to one window of a windowed
         * read.  Emit its chunk, then continue (next window) or finish.
         */
        if (brix_read_window_emit(ctx, c, t->nread, t->io_errno)
            == NGX_ERROR)
        {
            brix_aio_resume(c);
            return;
        }
        /*
         * After emit, exactly one of three things is true and each takes a
         * different path (no fall-through — every branch returns):
         *   a) chunk is still draining (XRD_ST_SENDING): hand off; send.c will
         *      re-enter the pump once the socket has flushed this window.
         *   b) chunk sent synchronously and more windows remain
         *      (rd_win_active still set): drive the next window now.
         *   c) windowed read complete (rd_win_active cleared by emit): the read
         *      is done, so resume the normal request event loop.
         */
        if (ctx->state == XRD_ST_SENDING) {
            return;            /* (a) send.c resumes the pump when the chunk drains */
        }
        if (ctx->rd.win_active) {
            brix_read_window_pump(ctx, c, t->conf);   /* (b) sync-sent: next window */
            return;
        }
        brix_aio_resume(c);  /* (c) finished */
        return;
    }

    if (t->nread < 0) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
        brix_release_read_buffer(ctx, c, t->databuf);
        BRIX_OP_ERR(ctx, BRIX_OP_READ);
        brix_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        brix_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->totals.bytes += (size_t) t->nread;
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    rsp_chain = brix_build_chunked_chain(ctx, c,
                                           t->databuf, (size_t) t->nread);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, t->databuf);
        ctx->state = XRD_ST_REQ_HEADER;
        brix_aio_resume(c);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;

    brix_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, t->databuf);
    } else {
        /*
         * Parked and draining: the buffer is a per-in-flight rd_pool slot and the
         * header is per-slot, so this memory-backed read is SAFE to pipeline.  Note
         * the cold-AIO path does not yet ACTUALLY pipeline: recv already suspended
         * on this read's AIO and brix_aio_resume() only drains the write side, so
         * the next read is not issued until this response drains.  Setting the flag
         * is correct and forward-compatible with the non-suspending read-AIO change
         * that will let cold reads pipeline like the warm-cache inline path does.
         * Single-chunk only (non-windowed read <= BRIX_READ_WINDOW < CHUNK_MAX).
         */
        ctx->out.resp_pipelinable = 1;
    }
    brix_aio_resume(c);
}


/*
 * This section implements the thread-pool offload for pgread, where each
 * 4096-byte page is read and a CRC32C checksum is computed on it.
 * The output format is: [CRC32C(4 bytes)][page data (4096 bytes)] × N_pages
 *
 * Two functions: the _thread function does the pread + CRC encoding on the
 * worker thread; the _done callback builds the response chain on the main
 * event loop.
 */


/*
 * brix_pgread_aio_thread — thread-pool worker for kXR_pgread.
 *
 * Reads file data DIRECTLY into the final interleaved [CRC32C(4)][data] wire
 * buffer (t->scratch, starting at offset 0) and computes each page CRC32C in
 * place — no separate flat-data copy pass. This runs on the worker thread so
 * both the (batched preadv) I/O and the CRC stay off the nginx event loop.
 * t->out_size is the encoded byte count; t->nread the file bytes read (<0 = I/O
 * error, t->io_errno set). See brix_pgread_read_encode_inplace().
 */
void
brix_pgread_aio_thread(void *data, ngx_log_t *log)
{
    brix_pgread_aio_t *t = data;
    brix_vfs_job_t     job;

    brix_vfs_job_read_init(&job, t->fd, t->offset, t->rlen,
                             t->scratch, t->rlen, 0);
    job.op = BRIX_VFS_IO_PGREAD;
    brix_vfs_job_set_obj(&job, &t->obj); /* Layer 3: route via driver if bound */
    brix_vfs_io_execute(&job);

    t->out_size = job.out_size;
    t->nread = job.nio;
    t->io_errno = job.io_errno;
}

/*
 * brix_pgread_aio_done — response builder for pgread AIO completion.
 *
 * pgread wire format ([CRC32C(4)][page data] × N) cannot use
 * brix_build_chunked_chain and requires direct chain construction with a
 * ServerStatusResponse_pgRead header.
 */
void
brix_pgread_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t          *task = ev->data;
    brix_pgread_aio_t        *t = task->ctx;
    brix_ctx_t               *ctx = t->ctx;
    ngx_connection_t           *c = t->c;
    ServerStatusResponse_pgRead *hdr_buf;
    ngx_chain_t                *rsp_chain;
    ngx_stream_brix_srv_conf_t *rconf;

    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->nread < 0) {
        brix_release_read_buffer(ctx, c, t->scratch);
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        brix_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async pgread error");
        brix_aio_resume(c);
        return;
    }

    /*
     * EOF / empty read: emit a pgRead status header with dlen 0 and no data
     * buffer at all. The client reads the header, sees zero payload bytes, and
     * treats it as end-of-data — there are no pages, hence no CRC32C words.
     */
    if (t->nread == 0 || t->out_size == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf) {
            brix_build_pgread_status(ctx, t->offset, 0, hdr_buf);
            BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
            brix_queue_response(ctx, c, (u_char *) hdr_buf, sizeof(*hdr_buf));
        }
        brix_release_read_buffer(ctx, c, t->scratch);
        brix_aio_resume(c);
        return;
    }

    /* PGREAD: the encoded page data (in t->scratch from offset 0) carries its
     * own per-page CRC32c and must be sent verbatim behind the pgRead status
     * header — never through brix_build_chunked_chain (wrong kXR_ok framing).
     * Shared with the synchronous handler via brix_build_pgread_chain. */
    rsp_chain = brix_build_pgread_chain(ctx, c, t->offset, t->scratch,
                                          (uint32_t) t->out_size);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, t->scratch);
        brix_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->totals.bytes += (size_t) t->nread;

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) t->offset, (size_t) t->nread);
        brix_log_access(ctx, c, "PGREAD", ctx->files[t->handle_idx].path,
                          detail, 1, 0, NULL, (size_t) t->nread);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);

    brix_queue_response_chain(ctx, c, rsp_chain, t->scratch);
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, t->scratch);
    }
    brix_aio_resume(c);
}
