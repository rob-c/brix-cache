#include "ngx_xrootd_module.h"

#if (NGX_THREADS)

/*
 * xrootd_read_aio_thread — thread-pool worker for kXR_read.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.  Only the blocking pread(2)
 * syscall belongs here; all protocol work happens in the done callback on the
 * main thread.
 *
 * t->nread: set to pread return value (< 0 on error, 0 on EOF, > 0 on success).
 * t->io_errno: saved errno on failure.
 */
void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;

    /*
     * Worker threads do the blocking syscall only; all protocol state updates
     * stay on the event-loop side in the completion callback.
     */
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}


/*
 * xrootd_read_aio_done — main-thread completion callback for kXR_read AIO.
 *
 * Called by nginx's event loop after the thread pool posts the result via
 * ngx_post_event.  Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check via restore_stream).
 *   2. On I/O error: send kXR_IOError, release databuf, resume event loop.
 *   3. On success: build a response chain (chunked if > 16 MiB), update per-
 *      handle and session byte counters, queue the chain.
 *   4. Call xrootd_aio_resume() to re-arm the appropriate event (write or read).
 *
 * NOTE: if the chain send blocks (XRD_ST_SENDING), databuf is kept alive as
 * wchain_base and freed by xrootd_release_pending_buffer after full drain.
 */
void
xrootd_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_read_aio_t  *t = task->ctx;
    xrootd_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c = t->c;
    ngx_chain_t        *rsp_chain;

    if (!xrootd_aio_restore_stream(ctx, t->streamid)) {
        return;
    }

    if (t->nread < 0) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->hdr_pos = 0;
        xrootd_release_read_buffer(ctx, c, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes += (size_t) t->nread;
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->databuf, (size_t) t->nread);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_aio_resume(c);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
    }
    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */
