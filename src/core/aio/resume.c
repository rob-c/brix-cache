#include "core/ngx_brix_module.h"
#include "uring.h"


/*
 * Re-enter the XRootD event flow after a thread-pool completion.
 *
 * All three helpers are called from AIO done callbacks running on the nginx
 * main thread (posted via ngx_post_event).  They check ctx->destroyed first
 * so that a callback that fires after the client has disconnected can abort
 * without touching freed memory.
 */

/*
 * brix_aio_restore_stream — restore the stream-id context field so the
 * subsequent response builder uses the correct stream-id from the request that
 * triggered the AIO.
 *
 * Returns 1 if the connection is still alive, 0 if it has been destroyed.
 */
ngx_flag_t
brix_aio_restore_stream(brix_ctx_t *ctx, const u_char streamid[2])
{
    if (ctx->destroyed) {
        return 0;
    }

    ctx->recv.cur_streamid[0] = streamid[0];
    ctx->recv.cur_streamid[1] = streamid[1];

    return 1;
}

/*
 * brix_aio_restore_request — like brix_aio_restore_stream, but also
 * resets the connection state back to XRD_ST_REQ_HEADER so the recv loop
 * can accept the next request.
 *
 * Call this from done callbacks that complete the request cycle (i.e. the
 * response has already been queued before calling brix_aio_resume).
 */
ngx_flag_t
brix_aio_restore_request(brix_ctx_t *ctx, const u_char streamid[2])
{
    if (!brix_aio_restore_stream(ctx, streamid)) {
        return 0;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;

    return 1;
}

/*
 * brix_aio_post_task — post a pre-built ngx_thread_task_t to the thread
 * pool and transition ctx->state to XRD_ST_AIO.
 *
 * If pool is NULL (thread pool not configured), returns NGX_OK without posting
 * and leaves *posted = 0 so the caller falls back to synchronous I/O.
 *
 * If ngx_thread_task_post() fails (pool queue full), logs a warning at
 * NGX_LOG_WARN and returns NGX_OK with *posted = 0 — again the caller falls
 * back to synchronous I/O rather than failing the request.
 *
 * On success: *posted = 1, ctx->state = XRD_ST_AIO.
 */
ngx_int_t
brix_aio_post_task(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted)
{
    *posted = 0;

    /*
     * Phase 44 tier 1: io_uring.  Compiled out entirely in a stub build (no
     * liburing), so this is exactly the historical thread-pool path there.  The
     * ring is selected only when it is up for this worker, not killed at
     * runtime, the op is mapped, and the ring is not full; any prep/submit
     * failure leaves *posted = 0 and falls through to the thread pool below.
     */
#if (BRIX_HAVE_LIBURING)
    {
        brix_uring_t   *u  = brix_uring_worker();
        brix_uring_op_e op = brix_uring_op_for(task);

        if (u != NULL && u->enabled && op != XRD_URING_OP_NONE) {
            if (!brix_uring_disabled(u) && u->inflight < u->queue_depth
                && brix_uring_submit(ctx, c, task, op, posted) == NGX_OK
                && *posted)
            {
                /* metrics: a mapped op that the ring accepted. */
                BRIX_SRV_METRIC_INC(ctx, io_uring_ops_total);
                if (ctx->metrics != NULL && ctx->metrics->io_uring_active == 0) {
                    ctx->metrics->io_uring_active = 1;
                }
                ctx->state = XRD_ST_AIO;
                return NGX_OK;
            }
            /* metrics: a mapped op the ring could not take (killed / full /
             * submit failed) — it falls through to the pool below. */
            BRIX_SRV_METRIC_INC(ctx, io_uring_fallback_total);
        }
    }
#endif

    /* Tier 2: thread pool (always built; the fallback for an unmapped op, a
     * full ring, or a stub build). */
    if (pool == NULL) {
        return NGX_OK;             /* tier 3: caller does inline sync I/O */
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", fallback_log);
        return NGX_OK;
    }

    ctx->state = XRD_ST_AIO;
    *posted = 1;

    return NGX_OK;
}

/*
 * brix_aio_resume — schedule the next event-loop step after an AIO task
 * completes and its done callback has already queued the response.
 *
 * If the response put the connection into XRD_ST_SENDING (it could not be
 * sent immediately), arm the write event.  Otherwise arm the read event so
 * pipelined requests buffered in the kernel are processed without waiting for
 * a new epoll notification.
 *
 * Guards against ctx->destroyed (client disconnected while AIO was in flight).
 */
void
brix_aio_resume(ngx_connection_t *c)
{
    ngx_stream_session_t *s;
    brix_ctx_t         *ctx;

    /*
     * AIO completion runs outside the normal recv path. If the completion
     * queued a response that still has bytes pending, resume the write side
     * first. Once there is no pending response, post the read side so already
     * arrived pipelined requests run before the next epoll_wait.
     */

    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_brix_module);
    if (ctx == NULL || ctx->destroyed) {
        return;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: aio_resume state=%d ravail=%d rready=%d "
                   "wready=%d wposted=%d",
                   (int) ctx->state, c->read->available,
                   (int) c->read->ready, (int) c->write->ready,
                   (int) c->write->posted);

    if (ctx->state == XRD_ST_SENDING) {
        if (brix_schedule_write_resume(c) != NGX_OK) {
            ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    if (brix_schedule_read_resume(c) != NGX_OK) {
        ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}

