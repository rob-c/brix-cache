#include "ngx_xrootd_module.h"


/*
 * Re-enter the XRootD event flow after a thread-pool completion.
 *
 * All three helpers are called from AIO done callbacks running on the nginx
 * main thread (posted via ngx_post_event).  They check ctx->destroyed first
 * so that a callback that fires after the client has disconnected can abort
 * without touching freed memory.
 */

/*
 * xrootd_aio_restore_stream — restore the stream-id context field so the
 * subsequent response builder uses the correct stream-id from the request that
 * triggered the AIO.
 *
 * Returns 1 if the connection is still alive, 0 if it has been destroyed.
 */
ngx_flag_t
xrootd_aio_restore_stream(xrootd_ctx_t *ctx, const u_char streamid[2])
{
    if (ctx->destroyed) {
        return 0;
    }

    ctx->cur_streamid[0] = streamid[0];
    ctx->cur_streamid[1] = streamid[1];

    return 1;
}

/*
 * xrootd_aio_restore_request — like xrootd_aio_restore_stream, but also
 * resets the connection state back to XRD_ST_REQ_HEADER so the recv loop
 * can accept the next request.
 *
 * Call this from done callbacks that complete the request cycle (i.e. the
 * response has already been queued before calling xrootd_aio_resume).
 */
ngx_flag_t
xrootd_aio_restore_request(xrootd_ctx_t *ctx, const u_char streamid[2])
{
    if (!xrootd_aio_restore_stream(ctx, streamid)) {
        return 0;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    return 1;
}

/*
 * xrootd_aio_post_task — post a pre-built ngx_thread_task_t to the thread
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
xrootd_aio_post_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted)
{
    *posted = 0;

    if (pool == NULL) {
        return NGX_OK;
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
 * xrootd_aio_resume — schedule the next event-loop step after an AIO task
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
xrootd_aio_resume(ngx_connection_t *c)
{
    ngx_stream_session_t *s;
    xrootd_ctx_t         *ctx;

    /*
     * AIO completion runs outside the normal recv path. If the completion
     * queued a response that still has bytes pending, resume the write side
     * first. Once there is no pending response, post the read side so already
     * arrived pipelined requests run before the next epoll_wait.
     */

    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    if (ctx == NULL || ctx->destroyed) {
        return;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: aio_resume state=%d ravail=%d rready=%d "
                   "wready=%d wposted=%d",
                   (int) ctx->state, c->read->available,
                   (int) c->read->ready, (int) c->write->ready,
                   (int) c->write->posted);

    if (ctx->state == XRD_ST_SENDING) {
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    if (xrootd_schedule_read_resume(c) != NGX_OK) {
        ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}

