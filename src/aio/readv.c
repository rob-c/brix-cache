#include "ngx_xrootd_module.h"

#if (NGX_THREADS)

/*
 * xrootd_readv_aio_thread — thread-pool worker for kXR_readv.
 *
 * The main nginx thread has already allocated the response buffer and computed
 * the segment layout (header + payload pointers per segment).  This worker
 * only calls pread() to fill each segment's payload region and records totals.
 *
 * The response layout is:
 *   For each segment i:
 *     [xrootd_readv_seg_header (XROOTD_READV_SEGSIZE bytes)]
 *     [up to read_length bytes of file data at payload_ptr]
 *
 * t->response_bytes = n_segments * XROOTD_READV_SEGSIZE + bytes_read_total.
 * Segments that pread to fewer bytes than requested are zero-padded by the
 * thread (the per-segment header's rlen is updated to reflect the actual bytes
 * read by xrootd_readv_read_segments).
 */
void
xrootd_readv_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_readv_aio_t *t = data;

    t->bytes_read_total = 0;
    t->io_error = 0;
    t->response_bytes = 0;
    t->err_msg[0] = '\0';

    /*
     * The main nginx thread already built the response layout.  The worker
     * only fills payload pointers and records totals; it must not touch the
     * connection or request parser state.
     */
    if (xrootd_readv_read_segments(t->segments, t->segment_count,
                                   &t->bytes_read_total,
                                   t->err_msg, sizeof(t->err_msg)) != NGX_OK)
    {
        t->io_error = 1;
        if (t->err_msg[0] == '\0') {
            snprintf(t->err_msg, sizeof(t->err_msg), "readv I/O error");
        }
        return;
    }

    t->response_bytes = t->segment_count * XROOTD_READV_SEGSIZE
                        + t->bytes_read_total;
}


void
xrootd_readv_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_readv_aio_t  *t = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c = t->c;
    ngx_chain_t         *rsp_chain;
    size_t               i;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        return;
    }

    if (t->io_error) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_READV);
    ctx->session_bytes += t->bytes_read_total;
    for (i = 0; i < t->segment_count; i++) {
        ctx->files[t->segments[i].handle_index].bytes_read +=
            t->segments[i].read_length;
    }

    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->response_buffer,
                                           t->response_bytes);
    if (rsp_chain == NULL) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        xrootd_aio_resume(c);
        return;
    }

    ngx_free(t->segments);
    xrootd_queue_response_chain(ctx, c, rsp_chain, t->response_buffer);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
    }
    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */
