#include "ngx_xrootd_module.h"

/*
 * Section: kXR_pgread async I/O — page-granular read with CRC32C checksum.
 *
 * This file implements the thread-pool offload for pgread, where each 4096-byte
 * page is read and a CRC32C checksum is computed on it. The output format is:
 *   [CRC32C(4 bytes)][page data (4096 bytes)] × N_pages
 *
 * Two functions: the _thread function does the pread + CRC encoding on the worker
 * thread; the _done callback builds the response chain on the main event loop.
 */


/*
 * xrootd_pgread_aio_thread — thread-pool worker for kXR_pgread.
 *
 * The scratch buffer is split into two halves:
 *   scratch[0 .. rlen-1]         — flat data read by pread(2) (Phase 1)
 *   scratch[rlen .. rlen+out_size-1] — CRC-interleaved wire output (Phase 2)
 *
 * Phase 1: pread() fills the flat portion.
 * Phase 2: xrootd_pgread_encode_pages() reads each 4096-byte page, computes
 *   CRC32C, and writes [CRC32C(4)][data(page)] into the output region.
 *
 * Both phases run on the worker thread so CRC computation does not block the
 * nginx event loop.  t->out_size is set to the encoded byte count.
 */
void
xrootd_pgread_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_pgread_aio_t *t = data;
    u_char              *out;

    /*
     * Phase 1: pread into the flat portion of scratch (scratch[0..rlen-1]).
     * Phase 2: interleave data + CRC32C into scratch[rlen..], page by page.
     * Both phases run on the worker thread to keep CRC off the event loop.
     */

    t->nread = pread(t->fd, t->scratch, t->rlen, t->offset);
    if (t->nread <= 0) {
        t->io_errno = (t->nread < 0) ? errno : 0;
        t->out_size = 0;
        return;
    }

    out = t->scratch + t->rlen;
    t->out_size = xrootd_pgread_encode_pages(t->scratch, (size_t) t->nread,
                                             out);
}

/*
 * xrootd_pgread_aio_done — main-thread response builder for pgread AIO completion.
 *
 * WHAT: Reconstructs the XRootD response chain after the worker thread finishes
 * pread() + CRC32C encoding of each 4096-byte page. The response consists of a
 * single ServerStatusResponse_pgRead header followed by the encoded data (t->scratch+rlen).
 * Unlike standard reads, pgread does NOT use xrootd_build_chunked_chain — its own
 * per-page CRC format requires direct chain construction.
 *
 * WHY: pgread responses have a unique wire format [CRC32C(4 bytes)][page data] × N that
 * cannot be handled by generic chunked-chain builders. This callback must build the
 * correct header type and payload layout on the main thread after AIO completion. It also
 * handles four error paths: connection teardown, I/O failure, empty read, and allocation
 * failure — each releasing buffers appropriately before resuming flow.
 *
 * HOW: 1) Restore request context via xrootd_aio_restore_request(). 2) Branch on nread:
 *     negative → kXR_IOError + release; zero/empty → status-only response.
 *   3) On success: allocates pgReadStatus header, builds two-link chain (hdr→data),
 *      updates ctx->files.bytes_read and session_bytes counters, logs access event,
 *      queues via xrootd_queue_response_chain(). Releases scratch if not already queued.
 */
void
xrootd_pgread_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t          *task = ev->data;
    xrootd_pgread_aio_t        *t = task->ctx;
    xrootd_ctx_t               *ctx = t->ctx;
    ngx_connection_t           *c = t->c;
    ServerStatusResponse_pgRead *hdr_buf;
    ngx_chain_t                *cl_hdr, *rsp_chain;
    ngx_stream_xrootd_srv_conf_t *rconf;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->nread < 0) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async pgread error");
        xrootd_aio_resume(c);
        return;
    }

    if (t->nread == 0 || t->out_size == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf) {
            xrootd_build_pgread_status(ctx, t->offset, 0, hdr_buf);
            XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);
            xrootd_queue_response(ctx, c, (u_char *) hdr_buf, sizeof(*hdr_buf));
        }
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }

    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    xrootd_build_pgread_status(ctx, t->offset, (uint32_t) t->out_size, hdr_buf);

    cl_hdr = ngx_alloc_chain_link(c->pool);
    if (cl_hdr == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    cl_hdr->buf = ngx_calloc_buf(c->pool);
    if (cl_hdr->buf == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    cl_hdr->buf->pos = (u_char *) hdr_buf;
    cl_hdr->buf->last = cl_hdr->buf->pos + sizeof(*hdr_buf);
    cl_hdr->buf->memory = 1;
    cl_hdr->buf->last_buf = 0;

    {
        ngx_chain_t *cl_data;
        ngx_buf_t   *bd;

        /* PGREAD: Send encoded page data directly, NOT via xrootd_build_chunked_chain
         * which adds wrong headers (kXR_ok) for pgread. The encoded data
         * (t->scratch + t->rlen) has its own per-page CRC32c - just send it.
         */
        cl_data = ngx_alloc_chain_link(c->pool);
        bd = ngx_calloc_buf(c->pool);
        if (cl_data == NULL || bd == NULL) {
            xrootd_release_read_buffer(ctx, c, t->scratch);
            xrootd_aio_resume(c);
            return;
        }
        bd->pos = t->scratch + t->rlen;
        bd->last = bd->pos + t->out_size;
        bd->memory = 1;
        bd->last_buf = 1;
        cl_data->buf = bd;
        cl_data->next = NULL;

        cl_hdr->next = cl_data;
        rsp_chain = cl_hdr;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes += (size_t) t->nread;

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) t->offset, (size_t) t->nread);
        xrootd_log_access(ctx, c, "PGREAD", ctx->files[t->handle_idx].path,
                          detail, 1, 0, NULL, (size_t) t->nread);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->scratch);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
    }
    xrootd_aio_resume(c);
}

