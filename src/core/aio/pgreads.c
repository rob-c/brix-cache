#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "protocols/root/connection/disconnect.h"  /* run_deferred_teardown (WS3) */
#include "protocols/root/read/read.h"

/*
 * pgreads.c — thread-pool offload for the stream kXR_pgread opcode.
 *
 * WHAT: The pgread half of the AIO read family; reads.c keeps the windowed
 *       memory read and plain kXR_read. Output is the interleaved wire form
 *       [CRC32C(4)][page data(4096)] × N behind a ServerStatusResponse_pgRead
 *       header (invariant #1), which brix_build_chunked_chain cannot produce —
 *       hence a dedicated chain builder rather than the kXR_read path.
 *
 * WHY:  Split out of reads.c when that file crossed the 600-line cap (see
 *       coding-standards §1). The seam is the natural one: pgread is the only
 *       read path that owns a checksum stage and its own framing, and it shares
 *       no file-local state with the plain-read half.
 *
 * HOW:  Same two-half discipline as reads.c — a *_thread function runs on a
 *       pool worker and may touch nothing but the brix_pgread_aio_t task
 *       struct; *_done runs back on the event loop, re-validates the stream
 *       through brix_aio_restore_request, owns all protocol/state mutation,
 *       and ends in brix_aio_resume(). The P44-B hybrid io_uring path adds a
 *       third entry point, brix_pgread_aio_crc_thread, for the case where the
 *       ring already delivered the bytes and only the CRC pass is left.
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
 * brix_pgread_aio_crc_thread — encode-only pool worker for the P44-B hybrid
 * io_uring pgread.
 *
 * The ring already scattered the file bytes into t->scratch's gapped wire
 * layout and the reaper stored the delivered byte count in t->nread; all that
 * remains is the per-page CRC32c pass, which must run here on a pool thread —
 * never on the event thread (R-07).  The reaper rebinds the (per-request
 * re-bound) task to this fn and re-posts it; the pool's completion then fires
 * the unchanged brix_pgread_aio_done.  Error/EOF completions (nread <= 0)
 * skip this hop entirely — the reaper posts the done event directly.
 */
void
brix_pgread_aio_crc_thread(void *data, ngx_log_t *log)
{
    brix_pgread_aio_t *t = data;

    (void) log;

    t->out_size = brix_pgread_crc_encode_delivered(t->offset, t->rlen,
                                                     t->scratch,
                                                     (size_t) t->nread);
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

    /* phase-56 D-2: pgread files as a READ op on the latency histogram. */
    brix_aio_metric_done(t->start_ns, BRIX_METRIC_OP_READ);

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
