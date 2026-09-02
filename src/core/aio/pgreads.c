#include "core/ngx_brix_module.h"
#include "pgreads_internal.h"                    /* pool-send engine seam */
#include "protocols/root/connection/budget.h"
#include "protocols/root/connection/disconnect.h"  /* run_deferred_teardown (WS3) */
#include "protocols/root/read/read.h"
#include <poll.h>   /* §1.2 pool-send: POLLOUT wait between short send()s */

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
 *       through brix_aio_restore_stream, owns all protocol/state mutation,
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

    if (t->sec_c != NULL && t->pool_send && brix_pgread_pool_stream(t)) {
        return;   /* §1.3: streamed (or error-shaped) entirely in-thread */
    }

    brix_vfs_job_read_init(&job, t->fd, t->offset, t->rlen,
                             t->scratch, t->rlen, 0);
    job.op = BRIX_VFS_IO_PGREAD;
    brix_vfs_job_set_obj(&job, &t->obj); /* Layer 3: route via driver if bound */
    brix_vfs_io_execute(&job);

    t->out_size = job.out_size;
    t->nread = job.nio;
    t->io_errno = job.io_errno;

    if (t->sec_c != NULL && t->pool_send) {
        brix_pgread_pool_send(t);   /* §1.2: this thread sends the frame */
    }
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

    if (t->sec_c != NULL && t->pool_send) {
        brix_pgread_pool_send(t);   /* §1.2: this thread sends the frame */
    }
}

/* Success-path accounting shared by the primary and offload epilogues:
 * per-handle/session byte counters, the optional access-log line, and the
 * op success metric. */
static void
brix_pgread_done_account(brix_pgread_aio_t *t)
{
    brix_ctx_t                 *ctx = t->ctx;
    ngx_stream_brix_srv_conf_t *rconf;

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->totals.bytes += (size_t) t->nread;

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) t->c->data, ngx_stream_brix_module);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) t->offset, (size_t) t->nread);
        brix_log_access(ctx, t->c, "PGREAD",
                          ctx->files[t->handle_idx].path,
                          detail, 1, 0, NULL, (size_t) t->nread);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
}

/* EOF / empty pgread on the primary stream: emit a pgRead status header with
 * dlen 0 and no data buffer at all.  The client reads the header, sees zero
 * payload bytes, and treats it as end-of-data — no pages, no CRC32C words. */
static void
brix_pgread_done_eof(brix_pgread_aio_t *t)
{
    brix_ctx_t                  *ctx = t->ctx;
    ngx_connection_t              *c = t->c;
    ServerStatusResponse_pgRead *hdr_buf;

    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf) {
        brix_build_pgread_status(ctx, t->offset, 0, hdr_buf);
        BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
        /* Self-contained per-response palloc — safe to pipeline behind. */
        ctx->out.resp_pipelinable = 1;
        brix_queue_response(ctx, c, (u_char *) hdr_buf, sizeof(*hdr_buf));
    }
    brix_release_read_buffer(ctx, c, t->scratch);
    brix_aio_resume(c);
}

/* §1.2 pool-send wire disposition — MUST run before every early return in
 * the offload epilogue: the worker thread may have put bytes (or a held send
 * token) on the SECONDARY, and both belong to it regardless of the primary's
 * fate.  Returns 1 when the worker owned the wire (bytes sent, tail parked,
 * or the buffer already retired on a send error). */
static ngx_flag_t
brix_pgread_pool_disposition(brix_pgread_aio_t *t, u_char *fbuf)
{
    brix_ctx_t       *sec_ctx = t->sec_ctx;
    ngx_connection_t *sec_c   = t->sec_c;

    if (!t->pool_send
        || !(t->pool_sent_all || t->pool_token_held || t->pool_send_errno
             || t->chunk_error))
    {
        return 0;
    }

    if (t->pool_sent > 0) {
        sec_c->sent += (off_t) t->pool_sent;
        BRIX_SRV_METRIC_ADD(sec_ctx, wire_bytes_tx_total, t->pool_sent);
    }

    if (t->pool_sent_all) {
        BRIX_SRV_METRIC_ADD(sec_ctx, response_frames_total, t->pool_frames);
        brix_release_read_buffer(sec_ctx, sec_c, fbuf);
        if (sec_ctx->out.count > 0 && !sec_ctx->destroyed) {
            /* frames parked while the worker held the token */
            (void) brix_ensure_write_event(sec_c);
        }

    } else if (t->pool_token_held) {
        if (sec_ctx->destroyed) {
            brix_release_read_buffer(sec_ctx, sec_c, fbuf);
        } else {
            BRIX_SRV_METRIC_ADD(sec_ctx, response_frames_total,
                                  t->pool_frames);
            (void) brix_park_front_buf(sec_ctx, sec_c,
                      fbuf + t->pool_sent,
                      t->pool_image_len - t->pool_sent,
                      fbuf);
        }
        sec_ctx->out.send_token = 0;   /* park first, release second */

    } else {
        /* hard send error mid-image, or a chunk_error whose committed
         * frames were all sent: either way the buffer is done */
        brix_release_read_buffer(sec_ctx, sec_c, fbuf);
    }

    return 1;
}

/* Fire one side's deferred teardown if this completion was its last pending
 * work (per-side mirror of the brix_pgread_aio_done tail).  `counted` is the
 * caller's ownership guard — pass 0 to skip the side entirely. */
static void
brix_pgread_offload_reap(ngx_flag_t counted, brix_ctx_t *x,
    ngx_connection_t *xc)
{
    if (counted && x->out.finalize_pending
        && x->out.wr_inflight == 0 && x->rd.aio_inflight == 0)
    {
        brix_run_deferred_teardown(x, xc);
    }
}

/* §1.2/§1.3 failure epilogue for the offload done handler.  Returns 1 when
 * it consumed the completion (error frame queued, recv loop resumed). */
static ngx_flag_t
brix_pgread_offload_error_done(brix_pgread_aio_t *t, u_char *fbuf)
{
    brix_ctx_t *ctx = t->ctx;

    if (t->nread < 0) {
        brix_release_read_buffer(t->sec_ctx, t->sec_c, fbuf);
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        brix_send_error(ctx, t->c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno)
                                      : "async pgread error");
        brix_aio_resume(t->c);
        return 1;
    }

    if (t->pool_send_errno != 0 && !t->pool_sent_all) {
        /* §1.2: the read succeeded but the worker's send on the data channel
         * failed hard (buffer already released in the disposition block) —
         * best effort: error the request on the control stream. */
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        brix_send_error(ctx, t->c, kXR_IOError,
                          "pgread data channel send error");
        brix_aio_resume(t->c);
        return 1;
    }

    if (t->chunk_error) {
        /* §1.3: a chunk read failed AFTER partial frames were committed on
         * the SECONDARY — the terminating kXR_error must ride the same
         * channel under the request sid (any parked tail drains first: the
         * ring keeps wire order, and queue_response parks behind it). */
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        (void) brix_send_error_sid(t->sec_ctx, t->sec_c, t->streamid,
                  kXR_IOError,
                  t->io_errno ? strerror(t->io_errno) : "async pgread error");
        brix_aio_resume(t->c);
        return 1;
    }

    return 0;
}

/*
 * brix_pgread_aio_done_offload — completion epilogue for a pgread whose reply
 * rides a bound SECONDARY channel (t->sec_c != NULL, §1.1 offload-AIO).
 *
 * WHAT: Drops both connections' aio_inflight counts, then routes by liveness:
 *       both alive — stamp the pgRead status header at the head of the
 *       secondary's slot buffer and queue the contiguous [status|pages] frame
 *       on the SECONDARY's out-ring (release decided by the out.count delta,
 *       exactly as in brix_pgread_aio_done); primary dead — return the slot
 *       and fire the primary's deferred teardown if this was its last task;
 *       secondary dead — answer with kXR_error on the PRIMARY control stream
 *       (correlation is by streamid, so this is protocol-legal), return the
 *       slot, and fire the secondary's deferred teardown if last.
 *
 * WHY: The buffer belongs to the secondary and the request/recv state to the
 *      primary; each teardown was deferred on its own rd.aio_inflight, so
 *      both sides' memory is guaranteed live here and each release/teardown
 *      must land on its owner.
 */
static void
brix_pgread_aio_done_offload(brix_pgread_aio_t *t)
{
    brix_ctx_t                 *ctx = t->ctx;      /* primary: request owner */
    ngx_connection_t             *c = t->c;
    brix_ctx_t             *sec_ctx = t->sec_ctx;  /* secondary: buffer owner */
    ngx_connection_t         *sec_c = t->sec_c;
    u_char                    *fbuf;
    ngx_uint_t                  out_before;
    ngx_flag_t                  primary_alive;
    ngx_flag_t                  pool_handled;

    fbuf = t->scratch - sizeof(ServerStatusResponse_pgRead);

    if (t->sec_counted && sec_ctx->rd.aio_inflight > 0) {
        sec_ctx->rd.aio_inflight--;
    }

    pool_handled = brix_pgread_pool_disposition(t, fbuf);

    primary_alive = brix_aio_restore_stream(ctx, t->streamid);

    if (!primary_alive) {
        if (!pool_handled) {
            brix_release_read_buffer(sec_ctx, sec_c, fbuf);
        }
        /* both sides died with this task in flight: the secondary's deferred
         * teardown must fire too, or its session leaks */
        brix_pgread_offload_reap(t->sec_counted && sec_ctx->destroyed,
                                   sec_ctx, sec_c);
        brix_pgread_offload_reap(t->counted, ctx, c);  /* frees primary ctx */
        return;
    }

    if (ctx->state == XRD_ST_AIO) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
    }

    if (sec_ctx->destroyed) {
        /* Data channel lost mid-read: unless the worker already put the whole
         * frame on the wire (§1.2), the reply cannot ride it and its slot
         * buffer dies with it — error the request on the control stream. */
        if (!pool_handled) {
            brix_release_read_buffer(sec_ctx, sec_c, fbuf);
        }
        brix_pgread_offload_reap(t->sec_counted, sec_ctx, sec_c);
        if (!t->pool_sent_all) {
            BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
            brix_send_error(ctx, c, kXR_IOError, "pgread data channel lost");
            brix_aio_resume(c);
            return;
        }
        /* the frame reached the socket before the channel died — success */
    }

    brix_aio_metric_done(t->start_ns, BRIX_METRIC_OP_READ);

    if (brix_pgread_offload_error_done(t, fbuf)) {
        return;
    }

    /* EOF/short reads need no special casing: a zero out_size queues the bare
     * 32-byte status frame (dlen 0), which the client reads as end-of-data. */
    brix_pgread_done_account(t);

    if (pool_handled) {
        /* §1.2: the worker thread already sent (or parked) the frame — only
         * the observability tick and the recv-loop resume remain. */
        brix_metric_offload(BRIX_PROTO_ROOT);
        brix_aio_resume(c);
        return;
    }

    brix_build_pgread_status(ctx, t->offset, (uint32_t) t->out_size,
                               (ServerStatusResponse_pgRead *) fbuf);
    sec_ctx->out.resp_pipelinable = 1;   /* self-contained frame in its own slot */

    out_before = sec_ctx->out.count;
    (void) brix_queue_response_base(sec_ctx, sec_c, fbuf,
                                      sizeof(ServerStatusResponse_pgRead)
                                          + t->out_size, fbuf);
    if (sec_ctx->out.count == out_before) {
        brix_release_read_buffer(sec_ctx, sec_c, fbuf);
    }
    brix_metric_offload(BRIX_PROTO_ROOT);   /* §1.1 observability */
    brix_aio_resume(c);
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
    ngx_chain_t                *rsp_chain;
    ngx_uint_t                  out_before;

    /* §1.1 offload-AIO: a secondary-targeted reply has its own epilogue —
     * it must drop BOTH connections' aio counts and land each release and
     * deferred teardown on its owner. The primary decrement below still
     * applies to it, so branch before touching any counter. */
    if (t->sec_c != NULL) {
        if (t->counted && ctx->rd.aio_inflight > 0) {
            ctx->rd.aio_inflight--;
        }
        brix_pgread_aio_done_offload(t);
        return;
    }

    /*
     * Pipelined-pgread parity with brix_read_aio_done: this counted task is no
     * longer in flight.  Decrement BEFORE the liveness guard so a deferred
     * teardown (the client vanished while pipelined pgreads were running)
     * fires on the LAST completion — once no worker thread references any
     * rd_pool buffer.
     */
    if (t->counted && ctx->rd.aio_inflight > 0) {
        ctx->rd.aio_inflight--;
    }

    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        /* frees ctx when this was its last pending task — return now */
        brix_pgread_offload_reap(t->counted, ctx, c);
        return;
    }

    /*
     * Re-arm the request state only when recv is actually suspended on this
     * completion (XRD_ST_AIO).  Under pipelining the recv loop kept receiving
     * after the post — it may be mid-header or mid-payload of the NEXT
     * request, or parked in XRD_ST_SENDING behind an earlier response — and
     * blindly resetting state/hdr_pos would corrupt that receive.
     */
    if (ctx->state == XRD_ST_AIO) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
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

    if (t->nread == 0 || t->out_size == 0) {
        brix_pgread_done_eof(t);
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

    brix_pgread_done_account(t);

    /* Self-contained frame (per-response palloc'd header, data in this
     * request's own rd_pool slot): if it parks, the next pgread may safely
     * queue behind it while it drains (brix_recv_try_pipeline_read). */
    ctx->out.resp_pipelinable = 1;

    /*
     * Release ownership is decided by whether the out-ring took the chain
     * (out.count delta), NEVER by ctx->state: the recv loop parks itself in
     * XRD_ST_SENDING at the admission bound even with out.count == 0 (all
     * depth slots held by in-flight AIO), and under that stale SENDING a
     * fully-inline send would skip BOTH releases here and at drain — leaking
     * the rd_pool slot and (via the depth bound admitting one request too
     * many) killing the whole pipelined connection on acquire failure.
     */
    out_before = ctx->out.count;
    brix_queue_response_chain(ctx, c, rsp_chain, t->scratch);
    if (ctx->out.count == out_before) {
        brix_release_read_buffer(ctx, c, t->scratch);
    }
    brix_aio_resume(c);
}
