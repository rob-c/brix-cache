#include "recv_frame.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_waiter.h"
#include "protocols/root/handoff/handoff.h"

/*
 * recv_process.c — the process side of the recv framing loop (split from
 * recv_frame.c to keep each file focused / under the size cap): payload-buffer
 * management, the drain-barrier and pipelining predicates, and the per-PDU
 * process phases (kXR_writev/kXR_chkpoint body extension, header decode+dispatch,
 * payload dispatch).  Bodies are the original loop-body blocks moved verbatim;
 * only loop-exit statements became step codes.  brix_recv_read_frame and the
 * read-side helpers stay in recv_frame.c.
 */

/* brix_max_payload_for_request — per-opcode payload size limit, checked BEFORE
 * any allocation so an oversized dlen is rejected without allocating. */
static uint32_t
brix_max_payload_for_request(uint16_t reqid)
{
    if (reqid == kXR_pgwrite || reqid == kXR_write || reqid == kXR_writev
        || reqid == kXR_chkpoint) {
        return BRIX_MAX_WRITE_PAYLOAD;
    }

    if (reqid == kXR_readv) {
        /* Each segment is BRIX_READV_SEGSIZE (16) bytes. */
        return BRIX_READV_MAXSEGS * BRIX_READV_SEGSIZE;
    }

    if (reqid == kXR_auth) {
        return BRIX_MAX_AUTH_PAYLOAD;
    }

    if (reqid == kXR_prepare) {
        return BRIX_MAX_PREPARE_PAYLOAD;
    }

    /* All other requests carry only a path (BRIX_MAX_PATH) plus a small
     * fixed-size body.  The +64 covers opcode-specific extras (e.g. the
     * kXR_login info field that follows the username in the payload). */
    return BRIX_MAX_PATH + 64;
}

/* brix_ensure_payload_buffer: ensure payload_buf holds dlen (+1 NUL) bytes at
 * request start (free-then-alloc on resize — the buffer is empty here). */
static ngx_int_t
brix_ensure_payload_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    u_char  *buf;
    size_t   need;

    if (dlen > (uint32_t) (SIZE_MAX - 1)) {
        return NGX_ERROR;
    }
    need = (size_t) dlen + 1;

    if (ctx->recv.payload_buf != NULL && ctx->recv.payload_buf_size >= need) {
        ctx->recv.payload = ctx->recv.payload_buf;
        ctx->recv.payload[dlen] = '\0';
        return NGX_OK;
    }

    buf = ngx_alloc(need, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->recv.payload_buf != NULL) {
        ngx_free(ctx->recv.payload_buf);
    }

    ctx->recv.payload_buf = buf;
    ctx->recv.payload_buf_size = need;
    ctx->recv.payload = buf;
    ctx->recv.payload[dlen] = '\0';

    return NGX_OK;
}

/* brix_grow_payload_buffer — enlarge payload_buf PRESERVING the received bytes
 * (payload_pos of them), for the mid-request kXR_writev / kXR_chkpoint body
 * extension that raises the expected body length after data has landed. */
static ngx_int_t
brix_grow_payload_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    u_char  *buf;
    size_t   need;

    if (dlen > (uint32_t) (SIZE_MAX - 1)) {
        return NGX_ERROR;
    }
    need = (size_t) dlen + 1;

    if (ctx->recv.payload_buf != NULL && ctx->recv.payload_buf_size >= need) {
        ctx->recv.payload = ctx->recv.payload_buf;
        ctx->recv.payload[dlen] = '\0';
        return NGX_OK;
    }

    buf = ngx_alloc(need, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->recv.payload_buf != NULL) {
        ngx_memcpy(buf, ctx->recv.payload_buf, ctx->recv.payload_pos);
        ngx_free(ctx->recv.payload_buf);
    }

    ctx->recv.payload_buf = buf;
    ctx->recv.payload_buf_size = need;
    ctx->recv.payload = buf;
    ctx->recv.payload[dlen] = '\0';

    return NGX_OK;
}

/*
 * Phase 29 drain barrier condition: a non-read/write opcode arriving while
 * reads (out.count) or writes (wr_inflight) are still in flight must run with
 * the connection quiescent (a kXR_close could free a handle an in-flight
 * sendfile chain or pwrite still references).  kXR_read and kXR_write both
 * pipeline and are never deferred.
 */
static ngx_flag_t
brix_recv_should_defer(brix_ctx_t *ctx)
{
    return (ctx->out.count > 0 || ctx->out.wr_inflight > 0)
        && ctx->recv.cur_reqid != kXR_read
        && ctx->recv.cur_reqid != kXR_write;
}

/*
 * Phase 29 pipelining condition for a parked cleartext sendfile kXR_read: keep
 * reading so the next read's sendfile span queues behind this one while the
 * prior response drains.  All four conjuncts are load-bearing: resp_pipelinable
 * = a single self-contained sendfile span (safe to queue another behind);
 * !rd.win_active excludes a multi-window read still streaming out of the shared
 * read_scratch (which must stay serial); out.count < depth is the in-flight cap.
 */
static ngx_flag_t
brix_recv_try_pipeline_read(brix_ctx_t *ctx)
{
    return ctx->state == XRD_ST_SENDING
        && ctx->recv.cur_reqid == kXR_read
        && ctx->out.resp_pipelinable
        && !ctx->rd.win_active
        && ctx->out.count < ctx->out.pipeline_depth;
}

/*
 * kXR_writev / kXR_chkpoint stock wire framing: the header dlen covers only the
 * descriptor block (writev) or the embedded 24-byte sub-header (chkpoint/ckpXeq);
 * the trailing segment/sub-request data streams after the frame.  Just after
 * that first block lands, raise the read obligation by the trailing length so
 * descriptors + data land contiguously before dispatch.  A malformed block is
 * deliberately NOT rejected here — dispatch runs the login/auth/write gates
 * first and the handler emits the stock-parity error and drops the link.  Both
 * stages are bounded (BRIX_MAX_WRITE_PAYLOAD), so the grow is safe.  CONTINUE to
 * keep receiving the extended body, NEXT when no extension applies, BREAK on a
 * grow failure.
 */
static brix_recv_step_t
brix_recv_extend_body(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->recv.cur_reqid == kXR_writev && !ctx->recv.cur_body_extended) {
        uint32_t extra;

        ctx->recv.cur_body_extended = 2;

        if (brix_writev_body_extra(ctx->recv.payload, ctx->recv.cur_dlen,
                                     &extra) == NGX_OK
            && extra > 0)
        {
            if (brix_grow_payload_buffer(ctx, c,
                    ctx->recv.cur_dlen + extra) != NGX_OK)
            {
                return BRIX_RECV_STEP_BREAK;
            }
            ctx->recv.cur_body_extra = extra;
            return BRIX_RECV_STEP_CONTINUE;   /* receive the streamed segments */
        }
    }

    if (ctx->recv.cur_reqid == kXR_chkpoint
        && ctx->recv.cur_body[15] == kXR_ckpXeq
        && ctx->recv.cur_dlen == XRD_REQUEST_HDR_LEN
        && ctx->recv.cur_body_extended < 2)
    {
        uint32_t extra = 0;
        unsigned final = 1;

        (void) brix_ckpxeq_body_extra(ctx->recv.payload,
                   ctx->recv.cur_dlen + ctx->recv.cur_body_extra,
                   &extra, &final);
        ctx->recv.cur_body_extended = final ? 2 : 1;

        if (extra > 0) {
            if (brix_grow_payload_buffer(ctx, c,
                    ctx->recv.cur_dlen + ctx->recv.cur_body_extra + extra)
                != NGX_OK)
            {
                return BRIX_RECV_STEP_BREAK;
            }
            ctx->recv.cur_body_extra += extra;
            return BRIX_RECV_STEP_CONTINUE;   /* receive the streamed sub-body */
        }
    }

    return BRIX_RECV_STEP_NEXT;
}

/*
 * A fully-received 24-byte ClientRequestHdr just landed: decode it, reject an
 * oversized dlen before any allocation, and either accept a payload-bearing
 * request (→ REQ_PAYLOAD) or dispatch a dlen==0 request.  CONTINUE/RETURN/BREAK.
 */
static brix_recv_step_t
brix_recv_after_header(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->recv.hdr_buf;
    uint32_t          max_pl;
    ngx_int_t         rc;

    /*
     * Decode the fixed 24-byte ClientRequestHdr (wire layout: streamid[2] @0,
     * requestid @2, body[16] @4, dlen @20).  streamid is an opaque client tag
     * echoed verbatim — copied byte-for-byte, never byte-swapped.  requestid and
     * dlen are big-endian on the wire, so ntohs/ntohl to host order.  cur_body is
     * the raw 16-byte opcode argument block, handed to dispatch untouched.
     */
    ctx->recv.cur_streamid[0] = hdr->streamid[0];
    ctx->recv.cur_streamid[1] = hdr->streamid[1];
    ctx->recv.cur_reqid = ntohs(hdr->requestid);
    ngx_memcpy(ctx->recv.cur_body, hdr->body, 16);
    ctx->recv.cur_dlen = (uint32_t) ntohl(hdr->dlen);
    ctx->recv.cur_body_extra = 0;
    ctx->recv.cur_body_extended = 0;
    BRIX_SRV_METRIC_INC(ctx, request_frames_total);
    BRIX_SRV_METRIC_ADD(ctx, request_payload_bytes_total, ctx->recv.cur_dlen);

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "brix: req sid=[%02xd%02xd] reqid=%04xd dlen=%uz"
                  " avail=%d ready=%d",
                  (int) ctx->recv.cur_streamid[0],
                  (int) ctx->recv.cur_streamid[1],
                  (int) ctx->recv.cur_reqid, (size_t) ctx->recv.cur_dlen,
                  c->read->available, (int) c->read->ready);

    /* dlen is untrusted client input — reject before any allocation. */
    max_pl = brix_max_payload_for_request(ctx->recv.cur_reqid);
    if (ctx->recv.cur_dlen > max_pl) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: payload too large (%uz), closing",
                      (size_t) ctx->recv.cur_dlen);
        BRIX_SRV_METRIC_INC(ctx, oversized_payloads_total);
        return BRIX_RECV_STEP_BREAK;
    }

    if (ctx->recv.cur_dlen > 0) {
        if (brix_ensure_payload_buffer(ctx, c, ctx->recv.cur_dlen) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        ctx->recv.payload_pos = 0;
        ctx->state = XRD_ST_REQ_PAYLOAD;
        ctx->recv.hdr_pos = 0;
        return BRIX_RECV_STEP_CONTINUE;
    }

    ctx->recv.payload = NULL;

    /*
     * Phase 29 drain barrier (extended for write pipelining): a non-read/write
     * opcode arriving while reads or writes are still in flight must run with the
     * connection quiescent.  Defer it until both out.count and wr_inflight drain;
     * the recv loop re-dispatches it then.
     */
    if (brix_recv_should_defer(ctx)) {
        ctx->out.recv_deferred = 1;
        ctx->out.deferred_streamid[0] = ctx->recv.cur_streamid[0];
        ctx->out.deferred_streamid[1] = ctx->recv.cur_streamid[1];
        ctx->state = XRD_ST_SENDING;
        BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
        return BRIX_RECV_STEP_RETURN;
    }

    /*
     * Reset the pipelinable marker before dispatch; only the single-chunk
     * sendfile read builder sets it back to 1.  A read served from the
     * memory/window path thus stays non-pipelinable (its header/data live in the
     * shared scratch buffers).
     */
    ctx->out.resp_pipelinable = 0;

    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    *rx_pending = 0;
    rc = brix_dispatch(ctx, c, conf);
    if (rc == NGX_ERROR) {
        return BRIX_RECV_STEP_BREAK;
    }

    if (ctx->state == XRD_ST_AIO) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        return BRIX_RECV_STEP_RETURN;
    }

    /*
     * Phase 29 pipelining: a cleartext sendfile kXR_read parked its response
     * (state SENDING) and we are below the in-flight cap.  Keep reading so the
     * next read's sendfile span queues behind this one.
     */
    if (brix_recv_try_pipeline_read(ctx)) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
    }

    if (ctx->state != XRD_ST_SENDING) {
        if (ctx->tls_pending) {
            brix_start_tls(ctx, c, conf);
            return BRIX_RECV_STEP_RETURN;
        }
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
    }

    return BRIX_RECV_STEP_CONTINUE;
}

/*
 * A fully-received payload body just landed: run the kXR_writev / kXR_chkpoint
 * body extension (which may keep receiving), apply the drain barrier, then
 * dispatch — handling the write-pipelining and read-pipelining continuations.
 * CONTINUE/RETURN/BREAK.
 */
static brix_recv_step_t
brix_recv_after_payload(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    brix_recv_step_t ext;
    ngx_int_t        rc;

    ext = brix_recv_extend_body(ctx, c);
    if (ext != BRIX_RECV_STEP_NEXT) {
        return ext;   /* CONTINUE (receiving the streamed body) or BREAK */
    }

    /*
     * Phase 29 drain barrier (extended for write pipelining): every opcode other
     * than kXR_read / kXR_write must run with the connection quiescent, so defer
     * it until both the response/ack queue and the in-flight pwrites have drained
     * — e.g. a kXR_close must not retire a handle a pwrite is still writing.
     */
    if (brix_recv_should_defer(ctx)) {
        ctx->out.recv_deferred = 1;
        ctx->out.deferred_streamid[0] = ctx->recv.cur_streamid[0];
        ctx->out.deferred_streamid[1] = ctx->recv.cur_streamid[1];
        ctx->state = XRD_ST_SENDING;
        BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
        return BRIX_RECV_STEP_RETURN;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;

    /* Only the single-chunk sendfile read builder re-sets this. */
    ctx->out.resp_pipelinable = 0;

    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    *rx_pending = 0;
    rc = brix_dispatch(ctx, c, conf);
    if (rc == NGX_ERROR) {
        return BRIX_RECV_STEP_BREAK;
    }

    if (ctx->state == XRD_ST_AIO) {
        /*
         * Write pipelining: a plain kXR_write just posted its pwrite to the
         * thread pool (wr_inflight bumped in brix_handle_write).  Instead of
         * suspending until it completes — which would serialize the next chunk's
         * network receive behind this chunk's disk write — keep receiving.  The
         * backpressure boundary caps the depth; the completion callback queues
         * the ack asynchronously.  Every other AIO op still suspends.
         */
        if (ctx->recv.cur_reqid == kXR_write && ctx->out.wr_inflight > 0) {
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->recv.hdr_pos = 0;
            return BRIX_RECV_STEP_CONTINUE;
        }
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        return BRIX_RECV_STEP_RETURN;
    }

    /*
     * Phase 29 pipelining (payload-bearing kXR_read with a read-ahead list):
     * identical to the dlen==0 read path — keep reading so the next read's
     * sendfile span queues behind this one.
     */
    if (brix_recv_try_pipeline_read(ctx)) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
        return BRIX_RECV_STEP_CONTINUE;
    }

    if (ctx->state == XRD_ST_SENDING) {
        return BRIX_RECV_STEP_RETURN;
    }

    return BRIX_RECV_STEP_CONTINUE;
}

brix_recv_step_t
brix_recv_process_frame(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    if (ctx->state == XRD_ST_HANDSHAKE) {
        if (brix_process_handshake(ctx, c) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
        return BRIX_RECV_STEP_CONTINUE;
    }

    if (ctx->state == XRD_ST_REQ_HEADER) {
        return brix_recv_after_header(s, c, conf, ctx, rev, rx_pending);
    }

    return brix_recv_after_payload(s, c, conf, ctx, rev, rx_pending);
}
