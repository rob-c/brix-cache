#include "recv_frame.h"
#include "recv_frame_bounds.h"   /* brix_max_payload_for_request — carved pure (C-2) */
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_waiter.h"
#include "protocols/root/handoff/handoff.h"
#include "protocols/root/write/write.h"   /* brix_write_stream_* (streaming write) */

/*
 * recv_process.c — the process side of the recv framing loop (split from
 * recv_frame.c to keep each file focused / under the size cap): payload-buffer
 * management, the drain-barrier and pipelining predicates, and the per-PDU
 * process phases (kXR_writev/kXR_chkpoint body extension, header decode+dispatch,
 * payload dispatch).  Bodies are the original loop-body blocks moved verbatim;
 * only loop-exit statements became step codes.  brix_recv_read_frame and the
 * read-side helpers stay in recv_frame.c.
 */

/* brix_max_payload_for_request — the per-opcode payload cap — now lives in
 * recv_frame_bounds.c so the "reject an oversized dlen before allocation"
 * invariant can be fuzzed standalone (hyper-hardening C-2); see
 * recv_frame_bounds.h. Behaviour and the call site below are unchanged. */

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
 *
 * phase-32 WS3: a cold kXR_read now stays in flight on a worker thread
 * (rd.aio_inflight) with recv still receiving — a following kXR_close would
 * otherwise retire the very handle that read's pread is using.  Defer on
 * rd.aio_inflight too so the barrier waits for the read worker to finish.
 */
static ngx_flag_t
brix_recv_should_defer(brix_ctx_t *ctx)
{
    return (ctx->out.count > 0 || ctx->out.wr_inflight > 0
            || ctx->rd.aio_inflight > 0)
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
 * Phase 94 kXR_write header handling on THIS connection, before the payload-size
 * path.  Returns 1 (with *step set) when it fully handled the frame, else 0 (fall
 * through to the normal payload path).  Two cases:
 *  - a bound secondary carrying a plain write reopens the primary's published
 *    writable handle in this worker BEFORE the streaming/buffered paths inspect
 *    file->fd (brix_write_stream_begin runs at the header phase); the payload
 *    follows inline on this connection, so it falls through.
 *  - a primary-connection non-zero-pathid write is header-only (its data rides a
 *    bound secondary, which instead carries the WHOLE write itself), a
 *    cross-connection data-path BriX does not service — refuse it cleanly WITHOUT
 *    reading cur_dlen bytes (there are none; consuming them would desync framing).
 */
static int
brix_recv_write_hdr_hook(ngx_connection_t *c, brix_ctx_t *ctx,
    size_t *rx_pending, brix_recv_step_t *step)
{
    ngx_int_t serr;

    if (ctx->recv.cur_reqid != kXR_write) {
        return 0;
    }
    if (ctx->is_bound) {
        (void) brix_ensure_write_handle(ctx, c,
                   (int) (unsigned char) ctx->recv.cur_body[0]);
        return 0;
    }
    if (ctx->recv.cur_body[12] == 0) {   /* cur_body: fhandle[4] offset[8] pathid[1] */
        return 0;
    }
    ctx->recv.cur_dlen = 0;
    ctx->recv.payload  = NULL;
    BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
    serr = brix_send_error(ctx, c, kXR_Unsupported,
        "write data-path (pathid) unsupported; send data inline (pathid 0)");
    if (serr == NGX_ERROR) {
        *step = BRIX_RECV_STEP_BREAK;
        return 1;
    }
    ctx->out.resp_pipelinable = 0;
    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    *rx_pending = 0;
    if (ctx->state == XRD_ST_SENDING) {
        *step = BRIX_RECV_STEP_RETURN;
        return 1;
    }
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
    *step = BRIX_RECV_STEP_CONTINUE;
    return 1;
}

/* Re-arm the receive loop for the next 24-byte request header. */
static void
brix_recv_rearm_header(brix_ctx_t *ctx)
{
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
}

/*
 * AIO tail shared by the dlen==0 and payload dispatch paths: a cold kXR_read
 * whose pread just posted pipelines (back to REQ_HEADER, keep receiving);
 * every other AIO op suspends on the read event.  CONTINUE / RETURN / BREAK.
 */
static brix_recv_step_t
brix_recv_aio_tail(brix_ctx_t *ctx, ngx_event_t *rev)
{
    if (ctx->recv.cur_reqid == kXR_read && ctx->rd.aio_inflight > 0
        && !ctx->rd.win_active)
    {
        brix_recv_rearm_header(ctx);
        return BRIX_RECV_STEP_CONTINUE;
    }
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return BRIX_RECV_STEP_BREAK;
    }
    return BRIX_RECV_STEP_RETURN;
}

/*
 * Phase 29 drain barrier (extended for write pipelining): an opcode that must
 * run with the connection quiescent is parked — record the deferred streamid,
 * flip to SENDING, account the received bytes — until both the response/ack
 * queue and the in-flight pwrites drain; the recv loop re-dispatches it then.
 * Returns 1 = deferred (caller RETURNs), 0 = dispatch now.
 */
static int
brix_recv_defer_if_busy(brix_ctx_t *ctx, size_t *rx_pending)
{
    if (!brix_recv_should_defer(ctx)) {
        return 0;
    }
    ctx->out.recv_deferred = 1;
    ctx->out.deferred_streamid[0] = ctx->recv.cur_streamid[0];
    ctx->out.deferred_streamid[1] = ctx->recv.cur_streamid[1];
    ctx->state = XRD_ST_SENDING;
    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    return 1;
}

/*
 * The post-dispatch tail of the dlen==0 header path: a freshly posted read-AIO
 * either pipelines a cold read (keep receiving) or suspends; a cleartext sendfile
 * read pipelines; a pending TLS handshake is handed off; otherwise return to the
 * request-header state.  CONTINUE / RETURN / BREAK.
 */
static brix_recv_step_t
brix_recv_after_dispatch_hdr(ngx_connection_t *c, brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, ngx_event_t *rev)
{
    if (ctx->state == XRD_ST_AIO) {
        return brix_recv_aio_tail(ctx, rev);
    }
    if (brix_recv_try_pipeline_read(ctx)) {
        brix_recv_rearm_header(ctx);
    }
    if (ctx->state != XRD_ST_SENDING) {
        if (ctx->tls_pending) {
            brix_start_tls(ctx, c, conf);
            return BRIX_RECV_STEP_RETURN;
        }
        brix_recv_rearm_header(ctx);
    }
    return BRIX_RECV_STEP_CONTINUE;
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

    /*
     * Phase 94 kXR_write header handling: bound-secondary write-handle reopen, and
     * clean refusal of a header-only non-zero-pathid write on the primary.  Returns
     * 1 when it fully handled the frame (step set); otherwise falls through.
     */
    {
        brix_recv_step_t wstep;
        if (brix_recv_write_hdr_hook(c, ctx, rx_pending, &wstep)) {
            return wstep;
        }
    }

    /* dlen is untrusted client input — reject before any allocation. */
    max_pl = brix_max_payload_for_request(ctx->recv.cur_reqid);
    if (ctx->recv.cur_dlen > max_pl) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: payload too large (%uz), closing",
                      (size_t) ctx->recv.cur_dlen);
        BRIX_SRV_METRIC_INC(ctx, oversized_payloads_total);
        return BRIX_RECV_STEP_BREAK;
    }

    /*
     * Streaming large plain kXR_write: a single write whose dlen exceeds the
     * chunk size is delivered to the fd / staged writer in bounded chunks rather
     * than buffered whole (memory stays at one chunk).  brix_write_stream_begin
     * validates the handle, sets recv.sw_* state, and REWRITES cur_dlen to the
     * first chunk length so the shared payload-buffer setup below allocates one
     * chunk; brix_recv_after_payload then applies each chunk and re-arms the next.
     * If the write is not streamable (SSI / codec / require_pgwrite handle) and
     * is larger than the buffered write cap, reject it before allocating.
     */
    if (ctx->recv.cur_reqid == kXR_write
        && ctx->recv.cur_dlen > BRIX_WRITE_STREAM_CHUNK)
    {
        if (!brix_write_stream_begin(ctx, c, conf)
            && ctx->recv.cur_dlen > BRIX_MAX_WRITE_PAYLOAD)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: unstreamable write payload too large (%uz),"
                          " closing", (size_t) ctx->recv.cur_dlen);
            BRIX_SRV_METRIC_INC(ctx, oversized_payloads_total);
            return BRIX_RECV_STEP_BREAK;
        }
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

    if (brix_recv_defer_if_busy(ctx, rx_pending)) {
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

    return brix_recv_after_dispatch_hdr(c, ctx, conf, rev);
}

/*
 * Streaming large plain kXR_write (caller ensures recv.sw_active): one bounded
 * chunk (payload[0..cur_dlen)) just landed.  Apply it to the fd / staged writer at
 * sw_base_off+sw_done and either re-arm cur_dlen for the next chunk (keep
 * receiving) or, once the whole logical write has been applied, send the single
 * ack and return to the request-header state.  A streaming write is never deferred
 * / dispatched: it short-circuits the extend-body, drain-barrier, and dispatch.
 */
static brix_recv_step_t
brix_recv_stream_write_chunk(ngx_connection_t *c, brix_ctx_t *ctx,
    size_t *rx_pending)
{
    brix_write_stream_apply_chunk(ctx, c);
    ctx->recv.sw_done += ctx->recv.cur_dlen;

    if (ctx->recv.sw_done < ctx->recv.sw_total) {
        uint32_t remain = ctx->recv.sw_total - ctx->recv.sw_done;

        ctx->recv.cur_dlen = remain < BRIX_WRITE_STREAM_CHUNK
                             ? remain : BRIX_WRITE_STREAM_CHUNK;
        ctx->recv.payload_pos = 0;
        ctx->state = XRD_ST_REQ_PAYLOAD;
        ctx->recv.hdr_pos = 0;
        return BRIX_RECV_STEP_CONTINUE;   /* receive the next chunk */
    }

    /* Last chunk applied — emit exactly one reply for the logical write. */
    (void) brix_write_stream_finish(ctx, c);
    ctx->out.resp_pipelinable = 0;
    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    *rx_pending = 0;

    if (ctx->state == XRD_ST_SENDING) {
        return BRIX_RECV_STEP_RETURN;
    }
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
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

    if (ctx->recv.sw_active) {
        return brix_recv_stream_write_chunk(c, ctx, rx_pending);
    }

    ext = brix_recv_extend_body(ctx, c);
    if (ext != BRIX_RECV_STEP_NEXT) {
        return ext;   /* CONTINUE (receiving the streamed body) or BREAK */
    }

    /* e.g. a kXR_close must not retire a handle a pwrite is still writing. */
    if (brix_recv_defer_if_busy(ctx, rx_pending)) {
        return BRIX_RECV_STEP_RETURN;
    }

    brix_recv_rearm_header(ctx);

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
            brix_recv_rearm_header(ctx);
            return BRIX_RECV_STEP_CONTINUE;
        }
        /*
         * phase-32 WS3: a payload-bearing kXR_read (read-ahead list) whose cold
         * pread just posted — pipeline it exactly like the dlen==0 read path in
         * brix_recv_after_header rather than suspending on its AIO.
         */
        return brix_recv_aio_tail(ctx, rev);
    }

    /*
     * Phase 29 pipelining (payload-bearing kXR_read with a read-ahead list):
     * identical to the dlen==0 read path — keep reading so the next read's
     * sendfile span queues behind this one.
     */
    if (brix_recv_try_pipeline_read(ctx)) {
        brix_recv_rearm_header(ctx);
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
