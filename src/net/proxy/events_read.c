#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include <sys/socket.h>

/*
 * WHAT: Handle upstream read events — accumulate response header (8 bytes), optionally use Linux splice for zero-copy,
 *      then relay response body back to the client. Handles kXR_attn notifications, bootstrap responses, and forwarding mode.
 * WHY: The proxy must collect complete XRootD wire frames before relaying them to clients. Each frame has an 8-byte header (status + dlen)
 *      followed by variable-length payload. nginx-xrootd uses edge-triggered epoll so it must drain all available data from each read event
 *      rather than returning early — otherwise buffered data would be unread until the next TCP segment arrives.
 * HOW: Extract uconn and proxy ctx from rev->data; check client destruction/timeout; accumulate rhdr via recv() loop until XRD_RESPONSE_HDR_LEN;
 *      attempt Linux splice for zero-copy if FORWARDING state + resp_dlen fits in buffer; allocate resp_body via ngx_alloc; accumulate body data;
 *      handle kXR_attn relay (unsolicited notifications, special stream ID); process bootstrap or forwarding responses based on proxy->state.
 *      The pump is decomposed into fill (header/body recv + framing accumulation) and dispatch (per-frame forward decision) stages; each
 *      stage returns a step verdict telling the driver loop whether to stop, loop again, or fall through to the next stage.
 */

/* Step verdicts returned by the pump stages to the driver loop. */
typedef enum {
    BRIX_PXR_DONE,      /* stop pumping — handler must return           */
    BRIX_PXR_CONTINUE,  /* frame incomplete/consumed — loop again       */
    BRIX_PXR_PROCEED    /* stage satisfied — fall through to next stage */
} brix_pxr_verdict_t;

/*
 * WHAT: Re-arm the upstream read event after recv() returned NGX_AGAIN and
 *       (re)start the read timeout if one is configured.
 * WHY: Edge-triggered epoll delivers no further events unless the read is
 *      re-armed; a stalled upstream must still trip the read timeout.
 * HOW: ngx_handle_read_event + ngx_add_timer; on arm failure abort the proxy
 *      session with the caller-supplied reason. Always ends the pump.
 */
static brix_pxr_verdict_t
proxy_read_arm(ngx_event_t *rev, brix_proxy_ctx_t *proxy, const char *abort_msg)
{
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        brix_proxy_abort(proxy, abort_msg);
        return BRIX_PXR_DONE;
    }
    if (proxy->conf != NULL && proxy->conf->proxy.read_timeout > 0) {
        ngx_add_timer(rev, proxy->conf->proxy.read_timeout);
    }
    return BRIX_PXR_DONE;
}

/*
 * WHAT: Act on a just-completed 8-byte response header: decode status/dlen,
 *       attempt the zero-copy splice path, and allocate the body buffer.
 * WHY: The framing decision (splice vs buffered body) must be made exactly
 *      once, at the moment the header completes, before any body bytes are
 *      consumed from the socket.
 * HOW: Decode ServerResponseHdr fields into proxy state; in FORWARDING state
 *      try brix_proxy_try_splice (NGX_OK = splice pump owns the I/O now,
 *      NGX_ERROR = session already aborted, NGX_DECLINED = buffered path);
 *      then bound-check dlen and ngx_alloc the NUL-terminated body buffer.
 */
static brix_pxr_verdict_t
proxy_read_hdr_complete(brix_proxy_ctx_t *proxy, ngx_connection_t *uconn)
{
    ServerResponseHdr *hdr = (ServerResponseHdr *)(void *) proxy->rhdr;

    proxy->resp_status = ntohs(hdr->status);
    proxy->resp_dlen   = ntohl(hdr->dlen);

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                  "xrootd proxy: upstream hdr status=%d dlen=%uz state=%d",
                  (int) proxy->resp_status,
                  (size_t) proxy->resp_dlen,
                  (int) proxy->state);

    if (proxy->resp_dlen == 0) {
        return BRIX_PXR_PROCEED;
    }

#ifdef __linux__
    /* Attempt zero-copy splice for plain-text read responses. */
    if (proxy->state == XRD_PX_FORWARDING) {
        ngx_int_t srt = brix_proxy_try_splice(proxy);
        if (srt == NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                          "xrootd proxy: splice started dlen=%uz",
                          (size_t) proxy->resp_dlen);
            /* Splice started — pump drives I/O; don't buffer body. */
            return BRIX_PXR_DONE;
        }
        if (srt == NGX_ERROR) {
            /* PXY-6: try_splice aborted the session to avoid frame
             * corruption — proxy is gone, do not touch it. */
            return BRIX_PXR_DONE;
        }
        /* NGX_DECLINED — fall through to the buffered body path. */
    }
#endif
    if (proxy->resp_dlen > BRIX_PROXY_MAX_BODY) {
        brix_proxy_abort(proxy, "proxy: upstream response body too large");
        return BRIX_PXR_DONE;
    }
    proxy->resp_body = ngx_alloc(proxy->resp_dlen + 1, uconn->log);
    if (proxy->resp_body == NULL) {
        brix_proxy_abort(proxy, "proxy: body alloc failed");
        return BRIX_PXR_DONE;
    }
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                  "xrootd proxy: buffering body dlen=%uz",
                  (size_t) proxy->resp_dlen);
    proxy->resp_body[proxy->resp_dlen] = '\0';
    proxy->resp_body_pos = 0;

    return BRIX_PXR_PROCEED;
}

/*
 * WHAT: Accumulate the 8-byte response header from the upstream socket.
 * WHY: Frames must be reassembled from arbitrary TCP segmentation before any
 *      framing decision (splice/buffer/dispatch) can be made.
 * HOW: recv() the remaining header bytes; NGX_AGAIN re-arms the read event,
 *      EOF/error aborts, a short read loops again. Once complete, delegate
 *      the framing decision to proxy_read_hdr_complete. A header already
 *      complete from a previous iteration falls straight through.
 */
static brix_pxr_verdict_t
proxy_read_fill_hdr(brix_proxy_ctx_t *proxy, ngx_event_t *rev)
{
    ngx_connection_t *uconn = rev->data;
    size_t            need;
    ssize_t           n;

    if (proxy->rhdr_pos >= XRD_RESPONSE_HDR_LEN) {
        return BRIX_PXR_PROCEED;
    }

    need = XRD_RESPONSE_HDR_LEN - proxy->rhdr_pos;

    n = uconn->recv(uconn, proxy->rhdr + proxy->rhdr_pos, need);
    if (n == NGX_AGAIN) {
        return proxy_read_arm(rev, proxy, "proxy: read arm failed (hdr)");
    }
    if (n <= 0) {
        brix_proxy_abort(proxy, "proxy: upstream closed (hdr)");
        return BRIX_PXR_DONE;
    }

    proxy->rhdr_pos += (size_t) n;
    if (proxy->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
        return BRIX_PXR_CONTINUE;
    }

    return proxy_read_hdr_complete(proxy, uconn);
}

/*
 * WHAT: Accumulate the variable-length response body (or hand the event to
 *       the splice pump when a splice transfer is in flight).
 * WHY: The dispatch stage requires the complete frame body in one contiguous
 *      buffer; during a splice transfer, upstream readability instead means
 *      the zero-copy pump has more data to move.
 * HOW: If splice is active, run brix_proxy_splice_pump and stop. Otherwise
 *      recv() into resp_body at resp_body_pos; NGX_AGAIN re-arms the read,
 *      EOF/error aborts, a short read loops again; a complete (or absent)
 *      body falls through to the next stage.
 */
static brix_pxr_verdict_t
proxy_read_fill_body(brix_proxy_ctx_t *proxy, ngx_event_t *rev)
{
    ngx_connection_t *uconn = rev->data;
    size_t            need;
    ssize_t           n;

#ifdef __linux__
    /* If splice is active, upstream readable means more data to pump. */
    if (proxy->splice_active) {
        brix_proxy_splice_pump(proxy);
        return BRIX_PXR_DONE;
    }
#endif
    if (proxy->resp_dlen == 0 || proxy->resp_body_pos >= proxy->resp_dlen) {
        return BRIX_PXR_PROCEED;
    }

    need = proxy->resp_dlen - proxy->resp_body_pos;

    n = uconn->recv(uconn, proxy->resp_body + proxy->resp_body_pos, need);
    if (n == NGX_AGAIN) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                      "xrootd proxy: body AGAIN pos=%uz dlen=%uz",
                      (size_t) proxy->resp_body_pos,
                      (size_t) proxy->resp_dlen);
        return proxy_read_arm(rev, proxy, "proxy: read arm failed (body)");
    }
    if (n <= 0) {
        brix_proxy_abort(proxy, "proxy: upstream closed (body)");
        return BRIX_PXR_DONE;
    }

    proxy->resp_body_pos += (size_t) n;
    if (proxy->resp_body_pos < proxy->resp_dlen) {
        return BRIX_PXR_CONTINUE;
    }

    return BRIX_PXR_PROCEED;
}

/*
 * WHAT: Handle the kXR_status two-phase framing — expand the body buffer to
 *       cover the page data that follows the fixed 24-byte status body.
 * WHY: kXR_status (pgread/pgwrite) advertises hdr.dlen=24 but bdy.dlen more
 *      bytes of page data follow the standard body; the relay path expects a
 *      single contiguous buffer for the whole frame payload.
 * HOW: After the 24-byte fixed body completes, decode bdy.dlen at offset 12,
 *      bound-check it, re-allocate resp_body to 24+extra bytes and bump
 *      resp_dlen so the body-fill stage resumes for the extra bytes
 *      (resp_body_pos stays 24). Non-matching frames fall straight through.
 */
static brix_pxr_verdict_t
proxy_read_expand_status(brix_proxy_ctx_t *proxy, ngx_connection_t *uconn)
{
    uint32_t  extra;
    u_char   *new_body;

    if (proxy->resp_status != kXR_status
        || proxy->resp_dlen != 24
        || proxy->resp_body_pos != 24)
    {
        return BRIX_PXR_PROCEED;
    }

    ngx_memcpy(&extra, proxy->resp_body + 12, 4);
    extra = ntohl(extra);

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                  "xrootd proxy: kXR_status two-phase expand extra=%uz resptype=%d",
                  (size_t) extra,
                  (int)(unsigned char) proxy->resp_body[7]);

    if (extra > BRIX_PROXY_MAX_BODY) {
        brix_proxy_abort(proxy,
                           "proxy: kXR_status extra data too large");
        return BRIX_PXR_DONE;
    }
    if (extra == 0) {
        return BRIX_PXR_PROCEED;
    }

    new_body = ngx_alloc(24 + extra + 1, uconn->log);
    if (new_body == NULL) {
        brix_proxy_abort(proxy,
                           "proxy: kXR_status extra body alloc failed");
        return BRIX_PXR_DONE;
    }
    ngx_memcpy(new_body, proxy->resp_body, 24);
    ngx_free(proxy->resp_body);
    new_body[24 + extra]  = '\0';
    proxy->resp_body      = new_body;
    proxy->resp_dlen     += extra;
    /* resp_body_pos=24; body loop continues for extra bytes */
    return BRIX_PXR_CONTINUE;
}

/*
 * WHAT: Relay a complete kXR_attn frame straight to the client and reset the
 *       frame accumulator for the next upstream frame.
 * WHY: Protocol Correctness — kXR_attn (unsolicited or async notification)
 *      can arrive while IDLE (unsolicited) or while FORWARDING (after a
 *      kXR_waitresp). It carries its own stream ID and must NOT satisfy the
 *      FORWARDING state.
 * HOW: Copy header+body into a client-pool buffer and queue it via
 *      brix_queue_response (do not use proxy->fwd_streamid); free the body
 *      and zero the accumulator so the loop reads the actual expected
 *      response next. Non-attn frames fall straight through.
 */
static brix_pxr_verdict_t
proxy_read_relay_attn(brix_proxy_ctx_t *proxy)
{
    size_t   total;
    u_char  *buf;

    if (proxy->resp_status != kXR_attn) {
        return BRIX_PXR_PROCEED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                   "xrootd proxy: relaying kXR_attn frame (dlen=%uz)",
                   (size_t) proxy->resp_dlen);

    /* Relay directly to client; don't use proxy->fwd_streamid */
    total = XRD_RESPONSE_HDR_LEN + proxy->resp_dlen;
    buf   = ngx_palloc(proxy->client_conn->pool, total);
    if (buf != NULL) {
        ngx_memcpy(buf, proxy->rhdr, XRD_RESPONSE_HDR_LEN);
        if (proxy->resp_dlen > 0) {
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, proxy->resp_body,
                       proxy->resp_dlen);
        }
        brix_queue_response(proxy->client_ctx, proxy->client_conn,
                              buf, total);
    }

    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body_pos = 0;
    return BRIX_PXR_CONTINUE; /* Loop to check for the actual expected response */
}

/*
 * WHAT: Dispatch a fully-received upstream frame according to proxy state —
 *       bootstrap sequencing or client relay.
 * WHY: The same read pump serves both the upstream bootstrap conversation
 *      (handshake/protocol/login) and steady-state request forwarding; the
 *      forward decision per frame is keyed solely off proxy->state.
 * HOW: BOOTSTRAP → brix_proxy_handle_bootstrap, looping while more buffered
 *      bootstrap responses may follow (edge-triggered epoll). FORWARDING →
 *      splice-fallback finish or brix_proxy_relay_to_client, looping while
 *      more kXR_oksofar frames are expected and cancelling the stale read
 *      timeout once the response is fully relayed. Any other state aborts.
 */
static brix_pxr_verdict_t
proxy_read_dispatch(brix_proxy_ctx_t *proxy, ngx_event_t *rev)
{
    ngx_connection_t *uconn = rev->data;

    if (proxy->state == XRD_PX_BOOTSTRAP) {
        brix_proxy_handle_bootstrap(proxy);
        /*
         * Don't return here — the upstream may have already delivered
         * subsequent bootstrap responses (protocol + login) in the same
         * TCP segment.  In edge-triggered epoll, returning now would leave
         * that data unread with no further event to wake us up.  Continue
         * the loop; if there is no more data recv() will return NGX_AGAIN
         * and we arm the read event there.
         *
         * brix_proxy_handle_bootstrap transitions state to XRD_PX_IDLE
         * (and may call brix_proxy_flush / arm the read itself) when
         * bootstrap completes, so check before looping.
         */
        if (proxy->state != XRD_PX_BOOTSTRAP) {
            return BRIX_PXR_DONE;   /* bootstrap done or aborted */
        }
        return BRIX_PXR_CONTINUE;   /* read next bootstrap response from buffered data */
    }

    if (proxy->state == XRD_PX_FORWARDING) {
        /* Under-draining-splice fallback: the body just accumulated is the
         * RAW remainder of a spliced read (header already sent) — relay it
         * verbatim and finish, never through the header-building relay. */
        if (proxy->splice_fallback) {
            brix_proxy_splice_fallback_finish(proxy);
            return BRIX_PXR_DONE;
        }
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                      "xrootd proxy: relay_to_client status=%d dlen=%uz",
                      (int) proxy->resp_status,
                      (size_t) proxy->resp_dlen);
        brix_proxy_relay_to_client(proxy);
        /* relay_to_client resets rhdr_pos and resp_body for the
         * next frame if status was kXR_oksofar; otherwise it
         * resets ctx->state and returns, ending the loop. */
        if (proxy->state == XRD_PX_FORWARDING) {
            /* More kXR_oksofar frames expected — loop to read next */
            return BRIX_PXR_CONTINUE;
        }
        /* Cancel any pending read timeout — response was fully relayed.
         * Without this, the timer set during body accumulation (NGX_AGAIN)
         * fires 60s later, triggering the read handler with a stale IDLE
         * state and causing "unexpected state" abort + SIGSEGV. */
        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        return BRIX_PXR_DONE;
    }

    brix_proxy_abort(proxy, "proxy: unexpected state in read handler");
    return BRIX_PXR_DONE;
}

/*
 * WHAT: Run one iteration of the read pump — fill the frame (header then
 *       body), apply kXR_status expansion and kXR_attn relay, then dispatch.
 * WHY: Keeps the driver loop flat: each stage owns exactly one framing
 *      concern and reports whether the pump should stop, loop, or fall
 *      through to the next stage.
 * HOW: Chain the stages in wire order; the first non-PROCEED verdict wins.
 *      Dispatch always ends the iteration with DONE or CONTINUE.
 */
static brix_pxr_verdict_t
proxy_read_step(brix_proxy_ctx_t *proxy, ngx_event_t *rev)
{
    ngx_connection_t   *uconn = rev->data;
    brix_pxr_verdict_t  rc;

    /* accumulate response header (8 bytes) */
    rc = proxy_read_fill_hdr(proxy, rev);
    if (rc != BRIX_PXR_PROCEED) {
        return rc;
    }

    /* accumulate response body */
    rc = proxy_read_fill_body(proxy, rev);
    if (rc != BRIX_PXR_PROCEED) {
        return rc;
    }

    /* kXR_status two-phase: expand body to include page data */
    rc = proxy_read_expand_status(proxy, uconn);
    if (rc != BRIX_PXR_PROCEED) {
        return rc;
    }

    /* full response received */
    rc = proxy_read_relay_attn(proxy);
    if (rc != BRIX_PXR_PROCEED) {
        return rc;
    }

    return proxy_read_dispatch(proxy, rev);
}

/* read event handler */
void
brix_proxy_read_handler(ngx_event_t *rev)
{
    ngx_connection_t   *uconn = rev->data;
    brix_proxy_ctx_t *proxy = uconn->data;
    brix_ctx_t       *ctx;

    /* Guard against use-after-free: if the client pool was freed while a
     * reconnect was in progress, uconn->data may be NULL or stale. */
    if (proxy == NULL) {
        return;
    }
    ctx = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        brix_proxy_cleanup(proxy);
        return;
    }

    if (rev->timedout) {
        brix_proxy_abort(proxy, "proxy: upstream read timeout");
        return;
    }

    for (;;) {
        /*
         * Teardown guard (UAF + busy-loop): a handler invoked in a previous
         * iteration (handle_bootstrap, relay_to_client, …) may have called
         * brix_proxy_abort(), which tears the proxy down and clears
         * ctx->proxy *without* changing proxy->state.  The per-state branches
         * in the pump stages key off proxy->state, so without this check the
         * loop would spin straight back into the same handler and re-process
         * the still-buffered upstream frame on a dead proxy forever
         * (observed: a bad-credential upstream spinning a worker at 100% CPU,
         * re-aborting ~500K times/sec and leaking until OOM).  Once the proxy
         * is no longer the connection's live proxy, stop immediately.
         */
        if (ctx->proxy != proxy) {
            return;
        }

        if (proxy_read_step(proxy, rev) == BRIX_PXR_DONE) {
            return;
        }
    }
}
