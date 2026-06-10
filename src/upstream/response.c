#include "upstream_internal.h"

/*
 * WHAT: Translate upstream XRootD responses back to the client — kXR_redirect, kXR_wait, kXR_ok, and
 *      kXR_error handling with header reconstruction and state transitions.
 * WHY: The proxy relays opaque wire frames between client and backend server. Upstream responses must be
 *      re-wrapped with a fresh ServerResponseHdr using the client's streamid (not upstream's), then queued
 *      for delivery to the client connection. Special cases redirect (cleanup upstream, resume client read),
 *      wait (schedule retry timer), and error (extract errno+message). State machine transitions ensure
 *      correct sequencing across proxy lifecycle phases.
 * HOW: Single function xrootd_upstream_forward_response() with switch(status) covering all four response types.
 *      kXR_redirect rebuilds header + body, cleans upstream, queues to client. kXR_wait extracts seconds from
 *      body, sets timer handler, re-arms read event (epoll ET mode edge recovery). kXR_ok rebuilds header +
 *      body, cleans upstream, queues. kXR_error extracts errno/code/message, sends error frame. Default case
 *      aborts on unexpected status.
 */

void
xrootd_upstream_forward_response(xrootd_upstream_t *up)
{
    xrootd_ctx_t     *ctx = up->client_ctx;
    ngx_connection_t *c = up->client_conn;
    uint16_t          status = up->resp_status;
    u_char           *body = up->resp_body;
    uint32_t          dlen = up->resp_dlen;

    ctx->cur_streamid[0] = up->req_streamid[0];
    ctx->cur_streamid[1] = up->req_streamid[1];

    switch (status) {

    case kXR_redirect: {
        size_t  total;
        u_char *buf;

        if (dlen < 4) {
            xrootd_upstream_abort(up, "malformed kXR_redirect from upstream");
            return;
        }

        total = XRD_RESPONSE_HDR_LEN + dlen;
        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_upstream_abort(up, "pool alloc failed forwarding redirect");
            return;
        }

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_redirect, dlen,
                              (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);

        {
            uint32_t port_be;

            ngx_memcpy(&port_be, body, sizeof(port_be));
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: upstream redirect to %.*s:%u",
                          (int) (dlen - 4), body + 4, ntohl(port_be));
        }

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_queue_response(ctx, c, buf, total);
        xrootd_schedule_read_resume(c);
        return;
    }

    case kXR_wait: {
        uint32_t secs = 5;

        if (dlen >= 4) {
            uint32_t sbe;

            ngx_memcpy(&sbe, body, sizeof(sbe));
            secs = ntohl(sbe);
        }
        if (secs > XROOTD_UP_WAIT_MAX) {
            secs = XROOTD_UP_WAIT_MAX;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream kXR_wait %u s; scheduling retry",
                      secs);

        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;

        up->timer.handler = xrootd_upstream_wait_timer_handler;
        up->timer.data = up;
        up->timer.log = c->log;
        ngx_add_timer(&up->timer, (ngx_msec_t) secs * 1000);

        /* Re-arm the read event and post a synthetic event so any follow-up
         * response (e.g. kXR_redirect arriving in the same TCP segment as
         * kXR_wait) is drained this event cycle.  In epoll ET mode,
         * ngx_handle_read_event is a no-op when the fd is already active,
         * so buffered data would otherwise be missed until the retry timer. */
        if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
            xrootd_upstream_abort(up, "upstream read arm failed after kXR_wait");
            return;
        }
        ngx_post_event(up->conn->read, &ngx_posted_events);
        return;
    }

    case kXR_waitresp:
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream kXR_waitresp; forwarding to client");

        up->state = XRD_UP_ASYNC;
        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;

        if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
            xrootd_upstream_abort(up, "read arm failed after kXR_waitresp");
            return;
        }

        /* Post a synthetic read event so any kXR_redirect bytes already
         * buffered in the kernel socket are drained this event cycle.
         * In epoll ET mode, ngx_handle_read_event is a no-op when the fd is
         * already active, so buffered data would otherwise be missed. */
        ngx_post_event(up->conn->read, &ngx_posted_events);

        xrootd_send_waitresp(ctx, c);
        return;

    case kXR_ok: {
        size_t  total = XRD_RESPONSE_HDR_LEN + dlen;
        u_char *buf = ngx_palloc(c->pool, total);

        if (buf == NULL) {
            xrootd_upstream_abort(up, "pool alloc failed forwarding ok");
            return;
        }
        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, dlen,
                              (ServerResponseHdr *) buf);
        if (dlen > 0) {
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream ok (dlen=%u)", dlen);

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_queue_response(ctx, c, buf, total);
        xrootd_schedule_read_resume(c);
        return;
    }

    case kXR_error: {
        uint16_t    errcode = kXR_ServerError;
        const char *msg = "upstream error";
        char        msgbuf[256];

        if (dlen >= 4) {
            uint32_t ebe;

            ngx_memcpy(&ebe, body, sizeof(ebe));
            errcode = (uint16_t) ntohl(ebe);
        }
        if (dlen > 4) {
            size_t mlen = dlen - 4;

            if (mlen >= sizeof(msgbuf)) {
                mlen = sizeof(msgbuf) - 1;
            }
            ngx_memcpy(msgbuf, body + 4, mlen);
            msgbuf[mlen] = '\0';
            msg = msgbuf;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream error %d: %s", (int) errcode, msg);

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_send_error(ctx, c, errcode, msg);
        xrootd_schedule_read_resume(c);
        return;
    }

    default:
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: upstream unexpected status %d", (int) status);
        xrootd_upstream_abort(up, "unexpected status from upstream");
        return;
    }
}

