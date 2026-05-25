/* ---- File: events.c — Upstream connection non-blocking read/write event handlers and wait retry timer ----
 *
 * WHAT: Three nginx event-loop callbacks managing outbound upstream redirector connection lifecycle. xrootd_upstream_wait_timer_handler(ev) is the kXR_wait expiry timer callback — checks ctx validity/cleaned flag, logs info-level "upstream kXR_wait expired; retrying", calls xrootd_upstream_send_request() to resend saved client request, aborts on failure. xrootd_upstream_write_handler(wev) handles non-blocking upstream write: checks ctx validity, aborts on timeout ("connect/write timeout"), if state=XRD_UP_CONNECTING performs SO_ERROR getsockopt check (abort on TCP connect failure, otherwise transitions to XRD_UP_BOOTSTRAP with bs_phase=BS_HANDSHAKE and resets response accumulator), if wbuf_pos < wbuf_len calls xrootd_upstream_flush() for partial write drain (abort on error), after flush completes arms read event via ngx_handle_read_event(uconn->read, 0). xrootd_upstream_read_handler(rev) implements response accumulation loop: checks ctx validity/timeout, accumulates XRD_RESPONSE_HDR_LEN bytes parsing ServerResponseHdr to extract resp_status/resps_dlen (abort on NGX_AGAIN with re-arm, abort on n<=0), allocates resp_body from uconn->pool for dlen>0 bytes with size cap MAX_PATH+256 (abort on oversized or pool failure), accumulates body bytes until full (NGX_AGAIN re-arms read event, n<=0 closes connection), dispatches based on state: XRD_UP_BOOTSTRAP→handle_bootstrap_response(), XRD_UP_REQUEST/XRD_UP_ASYNC→forward_response(), default abort ("unexpected state"). All handlers clean up via xrootd_upstream_cleanup() when ctx destroyed. */

/*
 * WHY: Upstream connection uses nginx's non-blocking event model — write events drain partial buffers, read events accumulate response headers+body in a single loop. TCP connect completion detected via SO_ERROR on first write event (not separate connect callback). Bootstrap phase requires sequential header/body reads for handshake/protocol/TLS/login responses; request phase forwards accumulated responses verbatim to client. Wait timer handles kXR_wait opcode server-side processing delays — retries after timeout expires. Response body size cap MAX_PATH+256 prevents unbounded allocation from malicious upstream. Pool allocation (uconn->pool) ensures cleanup tied to connection lifecycle. State-based dispatch ensures correct handler called per phase: bootstrap responses go through state machine, request/async responses forwarded directly. ctx destroyed check prevents callbacks on closed connections from re-entering handlers. */

/*
 * HOW: Includes upstream_internal.h + sys/socket.h → wait timer handler (lines 5-22): ev->data=up pointer, ctx lookup via up->client_ctx, destroy check cleanup return (lines 11-14), info log retry message (lines 16-17), send_request call abort on failure (lines 19-21) → write handler (lines 24-78): wev->data=uconn, up lookup via uconn->data, ctx destroy check (lines 31-34), timeout abort (lines 36-39), connecting state SO_ERROR getsockopt abort/transition to bootstrap with phase reset accumulator (lines 41-64), wbuf partial flush abort on error (lines 66-72), read arm after full write (lines 75-77) → read handler (lines 80-178): rev->data=uconn, up lookup via uconn->data, ctx destroy check/timeout abort (lines 88-96), hdr accumulation loop XRD_RESPONSE_HDR_LEN NGX_AGAIN re-arm/n<=0 close parse ServerResponseHdr status/dlen from ntohs/ntohl (lines 98-141), body allocation cap MAX_PATH+256 pool alloc null terminate pos reset (lines 127-141), body accumulation loop NGX_AGAIN re-arm/n<=0 close pos increment (lines 143-163), state dispatch bootstrap→handle_bootstrap_response request/async→forward_response default abort (lines 165-177). */
#include "upstream_internal.h"

#include <sys/socket.h>

void
xrootd_upstream_wait_timer_handler(ngx_event_t *ev)
{
    xrootd_upstream_t *up = ev->data;
    xrootd_ctx_t      *ctx = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, up->client_conn->log, 0,
                  "xrootd: upstream kXR_wait expired; retrying");

    if (xrootd_upstream_send_request(up) != NGX_OK && up->conn != NULL) {
        xrootd_upstream_abort(up, "upstream retry failed");
    }
}

void
xrootd_upstream_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *uconn = wev->data;
    xrootd_upstream_t *up = uconn->data;
    xrootd_ctx_t      *ctx = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (wev->timedout) {
        xrootd_upstream_abort(up, "upstream connect/write timeout");
        return;
    }

    if (up->state == XRD_UP_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err)
        {
            ngx_log_error(NGX_LOG_ERR, up->client_conn->log,
                          err ? err : ngx_socket_errno,
                          "xrootd: upstream TCP connect failed");
            xrootd_upstream_abort(up, "upstream TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "xrootd: upstream TCP connected");

        up->state = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;
    }

    if (up->wbuf_pos < up->wbuf_len) {
        ngx_int_t rc = xrootd_upstream_flush(up);

        if (rc == NGX_ERROR) {
            xrootd_upstream_abort(up, "upstream write error");
        }
        return;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream read arm failed in write handler");
    }
}

void
xrootd_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *uconn = rev->data;
    xrootd_upstream_t *up = uconn->data;
    xrootd_ctx_t      *ctx = up->client_ctx;
    ssize_t            n;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (rev->timedout) {
        xrootd_upstream_abort(up, "upstream read timeout");
        return;
    }

    for (;;) {
        if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            size_t need = XRD_RESPONSE_HDR_LEN - up->rhdr_pos;

            n = uconn->recv(uconn, up->rhdr + up->rhdr_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up, "upstream read arm failed (hdr)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed");
                return;
            }

            up->rhdr_pos += (size_t) n;
            if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
                continue;
            }

            {
                ServerResponseHdr *hdr;

                hdr = (ServerResponseHdr *) (void *) up->rhdr;
                up->resp_status = ntohs(hdr->status);
                up->resp_dlen = ntohl(hdr->dlen);
            }

            if (up->resp_dlen > 0) {
                if (up->resp_dlen > XROOTD_MAX_PATH + 256) {
                    xrootd_upstream_abort(up,
                                          "upstream response body too large");
                    return;
                }
                up->resp_body = ngx_palloc(uconn->pool, up->resp_dlen + 1);
                if (up->resp_body == NULL) {
                    xrootd_upstream_abort(up, "upstream pool alloc failed");
                    return;
                }
                up->resp_body[up->resp_dlen] = '\0';
                up->resp_body_pos = 0;
            }
        }

        if (up->resp_body_pos < up->resp_dlen) {
            size_t need = up->resp_dlen - up->resp_body_pos;

            n = uconn->recv(uconn, up->resp_body + up->resp_body_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up,
                                          "upstream read arm failed (body)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed (body)");
                return;
            }

            up->resp_body_pos += (size_t) n;
            if (up->resp_body_pos < up->resp_dlen) {
                continue;
            }
        }

        if (up->state == XRD_UP_BOOTSTRAP) {
            xrootd_upstream_handle_bootstrap_response(up);
            return;
        }

        if (up->state == XRD_UP_REQUEST || up->state == XRD_UP_ASYNC) {
            xrootd_upstream_forward_response(up);
            return;
        }

        xrootd_upstream_abort(up, "upstream: unexpected state in read handler");
        return;
    }
}

