#include "../ngx_xrootd_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "../manager/pending.h"

/*
 * Read event handler and request framing state machine.
 *
 * State transitions (XRD_ST_* values from types/state.h):
 *
 *   XRD_ST_HANDSHAKE
 *     Accept exactly XRD_HANDSHAKE_LEN bytes.  Validate the fixed
 *     20-byte ClientInitHandShake; on success → XRD_ST_REQ_HEADER.
 *
 *   XRD_ST_REQ_HEADER
 *     Accept exactly XRD_REQUEST_HDR_LEN (24) bytes (ClientRequestHdr).
 *     Extract streamid, requestid, body[16], and dlen.
 *     Validate dlen against xrootd_max_payload_for_request().
 *     If dlen > 0 → XRD_ST_REQ_PAYLOAD.
 *     If dlen == 0 → dispatch immediately, then reset to XRD_ST_REQ_HEADER.
 *
 *   XRD_ST_REQ_PAYLOAD
 *     Accept ctx->cur_dlen bytes into ctx->payload_buf.
 *     On completion → dispatch, then XRD_ST_REQ_HEADER.
 *
 *   XRD_ST_SENDING
 *     The response writer owns the connection; recv suspends here and
 *     returns immediately.  The writer reactivates recv when done.
 *
 *   XRD_ST_AIO
 *     An async I/O thread has taken over.  Recv re-arms the read event
 *     and returns; the AIO completion resets the state.
 *
 *   XRD_ST_UPSTREAM / XRD_ST_TLS_HANDSHAKE
 *     Similar suspend states for cache upstream and TLS negotiation.
 *
 * Any protocol error or oversized dlen drops straight to disconnect.
 */

/*
 * Return the maximum permitted payload byte count for a given request
 * opcode.  This is the first line of defence against memory exhaustion:
 * a client that sends dlen > this limit is disconnected immediately,
 * before any allocation occurs.
 *
 * Per-opcode limits reflect the practical maximum for that operation's
 * legitimate use.  "dlen is untrusted input" — always check here first.
 *
 * Preconditions: none.
 * Returns: maximum allowed dlen in bytes.
 */
static uint32_t
xrootd_max_payload_for_request(uint16_t reqid)
{
    if (reqid == kXR_pgwrite || reqid == kXR_write || reqid == kXR_writev
        || reqid == kXR_chkpoint) {
        return XROOTD_MAX_WRITE_PAYLOAD;
    }

    if (reqid == kXR_readv) {
        /* Each segment is XROOTD_READV_SEGSIZE (16) bytes. */
        return XROOTD_READV_MAXSEGS * XROOTD_READV_SEGSIZE;
    }

    if (reqid == kXR_auth) {
        return XROOTD_MAX_AUTH_PAYLOAD;
    }

    if (reqid == kXR_prepare) {
        return XROOTD_MAX_PREPARE_PAYLOAD;
    }

    /* All other requests carry only a path (XROOTD_MAX_PATH) plus a small
     * fixed-size body.  The +64 covers opcode-specific extras (e.g. the
     * kXR_login info field that follows the username in the payload). */
    return XROOTD_MAX_PATH + 64;
}


/*
 * Ensure ctx->payload_buf holds at least (dlen + 1) bytes and point
 * ctx->payload at it.  The extra byte is pre-zeroed so that callers
 * treating the payload as a C string (e.g. path-based operations) see a
 * guaranteed NUL terminator even without one in the wire data.
 *
 * The buffer is heap-allocated (ngx_alloc / ngx_free) rather than
 * pool-allocated so it can be grown across requests on the same connection
 * without fragmenting the connection pool.  It is freed by
 * xrootd_on_disconnect() when the connection closes.
 *
 * Preconditions: dlen must have passed xrootd_max_payload_for_request().
 * Postconditions: ctx->payload points to a buffer of at least dlen+1 bytes;
 *   ctx->payload[dlen] == '\0'.
 * Returns: NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_int_t
xrootd_ensure_payload_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    u_char  *buf;
    size_t   need;

    if (dlen > (uint32_t) (SIZE_MAX - 1)) {
        return NGX_ERROR;
    }
    need = (size_t) dlen + 1;

    if (ctx->payload_buf != NULL && ctx->payload_buf_size >= need) {
        ctx->payload = ctx->payload_buf;
        ctx->payload[dlen] = '\0';
        return NGX_OK;
    }

    buf = ngx_alloc(need, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->payload_buf != NULL) {
        ngx_free(ctx->payload_buf);
    }

    ctx->payload_buf = buf;
    ctx->payload_buf_size = need;
    ctx->payload = buf;
    ctx->payload[dlen] = '\0';

    return NGX_OK;
}


/*
 * ngx_stream_xrootd_recv — nginx stream read-event callback.
 *
 * Drives the XRootD request-framing state machine.  nginx calls this
 * whenever data is available on the TCP socket (or when a timeout fires).
 *
 * The inner loop reads as much as is immediately available each time it
 * runs; it returns only when:
 *   (a) recv() returns NGX_AGAIN (kernel buffer empty), or
 *   (b) the state transitions to XRD_ST_SENDING / XRD_ST_AIO (another
 *       subsystem now owns the connection write/compute path), or
 *   (c) a protocol error occurs, causing disconnect.
 *
 * Thread safety: called exclusively on the nginx event thread.  No
 * locking required; all state is single-owner per connection.
 *
 * Preconditions: rev->data is a valid ngx_connection_t * whose ctx is an
 *   initialised xrootd_ctx_t *.
 * Postconditions: either the connection is still alive (state advanced) or
 *   ngx_stream_finalize_session() was called.
 */
void
ngx_stream_xrootd_recv(ngx_event_t *rev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ssize_t                        n;
    ngx_int_t                      rc;
    size_t                         rx_pending;

    c = rev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (rev->timedout) {
        if (ctx->state == XRD_ST_WAITING_CMS) {
            /* kYR_select did not arrive in time — tell client to retry. */
            rev->timedout = 0;
            xrootd_pending_remove(ctx->cms_wait_streamid, ngx_pid);
            ctx->state = XRD_ST_REQ_HEADER;
            xrootd_send_wait(ctx, c, 5);
            xrootd_schedule_read_resume(c);
            return;
        }
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: client connection timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rx_pending = 0;

    for (;;) {
        u_char *dest;
        size_t  need;
        size_t  avail;

        if (ctx->state == XRD_ST_SENDING) {
            return;
        }

        if (ctx->state == XRD_ST_AIO) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_UPSTREAM) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_PROXY) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_WAITING_CMS) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_TLS_HANDSHAKE) {
            return;
        }

        if (ctx->state == XRD_ST_HANDSHAKE) {
            dest = ctx->hdr_buf + ctx->hdr_pos;
            need = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            dest = ctx->hdr_buf + ctx->hdr_pos;
            need = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            dest = ctx->payload + ctx->payload_pos;
            need = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need > 0) {
            rev->available = -1;
            n = c->recv(c, dest, need);

            if (n == NGX_AGAIN) {
                ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                              "xrootd: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                              " ready=%d active=%d",
                              (int) ctx->state, ctx->hdr_pos,
                              rev->available, (int) rev->ready,
                              (int) rev->active);
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
                return;
            }

            if (n == NGX_ERROR || n == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                               "xrootd: client disconnected");
                xrootd_on_disconnect(ctx, c);
                xrootd_close_all_files(ctx);
                ngx_stream_finalize_session(s, NGX_STREAM_OK);
                return;
            }

            avail = (size_t) n;
            rx_pending += avail;

            if (ctx->state == XRD_ST_HANDSHAKE) {
                ctx->hdr_pos += avail;

                if (ctx->hdr_pos >= 1 && ctx->hdr_buf[0] != 0) {
                    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                                   "xrootd: non-XRootD client (first byte 0x%02xd)"
                                   " closing immediately",
                                   (unsigned) ctx->hdr_buf[0]);
                    break;
                }

            } else if (ctx->state == XRD_ST_REQ_HEADER) {
                ctx->hdr_pos += avail;

            } else {
                ctx->payload_pos += avail;
            }

            if (avail < need) {
                continue;
            }
        }

        if (ctx->state == XRD_ST_HANDSHAKE) {
            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                break;
            }
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;
            uint32_t          max_pl;

            ctx->cur_streamid[0] = hdr->streamid[0];
            ctx->cur_streamid[1] = hdr->streamid[1];
            ctx->cur_reqid = ntohs(hdr->requestid);
            ngx_memcpy(ctx->cur_body, hdr->body, 16);
            ctx->cur_dlen = (uint32_t) ntohl(hdr->dlen);
            XROOTD_SRV_METRIC_INC(ctx, request_frames_total);
            XROOTD_SRV_METRIC_ADD(ctx, request_payload_bytes_total,
                                  ctx->cur_dlen);

            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                          "xrootd: req sid=[%02xd%02xd] reqid=%04xd dlen=%uz"
                          " avail=%d ready=%d",
                          (int) ctx->cur_streamid[0],
                          (int) ctx->cur_streamid[1],
                          (int) ctx->cur_reqid, (size_t) ctx->cur_dlen,
                          c->read->available, (int) c->read->ready);

            /* dlen is untrusted client input — reject before any allocation. */
            max_pl = xrootd_max_payload_for_request(ctx->cur_reqid);
            if (ctx->cur_dlen > max_pl) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: payload too large (%uz), closing",
                              (size_t) ctx->cur_dlen);
                XROOTD_SRV_METRIC_INC(ctx, oversized_payloads_total);
                break;
            }

            if (ctx->cur_dlen > 0) {
                if (xrootd_ensure_payload_buffer(ctx, c, ctx->cur_dlen)
                    != NGX_OK)
                {
                    break;
                }
                ctx->payload_pos = 0;
                ctx->state = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos = 0;
                continue;
            }

            ctx->payload = NULL;
            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
            rx_pending = 0;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_AIO) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }

            if (ctx->state != XRD_ST_SENDING) {
                if (ctx->tls_pending) {
                    xrootd_start_tls(ctx, c, conf);
                    return;
                }

                ctx->state = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
            rx_pending = 0;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_SENDING) {
                return;
            }
        }
    }

    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}
