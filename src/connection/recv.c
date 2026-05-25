#include "../ngx_xrootd_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "../manager/pending.h"

/* ---- File: recv.c — TCP read-event loop and request framing state machine ----
 *
 * WHAT: The core async recv loop that drives the XRootD protocol lifecycle on each TCP connection. Frames handshake (20-byte ClientInitHandShake), request headers (24-byte ClientRequestHdr), and payload bytes into a deterministic four-state machine — HANDSHAKE → REQ_HEADER → REQ_PAYLOAD → dispatch, with suspend states for SENDING/AIO/UPSTREAM/TLS. Security invariant: dlen must pass xrootd_max_payload_for_request() BEFORE any allocation. Timeout handling: CMS wait timeout sends retry response; other timeouts disconnect. Thread safety: single-owner per connection on nginx event thread — no locking required.
 *
 * WHY: Every XRootD request flows through recv.c's state machine before dispatch to opcode handlers. The recv loop ensures correct byte-level framing (handshake → header → payload) so dispatch receives a complete, validated request with streamid/reqid/dlen extracted from the wire header. Without this framing layer, dispatch would receive partial or misaligned data causing protocol errors.
 *
 * HOW: On each read-ready event, recv checks ctx->state to determine what bytes are expected (handshake=20, header=24, payload=dlen), calls c->recv(), accumulates into hdr_buf/payload_buf, dispatches when complete, then resets state for the next request. Suspend states (SENDING/AIO/UPSTREAM/TLS) return immediately without reading.
 * ------------------------------------------------------------------ */

/* ---- xrootd_max_payload_for_request — return per-opcode payload size limit ----
 *
 * WHAT: Security guard that defines the maximum allowed wire payload for each request opcode. Called BEFORE any allocation to prevent memory exhaustion attacks — clients sending dlen > this limit are disconnected immediately. Limits vary by opcode type: write/pgwrite/chkpoint -> XROOTD_MAX_WRITE_PAYLOAD; readv -> segments x segsize; auth -> XROOTD_MAX_AUTH_PAYLOAD (16KB); prepare -> XROOTD_MAX_PREPARE_PAYLOAD; all others -> path + 64 bytes. This is the first line of defense against oversized payloads. */
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

/* ---- xrootd_ensure_payload_buffer: allocate/resize payload buffer for incoming request data ----
 *
 * WHAT: Ensures ctx->payload_buf has sufficient capacity (dlen + 1 bytes) and points ctx->payload to it. The extra byte is pre-zeroed as a C-string NUL terminator guarantee. Uses heap allocation (ngx_alloc), NOT pool-allocated, so the buffer can grow across multiple requests on the same connection without fragmenting the nginx pool. On resize: frees old buffer, allocates new one. Returns NGX_OK if capacity sufficient or successfully resized, NGX_ERROR on overflow check failure or allocation failure.
 *
 * WHY: Payload buffers must survive across multiple requests on a persistent TCP connection (pool-allocated buffers would fragment under repeated large allocations). Heap allocation (ngx_alloc) allows resizing without pool pressure and is freed explicitly when the connection closes via xrootd_on_disconnect(). The pre-zeroed NUL byte ensures ctx->payload always has a valid C-string terminator even for zero-length payloads.
 *
 * HOW: First checks if existing buffer has sufficient capacity (ctx->payload_buf_size >= need), reuses it and sets payload pointer. If insufficient, frees old buffer via ngx_free(), allocates new one via ngx_alloc(need), sets ctx->payload_buf/payload_buf_size/payload, pre-zeroes byte at position dlen. Returns NGX_OK or NGX_ERROR. */
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

 /* ---- Function: ngx_stream_xrootd_recv() ----
 *
 * WHAT: The core async recv loop that drives the XRootD protocol lifecycle on each TCP connection. Called by nginx whenever data is available or timeout fires.
 *
 * WHY: Every XRootD request requires byte-level framing before dispatch — handshake validates client identity, header extracts routing fields (streamid/reqid), payload accumulates opcode-specific data. Without this loop, dispatch would receive partial or misaligned wire data causing protocol errors. The suspend-state design prevents recv from reading while send/AIO/upstream subsystems own the connection.
 *
 * HOW: On each read-ready event, checks ctx->state to determine expected bytes (handshake=20, header=24, payload=dlen), calls c->recv(), accumulates into hdr_buf/payload_buf, dispatches when complete, resets state for next request. Suspend states return immediately without reading. Timeout handling: CMS wait timeout sends retry response; other timeouts disconnect.
 * ------------------------------------------------------------------ */
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
            /* kYR_select did not arrive in time - tell client to retry. */
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
