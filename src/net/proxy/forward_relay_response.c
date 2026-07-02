#include "proxy_internal.h"
#include "protocols/root/session/registry.h"
#include "protocols/root/protocol/frame_hdr.h"   /* shared kXR_wait seconds parse (libxrdproto) */

/*
 * WHAT: Relay upstream XRootD responses to the client, handling special cases:
 *       bound-secondary lazy-open (synthetic kXR_open), kXR_wait retry,
 *       kXR_redirect follow-through, fhandle translation, path audit,
 *       and streaming kXR_oksofar / mid-stream kXR_wait.
 *
 * WHY:  The transparent proxy must translate upstream file handles to local
 *       handles, absorb transient kXR_wait responses with timed retries,
 *       silently follow redirects (up to 3 hops), emit audit records for
 *       path operations, and support streaming multi-chunk reads — all
 *       while keeping the client unaware of upstream topology changes.
 *
 * HOW:  xrootd_proxy_relay_to_client() processes proxy->resp_status/body/dlen
 *       from the upstream response. It handles each special case in sequence:
 *       lazy-open → wait-retry → redirect-follow → audit → fhandle-translation
 *       → read/write tracking → close audit → build/send relay buffer.
 */

/* Audit helper declaration — defined in forward_relay_audit.c */
extern void proxy_write_path_audit(xrootd_proxy_ctx_t *proxy, uint16_t status);

/* public API: xrootd_proxy_relay_to_client() — relay upstream response to client * WHAT: Relay the upstream server's response frame back to the connected client.
 *       Handles bound-secondary lazy-open (synthetic kXR_open), kXR_wait retry,
 *       kXR_redirect follow-through, fhandle translation, path audit, and streaming. */

/* relay upstream response to client */
/* Handle the synthetic kXR_open response for a bound-secondary lazy open:
 * translate the upstream fhandle into the reserved local slot (or free it on
 * failure) and resume the client read loop.  Returns 1 when this was a lazy-
 * open response and the caller must return; 0 otherwise. */
static int
xrootd_proxy_relay_lazy_open(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    uint32_t          dlen   = proxy->resp_dlen;
    u_char           *body   = proxy->resp_body;

    if (!proxy->fwd_is_lazy_open) {
        return 0;
    }
    int local_fh = proxy->fwd_local_fh;

    proxy->fwd_is_lazy_open = 0;

    if (status == kXR_ok) {
        /* Extract upstream fhandle from open response body[0] */
        int upstream_fh = (body != NULL && dlen >= 1)
                          ? (int)(unsigned char) body[0] : 0;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = upstream_fh;
            proxy->fh_map[local_fh].open_msec   = ngx_current_msec;
        }
    } else {
        /* Open failed — report error to client and drop saved read */
        if (proxy->saved_req != NULL) {
            ngx_free(proxy->saved_req);
            proxy->saved_req = NULL;
        }
        if (proxy->resp_body != NULL) {
            ngx_free(proxy->resp_body);
            proxy->resp_body = NULL;
        }
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        proxy->state = XRD_PX_IDLE;
        ctx->state   = XRD_ST_REQ_HEADER;
        xrootd_send_error(ctx, c, kXR_IOError,
                          "proxy: lazy open for bound secondary failed");
        xrootd_schedule_read_resume(c);
        return 1;
    }

    /* Discard the open response body; don't relay it to the client */
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }

    /* If more fhs still need lazy-open (multi-handle readv), do next one */
    if (proxy->lazy_open_pending_count > 0) {
        int next_fh;

        proxy->lazy_open_pending_count--;
        next_fh = proxy->lazy_open_pending_fhs[proxy->lazy_open_pending_count];

        /* saved_req and saved_req_len are still set from the first lazy_open call */
        {
            u_char *rreq = proxy->saved_req;
            size_t  rlen = proxy->saved_req_len;

            /* Pass ownership to lazy_open */
            proxy->saved_req = NULL;
            if (xrootd_proxy_lazy_open(proxy, ctx, c, next_fh, rreq, rlen)
                != NGX_OK)
            {
                /* Error already handled / reported */
            }
        }
        return 1;
    }

    /* Dispatch the saved kXR_read / kXR_pgread / kXR_readv */
    if (proxy->saved_req != NULL) {
        u_char   *rreq     = proxy->saved_req;
        size_t    rlen     = proxy->saved_req_len;
        int       lfh      = proxy->saved_local_fh;
        uint16_t  saved_rid;

        /* Translate the client-side fhandle(s) to upstream handles */
        saved_rid = ntohs(((ClientRequestHdr *)(void *) rreq)->requestid);
        if (saved_rid == kXR_read || saved_rid == kXR_pgread) {
            int ufh = (lfh >= 0 && lfh < XROOTD_MAX_FILES)
                      ? proxy->fh_map[lfh].upstream_fh : -1;
            if (ufh >= 0) rreq[4] = (u_char)(unsigned int) ufh;
        } else if (saved_rid == kXR_readv) {
            /* Translate every segment's fhandle using the full fh_map */
            u_char *pl    = rreq + XRD_REQUEST_HDR_LEN;
            size_t  pos   = 0;
            size_t  pdlen = rlen > XRD_REQUEST_HDR_LEN
                            ? rlen - XRD_REQUEST_HDR_LEN : 0;
            while (pos + 16 <= pdlen) {
                int cfh = (int)(unsigned char) pl[pos];
                if (cfh >= 0 && cfh < XROOTD_MAX_FILES
                    && proxy->fh_map[cfh].upstream_fh >= 0)
                {
                    pl[pos] = (u_char)(unsigned int) proxy->fh_map[cfh].upstream_fh;
                }
                pos += 16;
            }
            lfh = -1; /* readv fwd_local_fh stays -1 */
        }

        {
            ClientRequestHdr *hdr = (ClientRequestHdr *)(void *) rreq;
            proxy->fwd_reqid       = ntohs(hdr->requestid);
            proxy->fwd_streamid[0] = hdr->streamid[0];
            proxy->fwd_streamid[1] = hdr->streamid[1];
        }
        proxy->fwd_local_fh    = lfh;
        proxy->fwd_streaming   = 0;
        proxy->fwd_payload_len = rlen > XRD_REQUEST_HDR_LEN
                                 ? rlen - XRD_REQUEST_HDR_LEN : 0;
        proxy->saved_req       = NULL;

        /* kXR_waitresp / kXR_attn: transparent async response support */        /*
         * Note: We don't need a specific opcode case here.  By default we forward
         * everything and await a response.  If we get kXR_waitresp (async ack),
         * we will transition back to IDLE in relay_to_client but stay ready to
         * receive unsolicited kXR_attn frames in events.c.
         */

        /* Save a copy for transparent kXR_wait retry (if payload is not huge) */
        if (rlen < 128 * 1024) {
            if (proxy->wait_retry_req != NULL) {
                ngx_free(proxy->wait_retry_req);
            }
            proxy->wait_retry_req = ngx_alloc(rlen, c->log);
            if (proxy->wait_retry_req != NULL) {
                ngx_memcpy(proxy->wait_retry_req, rreq, rlen);
                proxy->wait_retry_req_len  = rlen;
            } else {
                proxy->wait_retry_req_len  = 0;
            }
            proxy->wait_retry_local_fh = proxy->fwd_local_fh;
            proxy->wait_retry_count    = 0;
        }

        proxy->wbuf     = rreq;

        proxy->wbuf_len = rlen;
        proxy->wbuf_pos = 0;
        proxy->state    = XRD_PX_FORWARDING;

        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;

        if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
            xrootd_proxy_abort(proxy,
                "proxy: send deferred read after lazy open failed");
            return 1;
        }
        if (proxy->wbuf_pos < proxy->wbuf_len) {
            return 1; /* write handler completes the send */
        }
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy,
                "proxy: read arm failed after lazy open read");
        }
    } else {
        proxy->state = XRD_PX_IDLE;
        ctx->state   = XRD_ST_REQ_HEADER;
        xrootd_schedule_read_resume(c);
    }
    return 1;
}

/* kXR_redirect follow-through: when the upstream returns a redirect (and we are
 * under the 3-hop limit), parse the "host:port" target, tear down the current
 * upstream, and reconnect to it re-issuing the saved request.  Returns 1 when
 * the reconnect is in progress and the caller must return; 0 to fall through and
 * relay the redirect to the client (not a redirect, malformed target, or the
 * reconnect attempt failed). */
static int
xrootd_proxy_relay_try_redirect(xrootd_proxy_ctx_t *proxy, ngx_connection_t *c,
    uint16_t status, u_char *body, uint32_t dlen)
{
    if (status == kXR_redirect && body != NULL && dlen > 0
        && proxy->redirect_count < 3)
    {
        /* Payload is "host:port\0" */
        char *target = (char *) body;
        char *colon  = ngx_strchr(target, ':');

        if (colon != NULL) {
            *colon = '\0';
            if (proxy->redirect_host.data != NULL) {
                ngx_free(proxy->redirect_host.data);
            }
            proxy->redirect_host.len  = (size_t)(colon - target);
            proxy->redirect_host.data = ngx_alloc(proxy->redirect_host.len + 1,
                                                 c->log);
            if (proxy->redirect_host.data != NULL) {
                ngx_memcpy(proxy->redirect_host.data, target,
                           proxy->redirect_host.len);
                proxy->redirect_host.data[proxy->redirect_host.len] = '\0';
                {
                    char    *endp;
                    long     pval;
                    errno = 0;
                    pval = strtol(colon + 1, &endp, 10);
                    if (errno != 0 || endp == colon + 1 || pval < 1 || pval > 65535) {
                        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                      "xrootd proxy: invalid redirect port, dropping");
                    } else {
                        proxy->redirect_port = (uint16_t) pval;

                        proxy->redirect_count++;
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "xrootd proxy: following redirect %d to %s:%d",
                                      proxy->redirect_count,
                                      proxy->redirect_host.data,
                                      (int) proxy->redirect_port);

                        /* Close current upstream, reconnect to redirected target */
                        if (proxy->conn != NULL) {
                            ngx_close_connection(proxy->conn);
                            proxy->conn = NULL;
                        }
                        if (proxy->resp_body != NULL) {
                            ngx_free(proxy->resp_body);
                            proxy->resp_body = NULL;
                        }
                        /* Reuse the wait-retry copy to re-issue the request */
                        proxy->saved_req      = proxy->wait_retry_req;
                        proxy->saved_req_len  = proxy->wait_retry_req_len;
                        proxy->saved_local_fh = proxy->wait_retry_local_fh;
                        proxy->wait_retry_req     = NULL;
                        proxy->wait_retry_req_len = 0;

                        proxy->state         = XRD_PX_CONNECTING;
                        proxy->bs_phase      = XRD_PX_BS_HANDSHAKE;
                        proxy->rhdr_pos      = 0;
                        proxy->resp_dlen     = 0;
                        proxy->resp_body_pos = 0;

                        if (xrootd_proxy_connect(proxy, c, proxy->conf) == NGX_OK) {
                            return 1; /* reconnect in progress; dispatches saved_req */
                        }
                        /* reconnect failed — fall through to relay redirect */
                        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                      "xrootd proxy: redirect follow failed, relaying");
                    }
                }
            }
        }
    }

    return 0;
}

void
xrootd_proxy_relay_to_client(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    uint32_t          dlen   = proxy->resp_dlen;
    u_char           *body   = proxy->resp_body;
    size_t            total;
    u_char           *buf;

    /* Tap: emit the upstream response metadata (status/dlen) to the observation
     * tap, keyed to the client's streamid. */
    {
        xrootd_tap_frame_t tf;
        ngx_memzero(&tf, sizeof(tf));
        tf.is_request = 0;
        tf.streamid   = (uint16_t) (((unsigned) proxy->fwd_streamid[0] << 8)
                                     | proxy->fwd_streamid[1]);
        tf.status     = status;
        tf.dlen       = dlen;
        xrootd_tap_emit(&proxy->tap, &tf, XROOTD_TAP_U2C, NULL, 0);
    }

    /* lazy open (bound secondary): handle synthetic kXR_open response */    if (xrootd_proxy_relay_lazy_open(proxy)) {
        return;
    }

    /* kXR_wait: absorb upstream "busy, try later" */    if (status == kXR_wait
        && !proxy->fwd_streaming
        && proxy->wait_retry_req != NULL
        && proxy->wait_retry_count < XROOTD_PROXY_MAX_WAIT_RETRIES)
    {
        /* shared decode+clamp (libxrdproto): floor 1s, ceiling MAX. */
        uint32_t wait_secs = xrd_wait_secs_parse((const uint8_t *) body, dlen, 1,
                                                 XROOTD_PROXY_MAX_WAIT_SECS);

        proxy->wait_retry_count++;
        XROOTD_PROXY_METRIC_INC(ctx, wait_responses_total);
        XROOTD_PROXY_UP_INC(proxy, wait_responses_total);

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd proxy: kXR_wait for reqid=%d, retry %d in %us",
                       (int) proxy->fwd_reqid, proxy->wait_retry_count, wait_secs);

        if (proxy->resp_body != NULL) {
            ngx_free(proxy->resp_body);
            proxy->resp_body = NULL;
        }
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body_pos = 0;
        /* Stay FORWARDING: events_read loops and reads the next upstream
         * frame.  If upstream sends kXR_redirect/kXR_error before the timer
         * fires (common when both frames arrive in the same TCP segment) it is
         * handled immediately.  If the timer fires first, wait_handler
         * re-issues the request; wait_retry_req == NULL check there is a no-op
         * guard for the spontaneous-response case. */

        ngx_memzero(&proxy->wait_ev, sizeof(proxy->wait_ev));
        proxy->wait_ev.handler = xrootd_proxy_wait_handler;
        proxy->wait_ev.data    = proxy;
        proxy->wait_ev.log     = proxy->conn->log;
        ngx_add_timer(&proxy->wait_ev, wait_secs * 1000);
        return;
    }

    /* kXR_wait exhausted retries — free retry buffer and relay the wait to client */
    if (status == kXR_wait) {
        int local_fh = proxy->fwd_local_fh;
        if (proxy->fwd_reqid == kXR_open && local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
    }

    /* kXR_redirect follow-through (transparently reconnect to the target). */
    if (xrootd_proxy_relay_try_redirect(proxy, c, status, body, dlen)) {
        return;
    }

    /* path-op audit: rm, mkdir, rmdir, mv, chmod, truncate */    if (proxy->fwd_path_audit
        && (status == kXR_ok || status == kXR_error))
    {
        if (status == kXR_ok) {
            XROOTD_PROXY_METRIC_INC(ctx, path_ops_total);
            XROOTD_PROXY_UP_INC(proxy, path_ops_total);
        } else {
            XROOTD_PROXY_METRIC_INC(ctx, path_op_errors_total);
            XROOTD_PROXY_UP_INC(proxy, path_op_errors_total);
        }
        proxy_write_path_audit(proxy, status);
        proxy->fwd_path_audit = 0;
    }

    /* kXR_open: translate upstream fhandle to local fhandle */    if (proxy->fwd_reqid == kXR_open && status == kXR_ok) {
        int local_fh    = proxy->fwd_local_fh;
        int upstream_fh = (body != NULL && dlen >= 1)
                          ? (int)(unsigned char) body[0]
                          : 0;

        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = upstream_fh;
            proxy->fh_map[local_fh].open_msec   = ngx_current_msec;
            if (body != NULL) {
                body[0] = (u_char)(unsigned int) local_fh;
                /* Zero out bytes 1-3 of the fhandle field (match local convention) */
                body[1] = 0;
                body[2] = 0;
                body[3] = 0;
            }
        }
        /* Open is final — release the retry copy */
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
        XROOTD_PROXY_METRIC_INC(ctx, opens_total);
        XROOTD_PROXY_UP_INC(proxy, opens_total);
    }

    if (status == kXR_error && proxy->fwd_reqid == kXR_open) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
        XROOTD_PROXY_METRIC_INC(ctx, open_errors);
        XROOTD_PROXY_UP_INC(proxy, open_errors);
    }

    /* read/readv/pgread: track bytes returned to client */    if (status == kXR_ok || status == kXR_oksofar) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            switch (proxy->fwd_reqid) {
            case kXR_read:
            case kXR_pgread:
            case kXR_readv:
                proxy->fh_map[local_fh].bytes_read += dlen;
                XROOTD_PROXY_METRIC_INC(ctx, reads_total);
                XROOTD_PROXY_METRIC_ADD(ctx, read_bytes_total, dlen);
                XROOTD_PROXY_UP_INC(proxy, reads_total);
                XROOTD_PROXY_UP_ADD(proxy, read_bytes_total, dlen);
                break;
            case kXR_write:
            case kXR_pgwrite:
            case kXR_writev:
                proxy->fh_map[local_fh].bytes_written += proxy->fwd_payload_len;
                XROOTD_PROXY_METRIC_INC(ctx, writes_total);
                XROOTD_PROXY_METRIC_ADD(ctx, write_bytes_total,
                                        proxy->fwd_payload_len);
                XROOTD_PROXY_UP_INC(proxy, writes_total);
                XROOTD_PROXY_UP_ADD(proxy, write_bytes_total, proxy->fwd_payload_len);
                break;
            default:
                break;
            }
        }
    }

    /* kXR_close: emit audit record, free the handle slot on success */    if (proxy->fwd_reqid == kXR_close && status == kXR_ok) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy_write_audit(proxy, local_fh);
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        XROOTD_PROXY_METRIC_INC(ctx, closes_total);
        XROOTD_PROXY_UP_INC(proxy, closes_total);
    }

    /* build and send relay buffer */    /*
     * kXR_status (pgread/pgwrite): hdr.dlen must remain 24 (the fixed-size
     * ServerStatusBody+pgRead header), even though we expanded resp_dlen to
     * 24 + bdy.dlen to buffer the page data.  The client extracts bdy.dlen
     * from body[12:16] and reads that many more bytes after the 24-byte body.
     */
    if (status == kXR_status && dlen > 24) {
        total = XRD_RESPONSE_HDR_LEN + dlen;   /* 8 + 24 + extra */
        buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_proxy_abort(proxy, "proxy: pool alloc failed in relay");
            return;
        }
        /* Header: dlen=24 (the fixed kXR_status body size, not 24+extra) */
        xrootd_build_resp_hdr(proxy->fwd_streamid, status, 24,
                              (ServerResponseHdr *)(void *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
    } else {
        total = XRD_RESPONSE_HDR_LEN + dlen;
        buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_proxy_abort(proxy, "proxy: pool alloc failed in relay");
            return;
        }
        xrootd_build_resp_hdr(proxy->fwd_streamid, status, dlen,
                              (ServerResponseHdr *)(void *) buf);
        if (dlen > 0 && body != NULL) {
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
        }
    }

    /*
     * Save resptype from kXR_status body[7] before freeing.
     * kXR_PartialResult (0x01) means upstream will send more kXR_status frames;
     * we must stay FORWARDING rather than going IDLE after relaying this chunk.
     */
    u_char resptype = (status == kXR_status && body != NULL && dlen >= 8)
                      ? body[7] : 0;

    /* Free the heap-allocated body now that we've copied it */
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "xrootd proxy: relay reqid=%d status=%d dlen=%uz resptype=%d",
                  (int) proxy->fwd_reqid, (int) status, (size_t) dlen,
                  (int) resptype);

    if (status == kXR_oksofar) {
        /* More chunks to come — relay this frame but stay in FORWARDING */
        proxy->fwd_streaming = 1;
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;
        xrootd_queue_response(ctx, c, buf, total);
        /* State stays XRD_ST_PROXY; read handler loops */
        return;
    }

    if (status == kXR_wait && proxy->fwd_streaming) {
        /*
         * A wait after oksofar bytes have already been relayed cannot be
         * absorbed: replaying the original request would duplicate or reorder
         * the stream. Relay the control frame and keep reading for the terminal
         * response so the upstream read handler never sees follow-on frames
         * while the proxy is IDLE.
         */
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;
        xrootd_queue_response(ctx, c, buf, total);
        return;
    }

    if (status == kXR_waitresp) {
        /*
         * Async acknowledgement: relay it to the client, then keep reading the
         * upstream connection for the eventual final response on this request.
         */
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;
        xrootd_queue_response(ctx, c, buf, total);
        return;
    }

    /*
     * kXR_status partial result (resptype=0x01 kXR_PartialResult): upstream
     * will send more kXR_status frames for this pgread.  Relay this chunk to
     * the client but stay FORWARDING so the read handler loops and picks up
     * the subsequent frames.  Same logic as kXR_oksofar for kXR_read.
     */
    if (status == kXR_status && resptype == 0x01 /* kXR_PartialResult */) {
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;
        xrootd_queue_response(ctx, c, buf, total);
        /* State stays XRD_PX_FORWARDING; read handler loops to next frame */
        return;
    }

    /* Final response — transition back to client loop.
     * Cancel any pending kXR_wait retry timer: a final response arrived
     * before the timer fired (spontaneous upstream send).  Free the saved
     * retry buffer too; wait_handler checks req==NULL as a no-op guard. */
    if (proxy->wait_ev.timer_set) {
        ngx_del_timer(&proxy->wait_ev);
    }
    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
        proxy->wait_retry_req = NULL;
    }
    proxy->state = XRD_PX_IDLE;
    ctx->state   = XRD_ST_REQ_HEADER;
    xrootd_queue_response(ctx, c, buf, total);
    xrootd_schedule_read_resume(c);
}
