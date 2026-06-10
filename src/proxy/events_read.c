#include "proxy_internal.h"
#include "../connection/handler.h"
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
 */

/* ---- read event handler --------------------------------------------------- */

void
xrootd_proxy_read_handler(ngx_event_t *rev)
{
    ngx_connection_t   *uconn = rev->data;
    xrootd_proxy_ctx_t *proxy = uconn->data;
    xrootd_ctx_t       *ctx;
    ssize_t             n;

    /* Guard against use-after-free: if the client pool was freed while a
     * reconnect was in progress, uconn->data may be NULL or stale. */
    if (proxy == NULL) {
        return;
    }
    ctx = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    if (rev->timedout) {
        xrootd_proxy_abort(proxy, "proxy: upstream read timeout");
        return;
    }

    for (;;) {
        /* ---- accumulate response header (8 bytes) ---- */
        if (proxy->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            size_t need = XRD_RESPONSE_HDR_LEN - proxy->rhdr_pos;

            n = uconn->recv(uconn, proxy->rhdr + proxy->rhdr_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_proxy_abort(proxy, "proxy: read arm failed (hdr)");
                    return;
                }
                if (proxy->conf != NULL && proxy->conf->proxy_read_timeout > 0) {
                    ngx_add_timer(rev, proxy->conf->proxy_read_timeout);
                }
                return;
            }
            if (n <= 0) {
                xrootd_proxy_abort(proxy, "proxy: upstream closed (hdr)");
                return;
            }

            proxy->rhdr_pos += (size_t) n;
            if (proxy->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
                continue;
            }

            {
                ServerResponseHdr *hdr = (ServerResponseHdr *)(void *) proxy->rhdr;
                proxy->resp_status = ntohs(hdr->status);
                proxy->resp_dlen   = ntohl(hdr->dlen);
            }

            ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                          "xrootd proxy: upstream hdr status=%d dlen=%uz state=%d",
                          (int) proxy->resp_status,
                          (size_t) proxy->resp_dlen,
                          (int) proxy->state);

            if (proxy->resp_dlen > 0) {
#ifdef __linux__
                /* Attempt zero-copy splice for plain-text read responses. */
                if (proxy->state == XRD_PX_FORWARDING
                    && xrootd_proxy_try_splice(proxy) == NGX_OK)
                {
                    ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                                  "xrootd proxy: splice started dlen=%uz",
                                  (size_t) proxy->resp_dlen);
                    /* Splice started — pump drives I/O; don't buffer body. */
                    return;
                }
#endif
                if (proxy->resp_dlen > XROOTD_PROXY_MAX_BODY) {
                    xrootd_proxy_abort(proxy, "proxy: upstream response body too large");
                    return;
                }
                proxy->resp_body = ngx_alloc(proxy->resp_dlen + 1, uconn->log);
                if (proxy->resp_body == NULL) {
                    xrootd_proxy_abort(proxy, "proxy: body alloc failed");
                    return;
                }
                ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                              "xrootd proxy: buffering body dlen=%uz",
                              (size_t) proxy->resp_dlen);
                proxy->resp_body[proxy->resp_dlen] = '\0';
                proxy->resp_body_pos = 0;
            }
        }

        /* ---- accumulate response body ---- */
#ifdef __linux__
        /* If splice is active, upstream readable means more data to pump. */
        if (proxy->splice_active) {
            xrootd_proxy_splice_pump(proxy);
            return;
        }
#endif
        if (proxy->resp_dlen > 0 && proxy->resp_body_pos < proxy->resp_dlen) {
            size_t need = proxy->resp_dlen - proxy->resp_body_pos;

            n = uconn->recv(uconn,
                            proxy->resp_body + proxy->resp_body_pos, need);
            if (n == NGX_AGAIN) {
                ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                              "xrootd proxy: body AGAIN pos=%uz dlen=%uz",
                              (size_t) proxy->resp_body_pos,
                              (size_t) proxy->resp_dlen);
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_proxy_abort(proxy, "proxy: read arm failed (body)");
                    return;
                }
                if (proxy->conf != NULL && proxy->conf->proxy_read_timeout > 0) {
                    ngx_add_timer(rev, proxy->conf->proxy_read_timeout);
                }
                return;
            }
            if (n <= 0) {
                xrootd_proxy_abort(proxy, "proxy: upstream closed (body)");
                return;
            }

            proxy->resp_body_pos += (size_t) n;
            if (proxy->resp_body_pos < proxy->resp_dlen) {
                continue;
            }
        }

        /* ---- kXR_status two-phase: expand body to include page data ---- */
        /*
         * kXR_status (pgread/pgwrite) has hdr.dlen=24 (fixed header) but
         * bdy.dlen more bytes of page data follow the standard body.
         * After reading the 24-byte fixed body, re-allocate to include those
         * extra bytes so the relay path sees a single contiguous buffer.
         */
        if (proxy->resp_status == kXR_status
            && proxy->resp_dlen == 24
            && proxy->resp_body_pos == 24)
        {
            uint32_t  extra;
            u_char   *new_body;

            ngx_memcpy(&extra, proxy->resp_body + 12, 4);
            extra = ntohl(extra);

            ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                          "xrootd proxy: kXR_status two-phase expand extra=%uz resptype=%d",
                          (size_t) extra,
                          (int)(unsigned char) proxy->resp_body[7]);

            if (extra > XROOTD_PROXY_MAX_BODY) {
                xrootd_proxy_abort(proxy,
                                   "proxy: kXR_status extra data too large");
                return;
            }
            if (extra > 0) {
                new_body = ngx_alloc(24 + extra + 1, uconn->log);
                if (new_body == NULL) {
                    xrootd_proxy_abort(proxy,
                                       "proxy: kXR_status extra body alloc failed");
                    return;
                }
                ngx_memcpy(new_body, proxy->resp_body, 24);
                ngx_free(proxy->resp_body);
                new_body[24 + extra]  = '\0';
                proxy->resp_body      = new_body;
                proxy->resp_dlen     += extra;
                /* resp_body_pos=24; body loop continues for extra bytes */
                continue;
            }
        }

        /* ---- full response received ---- */

        /*
         * Protocol Correctness: Handle kXR_attn (unsolicited or async notification).
         * These frames can arrive while IDLE (unsolicited) or while FORWARDING
         * (after a kXR_waitresp).  We relay them using their own stream ID and
         * do NOT satisfy the FORWARDING state.
         */
        if (proxy->resp_status == kXR_attn) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                           "xrootd proxy: relaying kXR_attn frame (dlen=%uz)",
                           (size_t) proxy->resp_dlen);

            /* Relay directly to client; don't use proxy->fwd_streamid */
            {
                size_t total = XRD_RESPONSE_HDR_LEN + proxy->resp_dlen;
                u_char *buf  = ngx_palloc(proxy->client_conn->pool, total);
                if (buf != NULL) {
                    ngx_memcpy(buf, proxy->rhdr, XRD_RESPONSE_HDR_LEN);
                    if (proxy->resp_dlen > 0) {
                        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, proxy->resp_body,
                                   proxy->resp_dlen);
                    }
                    xrootd_queue_response(proxy->client_ctx, proxy->client_conn,
                                          buf, total);
                }
            }

            if (proxy->resp_body != NULL) {
                ngx_free(proxy->resp_body);
                proxy->resp_body = NULL;
            }
            proxy->rhdr_pos      = 0;
            proxy->resp_dlen     = 0;
            proxy->resp_body_pos = 0;
            continue; /* Loop to check for the actual expected response */
        }

        if (proxy->state == XRD_PX_BOOTSTRAP) {
            xrootd_proxy_handle_bootstrap(proxy);
            /*
             * Don't return here — the upstream may have already delivered
             * subsequent bootstrap responses (protocol + login) in the same
             * TCP segment.  In edge-triggered epoll, returning now would leave
             * that data unread with no further event to wake us up.  Continue
             * the loop; if there is no more data recv() will return NGX_AGAIN
             * and we arm the read event there.
             *
             * xrootd_proxy_handle_bootstrap transitions state to XRD_PX_IDLE
             * (and may call xrootd_proxy_flush / arm the read itself) when
             * bootstrap completes, so check before looping.
             */
            if (proxy->state != XRD_PX_BOOTSTRAP) {
                return;   /* bootstrap done or aborted */
            }
            continue;     /* read next bootstrap response from buffered data */
        }

        if (proxy->state == XRD_PX_FORWARDING) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, uconn->log, 0,
                          "xrootd proxy: relay_to_client status=%d dlen=%uz",
                          (int) proxy->resp_status,
                          (size_t) proxy->resp_dlen);
            xrootd_proxy_relay_to_client(proxy);
            /* relay_to_client resets rhdr_pos and resp_body for the
             * next frame if status was kXR_oksofar; otherwise it
             * resets ctx->state and returns, ending the loop. */
            if (proxy->state == XRD_PX_FORWARDING) {
                /* More kXR_oksofar frames expected — loop to read next */
                continue;
            }
            /* Cancel any pending read timeout — response was fully relayed.
             * Without this, the timer set during body accumulation (NGX_AGAIN)
             * fires 60s later, triggering the read handler with a stale IDLE
             * state and causing "unexpected state" abort + SIGSEGV. */
            if (rev->timer_set) {
                ngx_del_timer(rev);
            }
            return;
        }

        xrootd_proxy_abort(proxy, "proxy: unexpected state in read handler");
        return;
    }
}
