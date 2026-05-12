/*
 * events.c — upstream read/write event handlers for the proxy connection.
 *
 * Write handler: flushes the wbuf (bootstrap or forwarded request).
 * Read handler:  accumulates a full response (header + body), then dispatches
 *                to the bootstrap handler or to the client relay.
 */

#include "proxy_internal.h"

#include <sys/socket.h>

/* ---- auth-frame builder --------------------------------------------------- */

/*
 * Builds a kXR_auth frame carrying a ztn (bearer token) credential.
 * The payload format mirrors what XRootD clients send: [4-byte-BE-len][JWT].
 * Returns the total frame length (header + body).
 * buf must be at least 24 + 4 + token_len bytes.
 */
static size_t
proxy_build_auth_ztn(u_char *buf, const char *token, size_t token_len)
{
    uint16_t rid     = htons(kXR_auth);
    uint32_t dlen_be = htonl((uint32_t)(4 + token_len));
    uint32_t tlen_be = htonl((uint32_t) token_len);

    ngx_memzero(buf, 24);
    ngx_memcpy(buf + 2,  &rid,     2);
    ngx_memcpy(buf + 20, &dlen_be, 4);
    ngx_memcpy(buf + 24, &tlen_be, 4);
    ngx_memcpy(buf + 28, token,    token_len);

    return 28 + token_len;
}

/* ---- bootstrap response handling ----------------------------------------- */

static void
xrootd_proxy_handle_bootstrap(xrootd_proxy_ctx_t *proxy)
{
    switch (proxy->bs_phase) {

    case XRD_PX_BS_HANDSHAKE:
        /* Server hello: status field overlaps the zero prefix → always ok=0 */
        if (proxy->resp_status != kXR_ok) {
            xrootd_proxy_abort(proxy, "bad handshake from upstream");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_PROTOCOL;
        break;

    case XRD_PX_BS_PROTOCOL:
        if (proxy->resp_status != kXR_ok) {
            xrootd_proxy_abort(proxy, "upstream kXR_protocol failed");
            return;
        }
        if (proxy->resp_dlen >= 8) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, proxy->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) {
#if (NGX_SSL)
                /* gotoTLS from upstream is only valid when proxy_upstream_tls
                 * was NOT set (it's the upstream's choice to require TLS after
                 * the connection was made without TLS).  Not supported yet. */
#endif
                xrootd_proxy_abort(proxy,
                    "upstream requires TLS upgrade after connect "
                    "(use xrootd_proxy_upstream_tls on to start with TLS)");
                return;
            }
        }
        proxy->bs_phase = XRD_PX_BS_LOGIN;
        break;

    case XRD_PX_BS_LOGIN:
        if (proxy->resp_status == kXR_authmore) {
            /* Upstream requests authentication — handle by configured policy.
             * Effective policy: per-upstream override if set, else global conf->proxy_auth. */
            ngx_stream_xrootd_srv_conf_t  *conf      = proxy->conf;
            ngx_uint_t                     eff_auth   = conf ? conf->proxy_auth
                                                              : XROOTD_PROXY_AUTH_ANONYMOUS;
            const xrootd_sss_key_t        *eff_key    = NULL;

            if (proxy->upstream_idx >= 0
                && conf != NULL
                && conf->proxy_upstreams != NULL
                && proxy->upstream_idx < (int) conf->proxy_upstreams->nelts)
            {
                xrootd_proxy_upstream_t *u =
                    (xrootd_proxy_upstream_t *) conf->proxy_upstreams->elts
                    + proxy->upstream_idx;

                if (u->auth >= 0) {
                    eff_auth = (ngx_uint_t) u->auth;
                }
                if (eff_auth == XROOTD_PROXY_AUTH_SSS
                    && conf->sss_keys != NULL
                    && conf->sss_keys->nelts > 0)
                {
                    xrootd_sss_key_t *keys = conf->sss_keys->elts;
                    ngx_uint_t        ki;
                    if (u->sss_keyname[0] != '\0') {
                        for (ki = 0; ki < conf->sss_keys->nelts; ki++) {
                            if (ngx_strcmp(keys[ki].name, u->sss_keyname) == 0) {
                                eff_key = &keys[ki];
                                break;
                            }
                        }
                    }
                    if (eff_key == NULL) {
                        eff_key = keys; /* fall back to first key */
                    }
                }
            }

            if (eff_auth == XROOTD_PROXY_AUTH_FORWARD
                && proxy->client_ctx != NULL
                && proxy->client_ctx->bearer_token[0] != '\0')
            {
                /* Forward the client's WLCG bearer token as a ztn credential */
                const char *token     = proxy->client_ctx->bearer_token;
                size_t      token_len = ngx_strlen(token);
                size_t      frame_len = 28 + token_len; /* hdr24 + len4 + jwt */
                u_char     *frame;

                frame = ngx_palloc(proxy->conn->pool, frame_len);
                if (frame == NULL) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy, "proxy: OOM building auth frame");
                    return;
                }

                proxy_build_auth_ztn(frame, token, token_len);

                if (proxy->resp_body != NULL) {
                    ngx_free(proxy->resp_body);
                    proxy->resp_body = NULL;
                }
                proxy->rhdr_pos      = 0;
                proxy->resp_dlen     = 0;
                proxy->resp_body_pos = 0;

                proxy->wbuf     = frame;
                proxy->wbuf_len = frame_len;
                proxy->wbuf_pos = 0;
                proxy->bs_phase = XRD_PX_BS_AUTH;

                if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy, "proxy: auth frame send failed");
                    return;
                }
                if (proxy->wbuf_pos < proxy->wbuf_len) {
                    if (ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK) {
                        XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                upstream_auth_errors);
                        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                        xrootd_proxy_abort(proxy,
                            "proxy: write arm for auth failed");
                    }
                }
                return;
            }

            if (eff_auth == XROOTD_PROXY_AUTH_SSS
                && conf != NULL
                && conf->sss_keys != NULL
                && conf->sss_keys->nelts > 0)
            {
                /* Build SSS credential from the resolved key (per-upstream or global first key) */
                const xrootd_sss_key_t *key;
                u_char                  cred[512];
                size_t                  cred_len;
                u_char                 *frame;
                size_t                  frame_len;

                key = (eff_key != NULL) ? eff_key
                                       : (const xrootd_sss_key_t *) conf->sss_keys->elts;

                if (xrootd_sss_build_proxy_credential(key, key->user,
                        cred, sizeof(cred), &cred_len) != NGX_OK)
                {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy,
                        "proxy: SSS credential build failed");
                    return;
                }

                frame_len = XRD_REQUEST_HDR_LEN + cred_len;
                frame = ngx_palloc(proxy->conn->pool, frame_len);
                if (frame == NULL) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy, "proxy: OOM for SSS frame");
                    return;
                }

                /* Build kXR_auth request header */
                ngx_memzero(frame, XRD_REQUEST_HDR_LEN);
                frame[2] = (kXR_auth >> 8) & 0xFF;
                frame[3] =  kXR_auth       & 0xFF;
                {
                    uint32_t dlen_be = htonl((uint32_t) cred_len);
                    ngx_memcpy(frame + 20, &dlen_be, 4);
                }
                ngx_memcpy(frame + XRD_REQUEST_HDR_LEN, cred, cred_len);

                if (proxy->resp_body != NULL) {
                    ngx_free(proxy->resp_body);
                    proxy->resp_body = NULL;
                }
                proxy->rhdr_pos      = 0;
                proxy->resp_dlen     = 0;
                proxy->resp_body_pos = 0;

                proxy->wbuf     = frame;
                proxy->wbuf_len = frame_len;
                proxy->wbuf_pos = 0;
                proxy->bs_phase = XRD_PX_BS_AUTH;

                if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy, "proxy: SSS frame send failed");
                    return;
                }
                if (proxy->wbuf_pos < proxy->wbuf_len) {
                    if (ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK) {
                        XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                upstream_auth_errors);
                        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                        xrootd_proxy_abort(proxy,
                            "proxy: write arm for SSS failed");
                    }
                }
                return;
            }

            XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
            xrootd_proxy_abort(proxy,
                "upstream requires authentication "
                "(set xrootd_proxy_auth forward or sss)");
            return;
        }
        if (proxy->resp_status != kXR_ok) {
            XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
            xrootd_proxy_abort(proxy, "upstream login failed");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_DONE;
        break;

    case XRD_PX_BS_AUTH:
        if (proxy->resp_status != kXR_ok) {
            XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
            xrootd_proxy_abort(proxy, "upstream rejected forwarded token");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_DONE;
        break;

    default:
        xrootd_proxy_abort(proxy, "proxy: invalid bootstrap phase");
        return;
    }

    /* Reset response accumulator for the next bootstrap message or first req */
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body_pos = 0;

    if (proxy->bs_phase != XRD_PX_BS_DONE) {
        return;  /* caller (read_handler) will continue the loop */
    }

    /* Bootstrap complete — transition to IDLE */
    proxy->state = XRD_PX_IDLE;
    xrootd_proxy_up_mark_ok(proxy);
    XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connects_total);
    XROOTD_PROXY_UP_INC(proxy, upstream_connects_total);

    /* Restore the full reconnect budget on every successful bootstrap */
    if (proxy->conf != NULL) {
        proxy->reconnect_left = (int) proxy->conf->proxy_reconnect_attempts;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                   "xrootd proxy: upstream bootstrap done");

    /* If a request was queued during bootstrap, forward it now.
     * xrootd_proxy_dispatch_pending handles bound-secondary lazy-open. */
    if (proxy->saved_req != NULL) {
        xrootd_proxy_dispatch_pending(proxy);
        return;
    }

    /* No deferred request — just resume the client read loop */
    {
        xrootd_ctx_t *ctx = proxy->client_ctx;
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_schedule_read_resume(proxy->client_conn);
    }
}

/* ---- write event handler -------------------------------------------------- */

void
xrootd_proxy_write_handler(ngx_event_t *wev)
{
    ngx_connection_t   *uconn = wev->data;
    xrootd_proxy_ctx_t *proxy = uconn->data;
    xrootd_ctx_t       *ctx   = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    if (wev->timedout) {
        xrootd_proxy_abort(proxy, "proxy: upstream write timeout");
        return;
    }

    /* TLS handshake is driven by the SSL layer, not the write handler */
    if (proxy->state == XRD_PX_TLS_HANDSHAKE) {
        return;
    }

    /* On first write event after connect(), check socket error */
    if (proxy->state == XRD_PX_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err)
        {
            ngx_log_error(NGX_LOG_ERR, proxy->client_conn->log,
                          err ? err : ngx_socket_errno,
                          "xrootd proxy: upstream TCP connect failed");
            XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
            xrootd_proxy_abort(proxy, "proxy: TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                       "xrootd proxy: upstream TCP connected");

#if (NGX_SSL)
        if (proxy->conf != NULL
            && proxy->conf->proxy_upstream_tls
            && proxy->conf->proxy_tls_ctx != NULL)
        {
            if (ngx_ssl_create_connection(proxy->conf->proxy_tls_ctx, uconn,
                                          NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
            {
                XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
                XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
                xrootd_proxy_abort(proxy, "proxy: TLS setup failed");
                return;
            }
            /* SNI: prefer explicit name directive, fall back to configured host */
            {
                const char *sni =
                    (proxy->conf->proxy_upstream_tls_name.len > 0)
                    ? (const char *) proxy->conf->proxy_upstream_tls_name.data
                    : (const char *) proxy->conf->proxy_host.data;
                SSL_set_tlsext_host_name(uconn->ssl->connection, sni);
            }
            uconn->ssl->handler = xrootd_proxy_tls_handshake_done;
            proxy->state = XRD_PX_TLS_HANDSHAKE;
            if (ngx_ssl_handshake(uconn) != NGX_AGAIN) {
                xrootd_proxy_tls_handshake_done(uconn);
            }
            return;
        }
#endif

        proxy->state    = XRD_PX_BOOTSTRAP;
        proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
        proxy->rhdr_pos = 0;
    }

    if (proxy->wbuf_pos < proxy->wbuf_len) {
        ngx_int_t rc = xrootd_proxy_flush(proxy);
        if (rc == NGX_ERROR) {
            xrootd_proxy_abort(proxy, "proxy: upstream write error");
            return;
        }
        if (rc == NGX_AGAIN) {
            return;
        }
    }

    /* Write complete — arm upstream read */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        xrootd_proxy_abort(proxy, "proxy: read arm failed after write");
    }
}

/* ---- read event handler --------------------------------------------------- */

void
xrootd_proxy_read_handler(ngx_event_t *rev)
{
    ngx_connection_t   *uconn = rev->data;
    xrootd_proxy_ctx_t *proxy = uconn->data;
    xrootd_ctx_t       *ctx   = proxy->client_ctx;
    ssize_t             n;

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

            if (proxy->resp_dlen > 0) {
                if (proxy->resp_dlen > XROOTD_PROXY_MAX_BODY) {
                    xrootd_proxy_abort(proxy, "proxy: upstream response body too large");
                    return;
                }
                proxy->resp_body = ngx_alloc(proxy->resp_dlen + 1, uconn->log);
                if (proxy->resp_body == NULL) {
                    xrootd_proxy_abort(proxy, "proxy: body alloc failed");
                    return;
                }
                proxy->resp_body[proxy->resp_dlen] = '\0';
                proxy->resp_body_pos = 0;
            }
        }

        /* ---- accumulate response body ---- */
        if (proxy->resp_dlen > 0 && proxy->resp_body_pos < proxy->resp_dlen) {
            size_t need = proxy->resp_dlen - proxy->resp_body_pos;

            n = uconn->recv(uconn,
                            proxy->resp_body + proxy->resp_body_pos, need);
            if (n == NGX_AGAIN) {
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
            xrootd_proxy_relay_to_client(proxy);
            /* relay_to_client resets rhdr_pos and resp_body for the
             * next frame if status was kXR_oksofar; otherwise it
             * resets ctx->state and returns, ending the loop. */
            if (proxy->state == XRD_PX_FORWARDING) {
                /* More kXR_oksofar frames expected — loop to read next */
                continue;
            }
            return;
        }

        xrootd_proxy_abort(proxy, "proxy: unexpected state in read handler");
        return;
    }
}
