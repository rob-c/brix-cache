/*
 * events.c — upstream read/write event handlers for the proxy connection.
 *
 * Write handler: flushes the wbuf (bootstrap or forwarded request).
 * Read handler:  accumulates a full response (header + body), then dispatches
 *                to the bootstrap handler or to the client relay.
 */

#include "proxy_internal.h"
#include "../connection/handler.h"
#include "../token/file.h"

#include <sys/socket.h>

#define PROXY_UPSTREAM_BEARER_MAX  65536

/* ---- auth-frame builder --------------------------------------------------- */

/*
 * Builds a kXR_auth frame carrying a ztn (bearer token) credential.
 *
 * Wire format expected by the nginx-xrootd server (gsi/auth.c):
 *   Header bytes 16-19 (= cur_body[12:15]): "ztn\0"  ← credential type
 *   Header bytes 20-23 (dlen):               4 + token_len
 *   Payload bytes  0-3:                      "ztn\0"  ← payload prefix
 *   Payload bytes  4..:                      JWT token
 *
 * Returns the total frame length (24-byte header + 4 + token_len).
 * buf must be at least 24 + 4 + token_len bytes.
 */
static size_t
proxy_build_auth_ztn(u_char *buf, const char *token, size_t token_len)
{
    uint16_t rid     = htons(kXR_auth);
    uint32_t dlen_be = htonl((uint32_t)(4 + token_len));

    ngx_memzero(buf, 24);
    ngx_memcpy(buf + 2,  &rid,     2);
    /* credtype "ztn\0" at header body offset 12 (= buf offset 16) */
    buf[16] = 'z'; buf[17] = 't'; buf[18] = 'n'; buf[19] = '\0';
    ngx_memcpy(buf + 20, &dlen_be, 4);
    /* payload: "ztn\0" prefix followed by JWT token */
    buf[24] = 'z'; buf[25] = 't'; buf[26] = 'n'; buf[27] = '\0';
    ngx_memcpy(buf + 28, token, token_len);

    return 28 + token_len;
}

/* ---- bootstrap response handling ----------------------------------------- */

void
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

            /* FORWARD fallback — client has no bearer token but
             * xrootd_upstream_token_file is configured (credential bridge). */
            if (eff_auth == XROOTD_PROXY_AUTH_FORWARD
                && conf != NULL
                && conf->upstream_token_file.len > 0)
            {
                static u_char  ftok[PROXY_UPSTREAM_BEARER_MAX];
                size_t         flen = 0;
                size_t         fframe_len;
                u_char        *fframe;

                if (xrootd_token_read_file(&conf->upstream_token_file,
                                           ftok, sizeof(ftok), &flen,
                                           proxy->client_conn->log,
                                           "proxy authmore-file token") != NGX_OK
                    || flen == 0)
                {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                    xrootd_proxy_abort(proxy,
                        "upstream requires auth; set xrootd_upstream_token_file");
                    return;
                }
                fframe_len = 28 + flen;
                fframe = ngx_palloc(proxy->conn->pool, fframe_len);
                if (fframe == NULL) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    xrootd_proxy_abort(proxy, "proxy: OOM for file token frame");
                    return;
                }
                proxy_build_auth_ztn(fframe, (const char *) ftok, flen);
                if (proxy->resp_body != NULL) {
                    ngx_free(proxy->resp_body);
                    proxy->resp_body = NULL;
                }
                proxy->rhdr_pos      = 0;
                proxy->resp_dlen     = 0;
                proxy->resp_body_pos = 0;
                proxy->wbuf     = fframe;
                proxy->wbuf_len = fframe_len;
                proxy->wbuf_pos = 0;
                proxy->bs_phase = XRD_PX_BS_AUTH;
                if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    xrootd_proxy_abort(proxy,
                        "proxy: file token frame send failed");
                    return;
                }
                if (proxy->wbuf_pos < proxy->wbuf_len) {
                    if (ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK) {
                        XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                upstream_auth_errors);
                        xrootd_proxy_abort(proxy,
                            "proxy: write arm for file token failed");
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

        /*
         * Token-only servers embed a security challenge in the login response:
         *   [sessid:16][&P=ztn,v:10000]
         * The client must proactively send kXR_auth (no explicit kXR_authmore).
         * Detect the hint and inject the token from file or client bearer.
         */
        if (proxy->resp_dlen > XROOTD_SESSION_ID_LEN
            && proxy->resp_body != NULL)
        {
            const char *parms =
                (const char *)(proxy->resp_body + XROOTD_SESSION_ID_LEN);
            if (strstr(parms, "P=ztn") != NULL) {
                ngx_stream_xrootd_srv_conf_t *lconf = proxy->conf;
                const char *ltoken     = NULL;
                size_t      ltoken_len = 0;
                static u_char lftok[PROXY_UPSTREAM_BEARER_MAX];

                /* Prefer client's bearer token (FORWARD mode) */
                if (proxy->client_ctx != NULL
                    && proxy->client_ctx->bearer_token[0] != '\0')
                {
                    ltoken     = proxy->client_ctx->bearer_token;
                    ltoken_len = ngx_strlen(ltoken);
                }
                /* Fallback: read from upstream_token_file */
                else if (lconf != NULL
                         && lconf->upstream_token_file.len > 0)
                {
                    size_t lflen = 0;
                    if (xrootd_token_read_file(&lconf->upstream_token_file,
                                               lftok, sizeof(lftok), &lflen,
                                               proxy->client_conn->log,
                                               "proxy login-sec ztn") == NGX_OK
                        && lflen > 0)
                    {
                        ltoken     = (const char *) lftok;
                        ltoken_len = lflen;
                    }
                }

                if (ltoken != NULL && ltoken_len > 0) {
                    size_t  lframe_len = 28 + ltoken_len;
                    u_char *lframe = ngx_palloc(proxy->conn->pool, lframe_len);
                    if (lframe == NULL) {
                        XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                upstream_auth_errors);
                        xrootd_proxy_abort(proxy,
                            "proxy: OOM for login-sec token frame");
                        return;
                    }
                    proxy_build_auth_ztn(lframe, ltoken, ltoken_len);
                    if (proxy->resp_body != NULL) {
                        ngx_free(proxy->resp_body);
                        proxy->resp_body = NULL;
                    }
                    proxy->rhdr_pos      = 0;
                    proxy->resp_dlen     = 0;
                    proxy->resp_body_pos = 0;
                    proxy->wbuf     = lframe;
                    proxy->wbuf_len = lframe_len;
                    proxy->wbuf_pos = 0;
                    proxy->bs_phase = XRD_PX_BS_AUTH;
                    if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                        XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                upstream_auth_errors);
                        xrootd_proxy_abort(proxy,
                            "proxy: login-sec token frame send failed");
                        return;
                    }
                    if (proxy->wbuf_pos < proxy->wbuf_len) {
                        if (ngx_handle_write_event(proxy->conn->write, 0)
                            != NGX_OK)
                        {
                            XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                                    upstream_auth_errors);
                            xrootd_proxy_abort(proxy,
                                "proxy: write arm for login-sec failed");
                        }
                    }
                    return;
                }
            }
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

