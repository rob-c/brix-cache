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

/* auth-frame builder */
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

/* upstream auth resolution * WHAT: Resolve the effective upstream auth policy and (for SSS) the key to use
 *       for THIS upstream: a per-upstream `auth`/`sss:<keyname>` override wins,
 *       else the global xrootd_proxy_auth + first configured key.
 * WHY:  Both the kXR_authmore branch and the kXR_ok login-sec-hint branch need
 *       the same decision; factoring it keeps them in lock-step.
 * HOW:  Writes *eff_auth (XROOTD_PROXY_AUTH_*) and *eff_key (NULL unless an SSS
 *       key was selected). */
static void
proxy_resolve_upstream_auth(xrootd_proxy_ctx_t *proxy, ngx_uint_t *eff_auth,
    const xrootd_sss_key_t **eff_key)
{
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;

    *eff_auth = conf ? conf->proxy_auth : XROOTD_PROXY_AUTH_ANONYMOUS;
    *eff_key  = NULL;

    if (proxy->upstream_idx >= 0
        && conf != NULL
        && conf->proxy_upstreams != NULL
        && proxy->upstream_idx < (int) conf->proxy_upstreams->nelts)
    {
        xrootd_proxy_upstream_t *u =
            (xrootd_proxy_upstream_t *) conf->proxy_upstreams->elts
            + proxy->upstream_idx;

        if (u->auth >= 0) {
            *eff_auth = (ngx_uint_t) u->auth;
        }
        if (*eff_auth == XROOTD_PROXY_AUTH_SSS
            && conf->sss_keys != NULL
            && conf->sss_keys->nelts > 0)
        {
            xrootd_sss_key_t *keys = conf->sss_keys->elts;
            ngx_uint_t        ki;
            if (u->sss_keyname[0] != '\0') {
                for (ki = 0; ki < conf->sss_keys->nelts; ki++) {
                    if (ngx_strcmp(keys[ki].name, u->sss_keyname) == 0) {
                        *eff_key = &keys[ki];
                        break;
                    }
                }
            }
            if (*eff_key == NULL) {
                *eff_key = keys; /* fall back to first key */
            }
        }
    }
}

/* send an SSS kXR_auth credential to the upstream * WHAT: Build an SSS credential from `key`, wrap it in a kXR_auth request, and
 *       arm the write side; advance bs_phase to BS_AUTH.
 * WHY:  Used by BOTH the kXR_authmore path and the kXR_ok login-sec-hint path
 *       (our own server advertises SSS via the latter), so the logic lives once.
 * HOW:  Returns NGX_OK once the frame is queued (caller must return), or
 *       NGX_ERROR after aborting the proxy on any failure. */
static ngx_int_t
proxy_send_sss_auth(xrootd_proxy_ctx_t *proxy, const xrootd_sss_key_t *key)
{
    u_char  cred[512];
    size_t  cred_len;
    u_char *frame;
    size_t  frame_len;

    if (xrootd_sss_build_proxy_credential(key, key->user,
            cred, sizeof(cred), &cred_len) != NGX_OK)
    {
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
        xrootd_proxy_abort(proxy, "proxy: SSS credential build failed");
        return NGX_ERROR;
    }

    frame_len = XRD_REQUEST_HDR_LEN + cred_len;
    frame = ngx_palloc(proxy->conn->pool, frame_len);
    if (frame == NULL) {
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
        xrootd_proxy_abort(proxy, "proxy: OOM for SSS frame");
        return NGX_ERROR;
    }

    /* kXR_auth request header: reqid at [2:3], credtype "sss\0" at [16:19]
     * (the server routes on this field — leaving it zero yields "unknown
     * credtype"), dlen at [20:23], SSS credential body after the 24-byte hdr. */
    ngx_memzero(frame, XRD_REQUEST_HDR_LEN);
    frame[2] = (kXR_auth >> 8) & 0xFF;
    frame[3] =  kXR_auth       & 0xFF;
    frame[16] = 's'; frame[17] = 's'; frame[18] = 's'; frame[19] = '\0';
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
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
        xrootd_proxy_abort(proxy, "proxy: SSS frame send failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        if (ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK) {
            XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
            xrootd_proxy_abort(proxy, "proxy: write arm for SSS failed");
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* bootstrap response handling */
/*
 * WHAT: Advance the upstream login handshake one step, consuming the response
 *       that the read handler just finished accumulating (proxy->resp_status /
 *       resp_dlen / resp_body) and, where the next step requires sending,
 *       arming the write side with the next request frame.
 * WHY:  Connecting to an upstream XRootD server is a fixed conversation —
 *       hello -> kXR_protocol -> kXR_login -> (optional kXR_auth) — that must
 *       complete before any client request can be forwarded. Each leg is a
 *       separate wire round-trip, so the proxy drives it as a state machine
 *       (proxy->bs_phase) re-entered once per upstream response rather than
 *       blocking; the event loop never waits.
 * HOW:  Switch on bs_phase. Each arm validates the just-received response,
 *       optionally builds+flushes the next request, and either advances
 *       bs_phase or returns early (when it issued a send and must wait for the
 *       reply). The single fallthrough at the bottom frees the response
 *       accumulator; reaching XRD_PX_BS_DONE flips proxy->state to IDLE and
 *       releases any request queued during bootstrap.
 *
 * RE-ENTRY: this is called by xrootd_proxy_read_handler each time a complete
 *       upstream frame arrives. Arms that send (AUTH legs) return early and are
 *       resumed by the next read event; non-sending arms fall through to the
 *       shared reset/finish tail. The four auth-send arms (FORWARD bearer, SSS,
 *       FORWARD token-file fallback, login-sec hint) are structurally identical:
 *       build frame -> free+reset resp accumulator -> set wbuf -> flush -> arm
 *       write if partial -> return. They differ only in how the credential is
 *       sourced.
 */
/* BS_LOGIN bootstrap phase: handle the upstream login reply — kXR_authmore
 * (forward bearer / SSS / token-file), login failure, and the token-only
 * login-sec hint (proactive P=sss / P=ztn).  Returns 1 when it has issued a
 * frame or aborted and the caller must return; 0 when the phase is complete
 * (bs_phase advanced to DONE) and the caller falls through to the shared
 * reset/finish tail. */
static int
xrootd_proxy_bs_login(xrootd_proxy_ctx_t *proxy)
{
    if (proxy->resp_status == kXR_authmore) {
        /* Upstream requests authentication — handle by configured policy.
         * Effective policy: per-upstream override if set, else global conf->proxy_auth. */
        ngx_stream_xrootd_srv_conf_t  *conf      = proxy->conf;
        ngx_uint_t                     eff_auth;
        const xrootd_sss_key_t        *eff_key;

        proxy_resolve_upstream_auth(proxy, &eff_auth, &eff_key);

        /* auth-send arm 1 of 4: FORWARD using the client's bearer         * Preferred FORWARD path: the connecting client already presented a
         * WLCG bearer token, so re-present it verbatim to the upstream. */
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
                return 1;
            }

            proxy_build_auth_ztn(frame, token, token_len);

            /* Clear the just-consumed response so the accumulator is ready
             * for the kXR_auth reply, then install the auth frame as the
             * write buffer and advance to BS_AUTH before flushing. */
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

            /* flush() may only partially write under backpressure; if so,
             * arm the write event so the rest goes out later. Either way we
             * return and wait for the BS_AUTH reply on the next read event. */
            if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                        upstream_auth_errors);
                XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
                xrootd_proxy_abort(proxy, "proxy: auth frame send failed");
                return 1;
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
            return 1;
        }

        /* auth-send arm 2 of 4: SSS shared-secret credential */        if (eff_auth == XROOTD_PROXY_AUTH_SSS && eff_key != NULL) {
            (void) proxy_send_sss_auth(proxy, eff_key);
            return 1;   /* frame queued, or proxy aborted on failure */
        }

        /* auth-send arm 3 of 4: FORWARD token-file fallback         * FORWARD fallback — client has no bearer token but
         * xrootd_upstream_token_file is configured (credential bridge).
         * ftok is function-static (64 KiB) to keep it off the stack; safe
         * because nginx workers are single-threaded on the event loop and
         * the token is copied into the heap frame before any yield. */
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
                return 1;
            }
            fframe_len = 28 + flen;
            fframe = ngx_palloc(proxy->conn->pool, fframe_len);
            if (fframe == NULL) {
                XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                        upstream_auth_errors);
                xrootd_proxy_abort(proxy, "proxy: OOM for file token frame");
                return 1;
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
                return 1;
            }
            if (proxy->wbuf_pos < proxy->wbuf_len) {
                if (ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK) {
                    XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                            upstream_auth_errors);
                    xrootd_proxy_abort(proxy,
                        "proxy: write arm for file token failed");
                }
            }
            return 1;
        }

        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
        xrootd_proxy_abort(proxy,
            "upstream requires authentication "
            "(set xrootd_proxy_auth forward or sss)");
        return 1;
    }
    if (proxy->resp_status != kXR_ok) {
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_auth_errors);
        xrootd_proxy_abort(proxy, "upstream login failed");
        return 1;
    }

    /*
     * Token-only servers embed a security challenge in the login response:
     *   [sessid:16][&P=ztn,v:10000]
     * The client must proactively send kXR_auth (no explicit kXR_authmore).
     * Detect the hint and inject the token from file or client bearer.
     */
    /* The security hint string follows the fixed 16-byte session id in the
     * login body, so step past it before scanning. resp_body was NUL-padded
     * by the read handler (alloc dlen+1), making strstr() safe here. */
    if (proxy->resp_dlen > XROOTD_SESSION_ID_LEN
        && proxy->resp_body != NULL)
    {
        const char *parms =
            (const char *)(proxy->resp_body + XROOTD_SESSION_ID_LEN);

        /* auth-send arm 5 of 5: proactive SSS on login-sec hint         * The nginx-xrootd server (and stock xrootd) advertise SSS via the
         * kXR_ok login response sec hint ("&P=sss,..."), NOT via kXR_authmore.
         * If this upstream's effective policy is SSS, build and send the SSS
         * credential unprompted — without this, SSS upstream auth silently
         * never happens and the forwarded open is rejected NotAuthorized. */
        if (strstr(parms, "P=sss") != NULL) {
            ngx_uint_t              sss_auth;
            const xrootd_sss_key_t *sss_key;

            proxy_resolve_upstream_auth(proxy, &sss_auth, &sss_key);
            if (sss_auth == XROOTD_PROXY_AUTH_SSS && sss_key != NULL) {
                (void) proxy_send_sss_auth(proxy, sss_key);
                return 1;   /* frame queued, or proxy aborted on failure */
            }
        }

        /* auth-send arm 4 of 5: proactive ztn on login-sec hint         * Server advertised "P=ztn" but did not send kXR_authmore, so we
         * must send kXR_auth unprompted. Source the token from the client
         * bearer (FORWARD) first, else from the upstream token file. */
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
                    return 1;
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
                    return 1;
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
                return 1;
            }
        }
    }

    proxy->bs_phase = XRD_PX_BS_DONE;

    return 0;
}

void
xrootd_proxy_handle_bootstrap(xrootd_proxy_ctx_t *proxy)
{
    /* State machine over the upstream login conversation; see bs_phase enum. */
    switch (proxy->bs_phase) {

    case XRD_PX_BS_HANDSHAKE:
        /* Server hello: the 16-byte handshake reply begins with two zero
         * 32-bit words, and the read handler parsed status from the bytes that
         * happen to fall in the zero prefix, so resp_status is normally 0 ==
         * kXR_ok. A non-zero value here means the bytes did not line up as a
         * valid hello, i.e. this is not an XRootD server speaking. */
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
        /* kXR_protocol reply body: [4 bytes pval][4 bytes flags][...]. The
         * server's capability flags live at body offset 4; kXR_gotoTLS there
         * means the server wants the connection upgraded to TLS now. We only
         * reach this code on a cleartext connection (TLS-from-start uses a
         * different path), so an in-band upgrade request is unsupported. */
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
        if (xrootd_proxy_bs_login(proxy)) {
            return;
        }
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

    /* Shared tail: reached only by arms that fell through (i.e. did NOT issue a
     * send and return early). Reset the accumulator for whatever comes next. */
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

    /* The upstream accepted the forwarded credential — this connection is
     * healthy again, so clear the consecutive-failure budget. */
    if (proxy->client_ctx != NULL) {
        proxy->client_ctx->proxy_fail_count = 0;
    }

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

