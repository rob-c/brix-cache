/*
 * events.c — upstream read/write event handlers for the proxy connection.
 *
 * Write handler: flushes the wbuf (bootstrap or forwarded request).
 * Read handler:  accumulates a full response (header + body), then dispatches
 *                to the bootstrap handler or to the client relay.
 */

#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "auth/token/file.h"

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
 *       else the global brix_proxy_auth + first configured key.
 * WHY:  Both the kXR_authmore branch and the kXR_ok login-sec-hint branch need
 *       the same decision; factoring it keeps them in lock-step.
 * HOW:  Writes *eff_auth (BRIX_PROXY_AUTH_*) and *eff_key (NULL unless an SSS
 *       key was selected). */
static void
proxy_resolve_upstream_auth(brix_proxy_ctx_t *proxy, ngx_uint_t *eff_auth,
    const brix_sss_key_t **eff_key)
{
    ngx_stream_brix_srv_conf_t *conf = proxy->conf;

    *eff_auth = conf ? conf->proxy.auth : BRIX_PROXY_AUTH_ANONYMOUS;
    *eff_key  = NULL;

    if (proxy->upstream_idx >= 0
        && conf != NULL
        && conf->proxy.upstreams != NULL
        && proxy->upstream_idx < (int) conf->proxy.upstreams->nelts)
    {
        brix_proxy_upstream_t *u =
            (brix_proxy_upstream_t *) conf->proxy.upstreams->elts
            + proxy->upstream_idx;

        if (u->auth >= 0) {
            *eff_auth = (ngx_uint_t) u->auth;
        }
        if (*eff_auth == BRIX_PROXY_AUTH_SSS
            && conf->sss_keys != NULL
            && conf->sss_keys->nelts > 0)
        {
            brix_sss_key_t *keys = conf->sss_keys->elts;
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

/* auth-send failure/plumbing helpers */
/*
 * WHAT: Per-arm abort texts + metric policy for one auth-send attempt.
 * WHY:  The auth-send arms differ ONLY in message wording and in whether the
 *       per-upstream error counter is bumped alongside the global one; a
 *       descriptor keeps the shared send machinery literally identical.
 * HOW:  Each arm owns a function-local `static const` instance and threads it
 *       through proxy_bs_send_ztn / proxy_bs_queue_auth_frame.
 */
typedef struct {
    const char *oom_msg;   /* abort text: frame allocation failed */
    const char *send_msg;  /* abort text: flushing the frame failed */
    const char *arm_msg;   /* abort text: arming the write event failed */
    unsigned    up_inc;    /* 1 = also bump the per-upstream error counter */
} proxy_bs_auth_errs_t;

/*
 * WHAT: Record an upstream-auth failure and abort the proxy connection.
 * WHY:  Every failure exit of the bootstrap auth arms increments the global
 *       upstream_auth_errors metric; only some arms additionally bump the
 *       per-upstream counter (historical behavior, frozen).
 * HOW:  Bumps metrics per `up_inc`, then brix_proxy_abort(msg).
 */
static void
proxy_bs_auth_error(brix_proxy_ctx_t *proxy, unsigned up_inc, const char *msg)
{
    BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_auth_errors);
    if (up_inc) {
        BRIX_PROXY_UP_INC(proxy, upstream_auth_errors);
    }
    brix_proxy_abort(proxy, msg);
}

/*
 * WHAT: Reset the upstream response accumulator (header pos, dlen, body).
 * WHY:  Done after every consumed bootstrap response — both before sending
 *       the next request frame and in the shared handle_bootstrap tail — so
 *       the accumulator is ready for the next upstream reply.
 * HOW:  Frees resp_body if allocated and zeroes the three cursor fields.
 */
static void
proxy_bs_reset_resp(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body_pos = 0;
}

/*
 * WHAT: Install a built kXR_auth frame as the write buffer, advance the
 *       bootstrap to BS_AUTH, and flush it toward the upstream.
 * WHY:  All auth-send arms (bearer forward, SSS, token-file, login-sec hint)
 *       share this exact tail: reset accumulator -> set wbuf -> flush -> arm
 *       the write event on partial write. Factoring it makes the arms differ
 *       only in credential sourcing.
 * HOW:  flush() may only partially write under backpressure; if so, arm the
 *       write event so the rest goes out later. Either way the caller returns
 *       and waits for the BS_AUTH reply on the next read event. On any
 *       failure the proxy is aborted (per errs) and NGX_ERROR is returned.
 */
static ngx_int_t
proxy_bs_queue_auth_frame(brix_proxy_ctx_t *proxy, u_char *frame,
    size_t frame_len, const proxy_bs_auth_errs_t *errs)
{
    /* Clear the just-consumed response so the accumulator is ready for the
     * kXR_auth reply, then install the auth frame as the write buffer and
     * advance to BS_AUTH before flushing. */
    proxy_bs_reset_resp(proxy);

    proxy->wbuf     = frame;
    proxy->wbuf_len = frame_len;
    proxy->wbuf_pos = 0;
    proxy->bs_phase = XRD_PX_BS_AUTH;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        proxy_bs_auth_error(proxy, errs->up_inc, errs->send_msg);
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len
        && ngx_handle_write_event(proxy->conn->write, 0) != NGX_OK)
    {
        proxy_bs_auth_error(proxy, errs->up_inc, errs->arm_msg);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Build a ztn (bearer token) kXR_auth frame for `token` and queue it.
 * WHY:  Three arms send a ztn credential (client bearer forward, token-file
 *       fallback, login-sec hint); only the token source and abort texts
 *       differ, so the alloc/build/queue sequence lives once.
 * HOW:  Allocates the frame from the upstream connection pool, encodes it
 *       via proxy_build_auth_ztn, hands off to proxy_bs_queue_auth_frame.
 */
static ngx_int_t
proxy_bs_send_ztn(brix_proxy_ctx_t *proxy, const char *token,
    size_t token_len, const proxy_bs_auth_errs_t *errs)
{
    size_t  frame_len = 28 + token_len; /* hdr24 + "ztn\0" + jwt */
    u_char *frame     = ngx_palloc(proxy->conn->pool, frame_len);

    if (frame == NULL) {
        proxy_bs_auth_error(proxy, errs->up_inc, errs->oom_msg);
        return NGX_ERROR;
    }
    proxy_build_auth_ztn(frame, token, token_len);
    return proxy_bs_queue_auth_frame(proxy, frame, frame_len, errs);
}

/* send an SSS kXR_auth credential to the upstream * WHAT: Build an SSS credential from `key`, wrap it in a kXR_auth request, and
 *       arm the write side; advance bs_phase to BS_AUTH.
 * WHY:  Used by BOTH the kXR_authmore path and the kXR_ok login-sec-hint path
 *       (our own server advertises SSS via the latter), so the logic lives once.
 * HOW:  Returns NGX_OK once the frame is queued (caller must return), or
 *       NGX_ERROR after aborting the proxy on any failure. */
static ngx_int_t
proxy_send_sss_auth(brix_proxy_ctx_t *proxy, const brix_sss_key_t *key)
{
    static const proxy_bs_auth_errs_t  sss_errs = {
        "proxy: OOM for SSS frame",
        "proxy: SSS frame send failed",
        "proxy: write arm for SSS failed",
        1
    };
    u_char    cred[512];
    size_t    cred_len;
    u_char   *frame;
    size_t    frame_len;
    uint32_t  dlen_be;

    if (brix_sss_build_proxy_credential(key, key->user,
            cred, sizeof(cred), &cred_len) != NGX_OK)
    {
        proxy_bs_auth_error(proxy, 1, "proxy: SSS credential build failed");
        return NGX_ERROR;
    }

    frame_len = XRD_REQUEST_HDR_LEN + cred_len;
    frame = ngx_palloc(proxy->conn->pool, frame_len);
    if (frame == NULL) {
        proxy_bs_auth_error(proxy, 1, sss_errs.oom_msg);
        return NGX_ERROR;
    }

    /* kXR_auth request header: reqid at [2:3], credtype "sss\0" at [16:19]
     * (the server routes on this field — leaving it zero yields "unknown
     * credtype"), dlen at [20:23], SSS credential body after the 24-byte hdr. */
    ngx_memzero(frame, XRD_REQUEST_HDR_LEN);
    frame[2] = (kXR_auth >> 8) & 0xFF;
    frame[3] =  kXR_auth       & 0xFF;
    frame[16] = 's'; frame[17] = 's'; frame[18] = 's'; frame[19] = '\0';
    dlen_be = htonl((uint32_t) cred_len);
    ngx_memcpy(frame + 20, &dlen_be, 4);
    ngx_memcpy(frame + XRD_REQUEST_HDR_LEN, cred, cred_len);

    return proxy_bs_queue_auth_frame(proxy, frame, frame_len, &sss_errs);
}

/* per-mech auth-send arms (kXR_authmore path) */
/*
 * WHAT: FORWARD mode, preferred path — re-present the connecting client's
 *       WLCG bearer token verbatim to the upstream as a ztn credential.
 * WHY:  The client already authenticated to us with this token; forwarding
 *       it preserves the client identity end-to-end.
 * HOW:  Sources the token from client_ctx (caller verified it is non-empty)
 *       and delegates the frame build/send to proxy_bs_send_ztn.
 */
static void
proxy_bs_auth_forward_bearer(brix_proxy_ctx_t *proxy)
{
    static const proxy_bs_auth_errs_t  errs = {
        "proxy: OOM building auth frame",
        "proxy: auth frame send failed",
        "proxy: write arm for auth failed",
        1
    };
    const char *token = proxy->client_ctx->bearer_token;

    (void) proxy_bs_send_ztn(proxy, token, ngx_strlen(token), &errs);
}

/*
 * WHAT: FORWARD fallback — the client has no bearer token but
 *       brix_upstream_token_file is configured (credential bridge); read the
 *       token from the file and send it as a ztn credential.
 * WHY:  Lets an anonymous/GSI client traverse a token-authenticated upstream
 *       using a service credential.
 * HOW:  ftok is function-static (64 KiB) to keep it off the stack; safe
 *       because nginx workers are single-threaded on the event loop and the
 *       token is copied into the heap frame before any yield. Caller verified
 *       conf != NULL and the file directive is set.
 */
static void
proxy_bs_auth_token_file(brix_proxy_ctx_t *proxy)
{
    static const proxy_bs_auth_errs_t  errs = {
        "proxy: OOM for file token frame",
        "proxy: file token frame send failed",
        "proxy: write arm for file token failed",
        0
    };
    static u_char  ftok[PROXY_UPSTREAM_BEARER_MAX];
    size_t         flen = 0;

    if (brix_token_read_file(&proxy->conf->upstream_token_file,
                               ftok, sizeof(ftok), &flen,
                               proxy->client_conn->log,
                               "proxy authmore-file token") != NGX_OK
        || flen == 0)
    {
        proxy_bs_auth_error(proxy, 1,
            "upstream requires auth; set brix_upstream_token_file");
        return;
    }
    (void) proxy_bs_send_ztn(proxy, (const char *) ftok, flen, &errs);
}

/*
 * WHAT: Answer an upstream kXR_authmore by the configured auth policy —
 *       FORWARD client bearer, SSS shared secret, FORWARD token-file
 *       fallback, or abort when no mechanism applies.
 * WHY:  This is the per-mechanism dispatch of the bootstrap's do-auth step;
 *       each mechanism lives in its own helper so the selection order (the
 *       frozen behavior) reads as a flat ladder.
 * HOW:  Resolves the effective policy (per-upstream override wins), tries
 *       the arms in the historical order, always returns 1 (a frame was
 *       queued or the proxy was aborted; the caller must return).
 */
static int
proxy_bs_do_auth(brix_proxy_ctx_t *proxy)
{
    ngx_stream_brix_srv_conf_t  *conf = proxy->conf;
    ngx_uint_t                   eff_auth;
    const brix_sss_key_t        *eff_key;

    proxy_resolve_upstream_auth(proxy, &eff_auth, &eff_key);

    if (eff_auth == BRIX_PROXY_AUTH_FORWARD
        && proxy->client_ctx != NULL
        && proxy->client_ctx->bearer_token[0] != '\0')
    {
        proxy_bs_auth_forward_bearer(proxy);
        return 1;
    }

    if (eff_auth == BRIX_PROXY_AUTH_SSS && eff_key != NULL) {
        (void) proxy_send_sss_auth(proxy, eff_key);
        return 1;   /* frame queued, or proxy aborted on failure */
    }

    if (eff_auth == BRIX_PROXY_AUTH_FORWARD
        && conf != NULL
        && conf->upstream_token_file.len > 0)
    {
        proxy_bs_auth_token_file(proxy);
        return 1;
    }

    proxy_bs_auth_error(proxy, 1,
        "upstream requires authentication "
        "(set brix_proxy_auth forward or sss)");
    return 1;
}

/* login-sec hint arms (kXR_ok path) */
/*
 * WHAT: Proactive ztn send when the login response advertised "P=ztn" without
 *       a kXR_authmore. Source the token from the client bearer (FORWARD)
 *       first, else from the upstream token file.
 * WHY:  Token-only servers embed the challenge in the login reply; the client
 *       must send kXR_auth unprompted or the forwarded open is rejected.
 * HOW:  Returns 1 when a frame was queued (or the send aborted the proxy);
 *       0 when no token could be sourced and the caller should fall through.
 *       lftok is function-static (64 KiB) — same rationale as the authmore
 *       token-file arm.
 */
static int
proxy_bs_login_sec_ztn(brix_proxy_ctx_t *proxy)
{
    static const proxy_bs_auth_errs_t  errs = {
        "proxy: OOM for login-sec token frame",
        "proxy: login-sec token frame send failed",
        "proxy: write arm for login-sec failed",
        0
    };
    static u_char                lftok[PROXY_UPSTREAM_BEARER_MAX];
    ngx_stream_brix_srv_conf_t  *lconf      = proxy->conf;
    const char                  *ltoken     = NULL;
    size_t                       ltoken_len = 0;

    /* Prefer client's bearer token (FORWARD mode) */
    if (proxy->client_ctx != NULL
        && proxy->client_ctx->bearer_token[0] != '\0')
    {
        ltoken     = proxy->client_ctx->bearer_token;
        ltoken_len = ngx_strlen(ltoken);
    }
    /* Fallback: read from upstream_token_file */
    else if (lconf != NULL && lconf->upstream_token_file.len > 0) {
        size_t lflen = 0;
        if (brix_token_read_file(&lconf->upstream_token_file,
                                   lftok, sizeof(lftok), &lflen,
                                   proxy->client_conn->log,
                                   "proxy login-sec ztn") == NGX_OK
            && lflen > 0)
        {
            ltoken     = (const char *) lftok;
            ltoken_len = lflen;
        }
    }

    if (ltoken == NULL || ltoken_len == 0) {
        return 0;
    }
    (void) proxy_bs_send_ztn(proxy, ltoken, ltoken_len, &errs);
    return 1;
}

/*
 * WHAT: Scan the successful login reply for an embedded security hint and,
 *       if one matches our policy, proactively send the kXR_auth credential.
 * WHY:  Token-only servers embed a security challenge in the login response:
 *       [sessid:16][&P=ztn,v:10000] — and the nginx-xrootd server (and stock
 *       xrootd) advertise SSS the same way ("&P=sss,...") — NOT via
 *       kXR_authmore. Without this, SSS/ztn upstream auth silently never
 *       happens and the forwarded open is rejected NotAuthorized.
 * HOW:  The hint string follows the fixed 16-byte session id in the login
 *       body, so step past it before scanning. resp_body was NUL-padded by
 *       the read handler (alloc dlen+1), making strstr() safe here. Returns
 *       1 when an auth frame was issued (caller returns and waits for the
 *       BS_AUTH reply), 0 when the login phase is complete.
 */
static int
proxy_bs_login_sec_hint(brix_proxy_ctx_t *proxy)
{
    const char *parms;

    if (proxy->resp_dlen <= BRIX_SESSION_ID_LEN || proxy->resp_body == NULL) {
        return 0;
    }
    parms = (const char *)(proxy->resp_body + BRIX_SESSION_ID_LEN);

    if (strstr(parms, "P=sss") != NULL) {
        ngx_uint_t             sss_auth;
        const brix_sss_key_t  *sss_key;

        proxy_resolve_upstream_auth(proxy, &sss_auth, &sss_key);
        if (sss_auth == BRIX_PROXY_AUTH_SSS && sss_key != NULL) {
            (void) proxy_send_sss_auth(proxy, sss_key);
            return 1;   /* frame queued, or proxy aborted on failure */
        }
    }

    if (strstr(parms, "P=ztn") != NULL) {
        return proxy_bs_login_sec_ztn(proxy);
    }

    return 0;
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
 * RE-ENTRY: this is called by brix_proxy_read_handler each time a complete
 *       upstream frame arrives. Arms that send (AUTH legs) return early and are
 *       resumed by the next read event; non-sending arms fall through to the
 *       shared reset/finish tail. The auth-send arms (FORWARD bearer, SSS,
 *       FORWARD token-file fallback, login-sec hint) are structurally identical
 *       — build frame -> free+reset resp accumulator -> set wbuf -> flush ->
 *       arm write if partial -> return — and share proxy_bs_queue_auth_frame;
 *       they differ only in how the credential is sourced.
 */
/* BS_LOGIN bootstrap phase: handle the upstream login reply — kXR_authmore
 * (forward bearer / SSS / token-file), login failure, and the token-only
 * login-sec hint (proactive P=sss / P=ztn).  Returns 1 when it has issued a
 * frame or aborted and the caller must return; 0 when the phase is complete
 * (bs_phase advanced to DONE) and the caller falls through to the shared
 * reset/finish tail. */
static int
brix_proxy_bs_login(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_status == kXR_authmore) {
        /* Upstream requests authentication — handle by configured policy.
         * Effective policy: per-upstream override if set, else global
         * conf->proxy.auth. */
        return proxy_bs_do_auth(proxy);
    }

    if (proxy->resp_status != kXR_ok) {
        proxy_bs_auth_error(proxy, 1, "upstream login failed");
        return 1;
    }

    if (proxy_bs_login_sec_hint(proxy)) {
        return 1;
    }

    proxy->bs_phase = XRD_PX_BS_DONE;

    return 0;
}

/*
 * WHAT: Validate the upstream kXR_protocol reply (BS_PROTOCOL phase).
 * WHY:  kXR_protocol reply body: [4 bytes pval][4 bytes flags][...]. The
 *       server's capability flags live at body offset 4; kXR_gotoTLS there
 *       means the server wants the connection upgraded to TLS now. We only
 *       reach this code on a cleartext connection (TLS-from-start uses a
 *       different path), so an in-band upgrade request is unsupported.
 * HOW:  Returns NGX_OK when the reply is acceptable; NGX_ERROR after
 *       aborting the proxy (bad status or gotoTLS demand).
 */
static ngx_int_t
proxy_bs_check_protocol_reply(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_status != kXR_ok) {
        brix_proxy_abort(proxy, "upstream kXR_protocol failed");
        return NGX_ERROR;
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
            brix_proxy_abort(proxy,
                "upstream requires TLS upgrade after connect "
                "(use brix_proxy_upstream_tls on to start with TLS)");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Adopt the bootstrapped upstream connection into service — flip the
 *       proxy to IDLE, publish success metrics, restore failure budgets, and
 *       hand the fd over to whichever request is waiting.
 * WHY:  This is the single point where the upstream stops being "in
 *       bootstrap" and becomes usable by the client relay; keeping the
 *       transition in one helper freezes the handoff timing.
 * HOW:  Marks the upstream healthy, clears the consecutive-failure budget,
 *       refills the reconnect budget, then either forwards the request that
 *       was queued during bootstrap (dispatch_pending handles bound-secondary
 *       lazy-open) or resumes the client read loop.
 */
static void
proxy_bs_adopt_conn(brix_proxy_ctx_t *proxy)
{
    proxy->state = XRD_PX_IDLE;
    brix_proxy_up_mark_ok(proxy);
    BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connects_total);
    BRIX_PROXY_UP_INC(proxy, upstream_connects_total);

    /* The upstream accepted the forwarded credential — this connection is
     * healthy again, so clear the consecutive-failure budget. */
    if (proxy->client_ctx != NULL) {
        proxy->client_ctx->proxy_fail_count = 0;
    }

    /* Restore the full reconnect budget on every successful bootstrap */
    if (proxy->conf != NULL) {
        proxy->reconnect_left = (int) proxy->conf->proxy.reconnect_attempts;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                   "xrootd proxy: upstream bootstrap done");

    /* If a request was queued during bootstrap, forward it now.
     * brix_proxy_dispatch_pending handles bound-secondary lazy-open. */
    if (proxy->saved_req != NULL) {
        brix_proxy_dispatch_pending(proxy);
        return;
    }

    /* No deferred request — just resume the client read loop */
    {
        brix_ctx_t *ctx = proxy->client_ctx;
        ctx->state = XRD_ST_REQ_HEADER;
        brix_schedule_read_resume(proxy->client_conn);
    }
}

void
brix_proxy_handle_bootstrap(brix_proxy_ctx_t *proxy)
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
            brix_proxy_abort(proxy, "bad handshake from upstream");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_PROTOCOL;
        break;

    case XRD_PX_BS_PROTOCOL:
        if (proxy_bs_check_protocol_reply(proxy) != NGX_OK) {
            return;
        }
        proxy->bs_phase = XRD_PX_BS_LOGIN;
        break;

    case XRD_PX_BS_LOGIN:
        if (brix_proxy_bs_login(proxy)) {
            return;
        }
        break;

    case XRD_PX_BS_AUTH:
        if (proxy->resp_status != kXR_ok) {
            proxy_bs_auth_error(proxy, 1, "upstream rejected forwarded token");
            return;
        }
        proxy->bs_phase = XRD_PX_BS_DONE;
        break;

    default:
        brix_proxy_abort(proxy, "proxy: invalid bootstrap phase");
        return;
    }

    /* Shared tail: reached only by arms that fell through (i.e. did NOT issue a
     * send and return early). Reset the accumulator for whatever comes next. */
    /* Reset response accumulator for the next bootstrap message or first req */
    proxy_bs_reset_resp(proxy);

    if (proxy->bs_phase != XRD_PX_BS_DONE) {
        return;  /* caller (read_handler) will continue the loop */
    }

    /* Bootstrap complete — transition to IDLE */
    proxy_bs_adopt_conn(proxy);
}
