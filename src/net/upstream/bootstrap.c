#include "upstream_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */

/*
 * WHAT: XRootD upstream bootstrap sequence — handshake, protocol negotiation, TLS upgrade detection,
 *      and login authentication for transparent proxy mode.
 * WHY: When nginx connects to a backend XRootD server, it must complete the initial bootstrap protocol
 *      before sending client requests. This involves four phases in order: handshake (12 zero bytes +
 *      version markers), protocol request (streamid/kXR_protocol/kXR_PROTOCOLVERSION), TLS upgrade check
 *      (kXR_gotoTLS flag detection → ngx_ssl handshake callback), and login (pid/username/capver).
 *      kXR_authmore responses trigger token credential exchange via upstream_token_file.
 * HOW: brix_upstream_build_bootstrap() concatenates handshake zeros, protocol request struct, and
 *      login request struct into a single wire buffer. brix_upstream_handle_bootstrap_response()
 *      implements the state machine across XRD_UP_BS_HANDSHAKE → BS_PROTOCOL → BS_TLS (optional) →
 *      BS_LOGIN → BS_DONE, checking resp_status at each phase transition. bs_phase enum tracks current
 *      stage; on completion, brix_upstream_send_request() is called to forward the saved client request.
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>

/*
 * A server-internal connector owns a fixed streamid {0,1} and presents the
 * anonymous "xrd" identity with no TLS-capability flags in the protocol request
 * (TLS, when required, is driven by the server's kXR_gotoTLS response, not by a
 * client-side wantTLS flag). The wire layout itself lives in bootstrap_pack.h.
 */
static const uint8_t brix_upstream_streamid[2] = { 0, 1 };

void
brix_upstream_build_bootstrap(u_char *buf)
{
    u_char *cursor = buf;

    xrd_pack_handshake((ClientInitHandShake *) (void *) cursor);
    cursor += sizeof(ClientInitHandShake);

    xrd_pack_protocol_request((ClientProtocolRequest *) (void *) cursor,
                              brix_upstream_streamid, 0);
    cursor += sizeof(ClientProtocolRequest);

    xrd_pack_login_request((ClientLoginRequest *) (void *) cursor,
                           brix_upstream_streamid, (int32_t) ngx_pid,
                           "xrd", kXR_ver005);
}

/*
 * brix_upstream_build_login — fill a single kXR_login frame.
 *
 * Called after a kXR_gotoTLS upgrade to resend login over TLS; the server
 * discards the plaintext login that was pre-sent with the bootstrap buffer.
 */
void
brix_upstream_build_login(ClientLoginRequest *req)
{
    xrd_pack_login_request(req, brix_upstream_streamid, (int32_t) ngx_pid,
                           "xrd", kXR_ver005);
}

/*
 * brix_upstream_continue_auth — respond to a kXR_authmore challenge during the
 * outbound bootstrap (cache-fill origin), bounded by XRD_OBA_MAX_ROUNDS.
 *
 * WHAT: increments the per-connection authmore counter, aborts once it reaches the
 *   bound (hostile/misconfigured origin → no unbounded loop), else sends the ztn
 *   token credential and moves to the AUTH wait phase.
 * WHY: the origin's sec layer may issue more than one kXR_authmore; the former
 *   hard "second authmore → abort" both blocked any legitimate multi-round
 *   continuation and duplicated the LOGIN/AUTH handling. One bounded helper closes
 *   the hostile-loop security case and is the single seam a future GSI cache-fill
 *   continuation hooks into.
 * HOW: bound check → counter++ → require brix_upstream_token_file → delegate to
 *   brix_upstream_send_token_auth (which arms the next read in XRD_UP_BS_AUTH).
 *   Every failure path routes through brix_upstream_abort.
 */
static void
brix_upstream_continue_auth(brix_upstream_t *up)
{
    ngx_stream_brix_srv_conf_t *conf;

    if (up->authmore_count >= XRD_OBA_MAX_ROUNDS) {
        brix_upstream_abort(up,
            "upstream: too many kXR_authmore rounds (bounded)");
        return;
    }
    up->authmore_count++;

    conf = ngx_stream_get_module_srv_conf(
        up->client_ctx->session, ngx_stream_brix_module);

    if (conf->upstream_token_file.len == 0) {
        brix_upstream_abort(up,
            "upstream requires auth; set brix_upstream_token_file");
        return;
    }
    if (brix_upstream_send_token_auth(up, conf) != NGX_OK) {
        brix_upstream_abort(up, "upstream: token auth exchange failed");
    }
}

/*
 * Per-phase step contract: a phase handler returns NGX_OK when it has advanced
 * up->bs_phase and the shared tail (brix_upstream_bootstrap_advance) should run,
 * or NGX_DONE when it has already terminated the cycle itself — either by
 * aborting the connection or by deferring to a callback (TLS handshake, token
 * auth write/read) — in which case the caller must return without touching the
 * response buffers or read event.
 */

/*
 * brix_upstream_bs_handshake — phase 1, consume the server's fixed handshake
 * response.
 *
 * WHAT: fail the connection unless resp_status is kXR_ok, else advance to the
 *   protocol-negotiation phase.
 * WHY: no request payload is interpreted until the upstream confirms the
 *   handshake, so a bad status here is fatal.
 * HOW: status gate → set XRD_UP_BS_PROTOCOL → NGX_OK.
 */
static ngx_int_t
brix_upstream_bs_handshake(brix_upstream_t *up)
{
    if (up->resp_status != kXR_ok) {
        brix_upstream_abort(up, "upstream: bad handshake response");
        return NGX_DONE;
    }
    up->bs_phase = XRD_UP_BS_PROTOCOL;
    return NGX_OK;
}

/*
 * brix_upstream_bs_goto_tls — handle a kXR_gotoTLS flag seen in the protocol
 * response by upgrading the plaintext connection to TLS.
 *
 * WHAT: resolve the srv conf, then (when built with SSL) require an upstream TLS
 *   context and drive brix_upstream_start_tls; without SSL support the request
 *   is fatal.
 * WHY: TLS is server-driven (kXR_gotoTLS), not client-requested; the kXR_login
 *   frame already pre-sent in the socket buffer is discarded by the server and
 *   is resent over TLS from the handshake callback.
 * HOW: get conf → SSL-gated capability check → start_tls; always returns
 *   NGX_DONE because the cycle either aborts or resumes in the TLS callback.
 */
static ngx_int_t
brix_upstream_bs_goto_tls(brix_upstream_t *up)
{
    ngx_stream_brix_srv_conf_t *conf;

    conf = ngx_stream_get_module_srv_conf(
        up->client_ctx->session, ngx_stream_brix_module);

#if (NGX_SSL)
    if (!conf->upstream_tls || conf->upstream_tls_ctx == NULL) {
        brix_upstream_abort(up,
            "upstream requires TLS; set brix_upstream_tls on");
        return NGX_DONE;
    }
    if (brix_upstream_start_tls(up, conf) != NGX_OK) {
        brix_upstream_abort(up, "upstream: TLS upgrade failed");
    }
#else
    (void) conf;
    brix_upstream_abort(up,
        "upstream requires TLS but nginx was built without SSL");
#endif
    return NGX_DONE;  /* resume in TLS handshake callback (or aborted) */
}

/*
 * brix_upstream_bs_protocol — phase 2, protocol negotiation and TLS-upgrade
 * detection.
 *
 * WHAT: fail unless resp_status is kXR_ok; if the response carries the flags
 *   word (dlen >= 8) and it sets kXR_gotoTLS, hand off to the TLS upgrade path,
 *   otherwise advance to the login phase.
 * WHY: the server signals a mandatory TLS upgrade via a flag in the protocol
 *   response; only after ruling that out is a plaintext login valid.
 * HOW: status gate → extract big-endian flags at offset 4 → gotoTLS branch →
 *   else set XRD_UP_BS_LOGIN → NGX_OK.
 */
static ngx_int_t
brix_upstream_bs_protocol(brix_upstream_t *up)
{
    if (up->resp_status != kXR_ok) {
        brix_upstream_abort(up, "upstream: protocol response not ok");
        return NGX_DONE;
    }
    if (up->resp_dlen >= 8) {
        uint32_t flags_be;

        ngx_memcpy(&flags_be, up->resp_body + 4, sizeof(flags_be));

        if (ntohl(flags_be) & kXR_gotoTLS) {
            return brix_upstream_bs_goto_tls(up);
        }
    }
    up->bs_phase = XRD_UP_BS_LOGIN;
    return NGX_OK;
}

/*
 * brix_upstream_bs_login — phase 3, evaluate the login response.
 *
 * WHAT: a kXR_authmore status continues the bounded credential exchange; a
 *   non-ok status is fatal; kXR_ok advances to the done phase.
 * WHY: the origin's sec layer may demand a token round before granting login;
 *   only a clean kXR_ok means the session is ready to carry client requests.
 * HOW: authmore → brix_upstream_continue_auth (defer) → status gate → set
 *   XRD_UP_BS_DONE → NGX_OK.
 */
static ngx_int_t
brix_upstream_bs_login(brix_upstream_t *up)
{
    if (up->resp_status == kXR_authmore) {
        brix_upstream_continue_auth(up);
        return NGX_DONE;  /* resume after write + read cycle */
    }
    if (up->resp_status != kXR_ok) {
        brix_upstream_abort(up, "upstream: login failed");
        return NGX_DONE;
    }
    up->bs_phase = XRD_UP_BS_DONE;
    return NGX_OK;
}

/*
 * brix_upstream_bs_auth — phase 4, evaluate the kXR_auth response after a ztn
 * token credential was sent.
 *
 * WHAT: kXR_ok → authenticated, advance to done; kXR_authmore → the origin wants
 *   another bounded round (XRD_OBA_MAX_ROUNDS) rather than an outright failure;
 *   anything else → reject.
 * WHY: multi-round token exchanges are legitimate but must stay bounded so a
 *   hostile/misconfigured origin cannot loop us forever.
 * HOW: authmore → brix_upstream_continue_auth (defer) → status gate → set
 *   XRD_UP_BS_DONE → NGX_OK.
 */
static ngx_int_t
brix_upstream_bs_auth(brix_upstream_t *up)
{
    if (up->resp_status == kXR_authmore) {
        brix_upstream_continue_auth(up);
        return NGX_DONE;
    }
    if (up->resp_status != kXR_ok) {
        brix_upstream_abort(up, "upstream: token auth rejected by server");
        return NGX_DONE;
    }
    up->bs_phase = XRD_UP_BS_DONE;
    return NGX_OK;
}

/*
 * brix_upstream_bootstrap_advance — shared tail after a phase advances.
 *
 * WHAT: reset the response-frame cursors, then either send the saved client
 *   request (bootstrap complete) or re-arm the read event for the next phase.
 * WHY: every successful phase transition needs a fresh frame buffer, and epoll
 *   ET mode can leave already-buffered bytes without a new EPOLLIN — a synthetic
 *   posted read event drains them in the current loop cycle.
 * HOW: zero the cursors → XRD_UP_BS_DONE branch sends the request → else arm the
 *   read event and post a synthetic read.
 */
static void
brix_upstream_bootstrap_advance(brix_upstream_t *up)
{
    up->rhdr_pos = 0;
    up->resp_dlen = 0;
    up->resp_body = NULL;
    up->resp_body_pos = 0;

    if (up->bs_phase == XRD_UP_BS_DONE) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "brix: upstream bootstrap done; sending request");
        if (brix_upstream_send_request(up) == NGX_ERROR) {
            brix_upstream_abort(up, "upstream: send request failed");
        }
        return;
    }

    if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
        brix_upstream_abort(up, "upstream: read event arm failed");
        return;
    }
    /* In epoll ET mode, if multiple bootstrap responses arrived in the same
     * TCP segment, the remaining data in the socket buffer won't re-trigger
     * EPOLLIN.  Post a synthetic read event so the next phase is processed
     * in the current event-loop cycle rather than waiting for new data. */
    ngx_post_event(up->conn->read, &ngx_posted_events);
}

/*
 * brix_upstream_handle_bootstrap_response — bootstrap state-machine dispatcher.
 *
 * WHAT: route the current bs_phase to its handler; on a clean advance run the
 *   shared tail, otherwise let the handler's own termination stand.
 * WHY: keeps the four wire phases (handshake → protocol/TLS → login → auth) as
 *   independent, testable stages while preserving the exact original transitions
 *   and error paths.
 * HOW: switch on bs_phase → per-phase helper returns NGX_OK (advanced) or
 *   NGX_DONE (already terminated) → NGX_OK runs brix_upstream_bootstrap_advance.
 */
void
brix_upstream_handle_bootstrap_response(brix_upstream_t *up)
{
    ngx_int_t rc;

    switch (up->bs_phase) {

    case XRD_UP_BS_HANDSHAKE:
        rc = brix_upstream_bs_handshake(up);
        break;

    case XRD_UP_BS_PROTOCOL:
        rc = brix_upstream_bs_protocol(up);
        break;

    case XRD_UP_BS_TLS:
        /*
         * Should not arrive here: the TLS handshake callback transitions
         * directly to XRD_UP_BS_LOGIN before arming the read event.
         */
        brix_upstream_abort(up, "upstream: unexpected read in TLS phase");
        return;

    case XRD_UP_BS_LOGIN:
        rc = brix_upstream_bs_login(up);
        break;

    case XRD_UP_BS_AUTH:
        rc = brix_upstream_bs_auth(up);
        break;

    default:
        brix_upstream_abort(up, "upstream: invalid bootstrap phase");
        return;
    }

    if (rc != NGX_OK) {
        return;  /* handler aborted or deferred to a callback */
    }

    brix_upstream_bootstrap_advance(up);
}
