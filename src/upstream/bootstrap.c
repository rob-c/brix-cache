#include "upstream_internal.h"
#include "protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */

/*
 * WHAT: XRootD upstream bootstrap sequence — handshake, protocol negotiation, TLS upgrade detection,
 *      and login authentication for transparent proxy mode.
 * WHY: When nginx connects to a backend XRootD server, it must complete the initial bootstrap protocol
 *      before sending client requests. This involves four phases in order: handshake (12 zero bytes +
 *      version markers), protocol request (streamid/kXR_protocol/kXR_PROTOCOLVERSION), TLS upgrade check
 *      (kXR_gotoTLS flag detection → ngx_ssl handshake callback), and login (pid/username/capver).
 *      kXR_authmore responses trigger token credential exchange via upstream_token_file.
 * HOW: xrootd_upstream_build_bootstrap() concatenates handshake zeros, protocol request struct, and
 *      login request struct into a single wire buffer. xrootd_upstream_handle_bootstrap_response()
 *      implements the state machine across XRD_UP_BS_HANDSHAKE → BS_PROTOCOL → BS_TLS (optional) →
 *      BS_LOGIN → BS_DONE, checking resp_status at each phase transition. bs_phase enum tracks current
 *      stage; on completion, xrootd_upstream_send_request() is called to forward the saved client request.
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
static const uint8_t xrootd_upstream_streamid[2] = { 0, 1 };

void
xrootd_upstream_build_bootstrap(u_char *buf)
{
    u_char *cursor = buf;

    xrd_pack_handshake((ClientInitHandShake *) (void *) cursor);
    cursor += sizeof(ClientInitHandShake);

    xrd_pack_protocol_request((ClientProtocolRequest *) (void *) cursor,
                              xrootd_upstream_streamid, 0);
    cursor += sizeof(ClientProtocolRequest);

    xrd_pack_login_request((ClientLoginRequest *) (void *) cursor,
                           xrootd_upstream_streamid, (int32_t) ngx_pid,
                           "xrd", kXR_ver005);
}

/*
 * xrootd_upstream_build_login — fill a single kXR_login frame.
 *
 * Called after a kXR_gotoTLS upgrade to resend login over TLS; the server
 * discards the plaintext login that was pre-sent with the bootstrap buffer.
 */
void
xrootd_upstream_build_login(ClientLoginRequest *req)
{
    xrd_pack_login_request(req, xrootd_upstream_streamid, (int32_t) ngx_pid,
                           "xrd", kXR_ver005);
}

/*
 * xrootd_upstream_continue_auth — respond to a kXR_authmore challenge during the
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
 * HOW: bound check → counter++ → require xrootd_upstream_token_file → delegate to
 *   xrootd_upstream_send_token_auth (which arms the next read in XRD_UP_BS_AUTH).
 *   Every failure path routes through xrootd_upstream_abort.
 */
static void
xrootd_upstream_continue_auth(xrootd_upstream_t *up)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    if (up->authmore_count >= XRD_OBA_MAX_ROUNDS) {
        xrootd_upstream_abort(up,
            "upstream: too many kXR_authmore rounds (bounded)");
        return;
    }
    up->authmore_count++;

    conf = ngx_stream_get_module_srv_conf(
        up->client_ctx->session, ngx_stream_xrootd_module);

    if (conf->upstream_token_file.len == 0) {
        xrootd_upstream_abort(up,
            "upstream requires auth; set xrootd_upstream_token_file");
        return;
    }
    if (xrootd_upstream_send_token_auth(up, conf) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream: token auth exchange failed");
    }
}

void
xrootd_upstream_handle_bootstrap_response(xrootd_upstream_t *up)
{
    switch (up->bs_phase) {

    case XRD_UP_BS_HANDSHAKE:
        /*
         * Phase 1 consumes the server's fixed handshake response.  No request
         * payload is interpreted until the upstream confirms the handshake.
         */
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: bad handshake response");
            return;
        }
        up->bs_phase = XRD_UP_BS_PROTOCOL;
        break;

    case XRD_UP_BS_PROTOCOL: {
        ngx_stream_xrootd_srv_conf_t *conf;

        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: protocol response not ok");
            return;
        }
        if (up->resp_dlen >= 8) {
            uint32_t flags_be;

            ngx_memcpy(&flags_be, up->resp_body + 4, sizeof(flags_be));

            if (ntohl(flags_be) & kXR_gotoTLS) {
                conf = ngx_stream_get_module_srv_conf(
                    up->client_ctx->session, ngx_stream_xrootd_module);

#if (NGX_SSL)
                if (!conf->upstream_tls || conf->upstream_tls_ctx == NULL) {
                    xrootd_upstream_abort(up,
                        "upstream requires TLS; set xrootd_upstream_tls on");
                    return;
                }
                /*
                 * Upgrade the existing plaintext connection to TLS.
                 * The kXR_login frame already in the socket buffer is
                 * discarded by the server upon receiving gotoTLS; we resend
                 * it over TLS from the handshake callback.
                 */
                if (xrootd_upstream_start_tls(up, conf) != NGX_OK) {
                    xrootd_upstream_abort(up,
                        "upstream: TLS upgrade failed");
                }
#else
                (void) conf;
                xrootd_upstream_abort(up,
                    "upstream requires TLS but nginx was built without SSL");
#endif
                return;  /* resume in TLS handshake callback */
            }
        }
        up->bs_phase = XRD_UP_BS_LOGIN;
        break;
    }

    case XRD_UP_BS_TLS:
        /*
         * Should not arrive here: the TLS handshake callback transitions
         * directly to XRD_UP_BS_LOGIN before arming the read event.
         */
        xrootd_upstream_abort(up, "upstream: unexpected read in TLS phase");
        return;

    case XRD_UP_BS_LOGIN:
        if (up->resp_status == kXR_authmore) {
            xrootd_upstream_continue_auth(up);
            return;  /* resume after write + read cycle */
        }
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: login failed");
            return;
        }
        up->bs_phase = XRD_UP_BS_DONE;
        break;

    case XRD_UP_BS_AUTH:
        /*
         * kXR_auth response after we sent a ztn token credential.
         *   kXR_ok       → authenticated, proceed to send the request.
         *   kXR_authmore → the origin wants another round; continue the bounded
         *                  exchange (XRD_OBA_MAX_ROUNDS) rather than fail outright.
         *   anything else → reject.
         */
        if (up->resp_status == kXR_authmore) {
            xrootd_upstream_continue_auth(up);
            return;
        }
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: token auth rejected by server");
            return;
        }
        up->bs_phase = XRD_UP_BS_DONE;
        break;

    default:
        xrootd_upstream_abort(up, "upstream: invalid bootstrap phase");
        return;
    }

    up->rhdr_pos = 0;
    up->resp_dlen = 0;
    up->resp_body = NULL;
    up->resp_body_pos = 0;

    if (up->bs_phase == XRD_UP_BS_DONE) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "xrootd: upstream bootstrap done; sending request");
        if (xrootd_upstream_send_request(up) == NGX_ERROR) {
            xrootd_upstream_abort(up, "upstream: send request failed");
        }
        return;
    }

    if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream: read event arm failed");
        return;
    }
    /* In epoll ET mode, if multiple bootstrap responses arrived in the same
     * TCP segment, the remaining data in the socket buffer won't re-trigger
     * EPOLLIN.  Post a synthetic read event so the next phase is processed
     * in the current event-loop cycle rather than waiting for new data. */
    ngx_post_event(up->conn->read, &ngx_posted_events);
}
