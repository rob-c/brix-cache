#include "upstream_internal.h"

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

static u_char *
xrootd_upstream_write_be32(u_char *cursor, uint32_t value)
{
    uint32_t value_be;

    value_be = htonl(value);
    ngx_memcpy(cursor, &value_be, sizeof(value_be));

    return cursor + sizeof(value_be);
}

void
xrootd_upstream_build_bootstrap(u_char *buf)
{
    u_char *cursor;

    cursor = buf;

    /*
     * XRootD's initial server handshake is not a normal request header.  The
     * client sends 12 zero bytes followed by two big-endian words:
     *   client protocol version marker, ROOTD protocol selector.
     *
     * Use memcpy-based stores so this remains safe on platforms that dislike
     * unaligned uint32_t writes.
     */
    ngx_memzero(cursor, 12);
    cursor += 12;
    cursor = xrootd_upstream_write_be32(cursor, 4);
    cursor = xrootd_upstream_write_be32(cursor, ROOTD_PQ);

    {
        ClientProtocolRequest *protocol_request;

        protocol_request = (ClientProtocolRequest *) (void *) cursor;

        ngx_memzero(protocol_request, sizeof(*protocol_request));
        protocol_request->streamid[0] = 0;
        protocol_request->streamid[1] = 1;
        protocol_request->requestid = htons(kXR_protocol);
        protocol_request->clientpv = htonl(kXR_PROTOCOLVERSION);
        protocol_request->flags = 0;
        protocol_request->expect = 0x03;
        protocol_request->dlen = 0;
        cursor += sizeof(*protocol_request);
    }

    {
        ClientLoginRequest *login_request;

        login_request = (ClientLoginRequest *) (void *) cursor;

        ngx_memzero(login_request, sizeof(*login_request));
        login_request->streamid[0] = 0;
        login_request->streamid[1] = 1;
        login_request->requestid = htons(kXR_login);
        login_request->pid = htonl((kXR_int32) ngx_pid);
        login_request->username[0] = 'x';
        login_request->username[1] = 'r';
        login_request->username[2] = 'd';
        login_request->capver = kXR_ver005;
        login_request->dlen = 0;
    }
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
    ngx_memzero(req, sizeof(*req));
    req->streamid[0] = 0;
    req->streamid[1] = 1;
    req->requestid = htons(kXR_login);
    req->pid = htonl((kXR_int32) ngx_pid);
    req->username[0] = 'x';
    req->username[1] = 'r';
    req->username[2] = 'd';
    req->capver = kXR_ver005;
    req->dlen = 0;
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

    case XRD_UP_BS_LOGIN: {
        ngx_stream_xrootd_srv_conf_t *conf;

        if (up->resp_status == kXR_authmore) {
            if (up->authmore_count > 0) {
                xrootd_upstream_abort(up,
                    "upstream: repeated kXR_authmore (not supported)");
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
                xrootd_upstream_abort(up,
                    "upstream: token auth exchange failed");
            }
            return;  /* resume after write + read cycle */
        }
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: login failed");
            return;
        }
        up->bs_phase = XRD_UP_BS_DONE;
        break;
    }

    case XRD_UP_BS_AUTH:
        /*
         * kXR_auth response after we sent a ztn token credential.
         * kXR_ok → authenticated, proceed to send request.
         * Anything else (including a second kXR_authmore) → abort.
         */
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
    }
}
