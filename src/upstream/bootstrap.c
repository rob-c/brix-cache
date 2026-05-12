#include "upstream_internal.h"

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

    case XRD_UP_BS_PROTOCOL:
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: protocol response not ok");
            return;
        }
        if (up->resp_dlen >= 8) {
            uint32_t flags_be;

            ngx_memcpy(&flags_be, up->resp_body + 4, sizeof(flags_be));
            /*
             * This forwarding path is intentionally plaintext-only today.
             * Abort instead of silently forwarding credentials to a server that
             * requested TLS upgrade semantics we do not implement.
             */
            if (ntohl(flags_be) & kXR_gotoTLS) {
                xrootd_upstream_abort(up,
                    "upstream requires TLS (not supported on outbound)");
                return;
            }
        }
        up->bs_phase = XRD_UP_BS_LOGIN;
        break;

    case XRD_UP_BS_LOGIN:
        /*
         * Upstream auth negotiation would require proxy credentials and more
         * state.  For now, only unauthenticated upstream storage endpoints are
         * accepted by this forwarding path.
         */
        if (up->resp_status == kXR_authmore) {
            xrootd_upstream_abort(up,
                "upstream requires authentication (not supported)");
            return;
        }
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: login failed");
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
