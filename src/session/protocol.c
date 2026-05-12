#include "../ngx_xrootd_module.h"

/*
 * kXR_protocol - negotiate protocol version, auth protocols, and TLS support.
 *
 * This is the first XRootD request after the raw handshake.  It does not log a
 * user in; it only advertises server capabilities and, when configured, arms
 * the native TLS upgrade for the following login/auth flow.
 */
ngx_int_t
xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ServerProtocolBody  body;
    u_char             *buf;
    size_t              bodylen, total;
    u_char              client_flags;
    int                 want_gsi;
    int                 want_token;
    int                 want_sss;
    int                 client_wants_tls;
    int                 offer_tls;

    /* kXR_protocol packs client capability flags into the fifth byte of body[]. */
    client_flags = ctx->cur_body[4];
    want_gsi = (conf->auth == XROOTD_AUTH_GSI
                || conf->auth == XROOTD_AUTH_BOTH);
    want_token = (conf->auth == XROOTD_AUTH_TOKEN
                  || conf->auth == XROOTD_AUTH_BOTH);
    want_sss = (conf->auth == XROOTD_AUTH_SSS);

    /* kXR_wantTLS: client requires TLS; kXR_ableTLS: client is TLS-capable. */
    client_wants_tls = (client_flags & kXR_wantTLS) ? 1 : 0;
    offer_tls = (conf->tls && conf->tls_ctx != NULL
                 && (client_flags & (kXR_ableTLS | kXR_wantTLS)));

    /* Reject if the client demands TLS but this listener has none configured. */
    if (client_wants_tls && (!conf->tls || conf->tls_ctx == NULL)) {
        return xrootd_send_error(ctx, c, kXR_TLSRequired,
                                 "TLS required by client but not configured on this server");
    }

    /*
     * Base kXR_protocol reply is the fixed 8-byte ServerProtocolBody.
     * If the client advertised security negotiation support, append the small
     * SecurityInfo trailer describing which auth protocols we offer.
     */
    bodylen = sizeof(body);
    if (client_flags & kXR_secreqs) {
        int sec_count = (want_gsi ? 1 : 0) + (want_token ? 1 : 0)
                      + (want_sss ? 1 : 0);
        bodylen += 4;                            /* SecurityInfo header */
        bodylen += (size_t) sec_count * 8;       /* 8 bytes per SecurityProtocol entry */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                          (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    body.pval = htonl(kXR_PROTOCOLVERSION);
    body.flags = htonl(kXR_isServer
                       | ((conf->manager_map || conf->manager_mode) ? kXR_isManager : 0)
                       | (offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0));

    /* Fixed 8-byte prefix every protocol reply starts with after the response header. */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (client_flags & kXR_secreqs) {
        /*
         * SecurityInfo header:
         *   byte 1 advertises whether security is required,
         *   byte 2 is the number of following protocol entries.
         * bytes 0 and 3 are left zero because this implementation does not use
         * any of the optional legacy fields encoded there.
         */
        u_char *si = buf + XRD_RESPONSE_HDR_LEN + sizeof(body);
        int sec_count = (want_gsi ? 1 : 0) + (want_token ? 1 : 0)
                      + (want_sss ? 1 : 0);
        si[0] = 0;
        si[1] = sec_count > 0 ? 0x01 : 0x00;
        si[2] = (u_char) sec_count;
        si[3] = 0;
        {
            u_char *pe = si + 4;
            if (want_sss) {
                pe[0] = 's'; pe[1] = 's'; pe[2] = 's'; pe[3] = ' ';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_token) {
                pe[0] = 'z'; pe[1] = 't'; pe[2] = 'n'; pe[3] = ' ';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_gsi) {
                pe[0] = 'g'; pe[1] = 's'; pe[2] = 'i'; pe[3] = ' ';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
            }
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_protocol ok (client_flags=0x%02xd "
                   "bodylen=%uz auth=%s tls=%d)",
                   (int) client_flags, bodylen,
                   want_sss ? "sss" :
                   want_gsi && want_token ? "both" :
                   want_gsi ? "gsi" :
                   want_token ? "token" : "none",
                   offer_tls);

    if (offer_tls) {
        ctx->tls_pending = 1;
    }

    return xrootd_queue_response(ctx, c, buf, total);
}
