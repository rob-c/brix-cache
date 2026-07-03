/*
 * protocol.c — kXR_protocol opcode handler (capability negotiation).
 */

#include "core/ngx_brix_module.h"
#include "core/compat/alloc_guard.h"

/*
 * kXR_protocol - negotiate protocol version, auth protocols, and TLS support.
 *
 * This is the first XRootD request after the raw handshake.  It does not log a
 * user in; it only advertises server capabilities and, when configured, arms
 * the native TLS upgrade for the following login/auth flow.
 */
/* Handle kXR_protocol — negotiate server capabilities by building the fixed
 * 8-byte ServerProtocolBody response (protocol version, flags, and the security
 * requirement advertised to the client). */
ngx_int_t
brix_handle_protocol(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ServerProtocolBody  body;
    u_char             *buf;
    size_t              bodylen, total;
    u_char              client_flags;
    int                 want_gsi;
    int                 want_token;
    int                 want_sss;
    int                 want_unix;
    int                 want_krb5;
    int                 want_host;
    int                 want_pwd;
    int                 client_wants_tls;
    int                 offer_tls;

    /* kXR_protocol packs client capability flags into the fifth byte of body[]. */
    client_flags = ctx->cur_body[4];
    want_gsi = (conf->auth == BRIX_AUTH_GSI
                || conf->auth == BRIX_AUTH_BOTH);
    want_token = (conf->auth == BRIX_AUTH_TOKEN
                  || conf->auth == BRIX_AUTH_BOTH);
    want_sss = (conf->auth == BRIX_AUTH_SSS);
    want_unix = (conf->auth == BRIX_AUTH_UNIX);
    want_krb5 = (conf->auth == BRIX_AUTH_KRB5);
    want_host = (conf->auth == BRIX_AUTH_HOST);
    want_pwd = (conf->auth == BRIX_AUTH_PWD);

    /* kXR_wantTLS: client requires TLS; kXR_ableTLS: client is TLS-capable. */
    client_wants_tls = (client_flags & kXR_wantTLS) ? 1 : 0;
    offer_tls = (conf->tls && conf->tls_ctx != NULL
                 && (client_flags & (kXR_ableTLS | kXR_wantTLS)));

    /* Reject if the client demands TLS but this listener has none configured. */
    if (client_wants_tls && (!conf->tls || conf->tls_ctx == NULL)) {
        return brix_send_error(ctx, c, kXR_TLSRequired,
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
                      + (want_sss ? 1 : 0) + (want_unix ? 1 : 0)
                      + (want_krb5 ? 1 : 0) + (want_host ? 1 : 0)
                      + (want_pwd ? 1 : 0);
        bodylen += 4;                            /* SecurityInfo header */
        bodylen += (size_t) sec_count * 8;       /* 8 bytes per SecurityProtocol entry */
        bodylen += 6;                            /* ServerResponseReqs_Protocol */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                          (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    body.pval = htonl(kXR_PROTOCOLVERSION);
    {
        uint32_t caps = kXR_isServer
            | kXR_suppgrw   /* pgread/pgwrite always implemented */
            | kXR_supposc   /* POSC always implemented */
            | ((conf->manager_map || conf->manager_mode) ? kXR_isManager : 0)
            | (conf->supervisor
                   ? (kXR_isManager | kXR_attrSuper) : 0)
            | ((conf->virtual_redirector
                || (conf->manager_map != NULL && conf->cms_addr == NULL))
                   ? (kXR_isManager | kXR_attrVirtRdr) : 0)
            | (conf->metadata_only ? kXR_attrMeta : 0)
            | ((conf->proxy_enable > 0 || conf->proxy_upstreams != NULL)
                   ? kXR_attrProxy : 0)
            | ((conf->cache_root.len > 0 || conf->cache_origin_host.len > 0)
                   ? kXR_attrCache : 0)
            | (conf->collapse_redir ? kXR_collapseRedir : 0)
            | (conf->recover_writes ? kXR_recoverWrts : 0)
            | (offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0);
        body.flags = htonl(caps);
    }

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
                      + (want_sss ? 1 : 0) + (want_unix ? 1 : 0)
                      + (want_krb5 ? 1 : 0) + (want_host ? 1 : 0)
                      + (want_pwd ? 1 : 0);
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
            if (want_unix) {
                pe[0] = 'u'; pe[1] = 'n'; pe[2] = 'i'; pe[3] = 'x';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_krb5) {
                pe[0] = 'k'; pe[1] = 'r'; pe[2] = 'b'; pe[3] = '5';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_host) {
                pe[0] = 'h'; pe[1] = 'o'; pe[2] = 's'; pe[3] = 't';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_pwd) {
                pe[0] = 'p'; pe[1] = 'w'; pe[2] = 'd'; pe[3] = ' ';
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
                pe += 8;
            }

            /* ServerResponseReqs_Protocol — signing level requirements.
             * Always present when kXR_secreqs is set; seclvl=0 means none. */
            pe[0] = 'S';                              /* theTag  */
            pe[1] = 0;                                /* rsvd    */
            pe[2] = 0;                                /* secver (kXR_secver_0) */
            pe[3] = (conf->security_level >= 4) ? kXR_secOData : 0; /* secopt */
            pe[4] = (u_char) conf->security_level;    /* seclvl  */
            pe[5] = 0;                                /* secvsz=0: no secvec */
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_protocol ok (client_flags=0x%02xd "
                   "bodylen=%uz auth=%s tls=%d)",
                   (int) client_flags, bodylen,
                   want_sss ? "sss" :
                   want_unix ? "unix" :
                   want_krb5 ? "krb5" :
                   want_host ? "host" :
                   want_pwd ? "pwd" :
                   want_gsi && want_token ? "both" :
                   want_gsi ? "gsi" :
                   want_token ? "token" : "none",
                   offer_tls);

    if (offer_tls) {
        ctx->tls_pending = 1;
    }

    return brix_queue_response(ctx, c, buf, total);
}
