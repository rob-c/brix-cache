#include "../ngx_xrootd_module.h"

/* ------------------------------------------------------------------ */
/* Protocol Negotiation — kXR_protocol handler                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_protocol opcode — the first XRootD request after raw TCP handshake. It negotiates server capabilities including protocol version, available authentication protocols (GSI/token/SSS), and TLS upgrade support. The response body contains a fixed ServerProtocolBody struct plus optional SecurityInfo trailer when the client advertises security negotiation capability flags.
 *
 * WHY: Protocol negotiation determines which authentication flow follows (kXR_auth for GSI or token) and whether in-protocol TLS can be requested (kXR_wantTLS → kXR_ableTLS). Without this exchange, clients would not know what capabilities to expect from the server, potentially sending unsupported opcodes or attempting TLS on non-TLS listeners. The server also advertises its manager mode status (kXR_isManager flag) and security signing level requirements.
 *
 * HOW: Four-phase response assembly → parse client capability flags from body[4] byte → determine available auth protocols based on conf->auth directive → check TLS availability (conf->tls + tls_ctx + client kXR_ableTLS/kXR_wantTLS flag) → reject if client demands TLS but server has none configured → build fixed 8-byte ServerProtocolBody with version flags → append optional SecurityInfo trailer when kXR_secreqs flag set → queue response via xrootd_queue_response(). TLS upgrade pending state (ctx->tls_pending=1) is set when offer_tls=true. */

/* ------------------------------------------------------------------ */
/* Section: Protocol Body Construction                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: The fixed ServerProtocolBody contains four fields encoded as big-endian integers:
 *      pval = protocol version number, flags = server capability bitmask (kXR_isServer | kXR_isManager | kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin). These are the first eight bytes of every protocol reply body.
 *
 * WHY: Provides clients with a standardized capability advertisement before authentication begins. The flags determine which subsequent opcodes the client should attempt — for example, kXR_ableTLS in the flag tells the client that kXR_wantTLS is available after login.
 *
 * HOW: Server sets body.pval = htonl(kXR_PROTOCOLVERSION) and body.flags from conf->auth/manager/tls state → ngx_memcpy into response buffer at XRD_RESPONSE_HDR_LEN offset. This 8-byte prefix always precedes the optional SecurityInfo trailer. */

/* ------------------------------------------------------------------ */
/* Section: Security Info Trailer (kXR_secreqs)                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Optional SecurityInfo trailer appended when client advertises kXR_secreqs capability. Contains four sections: header byte indicating security presence, count of protocol entries, eight-byte entries per available auth method (sss/ztng/gsi), and ServerResponseReqs_Protocol structure specifying signing level requirements.
 *
 * WHY: Allows clients to determine which authentication plugin to load after login. The sec_count determines how many 8-byte entries follow; each entry uses three ASCII characters identifying the method plus four reserved bytes (zero). The seclvl field maps to conf->security_level enum values controlling subsequent opcode signing requirements.
 *
 * HOW: Server computes sec_count from available auth methods → writes SecurityInfo header (4 bytes) at offset bodylen+XRD_RESPONSE_HDR_LEN → appends 8-byte entries per method in order sss/ztng/gsi → adds ServerResponseReqs_Protocol with seclvl = conf->security_level → returns complete response via xrootd_queue_response(). */

/* ---- Function: xrootd_handle_protocol() ----
 *
 * WHAT: Handles the kXR_protocol opcode — negotiates server capabilities by building a fixed 8-byte ServerProtocolBody response with protocol version, capability flags (kXR_isServer | manager mode | TLS support), and optional SecurityInfo trailer when client advertises security negotiation. Advertises available auth protocols based on conf->auth directive (GSI/token/SSS). Rejects requests if client demands TLS but server has none configured. Sets ctx->tls_pending=1 when in-protocol TLS upgrade is available.
 *
 * WHY: Determines the authentication flow and transport capabilities for subsequent requests. Without protocol negotiation, clients would not know what auth methods or security signing levels are available, potentially attempting unsupported opcodes or failing to request necessary TLS upgrades. The SecurityInfo trailer enables clients to select their preferred authentication plugin (GSI proxy cert vs JWT bearer token vs SSS shared secret).
 *
 * HOW: Four-phase response → parse client flags from body[4] byte → determine auth availability from conf->auth enum → check TLS offer based on config + client kXR_ableTLS/kXR_wantTLS flag → reject if client demands TLS but server lacks it → build ServerProtocolBody with version + capability flags → append SecurityInfo trailer when kXR_secreqs set (sec_count entries per available method) → queue response via xrootd_queue_response(). ctx->tls_pending=1 set when offer_tls=true. */

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
    int                 want_unix;
    int                 want_krb5;
    int                 client_wants_tls;
    int                 offer_tls;

    /* kXR_protocol packs client capability flags into the fifth byte of body[]. */
    client_flags = ctx->cur_body[4];
    want_gsi = (conf->auth == XROOTD_AUTH_GSI
                || conf->auth == XROOTD_AUTH_BOTH);
    want_token = (conf->auth == XROOTD_AUTH_TOKEN
                  || conf->auth == XROOTD_AUTH_BOTH);
    want_sss = (conf->auth == XROOTD_AUTH_SSS);
    want_unix = (conf->auth == XROOTD_AUTH_UNIX);
    want_krb5 = (conf->auth == XROOTD_AUTH_KRB5);

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
                      + (want_sss ? 1 : 0) + (want_unix ? 1 : 0)
                      + (want_krb5 ? 1 : 0);
        bodylen += 4;                            /* SecurityInfo header */
        bodylen += (size_t) sec_count * 8;       /* 8 bytes per SecurityProtocol entry */
        bodylen += 6;                            /* ServerResponseReqs_Protocol */
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
            /* kXR_recoverWrts intentionally absent: requires kXR_attn write
               journal (not yet implemented) — setting it prematurely would
               cause clients to double-write on reconnect. */
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
                      + (want_krb5 ? 1 : 0);
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
                   want_gsi && want_token ? "both" :
                   want_gsi ? "gsi" :
                   want_token ? "token" : "none",
                   offer_tls);

    if (offer_tls) {
        ctx->tls_pending = 1;
    }

    return xrootd_queue_response(ctx, c, buf, total);
}
