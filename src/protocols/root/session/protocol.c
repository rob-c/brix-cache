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

/* WHAT: decoded client request + the server-side auth/TLS wants derived from it.
 * WHY:  the negotiation is a flag matrix over (client capability byte, configured
 *       auth mode, TLS availability); collecting the decoded flags in one struct
 *       lets each helper take a single explicit parameter instead of ten ints.
 * HOW:  filled once by protocol_parse_client_req(), then read-only everywhere. */
typedef struct {
    u_char  client_flags;      /* fifth byte of the kXR_protocol body        */
    int     gsi;               /* offer "gsi " SecurityProtocol entry        */
    int     token;             /* offer "ztn " SecurityProtocol entry        */
    int     sss;               /* offer "sss " SecurityProtocol entry        */
    int     unx;               /* offer "unix" SecurityProtocol entry        */
    int     krb5;              /* offer "krb5" SecurityProtocol entry        */
    int     host;              /* offer "host" SecurityProtocol entry        */
    int     pwd;               /* offer "pwd " SecurityProtocol entry        */
    int     client_wants_tls;  /* client set kXR_wantTLS (TLS is mandatory)  */
    int     offer_tls;         /* server can and will offer the TLS upgrade  */
} protocol_want_t;

/* WHAT: decode the kXR_protocol request into a protocol_want_t.
 * WHY:  isolates the request-byte decode and conf->auth fan-out so the handler
 *       body only deals with negotiation and response assembly.
 * HOW:  reads the client capability byte from the received body, maps the
 *       configured auth mode onto the per-protocol offer flags, and computes
 *       the two TLS decisions from the client flags + listener TLS config. */
static void
protocol_parse_client_req(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, protocol_want_t *want)
{
    /* kXR_protocol packs client capability flags into the fifth byte of body[]. */
    want->client_flags = ctx->recv.cur_body[4];
    want->gsi = (conf->auth == BRIX_AUTH_GSI
                 || conf->auth == BRIX_AUTH_BOTH);
    want->token = (conf->auth == BRIX_AUTH_TOKEN
                   || conf->auth == BRIX_AUTH_BOTH);
    want->sss = (conf->auth == BRIX_AUTH_SSS);
    want->unx = (conf->auth == BRIX_AUTH_UNIX);
    want->krb5 = (conf->auth == BRIX_AUTH_KRB5);
    want->host = (conf->auth == BRIX_AUTH_HOST);
    want->pwd = (conf->auth == BRIX_AUTH_PWD);

    /* kXR_wantTLS: client requires TLS; kXR_ableTLS: client is TLS-capable. */
    want->client_wants_tls = (want->client_flags & kXR_wantTLS) ? 1 : 0;
    want->offer_tls = (conf->tls && conf->tls_ctx != NULL
                       && (want->client_flags & (kXR_ableTLS | kXR_wantTLS)));
}

/* WHAT: number of SecurityProtocol entries the SecurityInfo trailer will carry.
 * WHY:  needed twice (body-length computation and trailer header) — computing
 *       it in one place keeps the two in lockstep.
 * HOW:  pure count over the offer flags. */
static int
protocol_sec_count(const protocol_want_t *want)
{
    return (want->gsi ? 1 : 0) + (want->token ? 1 : 0)
         + (want->sss ? 1 : 0) + (want->unx ? 1 : 0)
         + (want->krb5 ? 1 : 0) + (want->host ? 1 : 0)
         + (want->pwd ? 1 : 0);
}

/* WHAT: the server-role capability bits (manager/supervisor/redirector/meta/
 *       proxy/cache) for the ServerProtocolBody flags word.
 * WHY:  splits the role half of the capability bit-ladder out of the
 *       negotiation so each half stays a small pure expression.
 * HOW:  pure mapping from the merged server conf; no side effects. */
static uint32_t
protocol_role_flags(const ngx_stream_brix_srv_conf_t *conf)
{
    return ((conf->manager_map || conf->manager_mode) ? kXR_isManager : 0)
        | (conf->caps.supervisor
               ? (kXR_isManager | kXR_attrSuper) : 0)
        | ((conf->caps.virtual_redirector
            || (conf->manager_map != NULL && conf->cms.addr == NULL))
               ? (kXR_isManager | kXR_attrVirtRdr) : 0)
        | (conf->caps.metadata_only ? kXR_attrMeta : 0)
        | ((conf->proxy.enable > 0 || conf->proxy.upstreams != NULL)
               ? kXR_attrProxy : 0)
        | ((conf->cache_root.len > 0 || conf->cache_origin_host.len > 0)
               ? kXR_attrCache : 0);
}

/* WHAT: the full ServerProtocolBody flags word (host-order).
 * WHY:  the capability advertisement is the heart of kXR_protocol; keeping it
 *       one pure expression makes the negotiated bit-set reviewable at a glance.
 * HOW:  fixed server bits | role bits | per-conf feature bits | TLS bits. */
static uint32_t
protocol_negotiate_flags(const ngx_stream_brix_srv_conf_t *conf,
    const protocol_want_t *want)
{
    return kXR_isServer
        | kXR_suppgrw   /* pgread/pgwrite always implemented */
        | kXR_supposc   /* POSC always implemented */
        | protocol_role_flags(conf)
        | (conf->caps.collapse_redir ? kXR_collapseRedir : 0)
        | (conf->caps.recover_writes ? kXR_recoverWrts : 0)
        | (want->offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0);
}

/* WHAT: write one 8-byte SecurityProtocol entry (4-char tag + 4 zero bytes).
 * WHY:  the trailer emits up to seven identically-shaped entries; one writer
 *       replaces seven copies of the byte layout.
 * HOW:  copies the fixed 4-byte tag, zeroes the reserved tail, returns the
 *       advanced cursor so callers chain entries linearly. */
static u_char *
protocol_sec_entry_write(u_char *pe, const char tag[4])
{
    pe[0] = (u_char) tag[0]; pe[1] = (u_char) tag[1];
    pe[2] = (u_char) tag[2]; pe[3] = (u_char) tag[3];
    pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
    return pe + 8;
}

/* WHAT: write the SecurityInfo trailer (header + protocol entries + signing
 *       requirements) at si.
 * WHY:  the trailer is only present when the client set kXR_secreqs; hoisting
 *       it keeps the handler's response assembly linear.
 * HOW:  emits the 4-byte SecurityInfo header, one entry per offered auth
 *       protocol in the fixed wire order (sss, unix, krb5, host, pwd, ztn,
 *       gsi), then the 6-byte ServerResponseReqs_Protocol signing block.
 *       The caller sized the buffer with protocol_sec_count(). */
static void
protocol_write_sec_trailer(const ngx_stream_brix_srv_conf_t *conf,
    const protocol_want_t *want, u_char *si)
{
    int     sec_count = protocol_sec_count(want);
    u_char *pe;

    /*
     * SecurityInfo header:
     *   byte 1 advertises whether security is required,
     *   byte 2 is the number of following protocol entries.
     * bytes 0 and 3 are left zero because this implementation does not use
     * any of the optional legacy fields encoded there.
     */
    si[0] = 0;
    si[1] = sec_count > 0 ? 0x01 : 0x00;
    si[2] = (u_char) sec_count;
    si[3] = 0;

    pe = si + 4;
    if (want->sss) {
        pe = protocol_sec_entry_write(pe, "sss ");
    }
    if (want->unx) {
        pe = protocol_sec_entry_write(pe, "unix");
    }
    if (want->krb5) {
        pe = protocol_sec_entry_write(pe, "krb5");
    }
    if (want->host) {
        pe = protocol_sec_entry_write(pe, "host");
    }
    if (want->pwd) {
        pe = protocol_sec_entry_write(pe, "pwd ");
    }
    if (want->token) {
        pe = protocol_sec_entry_write(pe, "ztn ");
    }
    if (want->gsi) {
        pe = protocol_sec_entry_write(pe, "gsi ");
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

#if (NGX_DEBUG)
/* WHAT: short auth-mode label for the kXR_protocol debug log line.
 * WHY:  keeps the nine-way ternary chain out of the handler's log call.
 *       Debug-build only — its sole caller is ngx_log_debug4, which compiles
 *       out without NGX_DEBUG and would leave this unused under -Werror.
 * HOW:  pure priority chain over the offer flags — identical ordering to the
 *       historical inline expression so the logged string never changes. */
static const char *
protocol_auth_label(const protocol_want_t *want)
{
    return want->sss ? "sss" :
           want->unx ? "unix" :
           want->krb5 ? "krb5" :
           want->host ? "host" :
           want->pwd ? "pwd" :
           want->gsi && want->token ? "both" :
           want->gsi ? "gsi" :
           want->token ? "token" : "none";
}
#endif

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
    protocol_want_t     want;

    protocol_parse_client_req(ctx, conf, &want);

    /* Reject if the client demands TLS but this listener has none configured. */
    if (want.client_wants_tls && (!conf->tls || conf->tls_ctx == NULL)) {
        return brix_send_error(ctx, c, kXR_TLSRequired,
                                 "TLS required by client but not configured on this server");
    }

    /*
     * Base kXR_protocol reply is the fixed 8-byte ServerProtocolBody.
     * If the client advertised security negotiation support, append the small
     * SecurityInfo trailer describing which auth protocols we offer.
     */
    bodylen = sizeof(body);
    if (want.client_flags & kXR_secreqs) {
        bodylen += 4;                                            /* SecurityInfo header */
        bodylen += (size_t) protocol_sec_count(&want) * 8;       /* 8 bytes per SecurityProtocol entry */
        bodylen += 6;                                            /* ServerResponseReqs_Protocol */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                          (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    body.pval = htonl(kXR_PROTOCOLVERSION);
    body.flags = htonl(protocol_negotiate_flags(conf, &want));

    /* Fixed 8-byte prefix every protocol reply starts with after the response header. */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (want.client_flags & kXR_secreqs) {
        protocol_write_sec_trailer(conf, &want,
                                   buf + XRD_RESPONSE_HDR_LEN + sizeof(body));
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_protocol ok (client_flags=0x%02xd "
                   "bodylen=%uz auth=%s tls=%d)",
                   (int) want.client_flags, bodylen,
                   protocol_auth_label(&want),
                   want.offer_tls);

    if (want.offer_tls) {
        ctx->tls_pending = 1;
    }

    return brix_queue_response(ctx, c, buf, total);
}
