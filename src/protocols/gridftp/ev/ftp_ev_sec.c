#include "ftp_ev.h"

#include "core/types/identity.h"
#include "auth/gssapi/gsi_mech.h"

#include <strings.h>   /* strcasecmp */

/*
 * ftp_ev_sec.c — RFC 2228 GSI security handshake on the control channel:
 * AUTH GSSAPI, the ADAT token exchange, and the MIC/CONF/ENC protected-command
 * unwrap.
 *
 * WHAT: stand up the mem-BIO GSSAPI engine on AUTH, feed each ADAT token through
 * it until the handshake completes, then bind the verified proxy DN into a
 * brix_identity_t and switch the control channel to GSS-wrapped replies.
 *
 * WHY: the security handshake is the one part of the protocol that is *already*
 * event-compatible — brix_gssapi_srv_step() is token-driven, not socket-driven:
 * each ADAT command line carries one handshake token and the reply carries the
 * next, so no inline TLS I/O is needed on the control channel.  That lets the
 * event engine reach GSI parity here with no state-machine surgery; only the
 * PROT P *data* channel needs event-driven TLS (P82.3).
 *
 * HOW: ported from the sync engine's ftp_cmd_auth/adat/protected + ftp_gss_finalize,
 * writing through the event reply queue.  The pre-auth handshake replies
 * (334/335/235) go out cleartext because ->sec_active is still 0; finalize flips
 * it so every subsequent reply is wrapped.
 */


/* After AUTH GSSAPI completes, bind the verified proxy DN into a brix_identity_t
 * (so the VFS ctx and audit see a real GSI principal), capture any delegated
 * credential, and activate the wrapped control channel. */
static void
ev_gss_finalize(ftp_ev_t *fc)
{
    ngx_str_t        dn = { 0, NULL }, proxy = { 0, NULL };
    brix_identity_t *id;

    if (brix_gssapi_srv_peer(fc->gss, &dn, &proxy) == NGX_OK && dn.len > 0) {
        id = brix_identity_alloc(fc->c->pool);
        if (id != NULL) {
            char   dbuf[512];
            size_t n = ngx_min(dn.len, sizeof(dbuf) - 1);
            ngx_memcpy(dbuf, dn.data, n);
            dbuf[n] = '\0';
            if (brix_identity_set_dn(id, fc->c->pool, dbuf, BRIX_AUTHN_GSI)
                == NGX_OK)
            {
                fc->identity = id;
            }
        }
        fc->deleg_proxy = proxy;
        fc->ctrl_dn.data = ngx_pnalloc(fc->c->pool, dn.len);
        if (fc->ctrl_dn.data != NULL) {
            ngx_memcpy(fc->ctrl_dn.data, dn.data, dn.len);
            fc->ctrl_dn.len = dn.len;
        }
        /* the client's control leaf is the delegated proxy's direct issuer;
         * needed to present a complete chain on a PROT P data channel. */
        (void) brix_gssapi_srv_peer_cert_pem(fc->gss, &fc->ctrl_leaf_pem);
        fc->authed = 1;
        ngx_log_error(NGX_LOG_INFO, fc->c->log, 0,
                      "brix: GridFTP(ev) gsiftp authenticated dn=\"%V\" deleg=%uz",
                      &dn, proxy.len);
    }
    fc->wrap_code  = "633";              /* default: private (ENC) replies      */
    fc->sec_active = 1;
}


/* AUTH GSSAPI: stand up the mem-BIO engine and invite ADAT tokens (334). */
ngx_int_t
brix_ftp_ev_cmd_auth(ftp_ev_t *fc, const char *arg)
{
    if (!fc->conf->gsi || fc->conf->tls_ctx == NULL
        || fc->conf->tls_ctx->ctx == NULL)
    {
        return brix_ftp_ev_reply(fc, "534 Security mechanism not available\r\n");
    }
    if (strcasecmp(arg, "GSSAPI") != 0) {
        return brix_ftp_ev_reply(fc, "504 Unknown security mechanism %s\r\n", arg);
    }
    if (fc->gss != NULL) {
        return brix_ftp_ev_reply(fc,
            "534 Security handshake already in progress\r\n");
    }
    fc->gss = brix_gssapi_srv_create(fc->c->pool, fc->c->log,
        fc->conf->tls_ctx->ctx, fc->conf->ca_store, 1 /* accept delegation */);
    if (fc->gss == NULL) {
        return brix_ftp_ev_reply(fc, "431 GSSAPI context init failed\r\n");
    }
    return brix_ftp_ev_reply(fc,
        "334 Using authentication type GSSAPI; ADAT must follow\r\n");
}


/* ADAT: feed one decoded token to the engine and reply 335 (continue) or 235
 * (complete, then switch on the wrapped control channel). */
ngx_int_t
brix_ftp_ev_cmd_adat(ftp_ev_t *fc, const char *arg)
{
    ngx_str_t         tok, out;
    brix_gss_status_e st;

    if (fc->gss == NULL) {
        return brix_ftp_ev_reply(fc, "503 Send AUTH GSSAPI first\r\n");
    }
    if (brix_ftp_ev_b64_decode(fc->c->pool, arg, &tok) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "501 Malformed ADAT token\r\n");
    }

    st = brix_gssapi_srv_step(fc->gss, tok.data, tok.len, &out);
    if (st == BRIX_GSS_FAILED) {
        return brix_ftp_ev_reply(fc, "535 GSSAPI authentication failed\r\n");
    }
    if (st == BRIX_GSS_CONTINUE) {
        return brix_ftp_ev_send_adat(fc, 335, &out);
    }

    /* COMPLETE: emit the final 235 cleartext, THEN activate wrapping.  A final
     * token is framed "235 ADAT=<b64>"; with none, send a bare completion line
     * (an empty "ADAT=" would decode to a zero-length token and fail the client). */
    if (out.len > 0) {
        if (brix_ftp_ev_send_adat(fc, 235, &out) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (brix_ftp_ev_reply(fc, "235 GSSAPI authentication succeeded\r\n")
               != NGX_OK)
    {
        return NGX_ERROR;
    }
    ev_gss_finalize(fc);
    return NGX_OK;
}


/* MIC/CONF/ENC: unwrap a protected command and re-dispatch its plaintext.  The
 * safety code chosen here also frames the reply(ies) that command emits. */
ngx_int_t
brix_ftp_ev_cmd_protected(ftp_ev_t *fc, const char *code, const char *arg)
{
    ngx_str_t  tok, inner;
    char      *innerline;
    size_t     n;

    if (fc->gss == NULL || !fc->sec_active) {
        return brix_ftp_ev_reply(fc, "503 Not authenticated\r\n");
    }
    fc->wrap_code = code;
    if (brix_ftp_ev_b64_decode(fc->c->pool, arg, &tok) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "501 Malformed protected token\r\n");
    }
    if (brix_gssapi_unwrap(fc->gss, tok.data, tok.len, &inner) != NGX_OK
        || inner.len == 0)
    {
        return brix_ftp_ev_reply(fc, "535 Cannot decode protected command\r\n");
    }
    innerline = ngx_pnalloc(fc->c->pool, BRIX_FTP_EV_CMD_MAX);
    if (innerline == NULL) {
        return NGX_ERROR;
    }
    n = ngx_min(inner.len, (size_t) BRIX_FTP_EV_CMD_MAX - 1);
    ngx_memcpy(innerline, inner.data, n);
    while (n > 0 && (innerline[n - 1] == '\r' || innerline[n - 1] == '\n')) {
        n--;
    }
    innerline[n] = '\0';
    return brix_ftp_ev_dispatch(fc, innerline);
}
