/*
 * login.c — kXR_login opcode handler + login-success metric.
 */

#include "ngx_xrootd_module.h"
#include "registry.h"
#include "compat/alloc_guard.h"

/* Atomically increment the LOGIN-success metric counter. */
static void
xrootd_count_login_ok(xrootd_ctx_t *ctx)
{
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->op_ok[XROOTD_OP_LOGIN], 1);
    }
}

/* Handle kXR_login — accept a client username, generate a session id (sessid),
 * and begin auth negotiation (advertising the configured security requirement). */
ngx_int_t
xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrdw_login_req_t    req;
    u_char             *buf;
    size_t              total;
    char                user[9];
    char                user_log[64];

    if (conf->cms_suspended) {
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "server suspended by manager");
    }

    /* The reference do_Login rejects a SECOND kXR_login on an already-logged-in
     * connection ("if (Status) return Response.Send(kXR_InvalidRequest,
     * \"duplicate login; already logged in\")", XrdXrootdXeq.cc:1095).  Match the
     * reference code and message verbatim.  (Note: installed stock v5.9.5 happens
     * to surface kXR_ArgMissing here, but the current reference source — and the
     * correct semantics for a malformed-in-context request — is kXR_InvalidRequest;
     * either way a live session cannot re-login.) */
    if (ctx->logged_in) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "duplicate login; already logged in");
    }

    xrdw_login_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);

    /* Username is an 8-byte fixed field on the wire, so copy and terminate it locally. */
    ngx_memcpy(user, req.username, 8);
    user[8] = '\0';

    /* Reject usernames with NUL bytes or non-printable ASCII.  A NUL in the
     * middle of the field silently truncates it when treated as a C string,
     * which could let "a\x00evil" impersonate user "a".  The XRootD spec
     * says the field is "null-padded ASCII"; enforce that here. */
    {
        int i;
        for (i = 0; i < 8 && user[i] != '\0'; i++) {
            if ((u_char) user[i] < 0x20 || (u_char) user[i] > 0x7e) {
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "username contains invalid characters");
            }
        }
    }

    ngx_memcpy(ctx->login_user, user, sizeof(ctx->login_user));
    ctx->login_pid = (uint32_t) req.pid;
    xrootd_sanitize_log_string(user, user_log, sizeof(user_log));

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d auth=%s",
                   user_log, (int) req.pid,
                   (conf->auth == XROOTD_AUTH_GSI) ? "gsi" :
                   (conf->auth == XROOTD_AUTH_TOKEN) ? "token" :
                   (conf->auth == XROOTD_AUTH_BOTH) ? "both" :
                   (conf->auth == XROOTD_AUTH_SSS) ? "sss" :
                   (conf->auth == XROOTD_AUTH_UNIX) ? "unix" :
                   (conf->auth == XROOTD_AUTH_KRB5) ? "krb5" : "none");

    /* Login marks the session as known; auth_done is deferred for GSI mode. */
    ctx->logged_in = 1;

    if (conf->auth == XROOTD_AUTH_NONE) {
        /* Anonymous mode completes login in one round-trip with only the sessid. */
        ctx->auth_done = 1;

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN;
        XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                              XROOTD_SESSION_ID_LEN,
                              (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
                   XROOTD_SESSION_ID_LEN);

        /* Session timing starts at successful login so later disconnect stats have an origin. */
        ctx->session_start = ngx_current_msec;
        if (ctx->identity != NULL) {
            ctx->identity->auth_method = XROOTD_AUTHN_NONE;
        }
        xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        xrootd_count_login_ok(ctx);

        return xrootd_queue_response(ctx, c, buf, total);
    }

    /*
     * Authenticated modes send a text parameter block after the 16-byte
     * session id.  The client parses "&P=..." entries to decide which
     * security plugin to load.
     */
    {
        char     parms[256];
        size_t   parms_len;
        unsigned gsi_ver;

        /* Re-fetch the live merged srv_conf in case login inherited settings. */
        conf = ngx_stream_get_module_srv_conf(ctx->session,
                                              ngx_stream_xrootd_module);

        /* Advertised GSI version drives the client's signed-DH decision:
         * >=XROOTD_GSI_VERS_DHSIGNED (10400) lets capable clients use the
         * RSA-signed-DH variant.  Default 10000 (unsigned, universally
         * compatible) unless the xrootd_gsi_signed_dh policy opts in. */
        gsi_ver = (conf->gsi_signed_dh != XROOTD_GSI_SDH_OFF) ? 10600u : 10000u;

        if (conf->auth == XROOTD_AUTH_TOKEN) {
            /* Token-only: advertise ztn, no CA hash needed. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=ztn,v:10000") + 1;
        } else if (conf->auth == XROOTD_AUTH_SSS) {
            /* XRootD SSS: bf32 ('0'), v2 server ('+'), client chooses keytab. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=sss,0.+%d:",
                                          (int) conf->sss_lifetime) + 1;
        } else if (conf->auth == XROOTD_AUTH_UNIX) {
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=unix") + 1;
        } else if (conf->auth == XROOTD_AUTH_KRB5) {
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=krb5,%s",
                                          (const char *) conf->krb5_principal.data)
                        + 1;
        } else if (conf->auth == XROOTD_AUTH_HOST) {
            /* Phase 52 WS-C: host auth asserts no credential — bare protocol id. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=host") + 1;
        } else if (conf->auth == XROOTD_AUTH_PWD) {
            /* Phase 52 WS-B: XrdSecpwd password protocol (v:10100, ssl crypto). */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=pwd,v:10100,c:ssl") + 1;
        } else if (conf->auth == XROOTD_AUTH_BOTH) {
            /* Both: token first (preferred), then GSI. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=ztn,v:10000&P=gsi,v:%u,c:ssl,ca:%08x",
                                          gsi_ver,
                                          (unsigned) conf->gsi_ca_hash) + 1;
        } else {
            /* GSI-only.  The advertised version drives the client's signed-DH
             * decision: >=10400 makes capable clients use the RSA-signed-DH
             * variant.  Defaults to 10000 (unsigned, universal) unless the
             * xrootd_gsi_signed_dh policy opts in. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=gsi,v:%u,c:ssl,ca:%08x",
                                          gsi_ver,
                                          (unsigned) conf->gsi_ca_hash) + 1;
        }

        /* Include the trailing NUL because clients treat the parameter block as C-string data. */
        if (parms_len > sizeof(parms)) {
            return xrootd_send_error(ctx, c, kXR_ServerError,
                                     "auth parameter block too long");
        }

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN + parms_len;
        XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                              (uint32_t)(XROOTD_SESSION_ID_LEN + parms_len),
                              (ServerResponseHdr *) buf);

        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
                   XROOTD_SESSION_ID_LEN);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN,
                   parms, parms_len);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: login->kXGS_init parms=\"%s\" ca_hash=%08xd",
                       parms, (unsigned) conf->gsi_ca_hash);

        /* Successful login still marks the start of the session even though auth continues. */
        ctx->session_start = ngx_current_msec;
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        xrootd_count_login_ok(ctx);

        return xrootd_queue_response(ctx, c, buf, total);
    }
}
