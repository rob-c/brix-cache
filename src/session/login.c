#include "../ngx_xrootd_module.h"
#include "registry.h"

/*
 * kXR_login - accept the username and advertise any required auth exchange.
 *
 * Anonymous sessions complete here.  GSI/token sessions return the server
 * session id plus a plugin parameter block; kXR_auth then finishes the auth
 * state machine in the GSI/token sources.
 */

static void
xrootd_count_login_ok(xrootd_ctx_t *ctx)
{
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->op_ok[XROOTD_OP_LOGIN], 1);
    }
}

ngx_int_t
xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientLoginRequest *req;
    u_char             *buf;
    size_t              total;
    char                user[9];
    char                user_log[64];

    if (conf->cms_suspended) {
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "server suspended by manager");
    }

    req = (ClientLoginRequest *) ctx->hdr_buf;

    /* Username is an 8-byte fixed field on the wire, so copy and terminate it locally. */
    ngx_memcpy(user, req->username, 8);
    user[8] = '\0';
    ngx_memcpy(ctx->login_user, user, sizeof(ctx->login_user));
    ctx->login_pid = (uint32_t) ntohl(req->pid);
    xrootd_sanitize_log_string(user, user_log, sizeof(user_log));

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d auth=%s",
                   user_log, (int) ntohl(req->pid),
                   (conf->auth == XROOTD_AUTH_GSI) ? "gsi" :
                   (conf->auth == XROOTD_AUTH_TOKEN) ? "token" :
                   (conf->auth == XROOTD_AUTH_BOTH) ? "both" :
                   (conf->auth == XROOTD_AUTH_SSS) ? "sss" : "none");

    /* Login marks the session as known; auth_done is deferred for GSI mode. */
    ctx->logged_in = 1;

    if (conf->auth == XROOTD_AUTH_NONE) {
        /* Anonymous mode completes login in one round-trip with only the sessid. */
        ctx->auth_done = 1;

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN;
        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                              XROOTD_SESSION_ID_LEN,
                              (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
                   XROOTD_SESSION_ID_LEN);

        /* Session timing starts at successful login so later disconnect stats have an origin. */
        ctx->session_start = ngx_current_msec;
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
        char   parms[256];
        size_t parms_len;

        /* Re-fetch the live merged srv_conf in case login inherited settings. */
        conf = ngx_stream_get_module_srv_conf(ctx->session,
                                              ngx_stream_xrootd_module);

        if (conf->auth == XROOTD_AUTH_TOKEN) {
            /* Token-only: advertise ztn, no CA hash needed. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=ztn,v:10000") + 1;
        } else if (conf->auth == XROOTD_AUTH_SSS) {
            /* XRootD SSS: bf32 ('0'), v2 server ('+'), client chooses keytab. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=sss,0.+%d:",
                                          (int) conf->sss_lifetime) + 1;
        } else if (conf->auth == XROOTD_AUTH_BOTH) {
            /* Both: token first (preferred), then GSI. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=ztn,v:10000&P=gsi,v:10000,c:ssl,ca:%08x",
                                          (unsigned) conf->gsi_ca_hash) + 1;
        } else {
            /* GSI-only */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=gsi,v:10000,c:ssl,ca:%08x",
                                          (unsigned) conf->gsi_ca_hash) + 1;
        }

        /* Include the trailing NUL because clients treat the parameter block as C-string data. */

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN + parms_len;
        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return NGX_ERROR;
        }

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
