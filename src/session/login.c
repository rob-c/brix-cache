#include "../ngx_xrootd_module.h"
#include "registry.h"

/* ------------------------------------------------------------------ */
/* Session Login — kXR_login opcode handler                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_login request — the first step of session
 *       establishment where the client presents a username and the server assigns
 *       a session ID. After login, GSI/token/SSS clients proceed to kXR_auth for
 *       actual credential verification; anonymous clients complete immediately.
 *
 * WHY: Login is mandatory before any file operation regardless of auth mode. It
 *      establishes the session identity (sessid) and begins tracking session-level
 *      metrics (bytes_read/written, duration). In CMS manager mode, login also triggers
 *      server registration with the central registry if not already bound.
 *
 * HOW: Three phases:
 *      1. CMS suspension check — reject login if manager has suspended this server
 *      2. Parse username (8-byte fixed field) and PID from ClientLoginRequest wire format
 *      3. Generate session ID, set logged_in=1, then branch based on auth mode:
 *         - NONE: complete immediately with sessid only
 *         - GSI/SSS/TOKEN/BOTH: return sessid + parameter block advertising required plugin */

/* ------------------------------------------------------------------ */
/* Section: Login Success Counter                                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Helper function that atomically increments the LOGIN success counter in
 *       the metrics subsystem. Called after every successful login regardless of auth mode.
 *
 * WHY: Provides production-level visibility into authentication throughput — helps detect
 *      suspicious patterns (e.g., many failed logins followed by a sudden spike) and capacity planning.
 *
 * HOW: Uses ngx_atomic_fetch_add for thread-safe counter increment without locks. */

static void
xrootd_count_login_ok(xrootd_ctx_t *ctx)
{
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->op_ok[XROOTD_OP_LOGIN], 1);
    }
}

/* ---- Function: xrootd_handle_login() ----
 *
 * WHAT: Handles the kXR_login opcode — accepts a client username, generates a session ID (sessid),
 *       sets logged_in=1, and returns either just the sessid (anonymous mode) or sessid + parameter
 *       block advertising required auth plugin (GSI/token/SSS modes). After login, GSI clients proceed
 *       to kXR_auth for certificate verification; anonymous clients can immediately begin file operations.
 *
 * WHY: Login is mandatory before any XRootD operation regardless of authentication mode. It establishes
 *      session identity, begins tracking session-level metrics (bytes_read/written/duration), and in CMS
 *      manager mode triggers server registry registration if not already bound to a data server.
 *
 * HOW: Three-phase flow → CMS suspension check → username/PID parse from 8-byte wire field → sessid
 *      generation + logged_in=1 → auth-mode branch (NONE=sessid-only, GSI/SSS/TOKEN/BOTH=sessid+params) →
 *      session registration + access-log entry + counter increment. */

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
    ctx->login_pid = (uint32_t) ntohl(req->pid);
    xrootd_sanitize_log_string(user, user_log, sizeof(user_log));

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d auth=%s",
                   user_log, (int) ntohl(req->pid),
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
        } else if (conf->auth == XROOTD_AUTH_UNIX) {
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=unix") + 1;
        } else if (conf->auth == XROOTD_AUTH_KRB5) {
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                                          "&P=krb5,%s",
                                          (const char *) conf->krb5_principal.data)
                        + 1;
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
        if (parms_len > sizeof(parms)) {
            return xrootd_send_error(ctx, c, kXR_ServerError,
                                     "auth parameter block too long");
        }

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
