/*
 * login.c — kXR_login opcode handler + login-success metric.
 */

#include "core/ngx_brix_module.h"
#include "registry.h"
#include "core/compat/alloc_guard.h"
#include "observability/sesslog/sesslog_ngx.h"

/* Atomically increment the LOGIN-success metric counter. */
static void
brix_count_login_ok(brix_ctx_t *ctx)
{
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->op_ok[BRIX_OP_LOGIN], 1);
    }
}

/*
 * WHAT: Validate the 8-byte fixed username field copied off the wire.
 * WHY:  A NUL in the middle silently truncates the field when treated as a C
 *       string, letting "a\x00evil" impersonate user "a"; the XRootD spec says
 *       the field is "null-padded ASCII", so reject NUL-embedded / non-printable
 *       bytes.  Isolating the scan keeps the caller's control flow flat.
 * HOW:  Scan the up-to-8 leading non-NUL bytes; on the first out-of-range byte
 *       emit the exact kXR_ArgInvalid refusal and return NGX_DONE so the caller
 *       stops (brix_send_error itself returns NGX_OK, which must NOT continue).
 *       Returns NGX_OK when every byte is printable ASCII.
 */
static ngx_int_t
brix_login_check_username(brix_ctx_t *ctx, ngx_connection_t *c,
    const char user[9])
{
    int i;

    for (i = 0; i < 8 && user[i] != '\0'; i++) {
        if ((u_char) user[i] < 0x20 || (u_char) user[i] > 0x7e) {
            brix_send_error(ctx, c, kXR_ArgInvalid,
                            "username contains invalid characters");
            return NGX_DONE;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Run the pre-response login preconditions and parse the request into
 *       ctx->login (username, pid) plus a sanitized copy for logging.
 * WHY:  These checks (suspended, duplicate login, username validity) all short-
 *       circuit with an exact wire refusal before any response is built; keeping
 *       them together preserves the reference ordering and messages verbatim.
 * HOW:  On any refusal, emit the exact error and return NGX_DONE (brix_send_error
 *       returns NGX_OK, which must not fall through).  On success populate
 *       ctx->login, mark the session logged_in, emit the debug trace, and return
 *       NGX_OK.  `user`/`user_log` are caller-owned so the response stage can log.
 */
static ngx_int_t
brix_login_precheck_and_parse(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, char user[9], char user_log[64])
{
    xrdw_login_req_t    req;
    ngx_int_t           rc;

    if (conf->cms.suspended) {
        brix_send_error(ctx, c, kXR_Overloaded, "server suspended by manager");
        return NGX_DONE;
    }

    /* The reference do_Login rejects a SECOND kXR_login on an already-logged-in
     * connection ("if (Status) return Response.Send(kXR_InvalidRequest,
     * \"duplicate login; already logged in\")", XrdXrootdXeq.cc:1095).  Match the
     * reference code and message verbatim.  (Note: installed stock v5.9.5 happens
     * to surface kXR_ArgMissing here, but the current reference source — and the
     * correct semantics for a malformed-in-context request — is kXR_InvalidRequest;
     * either way a live session cannot re-login.) */
    if (ctx->login.logged_in) {
        brix_send_error(ctx, c, kXR_InvalidRequest,
                        "duplicate login; already logged in");
        return NGX_DONE;
    }

    xrdw_login_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);

    /* Username is an 8-byte fixed field on the wire, so copy and terminate it locally. */
    ngx_memcpy(user, req.username, 8);
    user[8] = '\0';

    rc = brix_login_check_username(ctx, c, user);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memcpy(ctx->login.user, user, sizeof(ctx->login.user));
    ctx->login.pid = (uint32_t) req.pid;
    brix_sanitize_log_string(user, user_log, 64);

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: login user=\"%s\" pid=%d auth=%s",
                   user_log, (int) req.pid,
                   (conf->auth == BRIX_AUTH_GSI) ? "gsi" :
                   (conf->auth == BRIX_AUTH_TOKEN) ? "token" :
                   (conf->auth == BRIX_AUTH_BOTH) ? "both" :
                   (conf->auth == BRIX_AUTH_SSS) ? "sss" :
                   (conf->auth == BRIX_AUTH_UNIX) ? "unix" :
                   (conf->auth == BRIX_AUTH_KRB5) ? "krb5" : "none");

    /* Login marks the session as known; auth_done is deferred for GSI mode. */
    ctx->login.logged_in = 1;

    return NGX_OK;
}

/*
 * WHAT: Emit the anonymous-mode login response (sessid only, single round-trip).
 * WHY:  BRIX_AUTH_NONE completes login immediately with no auth negotiation, so
 *       its response, session registration, and access log differ from the
 *       authenticated path and are kept separate for clarity.
 * HOW:  Mark auth_done, build the kXR_ok header + sessid body, record session
 *       start/identity, register the session, log access, count the metric, and
 *       queue the response (returning whatever brix_queue_response returns).
 */
static ngx_int_t
brix_login_respond_anon(brix_ctx_t *ctx, ngx_connection_t *c, const char *user)
{
    u_char *buf;
    size_t  total;

    /* Anonymous mode completes login in one round-trip with only the sessid. */
    ctx->login.auth_done = 1;

    total = XRD_RESPONSE_HDR_LEN + BRIX_SESSION_ID_LEN;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                          BRIX_SESSION_ID_LEN,
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->login.sessid,
               BRIX_SESSION_ID_LEN);

    /* Session timing starts at successful login so later disconnect stats have an origin. */
    ctx->totals.start = ngx_current_msec;
    if (ctx->identity != NULL) {
        ctx->identity->auth_method = BRIX_AUTHN_NONE;
    }
    brix_sess_auth_once(ctx->sess, BRIX_SESS_AM_ANON, "-", "-");
    brix_session_register(ctx->login.sessid, ctx->login.dn, ctx->login.vo_list, 0);
    brix_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
    brix_count_login_ok(ctx);

    return brix_queue_response(ctx, c, buf, total);
}

/*
 * WHAT: Format the "&P=..." security parameter block for an authenticated mode.
 * WHY:  The client parses this block to decide which security plugin to load;
 *       each auth mode advertises a distinct protocol string.  Isolating the
 *       per-mode ladder here keeps the branch count out of the caller.
 * HOW:  Write into caller-owned `parms` (cap `sizeof`), returning the byte count
 *       INCLUDING the trailing NUL (clients treat the block as C-string data).
 *       The GSI-capable modes advertise a version that gates signed-DH.
 */
static size_t
brix_login_build_parms(ngx_stream_brix_srv_conf_t *conf,
    char *parms, size_t cap)
{
    /* Advertised GSI version drives the client's signed-DH decision:
     * >=BRIX_GSI_VERS_DHSIGNED (10400) lets capable clients use the
     * RSA-signed-DH variant.  Default 10000 (unsigned, universally
     * compatible) unless the brix_gsi_signed_dh policy opts in. */
    unsigned gsi_ver = (conf->gsi_signed_dh != BRIX_GSI_SDH_OFF) ? 10600u : 10000u;

    if (conf->auth == BRIX_AUTH_TOKEN) {
        /* Token-only: advertise ztn, no CA hash needed. */
        return (size_t) snprintf(parms, cap, "&P=ztn,v:10000") + 1;
    }
    if (conf->auth == BRIX_AUTH_SSS) {
        /* XRootD SSS: bf32 ('0'), v2 server ('+'), client chooses keytab. */
        return (size_t) snprintf(parms, cap, "&P=sss,0.+%d:",
                                 (int) conf->sss_lifetime) + 1;
    }
    if (conf->auth == BRIX_AUTH_UNIX) {
        return (size_t) snprintf(parms, cap, "&P=unix") + 1;
    }
    if (conf->auth == BRIX_AUTH_KRB5) {
        return (size_t) snprintf(parms, cap, "&P=krb5,%s",
                                 (const char *) conf->krb5.principal.data) + 1;
    }
    if (conf->auth == BRIX_AUTH_HOST) {
        /* Phase 52 WS-C: host auth asserts no credential — bare protocol id. */
        return (size_t) snprintf(parms, cap, "&P=host") + 1;
    }
    if (conf->auth == BRIX_AUTH_PWD) {
        /* Phase 52 WS-B: XrdSecpwd password protocol (v:10100, ssl crypto). */
        return (size_t) snprintf(parms, cap, "&P=pwd,v:10100,c:ssl") + 1;
    }
    if (conf->auth == BRIX_AUTH_BOTH) {
        /* Both: token first (preferred), then GSI. */
        return (size_t) snprintf(parms, cap,
                                 "&P=ztn,v:10000&P=gsi,v:%u,c:ssl,ca:%s",
                                 gsi_ver, conf->gsi_ca_hashes) + 1;
    }

    /* GSI-only.  The advertised version drives the client's signed-DH
     * decision: >=10400 makes capable clients use the RSA-signed-DH
     * variant.  Defaults to 10000 (unsigned, universal) unless the
     * brix_gsi_signed_dh policy opts in. */
    return (size_t) snprintf(parms, cap, "&P=gsi,v:%u,c:ssl,ca:%s",
                             gsi_ver, conf->gsi_ca_hashes) + 1;
}

/*
 * WHAT: Emit the authenticated-mode login response (sessid + "&P=..." block).
 * WHY:  Authenticated modes send a text parameter block after the 16-byte
 *       session id so the client can select its security plugin; login succeeds
 *       here but auth negotiation continues in later round-trips.
 * HOW:  Re-fetch the live merged srv_conf, format the parameter block, guard its
 *       length (kXR_ServerError → NGX_DONE, since brix_send_error returns NGX_OK
 *       and must not fall through), build the kXR_ok header + sessid + parms,
 *       record session start, log access, count the metric, and queue.
 */
static ngx_int_t
brix_login_respond_authenticated(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *user)
{
    ngx_stream_brix_srv_conf_t *conf;
    char     parms[256];
    size_t   parms_len;
    u_char  *buf;
    size_t   total;

    /* Re-fetch the live merged srv_conf in case login inherited settings. */
    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);

    parms_len = brix_login_build_parms(conf, parms, sizeof(parms));

    /* Include the trailing NUL because clients treat the parameter block as C-string data. */
    if (parms_len > sizeof(parms)) {
        brix_send_error(ctx, c, kXR_ServerError,
                        "auth parameter block too long");
        return NGX_DONE;
    }

    total = XRD_RESPONSE_HDR_LEN + BRIX_SESSION_ID_LEN + parms_len;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                          (uint32_t)(BRIX_SESSION_ID_LEN + parms_len),
                          (ServerResponseHdr *) buf);

    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->login.sessid,
               BRIX_SESSION_ID_LEN);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + BRIX_SESSION_ID_LEN,
               parms, parms_len);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: login->kXGS_init parms=\"%s\" ca_hashes=%s",
                   parms, conf->gsi_ca_hashes);

    /* Successful login still marks the start of the session even though auth continues. */
    ctx->totals.start = ngx_current_msec;
    brix_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
    brix_count_login_ok(ctx);

    return brix_queue_response(ctx, c, buf, total);
}

/* Handle kXR_login — accept a client username, generate a session id (sessid),
 * and begin auth negotiation (advertising the configured security requirement). */
ngx_int_t
brix_handle_login(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char       user[9];
    char       user_log[64];
    ngx_int_t  rc;

    rc = brix_login_precheck_and_parse(ctx, c, conf, user, user_log);
    if (rc != NGX_OK) {
        return (rc == NGX_DONE) ? NGX_OK : rc;
    }

    if (conf->auth == BRIX_AUTH_NONE) {
        return brix_login_respond_anon(ctx, c, user);
    }

    rc = brix_login_respond_authenticated(ctx, c, user);
    return (rc == NGX_DONE) ? NGX_OK : rc;
}
