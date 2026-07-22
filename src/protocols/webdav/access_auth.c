/*
 * access_auth.c - WebDAV access-phase authentication gate.
 *
 * WHAT: The credential-source tier of the WebDAV access phase: GSI proxy
 * cert, bearer token, and Basic password sources, the RFC 7617 Basic
 * challenge for browser clients, and the policy gate (access_authenticate)
 * that runs them in order and applies auth=required/optional/none.
 *
 * WHY: Split out of access.c so the authentication surface is grouped by
 * concern and individually reviewable while access.c keeps the access-phase
 * orchestration and the XrdAcc/authdb authorization tiers.
 *
 * HOW: access_authenticate is the sole cross-split entry point (declared in
 * access_internal.h); the per-source wrappers and the Basic challenge stay
 * file-local statics.  Each outcome increments exactly the same metric slot
 * as before the decomposition.
 */

#include "webdav.h"
#include "observability/metrics/unified.h"
#include "auth/authz/acc/acc.h"
#include "fs/path/path.h"   /* brix_check_authdb_identity, brix_check_vo_acl_identity */
#include "webdav_tpc.h"     /* webdav_tpc_find_header — COPY PULL/PUSH direction */
#include "protocols/shared/deleg_capture.h"  /* phase-70 §5.1 proxy header capture */
#include "fs/backend/sd.h"  /* enum brix_cred_mode / BRIX_CRED_SELECT */
#include "access_internal.h"

/*
 * access_try_cert — GSI proxy-certificate credential source.
 *
 * WHAT: Attempts client-certificate authentication and records the cert-OK
 * metrics on success.
 *
 * WHY: The cert tier is tried FIRST (before bearer token), matching the
 * root:// auth ordering; metrics must attribute the session to GSI.
 *
 * HOW: Thin wrapper over webdav_verify_proxy_cert; returns its verdict.
 */
static ngx_int_t
access_try_cert(ngx_http_request_t *r,
                ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_proxy_cert(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_CERT_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_GSI, 1);
    }
    return rc;
}

/*
 * access_try_token — bearer-token credential source.
 *
 * WHAT: Attempts bearer-token authentication and records the token-OK metrics
 * on success.
 *
 * WHY: Tried only after the cert tier fails; metrics must attribute the
 * session to TOKEN.
 *
 * HOW: Thin wrapper over webdav_verify_bearer_token; returns its verdict.
 */
static ngx_int_t
access_try_token(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_bearer_token(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_TOKEN, 1);
    }
    return rc;
}

/*
 * access_try_basic — Basic-password credential source.
 *
 * WHAT: Attempts HTTP Basic authentication against the configured pwd db and
 * records the pwd-OK metrics on success.
 *
 * WHY: Tried LAST (after cert and token) so stronger credentials always win;
 * metrics must attribute the session to PWD.
 *
 * HOW: Thin wrapper over webdav_verify_basic_pwd; returns its verdict.
 */
static ngx_int_t
access_try_basic(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_basic_pwd(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_PWD_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_PWD, 1);
    }
    return rc;
}

/*
 * access_basic_challenge — RFC 7617 Basic challenge for browser clients.
 *
 * WHAT: Attaches `WWW-Authenticate: Basic realm="brix"` to the response and
 * returns NGX_HTTP_UNAUTHORIZED, or NGX_HTTP_INTERNAL_SERVER_ERROR on
 * allocation failure.
 *
 * WHY: A browser only shows its login prompt (and re-prompts after a wrong
 * password) on 401 + a challenge header; a bare 403 is a dead end.  Emitted
 * only when Basic is actually enabled on the export, so cert/token-only
 * exports keep their historical 403 and never invite a password prompt that
 * cannot succeed.
 *
 * HOW: The same headers_out wiring nginx's own auth_basic module uses — push
 * the header and point headers_out.www_authenticate at it so the special-
 * response path emits it.
 */
static ngx_int_t
access_basic_challenge(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "WWW-Authenticate");
    ngx_str_set(&h->value, "Basic realm=\"brix\"");
    r->headers_out.www_authenticate = h;
    return NGX_HTTP_UNAUTHORIZED;
}

/*
 * access_authenticate — the authentication gate.
 *
 * WHAT: Runs the credential sources in order (GSI proxy cert, bearer token,
 * then Basic password) and applies the location's auth policy to the outcome.
 *
 * WHY: auth=required rejects unauthenticated requests — with a 401 Basic
 * challenge when a pwd db is configured (so browsers prompt for credentials),
 * else the historical 403; auth=optional lets them proceed as anonymous;
 * auth=none skips verification entirely.  Each outcome increments exactly
 * the same metric slot as before the decomposition.
 *
 * HOW: Returns NGX_OK to continue (authenticated or anonymous) or the
 * metrics-counted rejection.
 */
ngx_int_t
access_authenticate(ngx_http_request_t *r,
                    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t auth_rc;

    if (conf->auth == WEBDAV_AUTH_NONE) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_NONE]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
        return NGX_OK;
    }

    auth_rc = access_try_cert(r, conf);
    if (auth_rc != NGX_OK) {
        auth_rc = access_try_token(r, conf);
    }
    if (auth_rc != NGX_OK) {
        auth_rc = access_try_basic(r, conf);
    }

    if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unauthenticated request rejected"
                      " (auth=required)");
        if (conf->pwd_file.len > 0) {
            return webdav_metrics_return(r, access_basic_challenge(r));
        }
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    if (auth_rc != NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
    }

    return NGX_OK;
}
