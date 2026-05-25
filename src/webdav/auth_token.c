/*
 * auth_token.c - bearer token authentication and WebDAV write scopes.
 */

#include "webdav.h"
#include "../compat/http_headers.h"
#include "../token/macaroon.h"

#include <string.h>

/*
 * webdav_check_token_write_scope — enforce WLCG/SciToken write scope for
 * WebDAV mutating methods (PUT, DELETE, MKCOL, MOVE).
 *
 * If the request was authenticated via a bearer token (rctx->token_auth == 1),
 * checks whether the token's write scope covers the request URI path.
 * Returns NGX_OK if the scope check passes or if auth was not token-based.
 * Returns NGX_HTTP_FORBIDDEN if the token lacks write scope for the URI.
 *
 * NOTE: scope is checked against the raw decoded URI path, not the filesystem
 * path — the path-prefix invariant is enforced by the scope matching code in
 * token/scopes.c (must be an exact prefix, not a partial directory name match).
 */
/* ---- Function: webdav_check_token_write_scope() ----
 *
 * WHAT: Enforces WLCG/SciToken write scope authorization for WebDAV mutating methods (PUT, DELETE, MKCOL, MOVE). Checks whether the authenticated bearer token's write scopes cover the request URI path before allowing any file modification operation. Returns NGX_OK if the scope check passes or if authentication was not via token (e.g., GSI cert auth has no equivalent scope concept). Returns NGX_HTTP_FORBIDDEN when the token lacks sufficient write permissions for the target resource.
 *
 * WHY: WLCG/SciToken grants fine-grained path-based access rights rather than binary allow/deny. A token might grant read-only access to /data/atlas but write access to /data/cms — this function prevents cross-VO file mutation by ensuring only tokens with matching scope prefixes can execute mutating operations. The raw URI path check (not filesystem path) is intentional because scope granularity must match the client-facing namespace, not the underlying storage layout.
 *
 * HOW: Retrieves request context and verifies token_auth flag is set; copies r->uri into a null-terminated buffer for scope checking; calls xrootd_token_check_write() with the extracted scopes to verify the URI path is covered by at least one write scope prefix; logs warning and returns 403 if no matching scope found. */
ngx_int_t
webdav_check_token_write_scope(ngx_http_request_t *r, const char *method_name)
{
    ngx_http_xrootd_webdav_req_ctx_t *rctx;
    char                              uri_path[WEBDAV_MAX_PATH];
    size_t                            ulen;

    rctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (rctx == NULL || !rctx->token_auth) {
        return NGX_OK;
    }

    ulen = r->uri.len < sizeof(uri_path) - 1
           ? r->uri.len : sizeof(uri_path) - 1;
    ngx_memcpy(uri_path, r->uri.data, ulen);
    uri_path[ulen] = '\0';

    if (xrootd_token_check_write(rctx->token_scopes,
                                 rctx->token_scope_count,
                                 uri_path))
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xrootd_webdav: token scope denies %s write to \"%s\"",
                  method_name, uri_path);

    return NGX_HTTP_FORBIDDEN;
}

/* ---- Function: webdav_verify_bearer_token() ----
 *
 * WHAT: Validates WLCG/SciToken bearer tokens presented in HTTP Authorization headers using either JWKS-based JWT verification or macaroon secret-key validation. Extracts token claims (subject, scopes, expiration) and stores them in the request context for downstream operations. Supports grace-period key rotation — if a macaroon is rejected by the current secret but accepted by an old secret configured via conf->token_macaroon_secret_old, the token is still accepted with an informational log message indicating graceful migration during nginx -s reload.
 *
 * WHY: WebDAV clients authenticate using bearer tokens rather than GSI certificates or anonymous access. This function must handle both JWT (via JWKS key set) and macaroon formats since different WLCG sites use different token types. The grace-period fallback prevents immediate access disruption during secret key rotation — in-flight tokens should be accepted until they naturally expire, avoiding a "hard break" scenario where all active clients are suddenly denied after a config reload.
 *
 * HOW: Declines if no keys/secrets configured; parses macaroon secret for validation if present; creates or retrieves request context (declines if already token-authenticated to avoid redundant verification); extracts a Bearer token from Authorization with shared case-insensitive scheme parsing; calls xrootd_token_validate() with JWKS keys, issuer/audience config, and optionally the macaroon secret; attempts old-secret fallback only when primary validation fails AND an old secret exists; on success stores claims (sub, scopes) in ctx for downstream scope checks. */
ngx_int_t
webdav_verify_bearer_token(ngx_http_request_t *r,
                           ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    xrootd_token_claims_t             claims;
    ngx_str_t                         auth_hdr;
    ngx_str_t                         bearer;
    const char                       *token;
    size_t                            token_len;
    int                               rc;
    int                               i;

    u_char                            secret[64];
    ssize_t                           slen = 0;

    if (conf->jwks_key_count <= 0 && conf->token_macaroon_secret.len == 0) {
        return NGX_DECLINED;
    }

    if (conf->token_macaroon_secret.len) {
        slen = xrootd_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret.data,
            conf->token_macaroon_secret.len, secret, sizeof(secret));
    }
 
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);
    }
 
    if (ctx->token_auth) {
        return NGX_OK;
    }
 
    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }
 
    auth_hdr = r->headers_in.authorization->value;

    rc = xrootd_http_extract_bearer(&auth_hdr, &bearer);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_HTTP_UNAUTHORIZED;
    }

    token = (const char *) bearer.data;
    token_len = bearer.len;
 
    rc = xrootd_token_validate(r->connection->log, token, token_len,
                               conf->jwks_keys, conf->jwks_key_count,
                               (const char *) conf->token_issuer.data,
                               (const char *) conf->token_audience.data,
                               slen > 0 ? secret : NULL, (size_t) slen,
                               &claims);

    /* Grace-period fallback: if the primary secret rejected a macaroon token
     * and an old secret is configured, try validating with the old key.
     * This lets in-flight tokens survive nginx -s reload during key rotation. */
    if (rc != 0 && conf->token_macaroon_secret_old.len) {
        u_char  old_secret[64];
        ssize_t old_slen;

        old_slen = xrootd_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret_old.data,
            conf->token_macaroon_secret_old.len,
            old_secret, sizeof(old_secret));

        if (old_slen > 0) {
            rc = xrootd_token_validate(r->connection->log, token, token_len,
                                       conf->jwks_keys, conf->jwks_key_count,
                                       (const char *) conf->token_issuer.data,
                                       (const char *) conf->token_audience.data,
                                       old_secret, (size_t) old_slen,
                                       &claims);
            if (rc == 0) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "xrootd_webdav: macaroon accepted via old secret "
                              "(grace-period key rotation)");
            }
        }
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: bearer token validation failed");
        return NGX_HTTP_UNAUTHORIZED;
    }

    ctx->verified = 1;
    ctx->token_auth = 1;
    ctx->auth_source = "token";
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) claims.sub, sizeof(ctx->dn));

    ctx->token_scope_count = claims.scope_count;
    for (i = 0; i < claims.scope_count && i < XROOTD_MAX_TOKEN_SCOPES; i++) {
        ctx->token_scopes[i] = claims.scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: token auth OK sub=\"%s\" scopes=%d",
                  claims.sub, claims.scope_count);

    return NGX_OK;
}
