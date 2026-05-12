/*
 * auth_token.c - bearer token authentication and WebDAV write scopes.
 */

#include "webdav.h"
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

ngx_int_t
webdav_verify_bearer_token(ngx_http_request_t *r,
                           ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    xrootd_token_claims_t             claims;
    ngx_str_t                         auth_hdr;
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
 
    if (auth_hdr.len < 7
        || ngx_strncmp(auth_hdr.data, "Bearer ", 7) != 0)
    {
        return NGX_DECLINED;
    }
 
    token = (const char *) (auth_hdr.data + 7);
    token_len = auth_hdr.len - 7;
 
    while (token_len > 0 && *token == ' ') {
        token++;
        token_len--;
    }
 
    if (token_len == 0) {
        return NGX_HTTP_UNAUTHORIZED;
    }
 
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
