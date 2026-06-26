/*
 * auth_token.c - bearer token authentication and WebDAV write scopes.
 */

#include "webdav.h"
#include "../compat/http_headers.h"
#include "../token/macaroon.h"
#include "../token/token_cache.h"
#include "../token/worker_cache.h"

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

    if (rctx->identity != NULL) {
        if (xrootd_identity_check_token_scope(rctx->identity, uri_path, 1)
            == NGX_OK)
        {
            return NGX_OK;
        }
    } else if (xrootd_token_check_write(rctx->token_scopes,
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

/* Largest accepted bearer token (DoS guard on the query-string path). */
#define WEBDAV_QUERY_TOKEN_MAX 8192

/*
 * webdav_bearer_from_query — extract a bearer token from ?authz= / ?access_token=.
 *
 * WHAT: query-string fallback used only when no Authorization header carries a
 *       Bearer token (davix/gfal2/xrdcp redirect + pre-signed-URL flows).
 * WHY:  XrdHttp accepts the token in the URL; matching it is required for WLCG
 *       client interop. The header path stays primary.
 * HOW:  copies the raw arg into r->pool, URL-decodes in place, strips an optional
 *       case-insensitive "Bearer " prefix, and enforces a length cap. On NGX_OK
 *       *out is a NUL-terminated pool slice. NGX_DECLINED when disabled/absent.
 */
static ngx_int_t
webdav_bearer_from_query(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf, ngx_str_t *out)
{
    ngx_str_t raw;
    size_t    len;

    if (!conf->http_query_token) {
        return NGX_DECLINED;
    }
    if (xrootd_http_arg(r, "authz", 5, &raw) != NGX_OK
        && xrootd_http_arg(r, "access_token", 12, &raw) != NGX_OK) {
        return NGX_DECLINED;
    }
    len = xrootd_urldecode_inplace((char *) raw.data);
    if (len >= 7 && ngx_strncasecmp(raw.data, (u_char *) "Bearer ", 7) == 0) {
        raw.data += 7;
        len      -= 7;
        while (len > 0 && raw.data[0] == ' ') { raw.data++; len--; }
    }
    if (len == 0 || len > WEBDAV_QUERY_TOKEN_MAX) {
        return NGX_DECLINED;
    }
    out->data = raw.data;
    out->len  = len;
    return NGX_OK;
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
        ctx->identity = xrootd_identity_alloc(r->pool);
        if (ctx->identity == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);
    } else if (ctx->identity == NULL) {
        ctx->identity = xrootd_identity_alloc(r->pool);
        if (ctx->identity == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
 
    if (ctx->token_auth) {
        return NGX_OK;
    }
 
    if (r->headers_in.authorization == NULL) {
        /* No Authorization header — try the ?authz= query fallback (§1). */
        if (webdav_bearer_from_query(r, conf, &bearer) != NGX_OK) {
            return NGX_DECLINED;
        }
    } else {
        auth_hdr = r->headers_in.authorization->value;
        rc = xrootd_http_extract_bearer(&auth_hdr, &bearer);
        if (rc == NGX_DECLINED) {
            /* Header present but not Bearer — still allow the query fallback. */
            if (webdav_bearer_from_query(r, conf, &bearer) != NGX_OK) {
                return NGX_DECLINED;
            }
        } else if (rc != NGX_OK) {
            return NGX_HTTP_UNAUTHORIZED;
        }
    }

    token = (const char *) bearer.data;
    token_len = bearer.len;

    /* §1: the token has now been consumed for auth. Scrub any ?authz=/?access_token=
     * value, length-preserving, from every log source (args, unparsed URI, request
     * line) so a URL-borne bearer token never reaches access/error logs. r->uri (the
     * decoded path used for routing/scope) excludes the query, so this is safe. */
    if (r->args.len > 0) {
        xrootd_http_redact_query_token(&r->args);
        xrootd_http_redact_query_token(&r->unparsed_uri);
        xrootd_http_redact_query_token(&r->request_line);
    }
 
    /*
     * Token-validation caches, consulted cheapest-first so token auth does not
     * re-run crypto + JSON parsing on the event loop under load:
     *   L1 — always-on, per-worker, lockless (lazily created here).  A hit skips
     *        BOTH the signature verification AND the L2 spinlock.
     *   L2 — the optional cross-worker SHM cache.  An L2 hit is promoted into L1
     *        so the next presentation to this worker is an L1 hit.
     * Only successfully validated claims are ever cached.
     */
    int cache_hit = 0;

    if (conf->token_l1 == NULL) {
        conf->token_l1 = xrootd_token_l1_create(ngx_cycle->pool,
                                                XROOTD_TOKEN_L1_SLOTS);
    }

    if (xrootd_token_l1_lookup(conf->token_l1, token, token_len, &claims)) {
        rc = 0;
        cache_hit = 1;
    } else if (conf->token_cache_kv != NULL
               && xrootd_token_cache_lookup(conf->token_cache_kv,
                                            token, token_len, &claims))
    {
        rc = 0;
        cache_hit = 1;
        xrootd_token_l1_store(conf->token_l1, token, token_len, &claims);
    } else {
        rc = xrootd_token_validate(r->connection->log, token, token_len,
                                   conf->jwks_keys, conf->jwks_key_count,
                                   (const char *) conf->token_issuer.data,
                                   (const char *) conf->token_audience.data,
                                   slen > 0 ? secret : NULL, (size_t) slen,
                                   &claims);
    }

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

    /* Cache the freshly verified claims for subsequent presentations (L1 always,
     * L2 when a SHM zone is configured). */
    if (!cache_hit) {
        xrootd_token_l1_store(conf->token_l1, token, token_len, &claims);
        if (conf->token_cache_kv != NULL) {
            xrootd_token_cache_store(conf->token_cache_kv, token, token_len,
                                     &claims);
        }
    }

    ctx->verified = 1;
    ctx->token_auth = 1;
    ctx->auth_source = "token";
    if (xrootd_identity_set_token_claims(ctx->identity, r->pool, &claims)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
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
