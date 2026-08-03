/*
 * auth_token.c - bearer token authentication and WebDAV write scopes.
 */

#include "webdav.h"
#include "core/http/http_headers.h"
#include "auth/token/macaroon.h"
#include "auth/token/token_cache.h"
#include "auth/token/worker_cache.h"
#include "auth/token/issuer_registry.h"

#include <string.h>
#include "auth_token_internal.h"

/* webdav_token_op_class — map the HTTP method to a registry op class * Read-ish verbs (GET/HEAD/PROPFIND/OPTIONS) authorize against read scopes;
 * everything else (PUT/DELETE/MKCOL/MOVE/COPY/PROPPATCH/LOCK/...) is a write. */
brix_token_op_e
webdav_token_op_class(ngx_http_request_t *r)
{
    switch (r->method) {
    case NGX_HTTP_GET:
    case NGX_HTTP_HEAD:
    case NGX_HTTP_PROPFIND:
    case NGX_HTTP_OPTIONS:
        return BRIX_TOKEN_OP_READ;
    default:
        return BRIX_TOKEN_OP_WRITE;
    }
}

/*
 * webdav_check_token_scope — enforce WLCG/SciToken read or write scope for
 * any WebDAV data-access method (GET, HEAD, PROPFIND, PUT, DELETE, MKCOL, …).
 *
 * If the request was authenticated via a bearer token (rctx->token_auth == 1),
 * checks whether the token's scope covers the request URI path for the
 * operation class (read vs write) derived from the HTTP method.
 * Returns NGX_OK if the scope check passes or if auth was not token-based.
 * Returns NGX_HTTP_FORBIDDEN if the token lacks scope for the URI.
 *
 * NOTE: scope is checked against the raw decoded URI path, not the filesystem
 * path — the path-prefix invariant is enforced by the scope matching code in
 * token/scopes.c (must be an exact prefix, not a partial directory name match).
 */
/*
 *
 * WHAT: Enforces WLCG/SciToken read or write scope authorization for WebDAV
 * data-access methods.  Derives the required op class (read vs write) from the
 * HTTP method via webdav_token_op_class(), then checks whether the
 * authenticated bearer token's scopes cover the request URI path.  Returns
 * NGX_OK if the scope check passes or if authentication was not token-based
 * (e.g., GSI cert auth has no equivalent scope concept).  Returns
 * NGX_HTTP_FORBIDDEN when the token lacks sufficient permission for the URI.
 *
 * WHY: WLCG/SciToken grants fine-grained path-based access rights rather than
 * binary allow/deny.  A token might grant read-only access to /data/atlas but
 * write access to /data/cms — this function prevents both cross-VO file reads
 * and cross-VO file mutation by enforcing scope on every data-access method,
 * not just writes.  The raw URI path check (not filesystem path) is intentional
 * because scope granularity must match the client-facing namespace, not the
 * underlying storage layout.
 *
 * HOW: Retrieves request context and verifies token_auth flag is set; derives
 * need_write from webdav_token_op_class(); copies r->uri into a
 * null-terminated buffer for scope checking; calls either
 * brix_token_check_write() or brix_token_check_read() (or the identity
 * wrapper) to verify the URI path is covered by a matching scope prefix; logs
 * warning and returns 403 if no matching scope found. */
ngx_int_t
webdav_check_token_scope(ngx_http_request_t *r, const char *method_name)
{
    ngx_http_brix_webdav_req_ctx_t *rctx;
    char                              uri_path[WEBDAV_MAX_PATH];
    size_t                            ulen;
    int                               need_write;

    rctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (rctx == NULL || !rctx->token_auth) {
        return NGX_OK;
    }

    ulen = r->uri.len < sizeof(uri_path) - 1
           ? r->uri.len : sizeof(uri_path) - 1;
    ngx_memcpy(uri_path, r->uri.data, ulen);
    uri_path[ulen] = '\0';

    need_write = (webdav_token_op_class(r) == BRIX_TOKEN_OP_WRITE);

    if (rctx->identity != NULL) {
        if (brix_identity_check_token_scope(rctx->identity, uri_path,
                                              need_write) == NGX_OK)
        {
            return NGX_OK;
        }
    } else if (need_write
               ? brix_token_check_write(rctx->token_scopes,
                                          rctx->token_scope_count, uri_path)
               : brix_token_check_read(rctx->token_scopes,
                                         rctx->token_scope_count, uri_path))
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "brix_webdav: token scope denies %s %s to \"%s\"",
                  method_name, need_write ? "write" : "read", uri_path);

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
                         ngx_http_brix_webdav_loc_conf_t *conf, ngx_str_t *out)
{
    ngx_str_t raw;
    size_t    len;

    if (!conf->http_query_token) {
        return NGX_DECLINED;
    }
    if (brix_http_arg(r, "authz", 5, &raw) != NGX_OK
        && brix_http_arg(r, "access_token", 12, &raw) != NGX_OK) {
        return NGX_DECLINED;
    }
    len = brix_urldecode_inplace((char *) raw.data);
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

/*
 * wt_ensure_ctx — get-or-create the WebDAV request context with an identity.
 *
 * WHAT: Retrieves the per-request module context, allocating a fresh one (with
 * an attached identity) on r->pool when absent, and back-fills an identity onto
 * a pre-existing context that lacks one.  Returns the context via *out.
 * WHY: bearer-token auth runs after other auth phases may (or may not) have
 * created the context; a NULL identity would crash the later claims-store step,
 * so both the create and the repair paths must guarantee one.  Factored out so
 * the orchestrator's allocation-failure branches don't inflate its complexity.
 * HOW: ngx_http_get_module_ctx(); on NULL allocate+attach identity+set_ctx; on a
 * context with a NULL identity allocate one; map every OOM to
 * NGX_HTTP_INTERNAL_SERVER_ERROR.  Returns NGX_OK with *out populated otherwise.
 */
static ngx_int_t
wt_ensure_ctx(ngx_http_request_t *r, ngx_http_brix_webdav_req_ctx_t **out)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->identity = brix_identity_alloc(r->pool);
        if (ctx->identity == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module);
    } else if (ctx->identity == NULL) {
        ctx->identity = brix_identity_alloc(r->pool);
        if (ctx->identity == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    *out = ctx;
    return NGX_OK;
}

/*
 * wt_redact_query_token — scrub a URL-borne bearer token from every log source.
 *
 * WHAT: length-preservingly redacts a ?authz=/?access_token= token from
 * r->args/unparsed_uri/request_line when a query string is present.
 * WHY: a URL token must never reach access/error logs; called on both the auth
 * success path and the dual-transport reject path so neither leaks it. r->uri
 * (the decoded path used for routing/scope) excludes the query, so this is safe.
 * HOW: guard on r->args.len then redact all three loggable fields.
 */
static void
wt_redact_query_token(ngx_http_request_t *r)
{
    if (r->args.len > 0) {
        brix_http_redact_query_token(&r->args);
        brix_http_redact_query_token(&r->unparsed_uri);
        brix_http_redact_query_token(&r->request_line);
    }
}

/*
 * webdav_add_nostore — attach Cache-Control: no-store to the response.
 *
 * WHAT: pushes a Cache-Control: no-store header onto headers_out.
 * WHY: RFC 6750 §2.3 (SEC MUST) — responses to a query-transported token MUST
 * carry no-store so the URL (with its embedded token) is never cached by an
 * intermediary. Applies to the response regardless of the auth outcome.
 * HOW: best-effort ngx_list_push; a push failure is non-fatal (the response
 * still goes out, just without the advisory header).
 */
static void
webdav_add_nostore(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Cache-Control");
    ngx_str_set(&h->value, "no-store");
}

/*
 * wt_parse_header — obtain the presented bearer token and scrub it from logs.
 *
 * WHAT: Resolves the request's bearer token from the Authorization header,
 * falling back to the ?authz=/?access_token= query parameter, enforces the
 * RFC 6750 §2 single-transport MUST, and — once the token has been consumed for
 * auth — length-preservingly redacts any URL-borne token from every loggable
 * request field.  Returns the token via *bearer.
 * WHY: WLCG clients present the token either in the header (primary) or the URL
 * (davix/gfal2 redirect + pre-signed flows); both must be accepted with the same
 * precedence XrdHttp uses, but NOT both at once (§2 SEC MUST — a header+query
 * collision is a confused-deputy vector → 400 invalid_request).  A URL token
 * must never reach access/error logs, so the scrub happens here, immediately
 * after extraction, before any early return that could log the request line.
 * HOW: no header → query fallback (NGX_DECLINED when absent); header present but
 * not Bearer → query fallback; a malformed Bearer header → NGX_HTTP_UNAUTHORIZED;
 * a header Bearer token together with a query token → NGX_HTTP_BAD_REQUEST; on a
 * query-sourced success attach Cache-Control: no-store (§2.3); always redact.
 */
static ngx_int_t
wt_parse_header(ngx_http_request_t *r,
                ngx_http_brix_webdav_loc_conf_t *conf, ngx_str_t *bearer)
{
    ngx_str_t auth_hdr;
    ngx_str_t qtok;
    int       from_query = 0;
    int       header_bearer = 0;
    int       rc;

    if (r->headers_in.authorization == NULL) {
        /* No Authorization header — try the ?authz= query fallback (§1). */
        if (webdav_bearer_from_query(r, conf, bearer) != NGX_OK) {
            return NGX_DECLINED;
        }
        from_query = 1;
    } else {
        auth_hdr = r->headers_in.authorization->value;
        rc = brix_http_extract_bearer(&auth_hdr, bearer);
        if (rc == NGX_DECLINED) {
            /* Header present but not Bearer — still allow the query fallback. */
            if (webdav_bearer_from_query(r, conf, bearer) != NGX_OK) {
                return NGX_DECLINED;
            }
            from_query = 1;
        } else if (rc != NGX_OK) {
            return NGX_HTTP_UNAUTHORIZED;
        } else {
            header_bearer = 1;
        }
    }

    /* RFC 6750 §2 (SEC MUST): a token MUST NOT be transmitted via more than one
     * method. A Bearer Authorization header together with a ?authz=/?access_token=
     * query token is a dual-transport request → 400 invalid_request. Redact the
     * URL token before returning so the reject path never leaks it. */
    if (header_bearer
        && webdav_bearer_from_query(r, conf, &qtok) == NGX_OK)
    {
        wt_redact_query_token(r);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* §1: the token has now been consumed for auth — scrub any URL-borne token
     * from every log source (length-preserving). */
    wt_redact_query_token(r);

    /* §2.3 (SEC MUST): a query-transported token requires Cache-Control:
     * no-store on the response, set now since it applies regardless of the
     * eventual auth outcome. */
    if (from_query) {
        webdav_add_nostore(r);
    }

    return NGX_OK;
}

static ngx_int_t
wt_check_claims(ngx_http_request_t *r,
                ngx_http_brix_webdav_req_ctx_t *ctx,
                const char *token, size_t token_len,
                brix_token_claims_t *claims)
{
    int i;

    ctx->verified = 1;
    ctx->token_auth = 1;
    ctx->auth_source = "token";

    /* Phase-70 §5.4: retain the raw JWT bytes for backend PASSTHROUGH. Copied
     * onto r->pool (the wire `token`/`bearer.data` may point into a header value
     * that later rewrites, e.g. query-token redaction) and never logged. */
    ctx->bearer_token.data = ngx_pnalloc(r->pool, token_len);
    if (ctx->bearer_token.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ctx->bearer_token.data, token, token_len);
    ctx->bearer_token.len = token_len;

    if (brix_identity_set_token_claims(ctx->identity, r->pool, claims)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) claims->sub, sizeof(ctx->dn));

    ctx->token_scope_count = claims->scope_count;
    for (i = 0; i < claims->scope_count && i < BRIX_MAX_TOKEN_SCOPES; i++) {
        ctx->token_scopes[i] = claims->scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: token auth OK sub=\"%s\" scopes=%d",
                  claims->sub, claims->scope_count);

    return NGX_OK;
}

/*
 *
 * WHAT: Validates WLCG/SciToken bearer tokens presented in HTTP Authorization headers using either JWKS-based JWT verification or macaroon secret-key validation. Extracts token claims (subject, scopes, expiration) and stores them in the request context for downstream operations. Supports grace-period key rotation — if a macaroon is rejected by the current secret but accepted by an old secret configured via conf->token_macaroon_secret_old, the token is still accepted with an informational log message indicating graceful migration during nginx -s reload.
 *
 * WHY: WebDAV clients authenticate using bearer tokens rather than GSI certificates or anonymous access. This function must handle both JWT (via JWKS key set) and macaroon formats since different WLCG sites use different token types. The grace-period fallback prevents immediate access disruption during secret key rotation — in-flight tokens should be accepted until they naturally expire, avoiding a "hard break" scenario where all active clients are suddenly denied after a config reload.
 *
 * HOW: Declines if no keys/secrets configured; parses macaroon secret for validation if present; creates or retrieves request context (declines if already token-authenticated to avoid redundant verification); extracts a Bearer token from Authorization with shared case-insensitive scheme parsing via wt_parse_header(); resolves validity via wt_check_issuer_keys() (caches → registry/JWKS → grace retry); caches freshly verified non-registry claims; on success stores claims (sub, scopes) in ctx via wt_check_claims() for downstream scope checks. */
ngx_int_t
webdav_verify_bearer_token(ngx_http_request_t *r,
                           ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *ctx = NULL;
    brix_token_claims_t             claims;
    ngx_str_t                         bearer;
    const char                       *token;
    size_t                            token_len;
    int                               rc;
    int                               cache_hit = 0;
    int                               via_registry = 0;
    ngx_int_t                         crc;

    u_char                            secret[64];
    ssize_t                           slen = 0;

    if (conf->jwks_key_count <= 0 && conf->token_macaroon_secret.len == 0
        && conf->token_registry == NULL)
    {
        return NGX_DECLINED;
    }

    if (conf->token_macaroon_secret.len) {
        slen = brix_macaroon_secret_parse(
            (const char *) conf->token_macaroon_secret.data,
            conf->token_macaroon_secret.len, secret, sizeof(secret));
    }

    crc = wt_ensure_ctx(r, &ctx);
    if (crc != NGX_OK) {
        return crc;
    }

    if (ctx->token_auth) {
        return NGX_OK;
    }

    crc = wt_parse_header(r, conf, &bearer);
    if (crc != NGX_OK) {
        return crc;
    }

    token = (const char *) bearer.data;
    token_len = bearer.len;

    {
        wt_validate_ctx_t v;

        v.r         = r;
        v.conf      = conf;
        v.token     = token;
        v.token_len = token_len;
        v.secret    = secret;
        v.slen      = slen;
        v.claims    = &claims;

        rc = wt_check_issuer_keys(&v, &cache_hit, &via_registry);
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: bearer token validation failed");
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Cache the freshly verified claims for subsequent presentations (L1 always,
     * L2 when a SHM zone is configured).  Registry-authorized tokens are never
     * cached: the decision is path-dependent and the cache is token-keyed. */
    if (!cache_hit && !via_registry) {
        brix_token_l1_store(conf->token_l1, token, token_len, &claims);
        if (conf->token_cache_kv != NULL) {
            brix_token_cache_store(conf->token_cache_kv, token, token_len,
                                     &claims);
        }
    }

    return wt_check_claims(r, ctx, token, token_len, &claims);
}
