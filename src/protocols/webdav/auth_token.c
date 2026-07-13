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

/* webdav_token_op_class — map the HTTP method to a registry op class * Read-ish verbs (GET/HEAD/PROPFIND/OPTIONS) authorize against read scopes;
 * everything else (PUT/DELETE/MKCOL/MOVE/COPY/PROPPATCH/LOCK/...) is a write. */
static brix_token_op_e
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
 * wt_validate_ctx_t — the immutable inputs shared by every token-validation
 * step (registry, JWKS, grace-period retry).  Bundled into one file-local struct
 * so the validation helpers thread a single context instead of a long,
 * error-prone parameter list; `claims` is the sole out-param and is written only
 * on a successful validation.
 */
typedef struct {
    ngx_http_request_t              *r;
    ngx_http_brix_webdav_loc_conf_t *conf;
    const char                      *token;
    size_t                           token_len;
    const u_char                    *secret;      /* parsed primary secret        */
    ssize_t                          slen;        /* <=0 => no macaroon secret     */
    brix_token_claims_t             *claims;      /* OUT: verified claims          */
} wt_validate_ctx_t;

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
 * wt_parse_header — obtain the presented bearer token and scrub it from logs.
 *
 * WHAT: Resolves the request's bearer token from the Authorization header,
 * falling back to the ?authz=/?access_token= query parameter, and — once the
 * token has been consumed for auth — length-preservingly redacts any URL-borne
 * token from every loggable request field.  Returns the token via *bearer.
 * WHY: WLCG clients present the token either in the header (primary) or the URL
 * (davix/gfal2 redirect + pre-signed flows); both must be accepted with the same
 * precedence XrdHttp uses.  A URL token must never reach access/error logs, so
 * the scrub happens here, immediately after extraction, before any early return
 * that could log the request line.
 * HOW: no header → query fallback (NGX_DECLINED when absent); header present but
 * not Bearer → query fallback; a malformed Bearer header → NGX_HTTP_UNAUTHORIZED;
 * on success redact r->args/unparsed_uri/request_line when a query string exists
 * (r->uri excludes the query, so routing/scope are unaffected).
 */
static ngx_int_t
wt_parse_header(ngx_http_request_t *r,
                ngx_http_brix_webdav_loc_conf_t *conf, ngx_str_t *bearer)
{
    ngx_str_t auth_hdr;
    int       rc;

    if (r->headers_in.authorization == NULL) {
        /* No Authorization header — try the ?authz= query fallback (§1). */
        if (webdav_bearer_from_query(r, conf, bearer) != NGX_OK) {
            return NGX_DECLINED;
        }
    } else {
        auth_hdr = r->headers_in.authorization->value;
        rc = brix_http_extract_bearer(&auth_hdr, bearer);
        if (rc == NGX_DECLINED) {
            /* Header present but not Bearer — still allow the query fallback. */
            if (webdav_bearer_from_query(r, conf, bearer) != NGX_OK) {
                return NGX_DECLINED;
            }
        } else if (rc != NGX_OK) {
            return NGX_HTTP_UNAUTHORIZED;
        }
    }

    /* §1: the token has now been consumed for auth. Scrub any ?authz=/?access_token=
     * value, length-preserving, from every log source (args, unparsed URI, request
     * line) so a URL-borne bearer token never reaches access/error logs. r->uri (the
     * decoded path used for routing/scope) excludes the query, so this is safe. */
    if (r->args.len > 0) {
        brix_http_redact_query_token(&r->args);
        brix_http_redact_query_token(&r->unparsed_uri);
        brix_http_redact_query_token(&r->request_line);
    }

    return NGX_OK;
}

/*
 * wt_validate_registry — run path+op-scoped registry validation for a token.
 *
 * WHAT: Copies the request URI into a bounded NUL-terminated buffer, populates a
 * brix_token_registry_args_t from the location config + parsed macaroon secret,
 * and validates the token against the issuer registry, returning the validator
 * rc (0 = accepted) with verified claims in *claims.
 * WHY: registry authz (phase-59 W1) is path+op dependent and therefore MUST NOT
 * consult the token-keyed caches — it is split out so the orchestrator can route
 * a registry config straight here every request without cache branching.
 * HOW: bound the URI to sizeof(pathz)-1, build the args struct (secret only when
 * slen>0), derive the op class from the HTTP method, and call
 * brix_token_validate_registry() with a throwaway bucket out-param.
 */
static int
wt_validate_registry(const wt_validate_ctx_t *v)
{
    ngx_http_request_t         *r = v->r;
    char                        pathz[2048];
    size_t                      plen;
    int                         bucket = 0;
    brix_token_registry_args_t  ra;

    plen = (r->uri.len < sizeof(pathz) - 1) ? r->uri.len : sizeof(pathz) - 1;
    ngx_memcpy(pathz, r->uri.data, plen);
    pathz[plen] = '\0';

    ra.log             = r->connection->log;
    ra.token           = v->token;
    ra.token_len       = v->token_len;
    ra.reg             = v->conf->token_registry;
    ra.macaroon_secret = v->slen > 0 ? v->secret : NULL;
    ra.secret_len      = (size_t) v->slen;
    ra.clock_skew      = (int) v->conf->token_clock_skew;
    ra.claims          = v->claims;

    return brix_token_validate_registry(&ra, pathz,
                                        webdav_token_op_class(r), &bucket);
}

/*
 * wt_validate_jwks — validate a token against the JWKS keys + macaroon secret.
 *
 * WHAT: Builds a brix_token_validate_args_t from the location config's JWKS keys,
 * issuer/audience, clock skew, and the supplied secret, then runs the JWT/macaroon
 * validator, returning its rc (0 = accepted) with verified claims in *claims.
 * WHY: both the primary validation and the old-secret grace-period retry issue an
 * identical validate call differing only in the secret bytes; centralising the
 * args assembly keeps the two callsites byte-identical and off the orchestrator's
 * complexity budget.
 * HOW: populate the args struct (secret NULL when slen<=0), call
 * brix_token_validate(); no side effects beyond writing *claims on success.  The
 * secret/slen are taken as explicit overrides so the grace-period retry can pass
 * the old secret while reusing the same immutable context.
 */
static int
wt_validate_jwks(const wt_validate_ctx_t *v,
                 const u_char *secret, ssize_t slen)
{
    brix_token_validate_args_t  va;

    va.log               = v->r->connection->log;
    va.token             = v->token;
    va.token_len         = v->token_len;
    va.keys              = v->conf->jwks_keys;
    va.key_count         = v->conf->jwks_key_count;
    va.expected_issuer   = (const char *) v->conf->token_issuer.data;
    va.expected_audience = (const char *) v->conf->token_audience.data;
    va.macaroon_secret   = slen > 0 ? secret : NULL;
    va.secret_len        = (size_t) slen;
    va.clock_skew        = (int) v->conf->token_clock_skew;
    va.claims            = v->claims;

    return brix_token_validate(&va);
}

/*
 * wt_grace_retry — retry macaroon validation with the rotated-out old secret.
 *
 * WHAT: When primary validation has failed on a non-registry request and an old
 * macaroon secret is configured, parses it and re-runs JWKS/macaroon validation
 * with the old key, logging an informational note on success.  Returns the retry
 * rc, or the unchanged incoming rc when the retry is not applicable.
 * WHY: an nginx -s reload that rotates the macaroon secret would otherwise hard-
 * break every in-flight macaroon; accepting the old secret until tokens expire
 * gives graceful migration.  Registry validation has no shared-secret concept and
 * is excluded.
 * HOW: return prev_rc unchanged unless (prev_rc!=0 && !via_registry && old secret
 * present); parse the old secret, and only if it parses (>0) call wt_validate_jwks
 * with it, emitting the grace-period NGX_LOG_INFO line when it now accepts.
 */
static int
wt_grace_retry(const wt_validate_ctx_t *v, int via_registry, int prev_rc)
{
    ngx_http_brix_webdav_loc_conf_t *conf = v->conf;
    u_char                           old_secret[64];
    ssize_t                          old_slen;
    int                              rc;

    /* Grace-period fallback: if the primary secret rejected a macaroon token
     * and an old secret is configured, try validating with the old key.
     * This lets in-flight tokens survive nginx -s reload during key rotation. */
    if (prev_rc == 0 || via_registry || conf->token_macaroon_secret_old.len == 0) {
        return prev_rc;
    }

    old_slen = brix_macaroon_secret_parse(
        (const char *) conf->token_macaroon_secret_old.data,
        conf->token_macaroon_secret_old.len,
        old_secret, sizeof(old_secret));
    if (old_slen <= 0) {
        return prev_rc;
    }

    rc = wt_validate_jwks(v, old_secret, old_slen);
    if (rc == 0) {
        ngx_log_error(NGX_LOG_INFO, v->r->connection->log, 0,
                      "brix_webdav: macaroon accepted via old secret "
                      "(grace-period key rotation)");
    }
    return rc;
}

/*
 * wt_check_issuer_keys — resolve token validity via caches, registry or keys.
 *
 * WHAT: Determines whether the presented token is valid, filling *claims and
 * flagging *cache_hit / *via_registry for the caller's caching decision.  Returns
 * 0 when the token is accepted (from L1, L2, registry, JWKS, or the grace-period
 * old-secret retry), non-zero when rejected.
 * WHY: this is the crypto/lookup hot path — consulting the cheapest source first
 * (per-worker L1, then cross-worker L2 SHM) avoids re-running signature checks and
 * JSON parsing on the event loop under load.  Registry authz is path+op dependent
 * so it MUST bypass the token-keyed caches and re-validate every request.
 * HOW: lazily create L1; on a non-registry request probe L1 then L2 (promoting an
 * L2 hit into L1); otherwise validate via registry or JWKS; finally apply the
 * old-secret grace retry.  Only successfully validated claims are ever cached, and
 * caching itself is left to the caller.
 */
static int
wt_check_issuer_keys(const wt_validate_ctx_t *v,
                     int *cache_hit, int *via_registry)
{
    ngx_http_brix_webdav_loc_conf_t *conf = v->conf;
    const char                      *token = v->token;
    size_t                           token_len = v->token_len;
    brix_token_claims_t             *claims = v->claims;
    int                              rc;

    /*
     * Token-validation caches, consulted cheapest-first so token auth does not
     * re-run crypto + JSON parsing on the event loop under load:
     *   L1 — always-on, per-worker, lockless (lazily created here).  A hit skips
     *        BOTH the signature verification AND the L2 spinlock.
     *   L2 — the optional cross-worker SHM cache.  An L2 hit is promoted into L1
     *        so the next presentation to this worker is an L1 hit.
     * Only successfully validated claims are ever cached.
     */
    *cache_hit = 0;

    /* The token-validity caches are keyed on the token alone.  Registry authz
     * (phase-59 W1) is path+op dependent, so a registry config MUST bypass the
     * caches and re-run the per-request base_path/strategy check every time. */
    *via_registry = (conf->token_registry != NULL);

    if (conf->token_l1 == NULL) {
        conf->token_l1 = brix_token_l1_create(ngx_cycle->pool,
                                                BRIX_TOKEN_L1_SLOTS);
    }

    if (!*via_registry
        && brix_token_l1_lookup(conf->token_l1, token, token_len, claims))
    {
        rc = 0;
        *cache_hit = 1;
    } else if (!*via_registry && conf->token_cache_kv != NULL
               && brix_token_cache_lookup(conf->token_cache_kv,
                                            token, token_len, claims))
    {
        rc = 0;
        *cache_hit = 1;
        brix_token_l1_store(conf->token_l1, token, token_len, claims);
    } else if (*via_registry) {
        rc = wt_validate_registry(v);
    } else {
        rc = wt_validate_jwks(v, v->secret, v->slen);
    }

    return wt_grace_retry(v, *via_registry, rc);
}

/*
 * wt_check_claims — persist verified token claims onto the request context.
 *
 * WHAT: Marks the context token-authenticated, retains the raw JWT bytes for
 * backend passthrough, records the identity claims (sub, scopes) and the DN, and
 * copies the scope list.  Returns NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR on an
 * allocation failure.
 * WHY: downstream scope enforcement (webdav_check_token_scope) and backend
 * credential passthrough read these fields; centralising the store keeps the
 * orchestrator a flat success path and matches the phase-70 §5.4 passthrough rule
 * that the JWT bytes be copied onto r->pool (the wire buffer may be rewritten,
 * e.g. by query-token redaction) and never logged.
 * HOW: set verified/token_auth/auth_source; pnalloc+copy the bearer bytes; call
 * brix_identity_set_token_claims(); cpystrn the subject into ctx->dn; copy up to
 * BRIX_MAX_TOKEN_SCOPES scopes; emit the token-auth-OK INFO line.
 */
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
