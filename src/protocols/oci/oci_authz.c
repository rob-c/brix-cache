/*
 * oci_authz.c — the registry surface's authorization gate (§D4.5).
 *
 * WHAT: decide, once per request, whether this client may act on the local
 *       registry and under what identity, and emit the spec's own refusal
 *       (401 + a `WWW-Authenticate` challenge naming our realm, or 403) when
 *       it may not.
 * WHY:  a push surface that answers 200 to an unauthenticated client is a
 *       supply-chain hole with a green checkmark on it: whatever it accepted
 *       is what every node on the site subsequently runs. So the gate is
 *       fail-closed in the strongest sense available here — a location that
 *       has not been told to accept writes cannot be talked into one, and an
 *       operator who genuinely wants an open registry has to say so in a
 *       directive whose name says what it does.
 *       The 401 shape matters as much as the refusal: `podman login` only
 *       works against a registry that answers an unauthenticated request with
 *       a challenge it can follow, so the header is part of the contract, not
 *       decoration.
 * HOW:  INVARIANT #3 order, without exception — `brix_allow_write` is
 *       consulted BEFORE any token is parsed, so a token with a generous
 *       scope can never open a location the operator kept read-only. Identity
 *       then comes from the plane the location already configured: a TLS
 *       client certificate if one is present, otherwise a bearer validated
 *       against `brix_oci_token_issuers`.
 */

#include "oci_registry.h"

#include "auth/token/token.h"
#include "core/http/http_headers.h"

#include <stdio.h>
#include <string.h>

/* The realm advertised in the challenge. A client follows it verbatim, so it
 * names THIS location's own token endpoint rather than any upstream's — the
 * registry surface never delegates its authentication to a mirror upstream. */
#define OCI_REALM_HEADER_MAX  512

/* Scopes are checked against a path, and the natural path for a repository is
 * the store route it maps onto. "/v2/<name>" is stable, hierarchical and is
 * exactly what an operator would write in a token's `storage.modify` scope. */
#define OCI_SCOPE_PATH_MAX    (BRIX_OCI_KEY_MAX)


/* Is this request asking to CHANGE the registry? Reads on the push surface
 * are ordinary object reads; everything else stores or destroys bytes. */
static int
oci_is_write(ngx_http_request_t *r)
{
    return !(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD));
}


/* The Bearer credential the client presented, or NULL. */
static const char *
oci_bearer_of(ngx_http_request_t *r, size_t *len_out)
{
    ngx_table_elt_t *h = r->headers_in.authorization;

    if (h == NULL || h->value.len <= sizeof("Bearer ") - 1) {
        return NULL;
    }
    if (ngx_strncasecmp(h->value.data, (u_char *) "Bearer ",
                        sizeof("Bearer ") - 1) != 0)
    {
        return NULL;
    }
    *len_out = h->value.len - (sizeof("Bearer ") - 1);
    return (const char *) h->value.data + sizeof("Bearer ") - 1;
}


/* 401 with the challenge a registry client knows how to follow. The realm is
 * this location's own URL: a client that cannot resolve it will fall back to
 * anonymous, which is the honest outcome for a site running no token plane. */
static ngx_int_t
oci_challenge(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    const char *detail)
{
    char  hdr[OCI_REALM_HEADER_MAX];
    int   n;

    ctx->disp = BRIX_OCI_OUT_REFUSED;

    n = snprintf(hdr, sizeof(hdr),
                 "Bearer realm=\"%s://%.*s/v2/token\",service=\"%.*s\"",
                 (r->connection->ssl != NULL) ? "https" : "http",
                 (int) r->headers_in.server.len, r->headers_in.server.data,
                 (int) r->headers_in.server.len, r->headers_in.server.data);
    if (n > 0 && (size_t) n < sizeof(hdr)
        && brix_http_set_header(r, "WWW-Authenticate", hdr, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_WRITE,
                        NGX_HTTP_UNAUTHORIZED);

    return brix_oci_refuse(r, NGX_HTTP_UNAUTHORIZED,
                           BRIX_OCI_ERR_UNAUTHORIZED, detail);
}


static ngx_int_t
oci_deny(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    const char *detail)
{
    ctx->disp = BRIX_OCI_OUT_REFUSED;

    brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_WRITE,
                        NGX_HTTP_FORBIDDEN);

    return brix_oci_refuse(r, NGX_HTTP_FORBIDDEN, BRIX_OCI_ERR_DENIED,
                           detail);
}


/* Validate the presented bearer against every configured issuer, and require
 * a write scope covering this repository. Returns NGX_OK with `principal`
 * filled, NGX_DECLINED when no issuer accepted it, NGX_ABORT when a valid
 * token simply lacks the scope (a 403, not a 401 — re-authenticating would
 * hand back the same token). */
static ngx_int_t
oci_authz_bearer(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    const ngx_http_brix_oci_ctx_t *ctx, char *principal, size_t principal_len)
{
    brix_token_validate_args_t  args;
    brix_token_claims_t         claims;
    char                        path[OCI_SCOPE_PATH_MAX];
    const char                 *tok;
    size_t                      tok_len = 0;
    int                         i;

    tok = oci_bearer_of(r, &tok_len);
    if (tok == NULL || lcf->issuers == NULL || lcf->issuers->count == 0) {
        return NGX_DECLINED;
    }

    for (i = 0; i < lcf->issuers->count; i++) {
        const brix_token_issuer_t *iss = &lcf->issuers->issuers[i];

        if (!iss->enabled || iss->jwks_key_count == 0) {
            continue;
        }
        ngx_memzero(&args, sizeof(args));
        ngx_memzero(&claims, sizeof(claims));
        args.log             = r->connection->log;
        args.token           = tok;
        args.token_len       = tok_len;
        args.keys            = iss->jwks_keys;
        args.key_count       = iss->jwks_key_count;
        args.expected_issuer = iss->issuer;
        args.claims          = &claims;

        if (brix_token_validate(&args) != 0) {
            continue;
        }

        /* A valid token from a trusted issuer. Whether it may WRITE is a
         * separate question with a separate answer code — conflating the two
         * is what sends clients into a re-login loop against a scope problem
         * no login can fix. */
        (void) snprintf(path, sizeof(path), "/v2/%.*s",
                        (int) ctx->req.name_len, ctx->req.name);

        if (oci_is_write(r)
            && !brix_token_check_write(claims.scopes, claims.scope_count,
                                       path))
        {
            return NGX_ABORT;
        }
        (void) snprintf(principal, principal_len, "%s", claims.sub);
        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
brix_oci_registry_authz(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    char *principal, size_t principal_len)
{
    ngx_int_t  rc;

    principal[0] = '\0';

    /* INVARIANT #3: the location's own write permission is consulted first
     * and independently. No credential of any strength promotes a read-only
     * location into a writable one. */
    if (oci_is_write(r) && !lcf->common.allow_write) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_WRITE,
                            NGX_HTTP_FORBIDDEN);
        return brix_oci_refuse(r, NGX_HTTP_FORBIDDEN, BRIX_OCI_ERR_DENIED,
                               "this registry location is read-only "
                               "(brix_allow_write is off)");
    }

    rc = oci_authz_bearer(r, lcf, ctx, principal, principal_len);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    if (rc == NGX_ABORT) {
        return oci_deny(r, ctx, "the presented token carries no write scope "
                                "for this repository");
    }

#if (NGX_HTTP_SSL)
    /* A TLS client certificate the location already validated is an identity
     * in its own right: the handshake did the proving, and requiring a bearer
     * on top would break the x509-only deployments the tree already serves. */
    if (r->connection->ssl != NULL && r->headers_in.authorization == NULL) {
        ngx_str_t  dn = ngx_null_string;

        if (ngx_ssl_get_subject_dn(r->connection, r->pool, &dn) == NGX_OK
            && dn.len > 0)
        {
            (void) snprintf(principal, principal_len, "%.*s",
                            (int) dn.len, dn.data);
            return NGX_OK;
        }
    }
#endif

    if (lcf->registry_anon) {
        /* The typed decision to run an open registry. Recorded as such in the
         * identity so the access log distinguishes "nobody authenticated" from
         * "somebody did, and it was anonymous". */
        (void) snprintf(principal, principal_len, "anonymous");
        return NGX_OK;
    }

    return oci_challenge(r, ctx,
                         "authentication required "
                         "(or set brix_oci_registry_allow_anonymous on)");
}
