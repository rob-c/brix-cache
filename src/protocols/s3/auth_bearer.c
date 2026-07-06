/*
 * auth_bearer.c — WLCG bearer-token validation for the S3 endpoint.
 *
 * WHAT: Implements Bearer-token detection and JWT validation for S3 requests.
 *       The two entry points (s3_bearer_present, s3_verify_bearer) are called by
 *       the s3_verify_sigv4 gate when brix_s3_token is enabled.
 *
 * WHY:  INVARIANT §6: S3 SigV4 and WLCG bearer are mutually exclusive per request
 *       — the auth logic for each scheme must live in separate compilation units
 *       so neither can accidentally depend on the other's internals.  The JWKS
 *       keys are loaded once at config time into cf->jwks_keys and reused across
 *       all requests in a worker process.
 *
 * HOW:
 *   s3_bearer_present — purely reads the Authorization header; no allocations.
 *   s3_verify_bearer  — extracts the token string, validates it with
 *       brix_token_validate(), copies the resulting claims into *identity, and
 *       returns NGX_OK on success.  On failure, sends an XML AccessDenied error
 *       and returns an HTTP error code; the caller propagates this directly.
 *       No goto; early-return style throughout.
 */

#include "s3.h"
#include "auth_bearer.h"
#include "auth/token/token.h"
#include "core/types/identity.h"
#include "observability/metrics/unified.h"

#include <string.h>

/* get_header() is defined (non-static) in auth_sigv4_parse.c; declared extern
 * here rather than adding a new shared header for a single helper — the
 * function has external linkage at the object-file level and the linker resolves
 * it within the same module. */
extern ngx_str_t get_header(ngx_http_request_t *r, const char *name);

/* Maximum JWT length we accept.  Real WLCG tokens are 300-2000 bytes; 8 KiB
 * is a generous guard against oversized-token DoS without pathological RAM use. */
#define S3_BEARER_MAX_TOKEN_LEN  8192

/* Length of the "Bearer " prefix (seven bytes, including the space). */
#define S3_BEARER_PREFIX_LEN  7

/*
 * s3_bearer_present — detect a Bearer Authorization header.
 *
 * WHAT: Pure predicate — reads the Authorization header and returns 1 if the
 *       value starts with "Bearer " (case-insensitive).
 * WHY:  The caller (s3_verify_sigv4) needs to decide whether to route to the
 *       bearer path or the SigV4/anonymous path before any token work happens.
 * HOW:  brix_http_get_header returns the raw Authorization value; we compare
 *       the first 7 bytes case-insensitively.  Short strings are rejected (< 7).
 */
int
s3_bearer_present(ngx_http_request_t *r)
{
    ngx_str_t authz;

    authz = get_header(r, "authorization");
    if (authz.len < S3_BEARER_PREFIX_LEN) {
        return 0;
    }

    return ngx_strncasecmp(authz.data,
                           (u_char *) "Bearer ",
                           S3_BEARER_PREFIX_LEN) == 0;
}

/*
 * s3_verify_bearer — validate a WLCG JWT bearer token from Authorization header.
 *
 * WHAT: Extracts the token from Authorization: Bearer <token>, validates the JWT
 *       signature and claims against the JWKS keys in *cf, and on success
 *       populates *identity with the subject, scopes, and groups from the claims.
 *
 * WHY:  brix_token_validate is the canonical JWT verifier shared across all
 *       protocols; this wrapper adapts its inputs/outputs to the S3 handler's
 *       calling convention (returns NGX_OK / HTTP-error-code, response already
 *       sent on error).
 *
 * HOW:  Extracts token bytes from the Authorization header (after "Bearer "),
 *       guards the length, calls brix_token_validate, on failure sends XML
 *       AccessDenied and returns the HTTP code, on success calls
 *       brix_identity_set_token_claims and records the auth metric.
 *       No goto; early-return on every failure.
 */
ngx_int_t
s3_verify_bearer(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, brix_identity_t *identity)
{
    ngx_str_t            authz;
    const char          *token;
    size_t               token_len;
    brix_token_claims_t  claims;
    int                  rc;

    authz = get_header(r, "authorization");

    /* Caller guarantees s3_bearer_present() returned 1, so the prefix is there;
     * advance past "Bearer " to the token proper. */
    if (authz.len <= S3_BEARER_PREFIX_LEN) {
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "Bearer token missing after Authorization prefix");
    }

    token     = (const char *) authz.data + S3_BEARER_PREFIX_LEN;
    token_len = authz.len - S3_BEARER_PREFIX_LEN;

    if (token_len > S3_BEARER_MAX_TOKEN_LEN) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_s3: bearer token too large (%uz bytes)", token_len);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "bearer token exceeds maximum permitted length");
    }

    ngx_memzero(&claims, sizeof(claims));

    rc = brix_token_validate(r->connection->log,
                               token, token_len,
                               cf->jwks_keys, cf->jwks_key_count,
                               (const char *) cf->token_issuer.data,
                               (const char *) cf->token_audience.data,
                               NULL, 0,
                               (int) cf->token_clock_skew,
                               &claims);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_s3: bearer token validation failed");
        brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_TOKEN, 0);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "bearer token validation failed");
    }

    if (identity != NULL
        && brix_identity_set_token_claims(identity, r->pool, &claims) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "brix_s3: failed to set token identity claims (OOM?)");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Record a successful token auth in the unified protocol metrics. */
    brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_TOKEN, 1);
    return NGX_OK;
}
