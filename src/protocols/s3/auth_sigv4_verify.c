/*
 * auth_sigv4_verify.c — AWS Signature Version 4 verification orchestrator.
 *
 * WHAT: Owns the SigV4 verification entry point (s3_verify_sigv4) and the
 *       decision-side helpers around it: the auth-result metric sink, the
 *       WLCG bearer-token intercept, the presigned-vs-header credential parse
 *       fork, the STS session-token gate, and the success-side commit.
 * WHY:  This file exceeded the ~500-line file-size guard, so the byte-frozen
 *       timestamp rules and the SigV4 crypto were carved into auth_sigv4_verify_
 *       time.c and auth_sigv4_verify_crypto.c (phase-79). What remains here is
 *       the orchestration — a flat early-return sequence over the split steps —
 *       plus the side-effect-light gates that guard it. INVARIANT §6: SigV4 and
 *       Bearer are mutually exclusive per request; the intercept keeps that
 *       arbitration in one auditable place.
 * HOW:  s3_verify_sigv4 threads the split steps: bearer intercept → anonymous
 *       short-circuit → parse credentials → deferred constant-time access-key
 *       match → session-token gate → resolve request time (verify_time.c) →
 *       compute signature (verify_crypto.c) → single constant-time compare
 *       (verify_crypto.c) → commit. Byte layout, messages, and result codes are
 *       preserved 1:1 with the pre-split single-file implementation.
 */

#include "s3.h"
#include "auth_bearer.h"
#include "s3_auth_internal.h"
#include "auth_sigv4_verify_internal.h"
#include "observability/metrics/unified.h"

#include <string.h>
#include <openssl/crypto.h>

/*
 * s3_record_auth_result — record a SigV4 auth outcome into the metric counters.
 *
 * WHAT:  Increment the per-result S3 auth counter and the unified auth metric
 *        for the given BRIX_S3_AUTH_* result code.
 * WHY:   Every SigV4 verify unit (this file plus verify_time.c / verify_crypto.c)
 *        records its outcome on both success and rejection edges, so the sink is
 *        exported here and called across the split.
 * HOW:   Bump the raw result counter, then map the result to the unified
 *        authn-method/success pair.
 */
void
s3_record_auth_result(ngx_uint_t result)
{
    BRIX_S3_METRIC_INC(auth_total[result]);

    switch (result) {
    case BRIX_S3_AUTH_ANONYMOUS:
        brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_NONE, 1);
        break;
    case BRIX_S3_AUTH_SIGV4_OK:
        brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_S3KEY, 1);
        break;
    case BRIX_S3_AUTH_MISSING:
        brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_NONE, 0);
        break;
    default:
        brix_metric_auth(BRIX_PROTO_S3, BRIX_AUTHN_S3KEY, 0);
        break;
    }
}

/*
 * s3_signed_headers_contains — test whether a SignedHeaders list names a header.
 *
 * WHAT:  Return 1 when the semicolon-separated signed_hdrs list contains name
 *        (case-insensitive, whole-token match), 0 otherwise.
 * WHY:   The session-token gate must confirm x-amz-security-token was actually
 *        covered by the signature; a whole-token scan avoids substring matches.
 * HOW:   Walk signed_hdrs token by token on ';', comparing each token's length
 *        and case-insensitive bytes against name.
 */
static ngx_flag_t
s3_signed_headers_contains(const char *signed_hdrs, const char *name)
{
    size_t      name_len;
    const char *p;
    const char *end;

    if (signed_hdrs == NULL || name == NULL) {
        return 0;
    }

    name_len = strlen(name);
    p = signed_hdrs;

    while (*p != '\0') {
        while (*p == ';') {
            p++;
        }

        end = strchr(p, ';');
        if (end == NULL) {
            end = p + strlen(p);
        }

        if ((size_t) (end - p) == name_len
            && ngx_strncasecmp((u_char *) p, (u_char *) name, name_len) == 0)
        {
            return 1;
        }

        p = end;
    }

    return 0;
}

/*
 * s3_request_has_session_token — detect an STS session token on the request.
 *
 * WHAT:  Return 1 when the request carries an X-Amz-Security-Token (header, or
 *        the query param on a presigned request), 0 otherwise.
 * WHY:   The session-token policy gate only engages when a token is actually
 *        present; this predicate keeps that detection in one place.
 * HOW:   Check the x-amz-security-token header first; for presigned requests
 *        also check the X-Amz-Security-Token query argument.
 */
static ngx_flag_t
s3_request_has_session_token(ngx_http_request_t *r, ngx_flag_t presigned)
{
    ngx_str_t token;

    token = get_header(r, "x-amz-security-token");
    if (token.len > 0) {
        return 1;
    }

    if (presigned
        && ngx_http_arg(r, (u_char *) "X-Amz-Security-Token", 20, &token)
           == NGX_OK
        && token.len > 0)
    {
        return 1;
    }

    return 0;
}

/*
 * WLCG bearer-token intercept (INVARIANT §6: SigV4 and Bearer are mutually
 * exclusive per request — never blend the auth logic).
 *
 * WHAT:  When brix_s3_token is enabled, decide whether the request should be
 *        handled by the Bearer path, rejected, or allowed to fall through to
 *        SigV4/anonymous.
 * WHY:   Keeps the token-vs-SigV4 arbitration in one place so the SigV4 verifier
 *        body stays a linear sequence and INVARIANT §6 is auditable at a glance.
 * HOW:   Detects Bearer and SigV4 presence; both-present is a 400 client error;
 *        Bearer-only dispatches to s3_verify_bearer; token-only mode with neither
 *        is a 403.  Returns NGX_DECLINED to mean "fall through to SigV4"; any
 *        other value is a terminal response already emitted by this helper.
 *
 * Returns: NGX_DECLINED to continue into the SigV4/anonymous path, otherwise the
 *   terminal ngx_int_t result (response emitted).
 */
static ngx_int_t
s3_sigv4_bearer_intercept(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    brix_identity_t *identity)
{
    ngx_str_t authz;
    int       has_bearer;
    int       has_sigv4;

    if (!cf->token_enable) {
        return NGX_DECLINED;
    }

    authz      = get_header(r, "authorization");
    has_bearer = s3_bearer_present(r);
    has_sigv4  = (authz.len >= 4
                 && ngx_strncasecmp(authz.data, (u_char *) "AWS4", 4) == 0);

    if (has_bearer && has_sigv4) {
        s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidRequest",
                                 "both Bearer and SigV4 credentials present");
    }

    if (has_bearer) {
        return s3_verify_bearer(r, cf, identity);
    }

    /* Enforcing token-only mode: no Bearer, no SigV4 — reject. */
    if (!has_sigv4) {
        s3_record_auth_result(BRIX_S3_AUTH_MISSING);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "bearer token required");
    }

    /* SigV4 credentials were presented: fall through to verify them if an
     * access_key is configured, or to the anonymous path if not. */
    return NGX_DECLINED;
}

/*
 * s3_sigv4_parse_authz_header — parse the SigV4 credentials into components.
 *
 * WHAT:  Populate *comp from either a presigned URL query string or the
 *        Authorization header.
 * WHY:   Isolates the presigned-vs-header parse fork (and its two distinct error
 *        messages) from the verifier orchestrator.
 * HOW:   Try presigned first; on NGX_DECLINED fall back to the header parse.
 *        Frozen error messages and result codes preserved 1:1.
 *
 * Returns: NGX_OK when *comp is filled, otherwise the terminal ngx_int_t result
 *   (response already emitted).
 */
static ngx_int_t
s3_sigv4_parse_authz_header(ngx_http_request_t *r, sigv4_components_t *comp)
{
    ngx_str_t auth;
    int       parse_rc;

    ngx_memzero(comp, sizeof(*comp));

    parse_rc = parse_presigned_authorization(r, comp);
    if (parse_rc == NGX_DECLINED) {
        auth = get_header(r, "authorization");
        if (auth.len == 0) {
            s3_record_auth_result(BRIX_S3_AUTH_MISSING);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Missing Authorization header");
        }

        if (!parse_authorization(&auth, comp)) {
            s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Malformed Authorization header");
        }

        return NGX_OK;
    }

    if (parse_rc != NGX_OK) {
        s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Malformed presigned URL");
    }

    return NGX_OK;
}

/*
 * s3_sigv4_check_session_token — enforce STS session-token policy.
 *
 * WHAT:  Reject requests that carry an X-Amz-Security-Token when STS session
 *        tokens are disabled, or (for header-signed requests) when the token was
 *        not covered by the signature.
 * WHY:   Keeps the session-token gate out of the verifier's main line.
 * HOW:   Only acts when the request actually carries a session token; frozen
 *        error messages and result codes preserved 1:1.
 *
 * Returns: NGX_OK to continue, otherwise the terminal ngx_int_t result.
 */
static ngx_int_t
s3_sigv4_check_session_token(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const sigv4_components_t *comp)
{
    if (!s3_request_has_session_token(r, comp->presigned)) {
        return NGX_OK;
    }

    if (!cf->allow_unsigned_session_token) {
        s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "STS session tokens are not enabled");
    }

    if (!comp->presigned
        && !s3_signed_headers_contains(comp->signed_hdrs,
                                       "x-amz-security-token"))
    {
        s3_record_auth_result(BRIX_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "X-Amz-Security-Token must be signed");
    }

    return NGX_OK;
}

/*
 * s3_sigv4_finish — commit a successful verification.
 *
 * WHAT:  Record the OK result, bind the S3-key subject identity, and (when
 *        per-chunk signature verification is enabled) retain the SigV4 material
 *        the streaming decoder needs.
 * WHY:   Keeps the success-side side effects at the edge of the verifier, out of
 *        the decision logic.
 * HOW:   Set identity subject; on the signed (non-presigned) path only, copy the
 *        signing key, seed signature, full timestamp, and scope into the request
 *        module ctx (W6a).  Frozen result codes and buffer layout preserved 1:1.
 *
 * Returns: NGX_OK on success, otherwise the terminal ngx_int_t result.
 */
static ngx_int_t
s3_sigv4_finish(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const sigv4_components_t *comp, brix_identity_t *identity,
    const u_char k4[32], const char *amz_date)
{
    ngx_http_s3_req_ctx_t *rx;

    s3_record_auth_result(BRIX_S3_AUTH_SIGV4_OK);
    if (identity != NULL
        && brix_identity_set_subject(identity, r->pool, comp->akid,
                                     BRIX_AUTHN_S3KEY) != NGX_OK)
    {
        s3_record_auth_result(BRIX_S3_AUTH_INTERNAL_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * W6a: when per-chunk signature verification is enabled, retain the SigV4
     * material the streaming decoder needs (seed signature, signing key, scope,
     * timestamp) — it is otherwise local to this function and discarded.  Only
     * the signed (non-presigned) header path produces a seed signature usable as
     * the first chunk's previous-signature.
     */
    if (cf->verify_chunk_signatures && !comp->presigned) {
        rx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
        if (rx != NULL) {
            u_char *e;
            ngx_memcpy(rx->sigv4_signing_key, k4, 32);
            ngx_cpystrn((u_char *) rx->sigv4_seed_signature,
                        (u_char *) comp->signature,
                        sizeof(rx->sigv4_seed_signature));
            ngx_cpystrn((u_char *) rx->sigv4_amz_date,
                        (u_char *) amz_date,   /* full timestamp (header path) */
                        sizeof(rx->sigv4_amz_date));
            e = ngx_snprintf((u_char *) rx->sigv4_scope,
                             sizeof(rx->sigv4_scope) - 1,
                             "%s/%s/s3/aws4_request", comp->date, comp->region);
            *e = '\0';
            rx->have_sigv4 = 1;
        }
    }

    return NGX_OK;
}

/*
 * Main verification entry point
 * */

/*
 * s3_verify_sigv4 — verify an AWS Signature Version 4 Authorization header.
 *
 * Implements the standard SigV4 verification algorithm:
 *   1. Parse the Authorization header into AKID, date, region, signed headers
 *      and signature components.
 *   2. Verify the access key matches the configured key.
 *   3. Build the canonical request (method, URI, query string, headers).
 *   4. Build the string-to-sign from the canonical request hash.
 *   5. Derive the signing key via four rounds of HMAC-SHA256:
 *        k1 = HMAC("AWS4" + secret, date)
 *        k2 = HMAC(k1, region)
 *        k3 = HMAC(k2, "s3")
 *        k4 = HMAC(k3, "aws4_request")
 *   6. Compute HMAC-SHA256(k4, string-to-sign) and compare with the
 *      client-provided signature.
 *
 * XrdClS3 always uses UNSIGNED-PAYLOAD so the request body is not hashed.
 *
 * Anonymous mode: when cf->access_key.len == 0, all requests pass without
 * any verification (useful for read-only public endpoints).
 *
 * Returns: NGX_OK if the signature is valid (or anonymous mode), or an
 *   XML S3 error response (via s3_send_xml_error) on failure.
 */
ngx_int_t
s3_verify_sigv4(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    brix_identity_t *identity)
{
    sigv4_components_t comp;
    s3_amz_date_out_t  amz;
    s3_sigv4_sig_out_t sig;
    ngx_int_t          rc;
    int                key_ok;        /* W5: deferred access-key match flag */

    ngx_memzero(&amz, sizeof(amz));
    ngx_memzero(&sig, sizeof(sig));

    /* WLCG bearer-token intercept (INVARIANT §6). NGX_DECLINED = fall through. */
    rc = s3_sigv4_bearer_intercept(r, cf, identity);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Anonymous mode */
    if (cf->access_key.len == 0) {
        if (identity != NULL) {
            identity->auth_method = BRIX_AUTHN_NONE;
        }
        s3_record_auth_result(BRIX_S3_AUTH_ANONYMOUS);
        return NGX_OK;
    }

    rc = s3_sigv4_parse_authz_header(r, &comp);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Verify the access key — W5: do NOT early-return on mismatch.
     *
     * An early exit here (before the signing-key derive + HMAC compute below)
     * created a timing AND message oracle: an unknown key returned quickly with
     * "InvalidAccessKeyId", while a known key with a bad signature ran the full
     * HMAC and returned "SignatureDoesNotMatch".  An attacker could enumerate
     * valid access keys from the response time and message alone.
     *
     * Instead, record the result in key_ok (constant-time compare) and fold it
     * into the single signature decision at the end, so both an unknown key and
     * a bad signature traverse the same HMAC work and return the identical
     * "SignatureDoesNotMatch" error.  The length check short-circuits the
     * CRYPTO_memcmp only to avoid an out-of-bounds read; the akid length is not
     * a sensitive secret.
     */
    key_ok = (cf->access_key.len == strlen(comp.akid))
             && CRYPTO_memcmp(cf->access_key.data,
                              (u_char *) comp.akid, cf->access_key.len) == 0;

    rc = s3_sigv4_check_session_token(r, cf, &comp);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = s3_sigv4_resolve_request_time(r, &comp, &amz);
    if (rc != NGX_OK) {
        return rc;
    }

    if (s3_sigv4_compute_signature(r, cf, &comp, &amz, &sig) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = s3_sigv4_compare(r, &comp, sig.computed_hex, key_ok);
    if (rc != NGX_OK) {
        return rc;
    }

    return s3_sigv4_finish(r, cf, &comp, identity, sig.k4, amz.date);
}
