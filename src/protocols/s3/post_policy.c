/*
 * post_policy.c - extracted concern
 * Phase-38 split of post_object.c; behavior-identical. SigV4 signature
 * verification over the POST policy. Condition evaluation + document
 * validation live in post_policy_conditions.c (shared via s3_post_internal.h).
 */
#include "s3_post_internal.h"


/*
 * WHAT: Validate the x-amz-credential scope and extract its date and region.
 * WHY:  The credential must be exactly "AKID/YYYYMMDD/REGION/s3/aws4_request"
 *       (full 5-part scope, unlike the parser in auth_sigv4_parse.c which only
 *       needs the first three). We enforce an 8-char date and the literal
 *       "s3/aws4_request" suffix so a forged/short scope is rejected before any
 *       crypto. HOW: locate the four '/' boundaries; *akid is set to point at
 *       the start (the caller measures its length up to p1).
 * Returns NGX_OK (date/region filled, *akid set), or NGX_ERROR if the scope is
 * malformed, the date is not 8 chars, or the suffix is wrong.
 */
ngx_int_t
s3_post_parse_credential(const char *credential, char *date, size_t date_sz,
    char *region, size_t region_sz, const char **akid)
{
    const char *p1, *p2, *p3, *p4;
    size_t      len;

    p1 = strchr(credential, '/');
    if (p1 == NULL) {
        return NGX_ERROR;
    }
    *akid = credential;                 /* AKID = [credential, p1) */

    /* Locate the remaining three slashes; require exactly the 5-part scope and
     * the fixed "s3/aws4_request" trailer (text after the third slash). */
    p2 = strchr(p1 + 1, '/');
    p3 = p2 ? strchr(p2 + 1, '/') : NULL;
    p4 = p3 ? strchr(p3 + 1, '/') : NULL;
    if (p2 == NULL || p3 == NULL || p4 == NULL
        || strcmp(p3 + 1, "s3/aws4_request") != 0)
    {
        return NGX_ERROR;
    }

    /* DATE = (p1, p2) — must be exactly 8 chars (YYYYMMDD). */
    len = (size_t) (p2 - (p1 + 1));
    if (len != 8 || len >= date_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(date, p1 + 1, len);
    date[len] = '\0';

    /* REGION = (p2, p3). */
    len = (size_t) (p3 - (p2 + 1));
    if (len == 0 || len >= region_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(region, p2 + 1, len);
    region[len] = '\0';

    return NGX_OK;
}


/*
 * Parsed SigV4 credential scope for one POST-policy verification, plus the
 * error-status out slot. Threaded (by pointer) through the verify helpers so the
 * per-step signatures stay narrow: `date`/`region` are the NUL-terminated
 * YYYYMMDD and region strings, `akid` points into form->credential at the AKID
 * start, and `status` receives the already-sent S3 error status on any failure.
 */
typedef struct {
    char        date[16];
    char        region[64];
    const char *akid;
    ngx_int_t   status;
} s3_post_scope_t;


/*
 * WHAT: Validate the signature-field shape and parse the credential scope.
 * WHY:  Before any crypto we reject uploads missing a signature field, and we
 *       require the fixed algorithm, a 64-hex signature, and a well-formed
 *       credential — cheap syntactic gates that fail-closed (INVARIANT 6: this
 *       is S3 SigV4, never shared with token auth). HOW: presence checks, then
 *       exact algorithm/length checks, then s3_post_parse_credential().
 * On success fills sc->date/region/akid. On failure sets sc->status to the
 * already-sent S3 error status and returns NGX_ERROR.
 * Returns NGX_OK when the fields are well-formed, NGX_ERROR otherwise.
 */
static ngx_int_t
s3_post_verify_fields(ngx_http_request_t *r, const s3_post_form_t *form,
    s3_post_scope_t *sc)
{
    /* Every signature-bearing field must be present. */
    if (form->policy[0] == '\0' || form->algorithm[0] == '\0'
        || form->credential[0] == '\0' || form->amz_date[0] == '\0'
        || form->signature[0] == '\0')
    {
        sc->status = s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                                   "Missing POST policy signature fields.");
        return NGX_ERROR;
    }

    /* Algorithm fixed, signature is 64 hex chars, credential well-formed. */
    if (strcmp(form->algorithm, "AWS4-HMAC-SHA256") != 0
        || strlen(form->signature) != 64
        || s3_post_parse_credential(form->credential, sc->date, sizeof(sc->date),
                                    sc->region, sizeof(sc->region), &sc->akid)
           != NGX_OK)
    {
        sc->status = s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidRequest",
                                   "Malformed POST policy signature fields.");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * WHAT: Match the credential's AKID, region, and date against this endpoint.
 * WHY:  A well-formed credential is not enough — its access key, region, and
 *       scope date must be the ones this location is configured for, else the
 *       upload is for a different key/endpoint. HOW: compare the AKID span
 *       ([akid, first '/')) to cf->access_key, then region to cf->region, then
 *       the scope date to the first 8 chars (YYYYMMDD) of x-amz-date.
 * On mismatch sets sc->status to the already-sent S3 error and returns
 * NGX_ERROR. Returns NGX_OK when all three agree, NGX_ERROR otherwise.
 */
static ngx_int_t
s3_post_verify_scope(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, s3_post_scope_t *sc)
{
    /* AKID = bytes from `akid` up to the first '/'; its length must equal the
     * configured key length AND the bytes must match exactly. */
    if ((size_t) (strchr(form->credential, '/') - sc->akid) != cf->access_key.len
        || ngx_strncmp(cf->access_key.data, (u_char *) sc->akid,
                       cf->access_key.len) != 0)
    {
        sc->status = s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidAccessKeyId",
                                   "The access key ID does not exist.");
        return NGX_ERROR;
    }

    /* Region must match the endpoint, and the credential-scope date must agree
     * with the first 8 chars (YYYYMMDD) of x-amz-date. */
    if (cf->region.len != strlen(sc->region)
        || ngx_strncmp(cf->region.data, (u_char *) sc->region, cf->region.len)
           != 0
        || ngx_strncmp((u_char *) form->amz_date, (u_char *) sc->date, 8) != 0)
    {
        sc->status = s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                                   "Credential scope does not match this "
                                   "endpoint.");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * WHAT: Derive the SigV4 signing key, HMAC the policy string, and compare it
 *       constant-time against the submitted signature.
 * WHY:  This proves the base64 policy string *as submitted* was signed by the
 *       secret-key holder; we HMAC the raw form->policy bytes, NOT the decoded
 *       JSON. HOW: derive the date/region-scoped key, HMAC-SHA256 the policy,
 *       hex-encode, then CRYPTO_memcmp (so a mismatch position cannot be
 *       timing-probed).
 * On a signature mismatch sets sc->status to the already-sent S3 error and
 * returns NGX_ERROR; on a crypto failure sets sc->status to 500 and returns
 * NGX_ERROR. Returns NGX_OK when the signature matches.
 */
static ngx_int_t
s3_post_verify_signature(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, s3_post_scope_t *sc)
{
    u_char  k4[32], computed[32];
    char    computed_hex[65];

    if (!s3_sigv4_derive_signing_key_cached(&cf->secret_key,
                                             sc->date, sc->region, k4)
        || !brix_hmac_sha256(k4, 32, (u_char *) form->policy,
                               strlen(form->policy), computed))
    {
        sc->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    brix_hex_encode(computed, 32, computed_hex);
    /* Constant-time compare to avoid leaking how many bytes matched. */
    if (CRYPTO_memcmp(computed_hex, form->signature, 64) != 0) {
        sc->status = s3_post_error(r, NGX_HTTP_FORBIDDEN,
                                   "SignatureDoesNotMatch",
                                   "The request signature we calculated does not "
                                   "match the signature you provided.");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * WHAT: Base64-decode the (already signature-verified) policy and enforce it.
 * WHY:  Only after the signature matches may we trust the policy string; we then
 *       decode it to JSON and check expiration + conditions. HOW: allocate a
 *       decode buffer (base64 expands ~4:3, plus slack and a NUL), decode, then
 *       s3_post_validate_policy_json(); map its verdict to an S3 error.
 * Returns NGX_OK if the policy authorises the upload; otherwise an already-sent
 * S3 error status (suitable for the metrics finalize call).
 */
static ngx_int_t
s3_post_enforce_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form)
{
    ngx_str_t  src, decoded;
    ngx_int_t  rc;

    src.data = (u_char *) form->policy;
    src.len = ngx_strlen(form->policy);
    decoded.len = src.len / 4 * 3 + 4;
    decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
    if (decoded.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&decoded, &src) != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }
    decoded.data[decoded.len] = '\0';

    rc = s3_post_validate_policy_json(r, cf, form, decoded.data, decoded.len);
    /* DECLINED = a condition/expiry failed (403); other non-OK = bad document. */
    if (rc == NGX_DECLINED) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "POST policy conditions were not satisfied.");
    }
    if (rc != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }

    return NGX_OK;
}


/*
 * WHAT: Verify the SigV4 signature over the POST policy, then enforce the policy.
 * WHY:  This is the authentication+authorization gate for a browser upload. The
 *       signature proves the policy was issued by the holder of the secret key;
 *       the policy then constrains what may be uploaded (INVARIANT 6: S3 SigV4,
 *       never shared with token auth).
 * HOW (in order, fail-closed at each step):
 *   1. If no access key is configured, S3 auth is disabled -> allow.
 *   2-3. s3_post_verify_fields: fields present, algorithm/length/scope shape.
 *   4. s3_post_verify_scope: AKID, region, and date match this endpoint.
 *   5. s3_post_verify_signature: derive key, HMAC, constant-time compare.
 *   6. s3_post_enforce_policy: decode and enforce expiration + conditions.
 * Returns NGX_OK if authorised; otherwise an already-sent S3 error status (the
 * return value is the HTTP status, suitable for the metrics finalize call).
 */
ngx_int_t
s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form)
{
    s3_post_scope_t sc = {0};

    /* Step 1: no configured key => S3 authentication disabled for this location. */
    if (cf->access_key.len == 0) {
        return NGX_OK;
    }

    /* Steps 2-3: signature fields present and well-formed; parse credential. */
    if (s3_post_verify_fields(r, form, &sc) != NGX_OK) {
        return sc.status;
    }

    /* Step 4: AKID, region, and scope date match this endpoint. */
    if (s3_post_verify_scope(r, cf, form, &sc) != NGX_OK) {
        return sc.status;
    }

    /* Step 5: derive signing key, HMAC the policy string, constant-time compare. */
    if (s3_post_verify_signature(r, cf, form, &sc) != NGX_OK) {
        return sc.status;
    }

    /* Step 6: signature is valid -> decode the policy and enforce its contents. */
    return s3_post_enforce_policy(r, cf, form);
}
