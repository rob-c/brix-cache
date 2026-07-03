/*
 * post_policy.c - extracted concern
 * Phase-38 split of post_object.c; behavior-identical.
 */
#include "s3_post_internal.h"


/*
 * WHAT: Convert a proleptic-Gregorian civil date (y, m, d) to a day count
 *       relative to the Unix epoch (1970-01-01 == 0).
 * WHY:  Policy expiry must be compared against ngx_time() without depending on
 *       the host timezone, so we compute a UTC epoch directly rather than via
 *       mktime() (which is local-time and not async-signal-safe).
 * HOW:  Howard Hinnant's well-known days_from_civil algorithm. It shifts the
 *       year so March is month 1 (Feb's leap day lands at year-end), groups
 *       years into 400-year "eras" (each exactly 146097 days), then offsets by
 *       719468 to re-anchor era day 0 onto the Unix epoch. Constants are exact,
 *       not approximations. Reference: howardhinnant.github.io/date_algorithms.html
 * Returns signed days since 1970-01-01 (negative for pre-epoch dates).
 */
int64_t
s3_post_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t   era;
    unsigned  yoe, doy, doe;
    int       mp;

    y -= m <= 2;                                /* Jan/Feb count to prior year */
    era = (y >= 0 ? y : y - 399) / 400;         /* 400-year era index */
    yoe = (unsigned) (y - era * 400);           /* year-of-era [0, 399] */
    mp = (int) m + (m > 2 ? -3 : 9);            /* month, March=0 .. Feb=11 */
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;/* day-of-year, March 1 == 0 */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;/* day-of-era [0, 146096] */

    return era * 146097 + (int64_t) doe - 719468;
}


/*
 * WHAT: Parse an ISO 8601 UTC timestamp "YYYY-MM-DDTHH:MM:SSZ" to a time_t.
 * WHY:  POST policy "expiration" is given in this exact UTC form; we need it as
 *       an epoch seconds value to compare against ngx_time(). HOW: strict
 *       sscanf with field widths, range-check each component (se <= 60 allows a
 *       leap second), then combine the civil-day count with the time-of-day.
 * Returns NGX_OK with *out set, or NGX_ERROR on a malformed/out-of-range value.
 */
ngx_int_t
s3_post_parse_iso8601(const char *s, time_t *out)
{
    int y, mo, d, h, mi, se;

    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2dZ",
               &y, &mo, &d, &h, &mi, &se) != 6)
    {
        return NGX_ERROR;
    }

    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
    {
        return NGX_ERROR;
    }

    /* epoch = (whole days since 1970) * 86400 + seconds within the day. */
    *out = (time_t) (s3_post_days_from_civil(y, (unsigned) mo, (unsigned) d)
                     * 86400 + h * 3600 + mi * 60 + se);
    return NGX_OK;
}


/*
 * WHAT: Exact-match a submitted field value against a policy-required value.
 * Returns NGX_OK on match, NGX_DECLINED on mismatch or a missing value.
 */
ngx_int_t
s3_post_check_field_eq(const char *actual, const char *expected)
{
    if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) {
        return NGX_DECLINED;
    }
    return NGX_OK;
}


/*
 * WHAT: Evaluate a single POST-policy condition against the submitted form.
 * WHY:  This is the access-control core: a signed policy lists conditions the
 *       upload must satisfy; if any fails the upload is rejected even though the
 *       signature is valid. Two JSON shapes occur (AWS spec):
 *         - Object  {"field":"value", ...}  : every field must equal exactly
 *           (the special "bucket" key is matched against the configured bucket).
 *         - Array   ["op", "field|$field", "value"] : op is "eq", "starts-with",
 *           or "content-length-range" (which bounds the file size).
 * HOW:  Dispatch on JSON type, then on operator; compare against the form
 *       value resolved via s3_post_field_value().
 * Returns NGX_OK if the condition is satisfied, NGX_DECLINED if it is violated,
 * NGX_ERROR if the condition itself is malformed (unknown shape/op/types).
 */
ngx_int_t
s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, json_t *cond)
{
    const char *key;
    json_t     *value;

    /* Object form: implicit "equals" for every key/value pair. */
    if (json_is_object(cond)) {
        json_object_foreach(cond, key, value) {
            const char *expected;
            const char *actual;

            if (!json_is_string(value)) {
                return NGX_ERROR;
            }

            expected = json_string_value(value);
            /* "bucket" is not a form field — match the configured bucket name. */
            if (strcmp(key, "bucket") == 0) {
                if (cf->bucket.len != strlen(expected)
                    || ngx_strncmp(cf->bucket.data, (u_char *) expected,
                                   cf->bucket.len) != 0)
                {
                    return NGX_DECLINED;
                }
                continue;
            }

            actual = s3_post_field_value(form, key);
            if (s3_post_check_field_eq(actual, expected) != NGX_OK) {
                return NGX_DECLINED;
            }
        }
        return NGX_OK;
    }

    /* Array form: ["op", arg1, arg2] — element 0 selects the comparison. */
    if (json_is_array(cond) && json_array_size(cond) >= 3) {
        const char *op;

        if (!json_is_string(json_array_get(cond, 0))) {
            return NGX_ERROR;
        }

        op = json_string_value(json_array_get(cond, 0));

        /* content-length-range: [op, min, max] bounds the uploaded file size. */
        if (strcmp(op, "content-length-range") == 0) {
            json_int_t minv, maxv;

            if (json_array_size(cond) != 3
                || !json_is_integer(json_array_get(cond, 1))
                || !json_is_integer(json_array_get(cond, 2)))
            {
                return NGX_ERROR;
            }

            minv = json_integer_value(json_array_get(cond, 1));
            maxv = json_integer_value(json_array_get(cond, 2));
            if ((json_int_t) form->file_len < minv
                || (json_int_t) form->file_len > maxv)
            {
                return NGX_DECLINED;
            }
            return NGX_OK;
        }

        /* eq: exact match; starts-with: prefix match (empty value => any). */
        if ((strcmp(op, "eq") == 0 || strcmp(op, "starts-with") == 0)
            && json_array_size(cond) == 3
            && json_is_string(json_array_get(cond, 1))
            && json_is_string(json_array_get(cond, 2)))
        {
            const char *field = json_string_value(json_array_get(cond, 1));
            const char *expected = json_string_value(json_array_get(cond, 2));
            const char *actual = s3_post_field_value(form, field);

            if (actual == NULL) {
                return NGX_DECLINED;
            }

            if (strcmp(op, "eq") == 0) {
                return strcmp(actual, expected) == 0 ? NGX_OK : NGX_DECLINED;
            }

            return strncmp(actual, expected, strlen(expected)) == 0
                   ? NGX_OK : NGX_DECLINED;
        }
    }

    (void) r;
    return NGX_ERROR;
}


/*
 * WHAT: Parse the base64-decoded POST policy JSON and enforce all of it.
 * WHY:  The policy document is what the signature actually covers; once the
 *       signature is verified we must (a) confirm the policy has not expired and
 *       (b) confirm every listed condition holds for this upload. The upload is
 *       only authorised if BOTH hold.
 * HOW:  Load JSON, check "expiration" against ngx_time(), then evaluate each
 *       entry of "conditions" via s3_post_policy_condition().
 * Ownership: `root` is jansson-refcounted; every early-return path json_decref()s
 *       it exactly once to avoid leaking the parse tree.
 * Returns NGX_OK (allow), NGX_DECLINED (expired or a condition failed -> 403),
 * NGX_ERROR (document malformed -> treated as invalid policy).
 */
ngx_int_t
s3_post_validate_policy_json(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form,
    u_char *policy_json, size_t policy_len)
{
    json_error_t  jerr;
    json_t       *root;
    json_t       *expiration;
    json_t       *conditions;
    size_t        i;
    time_t        exp;

    root = json_loadb((const char *) policy_json, policy_len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);          /* decref only if a tree was built */
        }
        return NGX_ERROR;
    }

    /* "expiration" must be present, parseable, and not in the past. */
    expiration = json_object_get(root, "expiration");
    if (!json_is_string(expiration)
        || s3_post_parse_iso8601(json_string_value(expiration), &exp)
           != NGX_OK
        || ngx_time() > exp)
    {
        json_decref(root);
        return NGX_DECLINED;
    }

    conditions = json_object_get(root, "conditions");
    if (!json_is_array(conditions)) {
        json_decref(root);
        return NGX_ERROR;
    }

    /* Every condition must pass; the first non-OK result short-circuits and is
     * propagated (DECLINED = violated, ERROR = malformed condition). */
    for (i = 0; i < json_array_size(conditions); i++) {
        ngx_int_t rc;

        rc = s3_post_policy_condition(r, cf, form,
                                      json_array_get(conditions, i));
        if (rc != NGX_OK) {
            json_decref(root);
            return rc;
        }
    }

    json_decref(root);
    return NGX_OK;
}


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
 * WHAT: Verify the SigV4 signature over the POST policy, then enforce the policy.
 * WHY:  This is the authentication+authorization gate for a browser upload. The
 *       signature in the form proves the policy was issued by the holder of the
 *       secret key; the policy then constrains what may be uploaded. Note the
 *       signed message is the base64 policy string *as submitted* — we HMAC the
 *       raw form->policy bytes, NOT the decoded JSON.
 * HOW (in order, fail-closed at each step):
 *   1. If no access key is configured, S3 auth is disabled -> allow.
 *   2. Require all signature fields to be present.
 *   3. Validate algorithm, signature length (hex64), and credential scope shape.
 *   4. Match the credential's AKID, region, and date against this endpoint.
 *   5. Derive the SigV4 signing key and HMAC-SHA256 the policy string; compare
 *      against the provided signature with CRYPTO_memcmp (constant-time, so a
 *      mismatch position cannot be timing-probed).
 *   6. Only after the signature matches, base64-decode the policy and enforce
 *      its expiration + conditions.
 * Returns NGX_OK if authorised; otherwise an already-sent S3 error status (the
 * return value is the HTTP status, suitable for the metrics finalize call).
 */
ngx_int_t
s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form)
{
    char        date[16];
    char        region[64];
    const char *akid;
    u_char      k4[32], computed[32];
    char        computed_hex[65];
    ngx_str_t   src, decoded;
    ngx_int_t   rc;

    /* Step 1: no configured key => S3 authentication disabled for this location. */
    if (cf->access_key.len == 0) {
        return NGX_OK;
    }

    /* Step 2: every signature-bearing field must be present. */
    if (form->policy[0] == '\0' || form->algorithm[0] == '\0'
        || form->credential[0] == '\0' || form->amz_date[0] == '\0'
        || form->signature[0] == '\0')
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Missing POST policy signature fields.");
    }

    /* Step 3: algorithm fixed, signature is 64 hex chars, credential well-formed. */
    if (strcmp(form->algorithm, "AWS4-HMAC-SHA256") != 0
        || strlen(form->signature) != 64
        || s3_post_parse_credential(form->credential, date, sizeof(date),
                                    region, sizeof(region), &akid) != NGX_OK)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidRequest",
                             "Malformed POST policy signature fields.");
    }

    /* Step 4a: AKID = bytes from `akid` up to the first '/'; its length must
     * equal the configured key length AND the bytes must match exactly. */
    if ((size_t) (strchr(form->credential, '/') - akid) != cf->access_key.len
        || ngx_strncmp(cf->access_key.data, (u_char *) akid,
                       cf->access_key.len) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidAccessKeyId",
                             "The access key ID does not exist.");
    }

    /* Step 4b: region must match the endpoint, and the credential-scope date
     * must agree with the first 8 chars (YYYYMMDD) of x-amz-date. */
    if (cf->region.len != strlen(region)
        || ngx_strncmp(cf->region.data, (u_char *) region, cf->region.len) != 0
        || ngx_strncmp((u_char *) form->amz_date, (u_char *) date, 8) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Credential scope does not match this endpoint.");
    }

    /* Step 5: derive the date/region-scoped signing key, HMAC the policy string
     * (the base64 text, not the JSON), hex-encode, and compare. */
    if (!s3_sigv4_derive_signing_key_cached(&cf->secret_key,
                                             date, region, k4)
        || !brix_hmac_sha256(k4, 32, (u_char *) form->policy,
                               strlen(form->policy), computed))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    brix_hex_encode(computed, 32, computed_hex);
    /* Constant-time compare to avoid leaking how many bytes matched. */
    if (CRYPTO_memcmp(computed_hex, form->signature, 64) != 0) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "SignatureDoesNotMatch",
                             "The request signature we calculated does not "
                             "match the signature you provided.");
    }

    /* Step 6: signature is valid -> decode the policy and enforce its contents.
     * base64 expands ~4:3, so allocate len/4*3 plus slack and a NUL terminator. */
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
