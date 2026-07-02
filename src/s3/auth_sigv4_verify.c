#include "s3.h"
#include "s3_auth_internal.h"
#include "compat/hex.h"
#include "compat/crypto.h"
#include "compat/uri.h"
#include "compat/sigv4.h"   /* shared SigV4 signing-key derive (libxrdproto) */
#include "metrics/unified.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/crypto.h>

/* Canonical query-string builder — defined in auth_sigv4_canonical.c */
extern size_t build_canonical_qs(const u_char *qs, size_t qslen,
    ngx_flag_t skip_signature, u_char *out, size_t outsz);

/* Header parser and authorization extractor — defined in auth_sigv4_parse.c */
extern ngx_str_t get_header(ngx_http_request_t *r, const char *name);
extern int parse_authorization(const ngx_str_t *auth, sigv4_components_t *out);
extern int parse_presigned_authorization(ngx_http_request_t *r,
    sigv4_components_t *out);


#define S3_SIGV4_MAX_HEADER_SKEW_SEC  900
#define S3_SIGV4_MAX_FUTURE_SKEW_SEC  900

static void
s3_record_auth_result(ngx_uint_t result)
{
    XROOTD_S3_METRIC_INC(auth_total[result]);

    switch (result) {
    case XROOTD_S3_AUTH_ANONYMOUS:
        xrootd_metric_auth(XROOTD_PROTO_S3, XROOTD_AUTHN_NONE, 1);
        break;
    case XROOTD_S3_AUTH_SIGV4_OK:
        xrootd_metric_auth(XROOTD_PROTO_S3, XROOTD_AUTHN_S3KEY, 1);
        break;
    case XROOTD_S3_AUTH_MISSING:
        xrootd_metric_auth(XROOTD_PROTO_S3, XROOTD_AUTHN_NONE, 0);
        break;
    default:
        xrootd_metric_auth(XROOTD_PROTO_S3, XROOTD_AUTHN_S3KEY, 0);
        break;
    }
}

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

static int
s3_digit(u_char c)
{
    return (c >= '0' && c <= '9') ? (int) (c - '0') : -1;
}

static int
s3_parse_2digits(const char *s)
{
    int hi, lo;

    hi = s3_digit((u_char) s[0]);
    lo = s3_digit((u_char) s[1]);
    if (hi < 0 || lo < 0) {
        return -1;
    }
    return hi * 10 + lo;
}

static int
s3_parse_4digits(const char *s)
{
    int a, b, c, d;

    a = s3_digit((u_char) s[0]);
    b = s3_digit((u_char) s[1]);
    c = s3_digit((u_char) s[2]);
    d = s3_digit((u_char) s[3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
        return -1;
    }
    return a * 1000 + b * 100 + c * 10 + d;
}

static ngx_int_t
s3_parse_amz_datetime(const char *s, time_t *out)
{
    struct tm  tm;
    int        year, mon, day, hour, min, sec;

    if (strlen(s) != 16 || s[8] != 'T' || s[15] != 'Z') {
        return NGX_ERROR;
    }

    year = s3_parse_4digits(s);
    mon  = s3_parse_2digits(s + 4);
    day  = s3_parse_2digits(s + 6);
    hour = s3_parse_2digits(s + 9);
    min  = s3_parse_2digits(s + 11);
    sec  = s3_parse_2digits(s + 13);

    if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31
        || hour < 0 || hour > 23 || min < 0 || min > 59
        || sec < 0 || sec > 60)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&tm, sizeof(tm));
    tm.tm_year = year - 1900;
    tm.tm_mon  = mon  - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min  = min;
    tm.tm_sec  = sec;
    *out = timegm(&tm);
    return NGX_OK;
}

static ngx_int_t
s3_reject_bad_amz_date(ngx_http_request_t *r, const char *message)
{
    s3_record_auth_result(XROOTD_S3_AUTH_BAD_DATE);
    return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                             "InvalidRequest", message);
}

static ngx_int_t
s3_reject_clock_skew(ngx_http_request_t *r)
{
    s3_record_auth_result(XROOTD_S3_AUTH_BAD_DATE);
    return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                             "RequestTimeTooSkewed",
                             "The difference between the request time and "
                             "the server time is too large.");
}

static ngx_int_t
s3_check_header_clock_skew(ngx_http_request_t *r, time_t request_time)
{
    time_t now;

    now = ngx_time();
    if (request_time > now) {
        if (request_time - now > S3_SIGV4_MAX_HEADER_SKEW_SEC) {
            return s3_reject_clock_skew(r);
        }
    } else if (now - request_time > S3_SIGV4_MAX_HEADER_SKEW_SEC) {
        return s3_reject_clock_skew(r);
    }

    return NGX_OK;
}

static ngx_int_t
s3_check_presigned_future_skew(ngx_http_request_t *r, time_t request_time)
{
    time_t now;

    now = ngx_time();
    if (request_time > now
        && request_time - now > S3_SIGV4_MAX_FUTURE_SKEW_SEC)
    {
        return s3_reject_clock_skew(r);
    }

    return NGX_OK;
}

/*
 * SigV4 signing key derivation
 *
 * Four-round HMAC chain:
 *   k1 = HMAC("AWS4" + secret, date)   k2 = HMAC(k1, region)
 *   k3 = HMAC(k2, "s3")               k4 = HMAC(k3, "aws4_request")
 * */

/* Worker-local one-slot cache: signing key is stable for one calendar day per
 * region, so cache the last key and avoid four HMAC rounds on every request. */
static struct {
    char   date[9];    /* YYYYMMDD\0, empty string means invalid */
    char   region[65];
    u_char key[32];
} s_signing_key_cache;

int
s3_sigv4_derive_signing_key_cached(const ngx_str_t *secret_key,
                                    const char *date, const char *region,
                                    u_char out[32])
{
    if (s_signing_key_cache.date[0] != '\0'
        && strcmp(s_signing_key_cache.date, date) == 0
        && strcmp(s_signing_key_cache.region, region) == 0)
    {
        ngx_memcpy(out, s_signing_key_cache.key, 32);
        return 1;
    }

    /* Shared 4-round HMAC chain (libxrdproto) — byte-identical to the client's
     * sign path so client-signs == server-verifies by construction. */
    if (!xrootd_sigv4_signing_key((const uint8_t *) secret_key->data,
                                  secret_key->len, date, region, "s3", out)) {
        return 0;
    }

    ngx_cpystrn((u_char *) s_signing_key_cache.date,
                (u_char *) date, sizeof(s_signing_key_cache.date));
    ngx_cpystrn((u_char *) s_signing_key_cache.region,
                (u_char *) region, sizeof(s_signing_key_cache.region));
    ngx_memcpy(s_signing_key_cache.key, out, 32);
    return 1;
}

/*
 * Canonical signed headers builder (merged from auth_sigv4_headers.c)
 *
 * Builds the "header-name:value\n" block required by SigV4.  signed_hdrs is
 * a semicolon-separated list, e.g. "host;x-amz-content-sha256;x-amz-date".
 * */

static size_t
build_canonical_headers(ngx_http_request_t *r,
                        const char *signed_hdrs,
                        u_char *out, size_t outsz)
{
    char   hdrs[256];
    size_t oi = 0;

    ngx_cpystrn((u_char *) hdrs, (u_char *) signed_hdrs, sizeof(hdrs));

    char *save = NULL;
    char *tok  = strtok_r(hdrs, ";", &save);

    while (tok) {
        ngx_str_t val;

        if (strcmp(tok, "host") == 0) {
            val = r->headers_in.host ? r->headers_in.host->value
                                     : (ngx_str_t) ngx_null_string;
        } else {
            val = get_header(r, tok);
        }

        size_t nlen = strlen(tok);
        size_t vlen = val.len;

        if (oi + nlen + 1 + vlen + 2 >= outsz) {
            break;
        }

        for (size_t i = 0; i < nlen; i++) {
            out[oi++] = (u_char) tolower((unsigned char) tok[i]);
        }
        out[oi++] = ':';

        const u_char *vs = val.data;
        const u_char *ve = val.data + vlen;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) { vs++; }
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) { ve--; }

        ngx_memcpy(out + oi, vs, (size_t)(ve - vs));
        oi += (size_t)(ve - vs);
        out[oi++] = '\n';

        tok = strtok_r(NULL, ";", &save);
    }

    out[oi] = '\0';
    return oi;
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
    xrootd_identity_t *identity)
{
    sigv4_components_t comp;
    u_char             canonical[8192];
    u_char             canon_qs[2048];
    u_char             canon_uri[S3_MAX_KEY];
    u_char             canon_hdrs[2048];
    u_char             string_to_sign[4096];
    u_char             hash_hex[65];
    u_char             cr_hash[32];
    u_char             k4[32];
    u_char             computed[32];
    char               computed_hex[65];
    size_t             n;
    ngx_str_t          auth, date_hdr;
    const char        *amz_date;
    size_t             amz_date_len;
    char               header_amz_date[32];
    time_t             request_time;
    int                parse_rc;
    int                key_ok;        /* W5: deferred access-key match flag */

    /* Anonymous mode */
    if (cf->access_key.len == 0) {
        if (identity != NULL) {
            identity->auth_method = XROOTD_AUTHN_NONE;
        }
        s3_record_auth_result(XROOTD_S3_AUTH_ANONYMOUS);
        return NGX_OK;
    }

    ngx_memzero(&comp, sizeof(comp));

    parse_rc = parse_presigned_authorization(r, &comp);
    if (parse_rc == NGX_DECLINED) {
        auth = get_header(r, "authorization");
        if (auth.len == 0) {
            s3_record_auth_result(XROOTD_S3_AUTH_MISSING);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Missing Authorization header");
        }

        if (!parse_authorization(&auth, &comp)) {
            s3_record_auth_result(XROOTD_S3_AUTH_MALFORMED);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Malformed Authorization header");
        }
    } else if (parse_rc != NGX_OK) {
        s3_record_auth_result(XROOTD_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Malformed presigned URL");
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

    if (s3_request_has_session_token(r, comp.presigned)) {
        if (!cf->allow_unsigned_session_token) {
            s3_record_auth_result(XROOTD_S3_AUTH_MALFORMED);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "AccessDenied",
                                     "STS session tokens are not enabled");
        }

        if (!comp.presigned
            && !s3_signed_headers_contains(comp.signed_hdrs,
                                           "x-amz-security-token"))
        {
            s3_record_auth_result(XROOTD_S3_AUTH_MALFORMED);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "X-Amz-Security-Token must be signed");
        }
    }

    if (comp.presigned) {
        if (s3_parse_amz_datetime(comp.amz_date, &request_time) != NGX_OK) {
            return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
        }

        {
            ngx_int_t skew_rc;

            skew_rc = s3_check_presigned_future_skew(r, request_time);
            if (skew_rc != NGX_OK) {
                return skew_rc;
            }
        }

        if (ngx_time() >= request_time
            && ngx_time() - request_time > (time_t) comp.amz_expires)
        {
            s3_record_auth_result(XROOTD_S3_AUTH_BAD_DATE);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "AccessDenied",
                                     "Request has expired");
        }

        amz_date = comp.amz_date;
        amz_date_len = strlen(comp.amz_date);

    } else {
        date_hdr = get_header(r, "x-amz-date");
        if (date_hdr.len == 0) {
            return s3_reject_bad_amz_date(r, "Missing X-Amz-Date header");
        }

        if (date_hdr.len >= sizeof(header_amz_date)) {
            return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
        }

        ngx_memcpy(header_amz_date, date_hdr.data, date_hdr.len);
        header_amz_date[date_hdr.len] = '\0';

        if (s3_parse_amz_datetime(header_amz_date, &request_time) != NGX_OK) {
            return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
        }

        {
            ngx_int_t skew_rc;

            skew_rc = s3_check_header_clock_skew(r, request_time);
            if (skew_rc != NGX_OK) {
                return skew_rc;
            }
        }

        amz_date = header_amz_date;
        amz_date_len = strlen(header_amz_date);
    }

/*
     * 1. Canonical URI
     * */
    xrootd_http_urlencode(r->uri.data, r->uri.len,
                          (char *) canon_uri, sizeof(canon_uri), "/");

/*
     * 2. Canonical query string
     * */
    build_canonical_qs(r->args.data, r->args.len, comp.presigned,
                       canon_qs, sizeof(canon_qs));

/*
     * 3. Canonical headers
     * */
    build_canonical_headers(r, comp.signed_hdrs,
                             canon_hdrs, sizeof(canon_hdrs));

/*
     * 4. Canonical request
     * */
    n = (size_t) snprintf((char *) canonical, sizeof(canonical),
        "%.*s\n"        /* method   */
        "%s\n"          /* uri      */
        "%s\n"          /* qs       */
        "%s\n"          /* headers  */
        "%s\n"          /* signed header names */
        "UNSIGNED-PAYLOAD",
        (int) r->method_name.len, r->method_name.data,
        (char *) canon_uri,
        (char *) canon_qs,
        (char *) canon_hdrs,
        comp.signed_hdrs);

    xrootd_sha256(canonical, n, cr_hash);
    xrootd_hex_encode(cr_hash, 32, (char *) hash_hex);

/*
     * 5. String to sign
     * */
    n = (size_t) snprintf((char *) string_to_sign, sizeof(string_to_sign),
        "AWS4-HMAC-SHA256\n"
        "%.*s\n"
        "%s/%s/s3/aws4_request\n"
        "%s",
        (int) amz_date_len, amz_date,
        comp.date,
        comp.region,
        (char *) hash_hex);

/*
     * 6. Derive signing key (cached: stable for one calendar day per region)
     * */
    if (!s3_sigv4_derive_signing_key_cached(&cf->secret_key,
                                             comp.date, comp.region, k4)) {
        s3_record_auth_result(XROOTD_S3_AUTH_INTERNAL_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

/*
     * 7. Compute and compare signatures
     * */
    if (!xrootd_hmac_sha256(k4, 32, string_to_sign, n, computed)) {
        s3_record_auth_result(XROOTD_S3_AUTH_INTERNAL_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    xrootd_hex_encode(computed, 32, computed_hex);

    /* Reject signatures that are not exactly 64 hex chars — prevents a short
     * client string from causing CRYPTO_memcmp to compare against pad bytes. */
    if (strlen(comp.signature) != 64) {
        s3_record_auth_result(XROOTD_S3_AUTH_MALFORMED);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Signature must be 64 hex characters");
    }

    /*
     * Single constant-time decision (W5): an unknown access key (!key_ok) and a
     * bad signature take the identical path, status, and message here, having
     * both run the full HMAC above — no timing or message oracle distinguishes
     * them.  CRYPTO_memcmp prevents a timing oracle on the HMAC value itself.
     */
    if (!key_ok || CRYPTO_memcmp(computed_hex, comp.signature, 64) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_s3: SigV4 auth failed for key=%s (key_ok=%d)",
                      comp.akid, key_ok);
        s3_record_auth_result(key_ok ? XROOTD_S3_AUTH_SIG_MISMATCH
                                     : XROOTD_S3_AUTH_BAD_KEY);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "SignatureDoesNotMatch",
                                 "The request signature we calculated does "
                                 "not match the signature you provided");
    }

    s3_record_auth_result(XROOTD_S3_AUTH_SIGV4_OK);
    if (identity != NULL
        && xrootd_identity_set_subject(identity, r->pool, comp.akid,
                                       XROOTD_AUTHN_S3KEY) != NGX_OK)
    {
        s3_record_auth_result(XROOTD_S3_AUTH_INTERNAL_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * W6a: when per-chunk signature verification is enabled, retain the SigV4
     * material the streaming decoder needs (seed signature, signing key, scope,
     * timestamp) — it is otherwise local to this function and discarded.  Only
     * the signed (non-presigned) header path produces a seed signature usable as
     * the first chunk's previous-signature.
     */
    if (cf->verify_chunk_signatures && !comp.presigned) {
        ngx_http_s3_req_ctx_t *rx =
            ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
        if (rx != NULL) {
            u_char *e;
            ngx_memcpy(rx->sigv4_signing_key, k4, 32);
            ngx_cpystrn((u_char *) rx->sigv4_seed_signature,
                        (u_char *) comp.signature,
                        sizeof(rx->sigv4_seed_signature));
            ngx_cpystrn((u_char *) rx->sigv4_amz_date,
                        (u_char *) amz_date,   /* full timestamp (header path) */
                        sizeof(rx->sigv4_amz_date));
            e = ngx_snprintf((u_char *) rx->sigv4_scope,
                             sizeof(rx->sigv4_scope) - 1,
                             "%s/%s/s3/aws4_request", comp.date, comp.region);
            *e = '\0';
            rx->have_sigv4 = 1;
        }
    }

    return NGX_OK;
}
