#include "s3.h"
#include "s3_auth_internal.h"
#include "../compat/hex.h"
#include "../compat/crypto.h"
#include "../compat/uri.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <openssl/crypto.h>

/* Canonical query-string builder — defined in auth_sigv4_canonical.c */
extern size_t build_canonical_qs(const u_char *qs, size_t qslen,
    ngx_flag_t skip_signature, u_char *out, size_t outsz);

/* Header parser and authorization extractor — defined in auth_sigv4_parse.c */
extern ngx_str_t get_header(ngx_http_request_t *r, const char *name);
extern int parse_authorization(const ngx_str_t *auth, sigv4_components_t *out);
extern int parse_presigned_authorization(ngx_http_request_t *r,
    sigv4_components_t *out);

/* Canonical headers builder — defined in auth_sigv4_headers.c */
extern size_t build_canonical_headers(ngx_http_request_t *r,
    const char *signed_hdrs, u_char *out, size_t outsz);

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

static int64_t
s3_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t      era;
    unsigned    yoe, doy, doe;
    int         mp;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned) (y - era * 400);
    mp = (int) m + (m > 2 ? -3 : 9);
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    return era * 146097 + (int64_t) doe - 719468;
}

static ngx_int_t
s3_parse_amz_datetime(const char *s, time_t *out)
{
    int      year, mon, day, hour, min, sec;
    int64_t  days;

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

    days = s3_days_from_civil(year, (unsigned) mon, (unsigned) day);
    *out = (time_t) (days * 86400 + hour * 3600 + min * 60 + sec);
    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Main verification entry point
 * ---------------------------------------------------------------------- */

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
s3_verify_sigv4(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    sigv4_components_t comp;
    u_char             canonical[8192];
    u_char             canon_qs[2048];
    u_char             canon_uri[S3_MAX_KEY];
    u_char             canon_hdrs[2048];
    u_char             string_to_sign[4096];
    u_char             hash_hex[65];
    u_char             cr_hash[32];
    u_char             k1[32], k2[32], k3[32], k4[32];
    u_char             computed[32];
    char               computed_hex[65];
    size_t             n;
    ngx_str_t          auth, date_hdr;
    const char        *amz_date;
    size_t             amz_date_len;
    int                parse_rc;

    /* Anonymous mode */
    if (cf->access_key.len == 0) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_ANONYMOUS]);
        return NGX_OK;
    }

    ngx_memzero(&comp, sizeof(comp));

    parse_rc = parse_presigned_authorization(r, &comp);
    if (parse_rc == NGX_DECLINED) {
        auth = get_header(r, "authorization");
        if (auth.len == 0) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MISSING]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Missing Authorization header");
        }

        if (!parse_authorization(&auth, &comp)) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MALFORMED]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Malformed Authorization header");
        }
    } else if (parse_rc != NGX_OK) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MALFORMED]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Malformed presigned URL");
    }

    /* Verify access key matches */
    if (cf->access_key.len != strlen(comp.akid)
        || ngx_strncmp(cf->access_key.data,
                       (u_char *) comp.akid, cf->access_key.len) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_s3: unknown access key: %s", comp.akid);
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_BAD_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidAccessKeyId",
                                 "The access key ID does not exist");
    }

    if (s3_request_has_session_token(r, comp.presigned)) {
        if (!cf->allow_unsigned_session_token) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MALFORMED]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "AccessDenied",
                                     "STS session tokens are not enabled");
        }

        if (!comp.presigned
            && !s3_signed_headers_contains(comp.signed_hdrs,
                                           "x-amz-security-token"))
        {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MALFORMED]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "X-Amz-Security-Token must be signed");
        }
    }

    if (comp.presigned) {
        time_t request_time;

        if (s3_parse_amz_datetime(comp.amz_date, &request_time) != NGX_OK) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_BAD_DATE]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Invalid X-Amz-Date");
        }

        if (ngx_time() > request_time + (time_t) comp.amz_expires) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_BAD_DATE]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "AccessDenied",
                                     "Request has expired");
        }

        amz_date = comp.amz_date;
        amz_date_len = strlen(comp.amz_date);

    } else {
        date_hdr = get_header(r, "x-amz-date");
        if (date_hdr.len < 8) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_BAD_DATE]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "InvalidRequest",
                                     "Missing X-Amz-Date header");
        }

        amz_date = (const char *) date_hdr.data;
        amz_date_len = date_hdr.len;
    }

    /* ----------------------------------------------------------------
     * 1. Canonical URI
     * -------------------------------------------------------------- */
    xrootd_http_urlencode(r->uri.data, r->uri.len,
                          (char *) canon_uri, sizeof(canon_uri), "/");

    /* ----------------------------------------------------------------
     * 2. Canonical query string
     * -------------------------------------------------------------- */
    build_canonical_qs(r->args.data, r->args.len, comp.presigned,
                       canon_qs, sizeof(canon_qs));

    /* ----------------------------------------------------------------
     * 3. Canonical headers
     * -------------------------------------------------------------- */
    build_canonical_headers(r, comp.signed_hdrs,
                             canon_hdrs, sizeof(canon_hdrs));

    /* ----------------------------------------------------------------
     * 4. Canonical request
     * -------------------------------------------------------------- */
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

    /* ----------------------------------------------------------------
     * 5. String to sign
     * -------------------------------------------------------------- */
    n = (size_t) snprintf((char *) string_to_sign, sizeof(string_to_sign),
        "AWS4-HMAC-SHA256\n"
        "%.*s\n"
        "%s/%s/s3/aws4_request\n"
        "%s",
        (int) amz_date_len, amz_date,
        comp.date,
        comp.region,
        (char *) hash_hex);

    /* ----------------------------------------------------------------
     * 6. Derive signing key
     *    k1 = HMAC-SHA256("AWS4" + secret, date)
     *    k2 = HMAC-SHA256(k1, region)
     *    k3 = HMAC-SHA256(k2, "s3")
     *    k4 = HMAC-SHA256(k3, "aws4_request")
     * -------------------------------------------------------------- */
    {
        u_char prefix_key[128];
        size_t pklen;

        if (cf->secret_key.len + 4 > sizeof(prefix_key)) {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(prefix_key, "AWS4", 4);
        ngx_memcpy(prefix_key + 4, cf->secret_key.data, cf->secret_key.len);
        pklen = 4 + cf->secret_key.len;

        if (!xrootd_hmac_sha256(prefix_key, pklen,
                         (u_char *) comp.date, strlen(comp.date), k1)
            || !xrootd_hmac_sha256(k1, 32,
                            (u_char *) comp.region, strlen(comp.region), k2)
            || !xrootd_hmac_sha256(k2, 32, (u_char *) "s3", 2, k3)
            || !xrootd_hmac_sha256(k3, 32,
                            (u_char *) "aws4_request", 12, k4))
        {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* ----------------------------------------------------------------
     * 7. Compute and compare signatures
     * -------------------------------------------------------------- */
    if (!xrootd_hmac_sha256(k4, 32, string_to_sign, n, computed)) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    xrootd_hex_encode(computed, 32, computed_hex);

    /* Reject signatures that are not exactly 64 hex chars — prevents a short
     * client string from causing CRYPTO_memcmp to compare against pad bytes. */
    if (strlen(comp.signature) != 64) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_MALFORMED]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Signature must be 64 hex characters");
    }

    /* Constant-time comparison prevents timing-oracle attacks on the HMAC value. */
    if (CRYPTO_memcmp(computed_hex, comp.signature, 64) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_s3: SigV4 mismatch for key=%s", comp.akid);
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_SIG_MISMATCH]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "SignatureDoesNotMatch",
                                 "The request signature we calculated does "
                                 "not match the signature you provided");
    }

    XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_SIGV4_OK]);
    return NGX_OK;
}
