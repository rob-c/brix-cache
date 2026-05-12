/*
 * auth.c — AWS Signature Version 4 (HMAC-SHA256) verification.
 *
 * Verifies the Authorization header sent by XrdClS3 and any other S3 client
 * that uses SigV4.  The implementation follows the AWS SigV4 specification.
 *
 * XrdClS3 always uses UNSIGNED-PAYLOAD so we do not verify the request body
 * hash.  The signed headers are typically: host;x-amz-content-sha256;x-amz-date
 *
 * Reference algorithm:
 *   https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */

#include "s3.h"

#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
 * HMAC-SHA256 helper
 * ---------------------------------------------------------------------- */

static int
hmac_sha256(const u_char *key, size_t keylen,
            const u_char *data, size_t datalen,
            u_char out[32])
{
    EVP_MAC     *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM   params[2];
    size_t       outlen = 32;
    int          ok = 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx
        && EVP_MAC_init(ctx, key, keylen, params) == 1
        && EVP_MAC_update(ctx, data, datalen) == 1
        && EVP_MAC_final(ctx, out, &outlen, 32) == 1)
    {
        ok = 1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

/* -------------------------------------------------------------------------
 * SHA-256 of a string
 * ---------------------------------------------------------------------- */

static int
sha256(const u_char *data, size_t len, u_char out[32])
{
    EVP_MD_CTX *ctx;
    unsigned int outlen = 32;
    int ok = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx
        && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, data, len) == 1
        && EVP_DigestFinal_ex(ctx, out, &outlen) == 1)
    {
        ok = 1;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

static void
hex_encode(const u_char *in, size_t len, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* -------------------------------------------------------------------------
 * Canonical URI: percent-encode the path preserving '/'
 * ---------------------------------------------------------------------- */

static size_t
canonical_uri(const u_char *uri, size_t urilen, u_char *out, size_t outsz)
{
    static const char safe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/";
    size_t i, oi = 0;

    for (i = 0; i < urilen && oi + 4 < outsz; i++) {
        u_char c = uri[i];
        if (strchr(safe, c)) {
            out[oi++] = c;
        } else {
            static const char h[] = "0123456789ABCDEF";
            out[oi++] = '%';
            out[oi++] = h[c >> 4];
            out[oi++] = h[c & 0xf];
        }
    }
    out[oi] = '\0';
    return oi;
}

/* -------------------------------------------------------------------------
 * Canonical query string: sort params, percent-encode name and value
 * ---------------------------------------------------------------------- */

typedef struct {
    const u_char *name;
    size_t        name_len;
    const u_char *value;
    size_t        value_len;
} qparam_t;

static int
qparam_cmp(const void *a, const void *b)
{
    const qparam_t *pa = (const qparam_t *) a;
    const qparam_t *pb = (const qparam_t *) b;
    size_t ml = pa->name_len < pb->name_len ? pa->name_len : pb->name_len;
    int r = memcmp(pa->name, pb->name, ml);
    if (r != 0) return r;
    return (pa->name_len < pb->name_len) ? -1
         : (pa->name_len > pb->name_len) ? 1 : 0;
}

static size_t
uriencode_param(const u_char *src, size_t slen, u_char *out, size_t outsz)
{
    /* percent-encode everything except unreserved chars (no /) */
    static const char safe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    static const char h[] = "0123456789ABCDEF";
    size_t oi = 0;
    for (size_t i = 0; i < slen && oi + 4 < outsz; i++) {
        u_char c = src[i];
        if (strchr(safe, c)) {
            out[oi++] = c;
        } else {
            out[oi++] = '%';
            out[oi++] = h[c >> 4];
            out[oi++] = h[c & 0xf];
        }
    }
    out[oi] = '\0';
    return oi;
}

static size_t
build_canonical_qs(const u_char *qs, size_t qslen,
                   u_char *out, size_t outsz)
{
    /* Parse query string into at most 64 parameters */
    qparam_t     params[64];
    int          param_count = 0;
    const u_char *cursor = qs;
    const u_char *end = qs + qslen;

    while (cursor < end && param_count < 64) {
        const u_char *segment_start = cursor;
        const u_char *segment_end = cursor;
        const u_char *equals = NULL;

        while (segment_end < end && *segment_end != '&') {
            if (*segment_end == '=' && equals == NULL) {
                equals = segment_end;
            }
            segment_end++;
        }

        if (segment_start < segment_end) {
            params[param_count].name = segment_start;
            params[param_count].name_len =
                (size_t) ((equals ? equals : segment_end) - segment_start);
            params[param_count].value = equals ? equals + 1 : (u_char *) "";
            params[param_count].value_len =
                equals ? (size_t) (segment_end - equals - 1) : 0;
            param_count++;
        }

        cursor = (segment_end < end) ? segment_end + 1 : segment_end;
    }

    qsort(params, (size_t) param_count, sizeof(params[0]), qparam_cmp);

    size_t oi = 0;
    u_char enc[1024];

    for (int i = 0; i < param_count; i++) {
        if (i > 0 && oi + 1 < outsz) {
            out[oi++] = '&';
        }
        size_t n;
        n = uriencode_param(params[i].name, params[i].name_len,
                            enc, sizeof(enc));
        if (oi + n < outsz) {
            ngx_memcpy(out + oi, enc, n);
            oi += n;
        }
        if (oi + 1 < outsz) out[oi++] = '=';
        n = uriencode_param(params[i].value, params[i].value_len,
                            enc, sizeof(enc));
        if (oi + n < outsz) {
            ngx_memcpy(out + oi, enc, n);
            oi += n;
        }
    }
    out[oi] = '\0';
    return oi;
}

/* -------------------------------------------------------------------------
 * Get a request header value (lowercased name)
 * ---------------------------------------------------------------------- */

static ngx_str_t
get_header(ngx_http_request_t *r, const char *name)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;
    size_t            nlen = strlen(name);

    part = &r->headers_in.headers.part;
    while (part) {
        h = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (h[i].key.len == nlen
                && ngx_strncasecmp(h[i].key.data,
                                   (u_char *) name, nlen) == 0)
            {
                return h[i].value;
            }
        }
        part = part->next;
    }
    return (ngx_str_t) ngx_null_string;
}

/* -------------------------------------------------------------------------
 * Parse Authorization header
 *
 * Format:
 *   AWS4-HMAC-SHA256 Credential=AKID/DATE/REGION/s3/aws4_request,
 *   SignedHeaders=host;x-amz-content-sha256;x-amz-date,
 *   Signature=<hex64>
 * ---------------------------------------------------------------------- */

typedef struct {
    char akid[128];
    char date[16];      /* YYYYMMDD */
    char region[64];
    char signed_hdrs[256];
    char signature[128];
} sigv4_components_t;

static const char *
sigv4_find_auth_pair(const char *start, const char *end, const char *name)
{
    const char *p;
    size_t      name_len;

    name_len = strlen(name);

    for (p = start; p < end; p++) {
        if ((size_t) (end - p) <= name_len) {
            return NULL;
        }

        if (p != start && p[-1] != ' ' && p[-1] != ',') {
            continue;
        }

        if (p[name_len] == '='
            && ngx_strncmp((u_char *) p, (u_char *) name, name_len) == 0)
        {
            return p;
        }
    }

    return NULL;
}


static int
sigv4_copy_component(const char *value_start, const char *value_end,
    char *dst, size_t dst_size)
{
    size_t value_len;

    value_len = (size_t) (value_end - value_start);
    if (value_len == 0 || value_len >= dst_size) {
        return 0;
    }

    memcpy(dst, value_start, value_len);
    dst[value_len] = '\0';
    return 1;
}


static int
sigv4_extract_auth_value(const char *start, const char *end,
    const char *name, char *dst, size_t dst_size)
{
    const char *field;
    const char *value_start;
    const char *value_end;
    size_t      name_len;

    field = sigv4_find_auth_pair(start, end, name);
    if (field == NULL) {
        return 0;
    }

    name_len = strlen(name);
    value_start = field + name_len + 1;
    value_end = value_start;

    while (value_end < end
           && *value_end != ','
           && *value_end != ' '
           && *value_end != '\0')
    {
        value_end++;
    }

    return sigv4_copy_component(value_start, value_end, dst, dst_size);
}


static int
parse_authorization(const ngx_str_t *auth, sigv4_components_t *out)
{
    char        credential[256];
    const char *start;
    const char *end;
    const char *credential_end;
    const char *slash1;
    const char *slash2;
    const char *slash3;

    if (auth->len < 17
        || ngx_strncasecmp(auth->data,
                           (u_char *) "AWS4-HMAC-SHA256 ", 17) != 0)
    {
        return 0;
    }

    start = (char *) auth->data + 17;
    end = (char *) auth->data + auth->len;

    if (!sigv4_extract_auth_value(start, end, "SignedHeaders",
                                  out->signed_hdrs,
                                  sizeof(out->signed_hdrs))
        || !sigv4_extract_auth_value(start, end, "Signature",
                                     out->signature,
                                     sizeof(out->signature))
        || !sigv4_extract_auth_value(start, end, "Credential",
                                     credential, sizeof(credential)))
    {
        return 0;
    }

    /* Parse Credential=AKID/DATE/REGION/s3/aws4_request */
    credential_end = credential + strlen(credential);

    slash1 = memchr(credential, '/', (size_t) (credential_end - credential));
    if (slash1 == NULL) {
        return 0;
    }

    slash2 = memchr(slash1 + 1, '/',
                    (size_t) (credential_end - slash1 - 1));
    if (slash2 == NULL) {
        return 0;
    }

    slash3 = memchr(slash2 + 1, '/',
                    (size_t) (credential_end - slash2 - 1));
    if (slash3 == NULL) {
        return 0;
    }

    if (!sigv4_copy_component(credential, slash1, out->akid,
                              sizeof(out->akid))
        || !sigv4_copy_component(slash1 + 1, slash2, out->date,
                                 sizeof(out->date))
        || !sigv4_copy_component(slash2 + 1, slash3, out->region,
                                 sizeof(out->region)))
    {
        return 0;
    }

    return 1;
}

/* -------------------------------------------------------------------------
 * Build canonical headers from the signed header list
 * ---------------------------------------------------------------------- */

static size_t
build_canonical_headers(ngx_http_request_t *r,
                        const char *signed_hdrs,
                        u_char *out, size_t outsz)
{
    /* signed_hdrs is semicolon-separated: "host;x-amz-content-sha256;x-amz-date" */
    char   hdrs[256];
    size_t oi = 0;

    ngx_cpystrn((u_char *) hdrs, (u_char *) signed_hdrs, sizeof(hdrs));

    char *save = NULL;
    char *tok  = strtok_r(hdrs, ";", &save);

    while (tok) {
        ngx_str_t val;

        /* Special case: host may not appear in standard header list */
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

        /* lowercase header name (already lower from AWS, but be safe) */
        for (size_t i = 0; i < nlen; i++) {
            out[oi++] = (u_char) tolower((unsigned char) tok[i]);
        }
        out[oi++] = ':';

        /* trim leading/trailing whitespace from value */
        const u_char *vs = val.data;
        const u_char *ve = val.data + vlen;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;

        ngx_memcpy(out + oi, vs, (size_t)(ve - vs));
        oi += (size_t)(ve - vs);
        out[oi++] = '\n';

        tok = strtok_r(NULL, ";", &save);
    }

    out[oi] = '\0';
    return oi;
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

    /* Anonymous mode */
    if (cf->access_key.len == 0) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_ANONYMOUS]);
        return NGX_OK;
    }

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

    date_hdr = get_header(r, "x-amz-date");
    if (date_hdr.len < 8) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_BAD_DATE]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "InvalidRequest",
                                 "Missing X-Amz-Date header");
    }

    /* ----------------------------------------------------------------
     * 1. Canonical URI
     * -------------------------------------------------------------- */
    n = canonical_uri(r->uri.data, r->uri.len, canon_uri, sizeof(canon_uri));

    /* ----------------------------------------------------------------
     * 2. Canonical query string
     * -------------------------------------------------------------- */
    build_canonical_qs(r->args.data, r->args.len,
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

    sha256(canonical, n, cr_hash);
    hex_encode(cr_hash, 32, (char *) hash_hex);

    /* ----------------------------------------------------------------
     * 5. String to sign
     * -------------------------------------------------------------- */
    n = (size_t) snprintf((char *) string_to_sign, sizeof(string_to_sign),
        "AWS4-HMAC-SHA256\n"
        "%.*s\n"
        "%s/%s/s3/aws4_request\n"
        "%s",
        (int) date_hdr.len, date_hdr.data,
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

        if (!hmac_sha256(prefix_key, pklen,
                         (u_char *) comp.date, strlen(comp.date), k1)
            || !hmac_sha256(k1, 32,
                            (u_char *) comp.region, strlen(comp.region), k2)
            || !hmac_sha256(k2, 32, (u_char *) "s3", 2, k3)
            || !hmac_sha256(k3, 32,
                            (u_char *) "aws4_request", 12, k4))
        {
            XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* ----------------------------------------------------------------
     * 7. Compute and compare signatures
     * -------------------------------------------------------------- */
    if (!hmac_sha256(k4, 32, string_to_sign, n, computed)) {
        XROOTD_S3_METRIC_INC(auth_total[XROOTD_S3_AUTH_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hex_encode(computed, 32, computed_hex);

    if (ngx_strcmp((u_char *) computed_hex,
                   (u_char *) comp.signature) != 0)
    {
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
