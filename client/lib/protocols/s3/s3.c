/*
 * s3.c — AWS Signature Version 4 (path-style) for the native client.
 *
 * WHAT: brix_s3_sign_v4() builds the x-amz-date / x-amz-content-sha256 /
 *       Authorization header block for any method+path+body-hash; the sha256
 *       helpers compute the payload hashes those headers carry.
 * WHY:  Both xrdcp's s3:// transfers and xrddiag's s3 probe need the identical
 *       signer — keeping one copy in the lib (rather than a private copy in each
 *       app) is the clean-room equivalent of XrdClS3's shared signing code.
 * HOW:  Canonical-request → string-to-sign → HMAC-SHA256 signing-key chain, using
 *       libxrdproto's SHA-256/HMAC kernels (compat/crypto.h). The CanonicalURI is
 *       percent-encoded (RFC-3986 unreserved + '/') to match the server's own
 *       canonicalization. Signed headers are host;x-amz-content-sha256;x-amz-date.
 *
 * Clean-room: implements the published SigV4 algorithm (AWS docs), not any SDK.
 */
#include "brix.h"
#include "core/compat/crypto.h"   /* brix_sha256 / brix_hmac_sha256 */
#include "core/compat/hex.h"      /* brix_hex_encode */
#include "core/compat/uri.h"      /* brix_http_urlencode (shared SigV4 canonical URI) */
#include "core/compat/sigv4.h"    /* brix_sigv4_signing_key (shared 4-round HMAC chain) */

#include <stdio.h>
#include <string.h>
#include <time.h>

void
brix_s3_sha256_hex(const void *data, size_t len, char *out)
{
    uint8_t d[32];
    brix_sha256((const uint8_t *) data, len, d);
    brix_hex_encode(d, 32, out);   /* lowercase 64 hex + NUL */
}

/* ---- Build the SigV4 canonical request and return its SHA-256 hex ----
 *
 * WHAT: Percent-encodes the URI, assembles the canonical request
 *       (method, URI, canonical query, the three signed headers, the trailing
 *       SignedHeaders list, and the payload hash), and writes its lowercase
 *       SHA-256 hex (65 bytes incl. NUL) into canon_hex. Returns 0 on success,
 *       -1 if the URI cannot be encoded or the canonical request would overflow.
 *
 * WHY:  The canonical-request hash is the first HMAC input; if this string
 *       differs by a single byte from what the server re-derives, the signature
 *       mismatches and the request 403s. Isolating its construction keeps the
 *       signer's stage boundaries explicit and each stage independently testable.
 *
 * HOW:  1. URL-encode uri with the shared RFC-3986 encoder (unreserved + '/'),
 *          byte-identical to the server's verify path.
 *       2. snprintf the canonical request; treat truncation as a hard failure so
 *          a short buffer never silently signs a different string.
 *       3. Hash the canonical request into canon_hex.
 */
static int
brix_s3_sigv4_build_canon_hash(const char *method, const char *host,
                               const char *uri, const char *canon_qs,
                               const char *payload_hex, const char *amzdate,
                               char *canon_hex)
{
    char enc_uri[2048];
    char canon[8192];
    int  cn;

    /* Shared SigV4 CanonicalURI encoder (RFC-3986 unreserved + '/'), byte-identical
     * to the server's verify path so client-signs == server-verifies. */
    if (brix_http_urlencode((const unsigned char *) uri, strlen(uri),
                              enc_uri, sizeof(enc_uri), "/") < 0) {
        return -1;
    }
    /* canonical request: method\nURI\nCANONICAL_QUERY\nheaders\nsignedHeaders\nhash.
     * canon_qs must already be sorted + RFC-3986 encoded (the server re-derives the
     * same string from the request query). */
    cn = snprintf(canon, sizeof(canon),
             "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\n"
             "host;x-amz-content-sha256;x-amz-date\n%s",
             method, enc_uri, canon_qs, host, payload_hex, amzdate, payload_hex);
    /* A truncated canonical request would sign a different string than the server
     * verifies → a confusing 403. Fail cleanly so the caller reports "can't sign". */
    if (cn < 0 || (size_t) cn >= sizeof(canon)) {
        return -1;
    }
    brix_s3_sha256_hex(canon, strlen(canon), canon_hex);
    return 0;
}

/* ---- Build the credential scope and the string-to-sign ----
 *
 * WHAT: Formats the credential scope (datestamp/region/s3/aws4_request) into
 *       scope and the AWS4-HMAC-SHA256 string-to-sign (algorithm, amzdate, scope,
 *       canonical-request hash) into sts. Returns 0 on success, -1 if either
 *       snprintf would overflow its caller-supplied buffer.
 *
 * WHY:  region is user/env-controlled (--s3-region / $AWS_DEFAULT_REGION); a
 *       truncated scope or string-to-sign would sign a different string than the
 *       Authorization header advertises → a confusing 403. Guarding both here
 *       keeps that contract in one place, matching the canonical-request guard.
 *
 * HOW:  1. snprintf the credential scope; fail on truncation.
 *       2. snprintf the string-to-sign from amzdate, scope, and canon_hex; fail
 *          on truncation.
 */
static int
brix_s3_sigv4_build_sts(const char *amzdate, const char *datestamp,
                        const char *region, const char *canon_hex,
                        char *scope, size_t scopesz, char *sts, size_t stssz)
{
    int cn;

    cn = snprintf(scope, scopesz, "%s/%s/s3/aws4_request", datestamp, region);
    if (cn < 0 || (size_t) cn >= scopesz) {
        return -1;
    }
    cn = snprintf(sts, stssz, "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                  amzdate, scope, canon_hex);
    if (cn < 0 || (size_t) cn >= stssz) {
        return -1;
    }
    return 0;
}

/* ---- Derive the signing key and sign the string-to-sign ----
 *
 * WHAT: Runs the 4-round HMAC signing-key derivation, HMAC-signs the
 *       string-to-sign, and writes its lowercase hexadecimal signature.
 *
 * WHY:  Header and query authentication must share the exact same key chain.
 *
 * HOW:  Derive with the shared four-round helper, HMAC, then hex-encode.
 */
static int
brix_s3_sigv4_signature(const char *sk, const char *datestamp,
                        const char *region, const char *sts,
                        char sighex[65])
{
    uint8_t k4[32], sig[32];

    if (!brix_sigv4_signing_key((const uint8_t *) sk, strlen(sk),
            datestamp, region, "s3", k4)
        || !brix_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig))
        return -1;
    brix_hex_encode(sig, 32, sighex);
    return 0;
}

/* Emit the ordinary SigV4 headers after signing the string-to-sign. */
static int
brix_s3_sigv4_sign_and_emit(const char *sk, const char *datestamp,
                            const char *region, const char *sts,
                            const char *ak, const char *payload_hex,
                            const char *amzdate, const char *scope,
                            char *hdrs, size_t hdrsz)
{
    char    sighex[65];
    int     cn;

    if (brix_s3_sigv4_signature(sk, datestamp, region, sts, sighex) != 0)
        return -1;

    cn = snprintf(hdrs, hdrsz,
             "x-amz-date: %s\r\nx-amz-content-sha256: %s\r\n"
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s\r\n",
             amzdate, payload_hex, ak, scope, sighex);
    if (cn < 0 || (size_t) cn >= hdrsz) {
        return -1;
    }
    return 0;
}

/* ---- Hash a host-only presigned canonical request ----
 *
 * WHAT: Writes the SHA-256 hex of a SigV4 presigned canonical request.
 * WHY: Presigned requests sign only `host` and carry auth material in the query.
 * HOW: Encode the URI, format the host-only canonical shape, then hash it.
 */
static int
brix_s3_presign_canon_hash(const char *method, const char *host,
                           const char *uri, const char *canon_qs,
                           char canon_hex[65])
{
    char encoded_uri[2048];
    char canonical[8192];
    int written;

    if (brix_http_urlencode((const unsigned char *) uri, strlen(uri),
            encoded_uri, sizeof(encoded_uri), "/") < 0) return -1;
    written = snprintf(canonical, sizeof(canonical),
        "%s\n%s\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD", method,
        encoded_uri, canon_qs, host);
    if (written < 0 || (size_t) written >= sizeof(canonical)) return -1;
    brix_s3_sha256_hex(canonical, strlen(canonical), canon_hex);
    return 0;
}

/* ---- Build a complete deterministic SigV4 presigned query ----
 *
 * WHAT: Returns zero with a canonical query including X-Amz-Signature.
 * WHY: Conformance probes need expired and path-replay URLs without an SDK.
 * HOW: Derive date/scope, encode Credential, hash host-only canonical request,
 *      sign its string-to-sign, and append the signature to the same query.
 */
static int
brix_s3_presign_dates(time_t signed_at, unsigned expires,
    char amzdate[20], char datestamp[12])
{
    struct tm tmv;

    if (expires == 0 || expires > 604800) return -1;
    if (gmtime_r(&signed_at, &tmv) == NULL) return -1;
    if (strftime(amzdate, 20, "%Y%m%dT%H%M%SZ", &tmv) == 0) return -1;
    return strftime(datestamp, 12, "%Y%m%d", &tmv) == 0 ? -1 : 0;
}

static int
brix_s3_presign_args_valid(const char *method, const char *host,
    const char *uri, const char *ak, const char *sk, const char *region,
    const char *query)
{
    return method != NULL && host != NULL && uri != NULL && ak != NULL
        && sk != NULL && region != NULL && query != NULL;
}

static int
brix_s3_presign_credential(const char *ak, const char *region,
    const char *datestamp, char scope[160], char encoded[1536])
{
    char credential[512];
    int written;

    written = snprintf(scope, 160, "%s/%s/s3/aws4_request",
        datestamp, region);
    if (written < 0 || written >= 160) return -1;
    written = snprintf(credential, sizeof(credential), "%s/%s", ak, scope);
    if (written < 0 || (size_t) written >= sizeof(credential)) return -1;
    return brix_http_urlencode((const unsigned char *) credential,
        strlen(credential), encoded, 1536, "") < 0 ? -1 : 0;
}

static int
brix_s3_presign_unsigned_query(const char *credential, const char *amzdate,
    unsigned expires, char query[3072])
{
    int written = snprintf(query, 3072,
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
        "&X-Amz-Date=%s&X-Amz-Expires=%u&X-Amz-SignedHeaders=host",
        credential, amzdate, expires);

    return written < 0 || written >= 3072 ? -1 : 0;
}

int
brix_s3_presign_v4_at(const char *method, const char *host, const char *uri,
    const char *ak, const char *sk, const char *region, time_t signed_at,
    unsigned expires, char *query, size_t query_size)
{
    char amzdate[20], datestamp[12];
    char scope[160], encoded_credential[1536];
    char unsigned_query[3072], canon_hex[65], sts[640], sighex[65];
    int written;

    if (!brix_s3_presign_args_valid(method, host, uri, ak, sk, region, query))
        return -1;
    if (brix_s3_presign_dates(signed_at, expires, amzdate, datestamp) != 0)
        return -1;
    if (brix_s3_presign_credential(ak, region, datestamp, scope,
            encoded_credential) != 0) return -1;
    if (brix_s3_presign_unsigned_query(encoded_credential, amzdate, expires,
            unsigned_query) != 0) return -1;
    if (brix_s3_presign_canon_hash(method, host, uri, unsigned_query,
            canon_hex) != 0) return -1;
    if (brix_s3_sigv4_build_sts(amzdate, datestamp, region, canon_hex,
            scope, sizeof(scope), sts, sizeof(sts)) != 0) return -1;
    if (brix_s3_sigv4_signature(sk, datestamp, region, sts, sighex) != 0)
        return -1;
    written = snprintf(query, query_size, "%s&X-Amz-Signature=%s",
        unsigned_query, sighex);
    return written < 0 || (size_t) written >= query_size ? -1 : 0;
}

int
brix_s3_sign_v4_q(const char *method, const char *host, const char *uri,
                  const char *canon_qs, const char *ak, const char *sk,
                  const char *region, const char *payload_hex,
                  char *hdrs, size_t hdrsz)
{
    char      amzdate[20], datestamp[12];
    char      canon_hex[65];
    char      scope[160], sts[640];
    time_t    now = time(NULL);
    struct tm tmv;

    if (canon_qs == NULL) { canon_qs = ""; }
    if (sk == NULL || ak == NULL || region == NULL || payload_hex == NULL) {
        return -1;
    }
    if (gmtime_r(&now, &tmv) == NULL) {
        return -1;
    }
    strftime(amzdate, sizeof(amzdate), "%Y%m%dT%H%M%SZ", &tmv);
    strftime(datestamp, sizeof(datestamp), "%Y%m%d", &tmv);

    if (brix_s3_sigv4_build_canon_hash(method, host, uri, canon_qs,
                                       payload_hex, amzdate, canon_hex) != 0) {
        return -1;
    }
    if (brix_s3_sigv4_build_sts(amzdate, datestamp, region, canon_hex,
                                scope, sizeof(scope), sts, sizeof(sts)) != 0) {
        return -1;
    }
    return brix_s3_sigv4_sign_and_emit(sk, datestamp, region, sts, ak,
                                       payload_hex, amzdate, scope, hdrs, hdrsz);
}

int
brix_s3_sign_v4(const char *method, const char *host, const char *uri,
                const char *ak, const char *sk, const char *region,
                const char *payload_hex, char *hdrs, size_t hdrsz)
{
    /* no query string (GET/HEAD/PUT on a plain object key) */
    return brix_s3_sign_v4_q(method, host, uri, "", ak, sk, region,
                             payload_hex, hdrs, hdrsz);
}
