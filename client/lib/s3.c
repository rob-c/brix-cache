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

int
brix_s3_sign_v4_q(const char *method, const char *host, const char *uri,
                  const char *canon_qs, const char *ak, const char *sk,
                  const char *region, const char *payload_hex,
                  char *hdrs, size_t hdrsz)
{
    char      amzdate[20], datestamp[12];
    char      canon_hex[65];
    char      canon[8192], scope[160], sts[640], enc_uri[2048];
    uint8_t   k4[32], sig[32];
    char      sighex[65];
    time_t    now = time(NULL);
    struct tm tmv;
    int       cn;

    if (canon_qs == NULL) { canon_qs = ""; }
    if (sk == NULL || ak == NULL || region == NULL || payload_hex == NULL) {
        return -1;
    }
    if (gmtime_r(&now, &tmv) == NULL) {
        return -1;
    }
    strftime(amzdate, sizeof(amzdate), "%Y%m%dT%H%M%SZ", &tmv);
    strftime(datestamp, sizeof(datestamp), "%Y%m%d", &tmv);

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

    /* region is user/env-controlled (--s3-region / $AWS_DEFAULT_REGION); a
     * truncated scope/sts/hdrs would sign a different string than it advertises →
     * a confusing 403. Check every snprintf and fail cleanly instead (same
     * contract as the canon guard above). */
    cn = snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", datestamp, region);
    if (cn < 0 || (size_t) cn >= sizeof(scope)) {
        return -1;
    }
    cn = snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                  amzdate, scope, canon_hex);
    if (cn < 0 || (size_t) cn >= sizeof(sts)) {
        return -1;
    }

    /* Shared 4-round signing-key derive (libxrdproto), then sign the STS. */
    if (!brix_sigv4_signing_key((const uint8_t *) sk, strlen(sk),
                                  datestamp, region, "s3", k4)
        || !brix_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig)) {
        return -1;
    }
    brix_hex_encode(sig, 32, sighex);

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

int
brix_s3_sign_v4(const char *method, const char *host, const char *uri,
                const char *ak, const char *sk, const char *region,
                const char *payload_hex, char *hdrs, size_t hdrsz)
{
    /* no query string (GET/HEAD/PUT on a plain object key) */
    return brix_s3_sign_v4_q(method, host, uri, "", ak, sk, region,
                             payload_hex, hdrs, hdrsz);
}
