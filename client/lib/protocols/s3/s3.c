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

/* ---- Derive the signing key, sign the STS, and emit the header block ----
 *
 * WHAT: Runs the 4-round HMAC signing-key derivation, HMAC-signs the
 *       string-to-sign, and writes the x-amz-date / x-amz-content-sha256 /
 *       Authorization header block into hdrs. Returns 0 on success, -1 if the
 *       key derivation or HMAC fails or the header block would overflow hdrs.
 *
 * WHY:  This is the final stage where the derived secret becomes bytes on the
 *       wire; a truncated Authorization header advertises a signature the server
 *       cannot reproduce, so truncation must fail cleanly rather than emit a
 *       partial header.
 *
 * HOW:  1. Derive the signing key with the shared libxrdproto 4-round chain and
 *          HMAC-sign the string-to-sign; bail on any crypto failure.
 *       2. Hex-encode the signature.
 *       3. snprintf the header block (Credential uses the same scope that was
 *          signed); fail on truncation.
 */
static int
brix_s3_sigv4_sign_and_emit(const char *sk, const char *datestamp,
                            const char *region, const char *sts,
                            const char *ak, const char *payload_hex,
                            const char *amzdate, const char *scope,
                            char *hdrs, size_t hdrsz)
{
    uint8_t k4[32], sig[32];
    char    sighex[65];
    int     cn;

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
