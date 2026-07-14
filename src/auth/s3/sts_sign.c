/*
 * sts_sign.c — SigV4 request construction for the S3 STS exchange (phase-79).
 *
 * WHAT: build the canonical (sorted, percent-encoded) STS query string and
 *       SigV4-sign it with the node's backend *service* credentials over the
 *       "sts" service, producing the exact query AWS/MinIO recomputes and checks.
 * WHY:  split out of sts.c (formerly 815 lines) as the pure request-building
 *       concern — no I/O, no allocation — so each STS file owns one job. The
 *       byte output is unchanged from the pre-split code: same canonical layout,
 *       same signing-key derivation, same signature.
 * HOW:  sts_build_action_qs emits Action=AssumeRole (+RoleArn/RoleSessionName)
 *       or Action=GetSessionToken in SigV4 canonical byte order; sts_sign_query
 *       forms the canonical request + string-to-sign, derives the signing key
 *       with brix_sigv4_signing_key(), and appends "&X-Amz-Signature=<hex>".
 *
 * The reused building blocks:
 *   - SigV4 signing key:  brix_sigv4_signing_key()  (core/compat/sigv4.h)
 *   - HMAC / SHA-256:      brix_hmac_sha256/brix_sha256 (core/compat/crypto.h)
 */
#include "sts_internal.h"

#include "core/compat/sigv4.h"
#include "core/compat/crypto.h"


/*
 * Lowercase-hex-encode `n` bytes of `in` into `out` (needs 2*n+1 bytes, incl.
 * NUL). Used for the payload hash and the final signature, both of which SigV4
 * carries as hex.
 */
static void
sts_hex(const uint8_t *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i]     = hx[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hx[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}


/*
 * sts_sign_query — build and SigV4-sign the STS request query string.
 *
 * WHAT: given the sorted action query (`action_qs`, already canonical and
 *       percent-encoded, WITHOUT the trailing X-Amz-Signature) and the target
 *       host, compute the SigV4 signature and return the full signed query.
 * WHY:  the STS endpoint authenticates the node by SigV4 over its service
 *       credentials; this is the exact string AWS/MinIO recomputes and checks.
 * HOW:  canonical request = "GET\n/\n<qs>\nhost:<h>\n\nhost\nUNSIGNED?..." with an
 *       empty-body SHA-256; string-to-sign wraps it with the credential scope;
 *       signing key from brix_sigv4_signing_key over "sts"; signature =
 *       HMAC(key, string_to_sign). Result "<qs>&X-Amz-Signature=<hex>" is
 *       written NUL-terminated into `out` (size `outsz`). NGX_OK / NGX_ERROR.
 *
 * The timestamps, host and config are read from `req` (amzdate is
 * "YYYYMMDDTHHMMSSZ", datestamp its "YYYYMMDD" prefix).
 */
ngx_int_t
sts_sign_query(const sts_req_t *req, const char *action_qs,
    char *out, size_t outsz)
{
    const brix_s3_sts_conf_t *cf        = req->cf;
    const char               *host      = req->host;
    const char               *amzdate   = req->amzdate;
    const char               *datestamp = req->datestamp;
    uint8_t  empty_hash[32];
    char     empty_hex[65];
    char     canonical[4096];
    uint8_t  canon_hash[32];
    char     canon_hex[65];
    char     scope[128];
    char     to_sign[512];
    uint8_t  key[32];
    uint8_t  sig[32];
    char     sig_hex[65];
    int      n;

    /* Empty request body — STS AssumeRole carries all params in the query. */
    if (!brix_sha256((const uint8_t *) "", 0, empty_hash)) {
        return NGX_ERROR;
    }
    sts_hex(empty_hash, 32, empty_hex);

    n = ngx_snprintf((u_char *) canonical, sizeof(canonical),
            "GET\n/\n%s\nhost:%s\nx-amz-date:%s\n\nhost;x-amz-date\n%s",
            action_qs, host, amzdate, empty_hex) - (u_char *) canonical;
    if (n <= 0 || (size_t) n >= sizeof(canonical)) {
        return NGX_ERROR;
    }
    if (!brix_sha256((const uint8_t *) canonical, (size_t) n, canon_hash)) {
        return NGX_ERROR;
    }
    sts_hex(canon_hash, 32, canon_hex);

    ngx_snprintf((u_char *) scope, sizeof(scope), "%s/%V/sts/aws4_request%Z",
        datestamp, &cf->region);

    n = ngx_snprintf((u_char *) to_sign, sizeof(to_sign),
            "AWS4-HMAC-SHA256\n%s\n%s\n%s",
            amzdate, scope, canon_hex) - (u_char *) to_sign;
    if (n <= 0 || (size_t) n >= sizeof(to_sign)) {
        return NGX_ERROR;
    }

    if (!brix_sigv4_signing_key(cf->svc_sk.data, cf->svc_sk.len,
            datestamp, (const char *) cf->region.data, "sts", key)) {
        return NGX_ERROR;
    }
    if (!brix_hmac_sha256(key, 32, (const uint8_t *) to_sign, (size_t) n, sig)) {
        return NGX_ERROR;
    }
    sts_hex(sig, 32, sig_hex);

    n = ngx_snprintf((u_char *) out, outsz, "%s&X-Amz-Signature=%s%Z",
            action_qs, sig_hex) - (u_char *) out;
    if (n <= 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * sts_build_action_qs — build the canonical (sorted, encoded) STS query string,
 * WITHOUT the trailing X-Amz-Signature.
 *
 * Parameters appear in SigV4 canonical (byte-sorted-by-name) order. When a role
 * ARN is configured we emit Action=AssumeRole (+ RoleArn/RoleSessionName);
 * otherwise Action=GetSessionToken. `req->credential` is the pre-encoded
 * "AKID%2FDATE%2Fregion%2Fsts%2Faws4_request" X-Amz-Credential value.
 */
ngx_int_t
sts_build_action_qs(const sts_req_t *req, char *out, size_t outsz)
{
    const brix_s3_sts_conf_t *cf         = req->cf;
    const char               *rsn        = req->rsn;
    const char               *credential = req->credential;
    const char               *amzdate    = req->amzdate;
    int                       ttl        = req->ttl;
    int n;

    if (cf->role_arn.len > 0) {
        n = ngx_snprintf((u_char *) out, outsz,
                "Action=AssumeRole"
                "&DurationSeconds=%d"
                "&RoleArn=%V"
                "&RoleSessionName=%s"
                "&Version=2011-06-15"
                "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=%s"
                "&X-Amz-Date=%s"
                "&X-Amz-SignedHeaders=host%%3Bx-amz-date%Z",
                ttl, &cf->role_arn, rsn, credential, amzdate)
            - (u_char *) out;
    } else {
        n = ngx_snprintf((u_char *) out, outsz,
                "Action=GetSessionToken"
                "&DurationSeconds=%d"
                "&Version=2011-06-15"
                "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=%s"
                "&X-Amz-Date=%s"
                "&X-Amz-SignedHeaders=host%%3Bx-amz-date%Z",
                ttl, credential, amzdate)
            - (u_char *) out;
    }

    if (n <= 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}
