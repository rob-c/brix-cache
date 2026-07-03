/*
 * sigv4.c — AWS SigV4 signing-key derivation (see sigv4.h).
 *
 * The four-round HMAC chain, shared by the S3 server's verify path and the native
 * client's sign path so they derive byte-identical keys. ngx-free; uses only the
 * shared brix_hmac_sha256 kernel + libc.
 */
#include "sigv4.h"
#include "crypto.h"

#include <string.h>

int
brix_sigv4_signing_key(const uint8_t *secret, size_t secret_len,
                         const char *date, const char *region,
                         const char *service, uint8_t out[32])
{
    uint8_t prefix[128];   /* "AWS4" + secret */
    uint8_t k1[32], k2[32], k3[32];

    if (secret == NULL || date == NULL || region == NULL || service == NULL) {
        return 0;
    }
    /* Bound so "AWS4"+secret never silently truncates (a truncation would yield a
     * wrong-but-not-erroring key). */
    if (secret_len + 4 > sizeof(prefix)) {
        return 0;
    }
    memcpy(prefix, "AWS4", 4);
    memcpy(prefix + 4, secret, secret_len);

    return brix_hmac_sha256(prefix, secret_len + 4,
                              (const uint8_t *) date, strlen(date), k1)
        && brix_hmac_sha256(k1, 32, (const uint8_t *) region, strlen(region), k2)
        && brix_hmac_sha256(k2, 32, (const uint8_t *) service, strlen(service), k3)
        && brix_hmac_sha256(k3, 32, (const uint8_t *) "aws4_request", 12, out);
}
