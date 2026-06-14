/*
 * crypto.c — shared OpenSSL HMAC-SHA256 and SHA-256 helpers.
 *
 * Provides two cryptographic primitives used across XRootD/WebDAV/S3:
 * HMAC-SHA256 for GSI kXR_sigver request signing, and plain SHA-256 for
 * digest computation.
 *
 * EVP_MAC and EVP_MD objects are fetched once at worker init
 * (xrootd_crypto_init) and freed at worker exit (xrootd_crypto_cleanup).
 * Each per-request call creates a lightweight CTX from the singleton,
 * avoiding the registry search and allocation cost of EVP_MAC_fetch per call.
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>

static EVP_MAC *s_hmac_mac;
static EVP_MD  *s_sha256_md;

int
xrootd_crypto_init(void)
{
    s_hmac_mac  = EVP_MAC_fetch(NULL, "HMAC", NULL);
    s_sha256_md = EVP_MD_fetch(NULL, "SHA256", NULL);
    return s_hmac_mac != NULL && s_sha256_md != NULL;
}

void
xrootd_crypto_cleanup(void)
{
    EVP_MAC_free(s_hmac_mac);
    s_hmac_mac = NULL;
    EVP_MD_free(s_sha256_md);
    s_sha256_md = NULL;
}

int
xrootd_hmac_sha256(const u_char *key, size_t keylen,
                   const u_char *data, size_t datalen,
                   u_char out[32])
{
    EVP_MAC_CTX *ctx;
    OSSL_PARAM   params[2];
    size_t       outlen = 32;
    int          ok = 0;

    if (s_hmac_mac == NULL) { return 0; }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(s_hmac_mac);
    if (ctx
        && EVP_MAC_init(ctx, key, keylen, params) == 1
        && EVP_MAC_update(ctx, data, datalen) == 1
        && EVP_MAC_final(ctx, out, &outlen, 32) == 1)
    {
        ok = 1;
    }

    EVP_MAC_CTX_free(ctx);
    return ok;
}

int
xrootd_sha256(const u_char *data, size_t len, u_char out[32])
{
    EVP_MD_CTX  *ctx;
    unsigned int outlen = 32;
    int          ok = 0;

    if (s_sha256_md == NULL) { return 0; }

    ctx = EVP_MD_CTX_new();
    if (ctx
        && EVP_DigestInit_ex(ctx, s_sha256_md, NULL) == 1
        && EVP_DigestUpdate(ctx, data, len) == 1
        && EVP_DigestFinal_ex(ctx, out, &outlen) == 1)
    {
        ok = 1;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}
