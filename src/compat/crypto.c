/*
 * crypto.c — shared OpenSSL HMAC-SHA256 and SHA-256 helpers.
 *
 * WHAT: Provides two cryptographic primitives used across XRootD/WebDAV/S3: HMAC-SHA256 for
 *      GSI kXR_sigver request signing, and plain SHA-256 for digest computation. WHY: Both
 *      native XRootD (GSI session HMAC) and WebDAV (token scope hashing) need these primitives;
 *      sharing avoids duplicating EVP_MAC/EVP_MD API calls in each caller. HOW: OpenSSL 3.x
 *      EVP_MAC API for HMAC, EVP_Digest API for SHA-256. */

#include "crypto.h"
#include <openssl/evp.h>

/*
 * xrootd_hmac_sha256 — compute HMAC-SHA256 of data with key.
 *
 * WHAT: Computes an HMAC-SHA256 over data[0..datalen] using key[0..keylen], writing the 32-byte
 *      result into out. WHY: GSI kXR_sigver request signing requires HMAC-SHA256 of each XRootD
 *      wire message; callers need a shared function to produce the signature bytes. HOW: OpenSSL
 *      3.x EVP_MAC API — fetch("HMAC") → create ctx → init with digest=SHA256 param → update
 *      with data → finalise into out[32]. Returns 1 on success, 0 on failure (fetch/ctx/init). */

int
xrootd_hmac_sha256(const u_char *key, size_t keylen,
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

/*
 * xrootd_sha256 — compute SHA-256 digest of data.
 *
 * WHAT: Computes a SHA-256 hash over data[0..len], writing the 32-byte binary result into out.
 * WHY: Used for token scope hashing, object checksums, and any caller needing a plain SHA-256
 *      digest without HMAC wrapping. HOW: OpenSSL EVP_Digest API — create MD_CTX → init with
 *      EVP_sha256() → update with data → finalise into out[32]. Returns 1 on success, 0 on
 *      failure (ctx creation or finalisation). */

int
xrootd_sha256(const u_char *data, size_t len, u_char out[32])
{
    EVP_MD_CTX  *ctx;
    unsigned int outlen = 32;
    int          ok = 0;

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
