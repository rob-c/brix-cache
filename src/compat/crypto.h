#ifndef XROOTD_COMPAT_CRYPTO_H
#define XROOTD_COMPAT_CRYPTO_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_hmac_sha256 — single-shot HMAC-SHA256.
 *
 * WHAT: Computes HMAC-SHA256 over data using key, writing 32-byte result into out.
 * WHY: GSI kXR_sigver request signing; callers need a shared function to produce signature bytes.
 * HOW: OpenSSL EVP_MAC API — fetch("HMAC") → init with digest=SHA256 param → update + finalise. */

int xrootd_hmac_sha256(const u_char *key, size_t keylen,
                       const u_char *data, size_t datalen,
                       u_char out[32]);

/*
 * xrootd_sha256 — single-shot SHA-256 digest.
 *
 * WHAT: Computes SHA-256 hash over data, writing 32-byte binary result into out.
 * WHY: Token scope hashing, object checksums, any caller needing plain SHA-256 without HMAC.
 * HOW: OpenSSL EVP_Digest API — create MD_CTX → init with EVP_sha256() → update + finalise. */

int xrootd_sha256(const u_char *data, size_t len, u_char out[32]);

#endif /* XROOTD_COMPAT_CRYPTO_H */
