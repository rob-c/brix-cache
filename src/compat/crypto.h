#ifndef XROOTD_COMPAT_CRYPTO_H
#define XROOTD_COMPAT_CRYPTO_H

/*
 * ngx-free: uses uint8_t (== nginx's u_char) so this header compiles into both
 * the nginx module and the standalone libxrdproto core. The module calls
 * xrootd_crypto_init/_cleanup from its worker lifecycle; a standalone client
 * calls them once from main()/atexit().
 */
#include <stddef.h>
#include <stdint.h>

/* Worker-lifecycle init/cleanup: call once in init_process / exit_process.
 * Fetches the EVP_MAC and EVP_MD algorithm objects once per worker so that
 * per-request HMAC/SHA256 calls pay only the CTX alloc cost, not a registry
 * lookup. Returns 1 on success, 0 on failure (init only). */
int  xrootd_crypto_init(void);
void xrootd_crypto_cleanup(void);

/* HMAC-SHA256: keyed hash of data, 32-byte result written to out.
 * Returns 1 on success, 0 on failure. */
int xrootd_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen,
                       uint8_t out[32]);

/* SHA-256: unkeyed digest of data, 32-byte result written to out.
 * Returns 1 on success, 0 on failure. */
int xrootd_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif /* XROOTD_COMPAT_CRYPTO_H */
