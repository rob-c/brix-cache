#ifndef BRIX_COMPAT_CRYPTO_H
#define BRIX_COMPAT_CRYPTO_H

/*
 * ngx-free: uses uint8_t (== nginx's u_char) so this header compiles into both
 * the nginx module and the standalone libxrdproto core. The module calls
 * brix_crypto_init/_cleanup from its worker lifecycle; a standalone client
 * calls them once from main()/atexit().
 */
#include <stddef.h>
#include <stdint.h>

/* Worker-lifecycle init/cleanup: call once in init_process / exit_process.
 * Fetches the EVP_MAC and EVP_MD algorithm objects once per worker so that
 * per-request HMAC/SHA256 calls pay only the CTX alloc cost, not a registry
 * lookup. Returns 1 on success, 0 on failure (init only). */
int  brix_crypto_init(void);
void brix_crypto_cleanup(void);

/* HMAC-SHA256: keyed hash of data, 32-byte result written to out.
 * Returns 1 on success, 0 on failure. */
int brix_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen,
                       uint8_t out[32]);

/* SHA-256: unkeyed digest of data, 32-byte result written to out.
 * Returns 1 on success, 0 on failure. */
int brix_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* Incremental (streaming) SHA-256 — for data that arrives in pieces (e.g. the
 * payload of each aws-chunked chunk, which may span many read windows).  The
 * handle is an opaque pointer (one EVP_MD_CTX); the API is OpenSSL-free so this
 * header still compiles into libxrdproto.  Usage: new() → update()* → final()
 * (which re-initialises the handle so it can hash the next chunk) → free(). */
void *brix_sha256_stream_new(void);                    /* NULL on failure   */
int   brix_sha256_stream_update(void *s, const uint8_t *data, size_t len);
int   brix_sha256_stream_final(void *s, uint8_t out[32]); /* re-inits on ok  */
void  brix_sha256_stream_free(void *s);

/* Phase-28 F3 / P90-28.1: keep a LONG-LIVED secret buffer (parsed keytab key
 * array, admin bearer secret, macaroon root-secret hex) out of core dumps and
 * off swap.  Page-aligns the range, then best-effort madvise(MADV_DONTDUMP)
 * + mlock().  Returns 0 when both succeeded (or len==0), -1 when either
 * failed — callers log a warning and continue; the guard is defence-in-depth,
 * never load-bearing.  Caveats (accepted, see phase-90 register P90-28.1):
 * page granularity over-covers neighbouring allocations (harmless — only
 * excludes MORE bytes from dumps); conf-pool pages recycled across a reload
 * stay guarded (marginal RSS pin, no correctness effect); and while the
 * MADV_DONTDUMP VMA flag SURVIVES fork — so conf-time guards protect every
 * worker's core dumps, the primary threat — mlock does NOT cross fork, so the
 * swap pin covers only the calling process's mapping. */
int brix_secret_page_guard(const void *p, size_t len);

#endif /* BRIX_COMPAT_CRYPTO_H */
