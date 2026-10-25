/*
 * crypto.c — shared OpenSSL HMAC-SHA256 and SHA-256 helpers.
 *
 * Provides two cryptographic primitives used across XRootD/WebDAV/S3:
 * HMAC-SHA256 for GSI kXR_sigver request signing, and plain SHA-256 for
 * digest computation.
 *
 * On OpenSSL 3+, EVP_MAC/EVP_MD objects are fetched once at worker init
 * and freed at worker exit. OpenSSL 1.1.1 uses its native HMAC interface
 * and a borrowed built-in SHA-256 descriptor; borrowed algorithms are never
 * freed. Both backends share the same initialized-lifetime and output contract.
 */

#include "crypto.h"
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#else
#include <openssl/hmac.h>
#endif
#include <limits.h>
#include <sys/mman.h>   /* madvise/mlock (F3 secret-page guard) */
#include <unistd.h>     /* sysconf(_SC_PAGESIZE) */
#include <stdint.h>
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static EVP_MAC *s_hmac_mac;
static EVP_MD  *s_sha256_md;
#else
static const EVP_MD *s_sha256_md;
#endif

int
brix_crypto_init(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *hmac_mac;
    EVP_MD *sha256_md;

    if (s_hmac_mac != NULL && s_sha256_md != NULL) return 1;
    brix_crypto_cleanup();
    hmac_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    sha256_md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (hmac_mac == NULL || sha256_md == NULL) {
        EVP_MAC_free(hmac_mac);
        EVP_MD_free(sha256_md);
        return 0;
    }
    s_hmac_mac = hmac_mac;
    s_sha256_md = sha256_md;
    return 1;
#else
    s_sha256_md = EVP_sha256();
    return s_sha256_md != NULL;
#endif
}

void
brix_crypto_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_free(s_hmac_mac);
    s_hmac_mac = NULL;
    EVP_MD_free(s_sha256_md);
#endif
    s_sha256_md = NULL;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* ---- Compute one provider-backed HMAC ----
 * WHAT: Return 1 after producing 32 bytes, otherwise 0; arguments are validated.
 * WHY: Keep native context ownership separate from the public bounds contract.
 * HOW: 1. Create context. 2. Initialize/update/finalize. 3. Free on every path.
 */
static int
brix_hmac_native(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen, uint8_t out[32])
{
    EVP_MAC_CTX *ctx;
    OSSL_PARAM   params[2];
    size_t       outlen = 32;
    int          ok = 0;

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(s_hmac_mac);
    if (ctx
        && EVP_MAC_init(ctx, key, keylen, params) == 1
        && EVP_MAC_update(ctx, data, datalen) == 1
        && EVP_MAC_final(ctx, out, &outlen, 32) == 1 && outlen == 32)
    {
        ok = 1;
    }

    EVP_MAC_CTX_free(ctx);
    return ok;
}
#else
/* ---- Compute one legacy HMAC using a private context ----
 * WHAT: Return 1 after producing 32 bytes, otherwise 0; arguments are validated.
 * WHY: Avoid shared mutable HMAC state and the legacy NULL-key reuse behavior.
 * HOW: 1. Create context. 2. Initialize/update/finalize. 3. Free on every path.
 */
static int
brix_hmac_native(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen, uint8_t out[32])
{
    HMAC_CTX *context;
    unsigned int outlen = 0;
    int ok = 0;
    context = HMAC_CTX_new();
    if (context != NULL && HMAC_Init_ex(context, key, (int) keylen, s_sha256_md, NULL) == 1
        && HMAC_Update(context, data, datalen) == 1
        && HMAC_Final(context, out, &outlen) == 1 && outlen == 32) {
        ok = 1;
    }
    HMAC_CTX_free(context);
    return ok;
}
#endif

/* ---- Enforce one MAC argument and lifecycle contract across versions ----
 * WHAT: Return 1 for a complete HMAC, 0 for invalid arguments or native failure.
 * WHY: Never truncate hostile size_t key lengths or reuse an implicit old key.
 * HOW: 1. Check bounds/pointers/lifetime. 2. Normalize an empty key. 3. Dispatch.
 */
int
brix_hmac_sha256(const uint8_t *key, size_t keylen,
                   const uint8_t *data, size_t datalen, uint8_t out[32])
{
    const uint8_t empty_key = 0;

    if (s_sha256_md == NULL || out == NULL || keylen > INT_MAX
        || (key == NULL && keylen != 0) || (data == NULL && datalen != 0)) {
        return 0;
    }
    if (key == NULL) {
        key = &empty_key;
    }
    return brix_hmac_native(key, keylen, data, datalen, out);
}

int
brix_sha256(const uint8_t *data, size_t len, uint8_t out[32])
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

    brix_evp_md_ctx_free(ctx);
    return ok;
}

/* The opaque streaming handle is simply the EVP_MD_CTX itself. */
void *
brix_sha256_stream_new(void)
{
    EVP_MD_CTX *ctx;

    if (s_sha256_md == NULL) { return NULL; }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) { return NULL; }
    if (EVP_DigestInit_ex(ctx, s_sha256_md, NULL) != 1) {
        brix_evp_md_ctx_free(ctx);
        return NULL;
    }
    return ctx;
}

int
brix_sha256_stream_update(void *s, const uint8_t *data, size_t len)
{
    return s != NULL && EVP_DigestUpdate((EVP_MD_CTX *) s, data, len) == 1;
}

int
brix_sha256_stream_final(void *s, uint8_t out[32])
{
    unsigned int outlen = 32;

    if (s == NULL
        || EVP_DigestFinal_ex((EVP_MD_CTX *) s, out, &outlen) != 1)
    {
        return 0;
    }
    /* Re-initialise so the same handle can hash the next chunk. */
    return EVP_DigestInit_ex((EVP_MD_CTX *) s, s_sha256_md, NULL) == 1;
}

void
brix_sha256_stream_free(void *s)
{
    brix_evp_md_ctx_free((EVP_MD_CTX *) s);
}

/* ---- brix_secret_page_guard (Phase-28 F3 / P90-28.1) -----------------------
 *
 * WHAT: Excludes the pages holding [p, p+len) from core dumps
 * (madvise MADV_DONTDUMP) and pins them off swap (mlock).  Best-effort and
 * never load-bearing: 0 = fully applied (or len==0), -1 = at least one knob
 * failed (caller logs and continues).
 *
 * WHY: F1 wipes secrets at end-of-life, but a LONG-LIVED secret (keytab key
 * array, admin bearer token, macaroon root-secret hex) sits in worker memory
 * for the process lifetime — one core dump or swap-out would persist it to
 * disk.  Guarding the pages closes both channels without touching how the
 * secret is used.
 *
 * HOW: Round p down / p+len up to the page boundary (madvise and mlock are
 * page-granular and EINVAL on unaligned starts), then apply both knobs
 * independently so one failing (e.g. RLIMIT_MEMLOCK exhausted) does not skip
 * the other.  MADV_DONTDUMP is Linux-specific — compiled out elsewhere and
 * that knob then counts as success (nothing to apply). */
int
brix_secret_page_guard(const void *p, size_t len)
{
    size_t     page, off;
    uintptr_t  start;
    int        rc = 0;

    if (p == NULL || len == 0) {
        return 0;
    }

    page  = (size_t) sysconf(_SC_PAGESIZE);
    start = (uintptr_t) p & ~(page - 1);
    off   = (size_t) ((uintptr_t) p - start);

#ifdef MADV_DONTDUMP
    if (madvise((void *) start, len + off, MADV_DONTDUMP) != 0) {
        rc = -1;
    }
#endif
    if (mlock((void *) start, len + off) != 0) {
        rc = -1;
    }
    return rc;
}
