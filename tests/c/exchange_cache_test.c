/* Unit test for the per-worker token-exchange result cache (P90-70.9,
 * phase-70 §5.4): brix_tx_cache_* in src/auth/token/exchange_cache.c.
 *
 * Links the REAL exchange_cache.o + b64url.o + json.o + crypto.o. Minted
 * tokens are crafted in-test via b64url_encode with explicit `exp` claims,
 * and `now` is injected everywhere — expiry behaviour is fully deterministic
 * (no wall clock; also sidesteps the WSL2 clock-backwards issue).
 *
 * Ritual: success (store→hit with exact bytes; expiry honours min(exp, +5min)
 * from BOTH sides) + error (unparseable / expired / oversized mints are never
 * cached; NULL-cache and zero-slot creation are inert) + security-negative
 * (a different subject token — even same audience — can NEVER be served the
 * cached mint; same subject with a different audience misses too). */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/token/exchange_cache.h"
#include "auth/token/b64url.h"
#include "core/compat/crypto.h"   /* brix_crypto_init: prefetch the EVP_MD */

/* ---- nginx surface stubs -------------------------------------------------- */

void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}

/* ---- token forging -------------------------------------------------------- */

static ngx_str_t
forge_jwt(const char *payload_json, char *buf, size_t bufsz)
{
    static const char *header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
    char       h64[128], p64[8192];
    int        n;
    ngx_str_t  tok;

    b64url_encode(header, strlen(header), h64, sizeof(h64));
    b64url_encode(payload_json, strlen(payload_json), p64, sizeof(p64));
    n = snprintf(buf, bufsz, "%s.%s.c2ln", h64, p64);
    assert(n > 0 && (size_t) n < bufsz);
    tok.data = (u_char *) buf;
    tok.len  = (size_t) n;
    return tok;
}

static ngx_str_t
forge_exp_jwt(long exp, char *buf, size_t bufsz)
{
    char payload[128];

    snprintf(payload, sizeof(payload),
             "{\"sub\":\"alice\",\"exp\":%ld}", exp);
    return forge_jwt(payload, buf, bufsz);
}

int
main(void)
{
    ngx_pool_t      *dummy_pool = (ngx_pool_t *) &dummy_pool;   /* opaque */
    brix_tx_cache_t *c;
    char             mbuf[8192], mbuf2[8192];
    ngx_str_t        minted, minted2, hit;
    const time_t     now = 1800000000;   /* fixed epoch; injected throughout */
    ngx_str_t        subject  = ngx_string("client-subject-token.abc.def");
    ngx_str_t        subject2 = ngx_string("other-subject-token.abc.def");
    ngx_str_t        aud      = ngx_string("https://dcache.example.org");
    ngx_str_t        aud2     = ngx_string("https://eos.example.org");

    /* Production calls this once at process init; brix_sha256() fails closed
     * (and the cache degrades to all-miss) without the prefetched EVP_MD. */
    assert(brix_crypto_init() == 1);

    c = brix_tx_cache_create(dummy_pool, BRIX_TX_CACHE_SLOTS);
    assert(c != NULL);

    /* 1. success: long-lived mint (exp = now+3600) — hit inside the 5-minute
     *    clamp with the exact stored bytes, miss once the clamp elapses. */
    minted = forge_exp_jwt((long) now + 3600, mbuf, sizeof(mbuf));
    brix_tx_cache_store(c, &subject, &aud, &minted, now);
    memset(&hit, 0, sizeof(hit));
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 299, &hit) == 1);
    assert(hit.len == minted.len
           && memcmp(hit.data, minted.data, hit.len) == 0
           && hit.data[hit.len] == '\0');
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 300, &hit) == 0);
    /* expiry frees the slot eagerly: even an earlier `now` misses afterwards */
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 1, &hit) == 0);

    /* 2. success: short-lived mint (exp = now+60) — the token's own exp binds
     *    below the clamp. */
    minted = forge_exp_jwt((long) now + 60, mbuf, sizeof(mbuf));
    brix_tx_cache_store(c, &subject, &aud, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 59, &hit) == 1);
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 60, &hit) == 0);

    /* 3. success: audience-less exchange (aud NULL) keys its own entry. */
    minted2 = forge_exp_jwt((long) now + 3600, mbuf2, sizeof(mbuf2));
    brix_tx_cache_store(c, &subject, NULL, &minted2, now);
    assert(brix_tx_cache_lookup(c, &subject, NULL, now + 1, &hit) == 1);

    /* 4. error: mint without a parseable positive exp is never cached. */
    minted = forge_jwt("{\"sub\":\"alice\"}", mbuf, sizeof(mbuf));
    brix_tx_cache_store(c, &subject, &aud2, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud2, now + 1, &hit) == 0);
    minted.data = (u_char *) "not-a-jwt-at-all";
    minted.len  = 16;
    brix_tx_cache_store(c, &subject, &aud2, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud2, now + 1, &hit) == 0);

    /* 5. error: already-expired mint refused; oversized mint refused. */
    minted = forge_exp_jwt((long) now - 10, mbuf, sizeof(mbuf));
    brix_tx_cache_store(c, &subject, &aud2, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud2, now + 1, &hit) == 0);
    minted = forge_exp_jwt((long) now + 3600, mbuf, sizeof(mbuf));
    minted.len = 5000;   /* claim > BRIX_TX_CACHE_TOKEN_MAX; bytes irrelevant */
    brix_tx_cache_store(c, &subject, &aud2, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud2, now + 1, &hit) == 0);

    /* 6. error: inert edges — NULL cache, zero slots, empty subject. */
    assert(brix_tx_cache_create(dummy_pool, 0) == NULL);
    assert(brix_tx_cache_create(NULL, 8) == NULL);
    assert(brix_tx_cache_lookup(NULL, &subject, &aud, now, &hit) == 0);
    brix_tx_cache_store(NULL, &subject, &aud, &minted, now);   /* no crash */
    {
        ngx_str_t empty = ngx_null_string;
        minted = forge_exp_jwt((long) now + 3600, mbuf, sizeof(mbuf));
        brix_tx_cache_store(c, &empty, &aud, &minted, now);
        assert(brix_tx_cache_lookup(c, &empty, &aud, now, &hit) == 0);
    }

    /* 7. security-neg: the cached mint for (subject, aud) must never be
     *    served to a DIFFERENT subject token, nor for another audience. */
    minted = forge_exp_jwt((long) now + 3600, mbuf, sizeof(mbuf));
    brix_tx_cache_store(c, &subject, &aud, &minted, now);
    assert(brix_tx_cache_lookup(c, &subject, &aud, now + 1, &hit) == 1);
    assert(brix_tx_cache_lookup(c, &subject2, &aud, now + 1, &hit) == 0);
    assert(brix_tx_cache_lookup(c, &subject, &aud2, now + 1, &hit) == 0);

    printf("exchange_cache: all cases passed\n");
    return 0;
}
