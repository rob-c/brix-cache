#ifndef BRIX_AUTH_TOKEN_EXCHANGE_CACHE_H
#define BRIX_AUTH_TOKEN_EXCHANGE_CACHE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <time.h>

/*
 * Per-worker RFC-8693 token-exchange result cache (phase-70 §5.4, P90-70.9).
 *
 * An EXCHANGE-mode export mints one backend-audienced token per (subject
 * token, audience) pair; without a cache every VFS op re-POSTs to the issuer.
 * This is the direct-mapped, lock-free, event-loop-only cache the exchange
 * integration layer owns (exchange.c deliberately keeps none): the key is
 * SHA-256(subject-token ‖ audience) so a different client token — even for
 * the same user — can NEVER be served another subject's minted token, and the
 * entry TTL is min(minted `exp`, store-time + BRIX_TX_CACHE_MAX_TTL_SECS) so
 * revocation at the issuer is picked up within the clamp window.
 *
 * `now` is injected by the caller (time(NULL) in production) so expiry is
 * deterministic under test. Lookup returns a BORROWED view of the cached
 * bytes — copy before the next store could evict the slot (in the
 * single-threaded event loop: before returning to it).
 */

typedef struct brix_tx_cache_s brix_tx_cache_t;

/* Never serve a cached minted token for longer than this, regardless of its
 * `exp`. Mirrors the validation caches' 5-minute revocation bound. */
#define BRIX_TX_CACHE_MAX_TTL_SECS  (5 * 60)

/* Default slot count for the lazily-created per-conf instance. */
#define BRIX_TX_CACHE_SLOTS  64

/* Allocate a cache of `slots` entries from `pool` (use ngx_cycle->pool for a
 * conf-lifetime instance). Returns NULL on OOM — callers treat that as
 * "no cache" and simply re-exchange. */
brix_tx_cache_t *brix_tx_cache_create(ngx_pool_t *pool, ngx_uint_t slots);

/* If a live entry for (subject, aud) exists at `now`, point *out at the cached
 * minted token (borrowed, NUL-terminated) and return 1; else 0. `aud` may be
 * NULL/empty (audience-less exchange) and is part of the key either way. */
int brix_tx_cache_lookup(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, time_t now, ngx_str_t *out);

/* Cache `minted` for (subject, aud). Refuses (silently — caching is best
 * effort) when the minted token is oversized, its payload/`exp` cannot be
 * parsed, or it is already expired at `now`; the stored TTL is clamped to
 * BRIX_TX_CACHE_MAX_TTL_SECS. */
void brix_tx_cache_store(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, const ngx_str_t *minted, time_t now);

#endif /* BRIX_AUTH_TOKEN_EXCHANGE_CACHE_H */
