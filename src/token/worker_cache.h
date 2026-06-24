#ifndef XROOTD_TOKEN_WORKER_CACHE_H
#define XROOTD_TOKEN_WORKER_CACHE_H

/*
 * worker_cache.h — always-on, per-worker L1 bearer-token validation cache.
 *
 * WHAT: a tiny lockless direct-mapped cache that maps a token fingerprint to its
 *   already-validated xrootd_token_claims_t, so a token presented repeatedly is
 *   validated with crypto + JSON parsing at most once per MAX_TTL window per
 *   worker.  It sits as the L1 in front of the OPTIONAL cross-worker SHM cache
 *   (token_cache.c / xrootd_token_cache_*): L1 hit -> no crypto AND no SHM
 *   spinlock; L1 miss -> fall through to L2/full validation, then populate L1.
 *
 * WHY: token validation runs inline on the single-threaded nginx event loop
 *   (RSA/ECDSA verify + base64url decode + JSON parse).  Under load, doing that
 *   per request starves the loop of time to service other connections' reads,
 *   producing client-side "HTTP ReadTimeout"s.  The pre-existing SHM cache is
 *   (a) opt-in (needs an xrootd_kv_zone) so most deployments had NO caching, and
 *   (b) takes a per-zone spinlock on every lookup/store, so it still contends
 *   under high concurrency.  This L1 is always on and lock-free, collapsing the
 *   overwhelmingly common "same client reuses its token for many requests" case
 *   to an O(1) hash probe.
 *
 * SECURITY / CORRECTNESS:
 *   - Only SUCCESSFULLY validated claims are ever stored (never failures).
 *   - Each entry is bounded by min(exp, now + MAX_TTL); a token is therefore
 *     re-validated at least every MAX_TTL even if not expired, so revocation /
 *     key rotation / clock changes are picked up within that bound (same policy
 *     as the SHM cache).
 *   - The cache is PER-CONF, so the issuer/audience/key-set/macaroon-secret that
 *     governed a validation are implicitly part of the cache identity — a token
 *     cached under one server/location is never served to another.
 *   - Keyed by SHA-256 of the raw token bytes (collision-resistant); a 32-byte
 *     fingerprint compare guards against bucket aliasing.
 *   - Lockless by construction: the cache is per-worker and only ever touched
 *     from the event loop (never from AIO threads), which is single-threaded.
 */

#include <ngx_core.h>
#include "token.h"

/*
 * Default per-worker L1 slot count.  Each slot holds a full claims struct
 * (~4.4 KB), so 1024 slots ≈ 4.5 MB per worker — generous for the number of
 * distinct active tokens a single worker sees, while bounding memory.
 */
#define XROOTD_TOKEN_L1_SLOTS  1024

typedef struct xrootd_token_l1_s xrootd_token_l1_t;

/*
 * Create a per-worker L1 cache with `slots` direct-mapped buckets, allocated
 * from `pool` (use the worker cycle pool — process lifetime).  `slots` is
 * clamped to a sane minimum.  Returns NULL on allocation failure (the caller
 * then simply runs without L1 — correctness is unaffected).
 */
xrootd_token_l1_t *xrootd_token_l1_create(ngx_pool_t *pool, ngx_uint_t slots);

/*
 * Look up `token` (token_len bytes).  On a fresh (non-expired) hit, copies the
 * stored claims into *claims and returns 1.  Returns 0 on miss/expiry/NULL cache
 * (caller falls through to L2 / full validation).
 */
int xrootd_token_l1_lookup(xrootd_token_l1_t *cache, const char *token,
    size_t token_len, xrootd_token_claims_t *claims);

/*
 * Store freshly validated `claims` for `token`.  No-op for a NULL cache or an
 * already-expired token.  Overwrites (evicts) whatever shared the bucket.
 */
void xrootd_token_l1_store(xrootd_token_l1_t *cache, const char *token,
    size_t token_len, const xrootd_token_claims_t *claims);

#endif /* XROOTD_TOKEN_WORKER_CACHE_H */
