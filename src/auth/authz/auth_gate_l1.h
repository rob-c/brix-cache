#ifndef XROOTD_PATH_AUTH_GATE_L1_H
#define XROOTD_PATH_AUTH_GATE_L1_H

/*
 * auth_gate_l1.h — per-worker L1 in front of the SHM auth-result cache.
 *
 * WHAT: a tiny lockless direct-mapped cache mapping the 32-byte auth-gate cache
 *   key (already a SHA-256, built in auth_gate.c) to its cached grant/deny
 *   verdict.  It sits as the L1 in front of the optional cross-worker SHM cache
 *   (auth_cache.c / `xrootd_kv_t`): an L1 hit returns the verdict WITHOUT taking
 *   the per-zone `ngx_shmtx` spinlock that `xrootd_kv_get` holds.
 *
 * WHY: the auth gate runs on the GSI/authz hot path.  When the SHM auth cache is
 *   enabled, every request — even a cache hit — takes the SHM spinlock, so under
 *   high concurrency (grid-scale GSI pilots/FTS) that single lock serializes auth
 *   decisions across all workers and stalls the event loop.  This L1 collapses
 *   the repeated-{op,path,identity} case to an O(1) lockless probe, mirroring the
 *   token L1 (src/token/worker_cache.c).
 *
 * SCOPE / CORRECTNESS:
 *   - Used ONLY when the operator enabled `xrootd_auth_cache` (it is an L1 in
 *     front of that L2, not an independent always-on cache) — so disabling auth
 *     caching still re-evaluates every request, and the L1 inherits the L2 TTL.
 *   - Per-conf, so the auth_level / rules / identity that produced a verdict are
 *     implicitly part of the cache identity.
 *   - Keyed by the caller's 32-byte SHA-256 (no re-hash); a full 32-byte compare
 *     guards against bucket aliasing.
 *   - Lockless: per-worker, only touched from the single-threaded event loop.
 */

#include <ngx_core.h>
#include "auth_cache.h"   /* xrootd_auth_cache_val_t */

typedef struct xrootd_auth_l1_s xrootd_auth_l1_t;

/* Create a per-worker L1 with `slots` direct-mapped buckets from `pool` (use the
 * worker cycle pool).  Returns NULL on OOM (caller then runs L2-only). */
xrootd_auth_l1_t *xrootd_auth_l1_create(ngx_pool_t *pool, ngx_uint_t slots);

/* Look up a verdict by its 32-byte key.  Returns 1 and fills *val on a fresh
 * (non-expired) hit; 0 on miss/expiry/NULL cache. */
int xrootd_auth_l1_lookup(xrootd_auth_l1_t *cache, const u_char key[32],
    xrootd_auth_cache_val_t *val);

/* Store a verdict for `key`, valid for ttl_ms milliseconds.  No-op on NULL. */
void xrootd_auth_l1_store(xrootd_auth_l1_t *cache, const u_char key[32],
    const xrootd_auth_cache_val_t *val, ngx_msec_t ttl_ms);

#endif /* XROOTD_PATH_AUTH_GATE_L1_H */
