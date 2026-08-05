#ifndef BRIX_SD_CACHE_H
#define BRIX_SD_CACHE_H

/*
 * sd_cache.h - the generic read-cache decorator (phase-64 section 12.1).
 *
 * WHAT: An SD-driver instance that WRAPS a source backend (the tier below: a stage
 *       decorator or the backend itself) and a cache store (a cstore adapter over
 *       any driver), interposing the READ-open path: a complete cached object is
 *       served from the cache store, a miss is filled from the source into the
 *       store and recorded in a cinfo. Every write / namespace / xattr / staged op
 *       delegates straight to the source (a write also invalidates the cached
 *       copy), and a served read object is the STORE's own object - so reads bypass
 *       the decorator entirely.
 *
 * WHY:  Before phase-64 the read cache was a scheme-dispatched subsystem bolted to
 *       a local POSIX tree. Folding it into one composable decorator the registry
 *       stacks (cache(stage(backend))) gives ONE read cache that fronts ANY source
 *       through the cstore, with no driver/protocol branch above the SD seam (P3,
 *       review gate G5). The VFS resolves to the composed top and never knows a
 *       cache is present (G4).
 *
 * HOW:  open(READ) consults cstore_cinfo_load: a COMPLETE hit returns
 *       cstore_serve_open; a miss runs the fill spine (source open/pread ->
 *       cstore_fill_*) then records the cinfo and serves. open(WRITE) passes
 *       through to the source and evicts the cached copy. The decorator's own
 *       byte/dir slots are never reached (open returns source/store objects).
 *
 *       The decorator is wired from config through the tier grammar
 *       (fs/tier/tier_build.c composes source + cache_store into this
 *       decorator per export). The miss-fill runs INLINE on a worker thread
 *       (WebDAV / S3); the event-loop planes stay non-blocking through the
 *       async-fill seam (brix_sd_cache_fill_would_block + thread-pool offload,
 *       see src/protocols/shared/http_cache_fill.c). A NEARLINE source (sd_frm, SP5)
 *       kicks its async recall on miss and the open fails soft with EAGAIN
 *       until the object is online. See docs/refactor/phase-64-fully-tiered-
 *       composable-storage.md (section 9, 10, 12, Appendix J).
 */

#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/tier/tier.h"          /* brix_cache_policy_t */

/* Wrap `source` in a read-cache decorator backed by the `store` instance (the
 * cache_store tier). `store_local_root` is the store's absolute directory for
 * LOCAL cinfo mode (NULL for a remote store, SP2). `policy` is copied. Returns a
 * malloc-owned instance (worker-safe, no nginx pool), or NULL (errno set).
 * `source` and `store` are BORROWED - not freed by brix_sd_cache_destroy (the
 * registry owns them). NULL source/store -> NULL. */
brix_sd_instance_t *brix_sd_cache_create(brix_sd_instance_t *source,
    brix_sd_instance_t *store, const brix_cache_policy_t *policy,
    const char *store_local_root, ngx_log_t *log);

/* Free a decorator built by brix_sd_cache_create (NOT the wrapped source/store;
 * it does release the decorator's cstore L1). NULL-safe. */
void brix_sd_cache_destroy(brix_sd_instance_t *inst);

/* ---- async-fill seam (SP2 "shell -> full"): see sd_cache.c. The HTTP read
 * plane uses these to run a remote cache miss-fill on a worker thread instead of
 * blocking the event loop in the inline open() fill. ---- */

/* 1 iff `inst` is a cache decorator built by brix_sd_cache_create. */
int brix_sd_cache_instance_is(const brix_sd_instance_t *inst);

/* Evict `key` from the decorator's cache store (no-op if `inst` is not a cache
 * decorator or `key` is NULL). The namespace VFS delete/rename ops dispatch on
 * the unwrapped leaf (for per-user cred threading) and so bypass the decorator's
 * own unlink/rename evict; they call this afterwards to keep the store coherent.
 * Returns the logical bytes evicted (0 when nothing was cached) for
 * brix_metric_cache_evicted accounting. */
uint64_t brix_sd_cache_evict(brix_sd_instance_t *inst, const char *key);

/* Logical size of the cached copy of `key` (0 when uncached or `inst` is not a
 * cache decorator). Read-only pre-probe for eviction accounting on paths where
 * the evict happens inside the decorator (e.g. staged open). */
uint64_t brix_sd_cache_cached_bytes(brix_sd_instance_t *inst, const char *key);

/* 1 iff a read-open of `key` would block on slow (remote) I/O and should be
 * offloaded; 0 to serve inline (hit / local / slice / non-cache). Non-blocking. */
int brix_sd_cache_fill_needs_offload(brix_sd_instance_t *inst,
    const char *key);

/* Fill `key` (source -> store + cinfo) on the calling (worker) thread. NGX_OK /
 * NGX_DECLINED (admission) / NGX_ERROR. When `cred` is non-NULL it is threaded
 * into the source open so a remote origin authenticates AS the inbound user
 * (phase-70 delegation carry) rather than the service credential; NULL opens the
 * source with the service/anonymous identity. */
ngx_int_t brix_sd_cache_fill_key(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred);

/* As brix_sd_cache_fill_key, plus the phase-92 store-then-evict passthrough:
 * with `allow_pt` non-zero and brix_cache_passthrough on, an object the
 * admission policy would decline (path-filtered or over the caching cap) is
 * filled anyway when it fits the brix_cache_passthrough_max spool cap; the call
 * returns NGX_OK and sets *out_pt = 1, and the caller MUST evict `key` after it
 * has served the object (it is a transient hit, not a retained cache entry).
 * With `allow_pt` 0, or the policy off, or the object over cap, an admission
 * decline still returns NGX_DECLINED. `out_pt` may be NULL. */
ngx_int_t brix_sd_cache_fill_key_ex(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, int allow_pt, int *out_pt);

/* The cache STORE instance (served objects live there), or NULL if `inst` is not a
 * cache decorator. Used by the serve-locality predicate. */
brix_sd_instance_t *brix_sd_cache_store_instance(
    const brix_sd_instance_t *inst);

/* The cache SOURCE instance (the tier below the cache), or NULL if not a cache.
 * Used to unwrap the composed stack to the stage decorator (SP4 reconcile). */
brix_sd_instance_t *brix_sd_cache_source_instance(
    const brix_sd_instance_t *inst);

/* The decorator's internal cstore (an (brix_cstore_t *); returned void* to keep
 * this header free of cstore.h), or NULL if `inst` is not a cache decorator. Lets
 * the eviction/reaper enumerate a composed tier cache through its own store adapter
 * (§14a — the same cstore the read path fills into). */
void *brix_sd_cache_cstore(const brix_sd_instance_t *inst);

/* ---- phase-85 F7: optional cold tier (hot/cold demote + promote) ---------- */

/* Attach the OPTIONAL cold store tier to a cache decorator (no-op for a non-cache
 * `inst`). `cold` is BORROWED (registry-owned, worker lifetime) — never freed by
 * brix_sd_cache_destroy. With a cold tier attached, a read miss first attempts a
 * verified promote from the cold store (falling back to the origin fill on any
 * cold failure), and the eviction engine demotes victims into it. NULL detaches. */
void brix_sd_cache_set_cold(brix_sd_instance_t *inst,
    brix_sd_instance_t *cold);

/* Demote the HOT cached object `key` into the cold store tier: copy its bytes
 * from the cache store into the cold store (staged write + commit). Called by
 * the eviction engine on space-pressure victims ONLY — never on write
 * invalidation (a written-over object is stale and must not survive in cold).
 * Returns NGX_OK (demoted), NGX_DECLINED (no cold tier / not a cache decorator
 * — nothing to do), or NGX_ERROR with errno set (the caller evicts anyway:
 * space relief wins, the origin refill preserves correctness). */
ngx_int_t brix_sd_cache_demote(brix_sd_instance_t *inst, const char *key);

/* ---- phase-85 F8: sibling mesh (peer CAS fetch before origin) ------------- */

#define BRIX_SD_CACHE_MAX_PEERS 16

/* One ring member: the rendezvous label ("host:port", identical on every node
 * of the mesh) plus the built http fill source — NULL for this node's own slot
 * (and for a member whose build failed: that member's keys fall through to the
 * origin). */
typedef struct {
    brix_sd_instance_t *inst;
    char                  label[272];
} brix_sd_cache_peer_t;

/* Attach the sibling-mesh ring to a cache decorator (no-op for a non-cache
 * `inst`). The peer instances are BORROWED (registry-owned, worker lifetime).
 * With a ring attached, a read miss whose rendezvous owner is a NON-self member
 * attempts one verified fill from that sibling before the origin; any peer
 * failure falls back to the origin. `self` indexes this node's own slot.
 * n <= BRIX_SD_CACHE_MAX_PEERS; n == 0 detaches. */
void brix_sd_cache_set_peers(brix_sd_instance_t *inst,
    const brix_sd_cache_peer_t *peers, int n, int self);

/* ---- phase-87 G12: dynamic (swarm) ring ----------------------------------- */

/* An immutable published ring: the swarm membership plane builds one per
 * membership change and swaps it in atomically; while attached it takes
 * precedence over the static brix_cache_peers ring in the fill spine. */
typedef struct {
    int                   n;
    int                   self;
    brix_sd_cache_peer_t  peers[BRIX_SD_CACHE_MAX_PEERS];
} brix_sd_cache_ring_t;

/* Publish `ring` as the live rendezvous ring (event loop only; no-op for a
 * non-cache `inst` or a malformed ring). Worker threads running fills read
 * the pointer once per fill, so `ring` must be fully built BEFORE the call
 * and must remain valid for the WORKER'S LIFETIME — the caller never frees
 * a published ring (membership-churn-bounded, ~4.5 KiB each). NULL detaches
 * (the static brix_cache_peers ring resumes). */
void brix_sd_cache_ring_swap(brix_sd_instance_t *inst,
    const brix_sd_cache_ring_t *ring);

/* Copy the STATIC configured ring (the brix_cache_peers seed list) into
 * `out` (BRIX_SD_CACHE_MAX_PEERS entries) and set *self to this node's own
 * slot. Returns the member count, or 0 for a non-cache instance / no ring.
 * The swarm membership plane seeds from this. */
int brix_sd_cache_get_peers(const brix_sd_instance_t *inst,
    brix_sd_cache_peer_t *out, int *self);

#endif /* BRIX_SD_CACHE_H */
