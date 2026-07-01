#ifndef XROOTD_SD_CACHE_H
#define XROOTD_SD_CACHE_H

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
 *       SP1 ships the decorator with an INLINE fill - correct for the WebDAV / S3
 *       worker-thread context, and not yet on the live root:// event loop (the
 *       config -> tier-grammar -> registry wiring is the deferred migration, and
 *       the non-blocking root:// async-offload + remote-store path is the SP2
 *       "shell -> full" step). The nearline (tape) recall+park branch is wired to
 *       the source's recall slot but only exercised once the frm driver lands
 *       (SP5). See docs/refactor/phase-64-fully-tiered-composable-storage.md
 *       (section 9, 10, 12, Appendix J).
 */

#include <ngx_core.h>

#include "../sd.h"
#include "../../tier/tier.h"          /* xrootd_cache_policy_t */

/* Wrap `source` in a read-cache decorator backed by the `store` instance (the
 * cache_store tier). `store_local_root` is the store's absolute directory for
 * LOCAL cinfo mode (NULL for a remote store, SP2). `policy` is copied. Returns a
 * malloc-owned instance (worker-safe, no nginx pool), or NULL (errno set).
 * `source` and `store` are BORROWED - not freed by xrootd_sd_cache_destroy (the
 * registry owns them). NULL source/store -> NULL. */
xrootd_sd_instance_t *xrootd_sd_cache_create(xrootd_sd_instance_t *source,
    xrootd_sd_instance_t *store, const xrootd_cache_policy_t *policy,
    const char *store_local_root, ngx_log_t *log);

/* Free a decorator built by xrootd_sd_cache_create (NOT the wrapped source/store;
 * it does release the decorator's cstore L1). NULL-safe. */
void xrootd_sd_cache_destroy(xrootd_sd_instance_t *inst);

/* ---- async-fill seam (SP2 "shell -> full"): see sd_cache.c. The HTTP read
 * plane uses these to run a remote cache miss-fill on a worker thread instead of
 * blocking the event loop in the inline open() fill. ---- */

/* 1 iff `inst` is a cache decorator built by xrootd_sd_cache_create. */
int xrootd_sd_cache_instance_is(const xrootd_sd_instance_t *inst);

/* 1 iff a read-open of `key` would block on slow (remote) I/O and should be
 * offloaded; 0 to serve inline (hit / local / slice / non-cache). Non-blocking. */
int xrootd_sd_cache_fill_needs_offload(xrootd_sd_instance_t *inst,
    const char *key);

/* Fill `key` (source -> store + cinfo) on the calling (worker) thread. NGX_OK /
 * NGX_DECLINED (admission) / NGX_ERROR. */
ngx_int_t xrootd_sd_cache_fill_key(xrootd_sd_instance_t *inst, const char *key);

/* The cache STORE instance (served objects live there), or NULL if `inst` is not a
 * cache decorator. Used by the serve-locality predicate. */
xrootd_sd_instance_t *xrootd_sd_cache_store_instance(
    const xrootd_sd_instance_t *inst);

/* The cache SOURCE instance (the tier below the cache), or NULL if not a cache.
 * Used to unwrap the composed stack to the stage decorator (SP4 reconcile). */
xrootd_sd_instance_t *xrootd_sd_cache_source_instance(
    const xrootd_sd_instance_t *inst);

#endif /* XROOTD_SD_CACHE_H */
