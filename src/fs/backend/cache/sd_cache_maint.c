/*
 * sd_cache_maint.c — the decorator's public maintenance + async-fill seam.
 *
 * WHAT: The non-driver entrypoints callers use to introspect and maintain a
 *       composed cache decorator from outside its own vtable: the
 *       caller-driven evict + cached-size probe (eviction accounting) and the
 *       SP2 async-fill offload trio (fill_needs_offload / fill_key /
 *       fill_key_ex).
 *
 * WHY:  Split from sd_cache.c for the file-size cap when the eviction
 *       accounting probes landed. These functions share no open-path state —
 *       each re-enters through the public instance handle — so they isolate
 *       cleanly from the interposed read-open decision tree that sd_cache.c
 *       owns.
 *
 * HOW:  Every entrypoint gates on brix_sd_cache_instance_is() — which stays in
 *       sd_cache.c beside the static driver vtable it compares against — and
 *       reaches the decorator state via SD_CACHE_ST from sd_cache_internal.h;
 *       the fill entrypoints delegate to the fill spine (sd_cache_fill.c).
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "fs/cache/cstore.h"

#include <errno.h>
#include <time.h>


/* Evict `key` from this decorator's cache store, if `inst` is a cache decorator
 * (a no-op otherwise). The namespace VFS ops (delete/rename) dispatch on the
 * unwrapped leaf instance so per-user credentials thread to the origin driver,
 * which skips the decorator's own unlink/rename and therefore its evict side
 * effect; the caller invokes this after a successful leaf op to keep the store
 * coherent. Mirrors the evict in sd_cache_unlink()/sd_cache_rename(). Returns
 * the logical bytes evicted (0 if nothing was cached / not a decorator) so the
 * caller can feed brix_metric_cache_evicted. */
uint64_t
brix_sd_cache_evict(brix_sd_instance_t *inst, const char *key)
{
    sd_cache_inst_state  *st;

    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        return 0;
    }
    st = SD_CACHE_ST(inst);
    return brix_cstore_evict_sized(&st->cstore, key);
}

/* Vtable evict pair (phase-107 C2) — the promoted form of brix_sd_cache_evict
 * above: drop THIS decorator's cached copy of `path`, then RELAY downward when
 * the source also carries the slot, summing the reclaimed bytes. The relay is
 * what keeps a nearline release reachable on a cache-fronted export — a cache
 * that only dropped its own copy would leave the frm online buffer full
 * forever — while a source without the slot (posix/http) simply contributes
 * nothing. INSTANCE-keyed cred twin: the decorator's own store is
 * service-owned so the cred adds nothing to the local drop; it exists so the
 * *_maybe_cred forwarder threads the per-user credential into the relay
 * instead of refusing in DENY mode (the truncate_path_cred rationale). The
 * local drop always happens; a relay failure propagates with *bytes_out still
 * carrying everything actually reclaimed. */
static ngx_int_t
sd_cache_evict_common(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    uint64_t              bytes, below = 0;
    ngx_int_t             rc = NGX_OK;

    bytes = brix_cstore_evict_sized(&st->cstore, path);
    if (st->source->driver->evict != NULL
        || st->source->driver->evict_cred != NULL)
    {
        rc = brix_sd_evict_maybe_cred(st->source, path, &below, cred);
    }
    if (bytes_out != NULL) {
        *bytes_out = bytes + below;
    }
    return rc;
}

ngx_int_t
sd_cache_evict_op(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out)
{
    return sd_cache_evict_common(inst, path, bytes_out, NULL);
}

ngx_int_t
sd_cache_evict_op_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    return sd_cache_evict_common(inst, path, bytes_out, cred);
}

/* Logical size of the cached copy of `key` (0 when uncached / not a cache
 * decorator). Read-only probe for callers that must account an eviction they
 * cannot observe directly (e.g. the staged-open path, where the decorator's
 * own staged slot drops the cached copy). */
uint64_t
brix_sd_cache_cached_bytes(brix_sd_instance_t *inst, const char *key)
{
    sd_cache_inst_state  *st;
    brix_cache_cinfo_t   ci;

    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        return 0;
    }
    st = SD_CACHE_ST(inst);
    if (brix_cstore_cinfo_load(&st->cstore, key, &ci) != NGX_OK) {
        return 0;
    }
    return ci.size;
}

/* ---- async-fill seam (SP2 "shell -> full") --------------------------------
 * The decorator's open() runs the miss-fill INLINE - correct on a worker thread
 * (the stream fill task, a WebDAV/S3 PUT worker) but a stall on the event loop
 * when the fill reads a remote source or writes a remote store (a socket wire
 * client cannot do blocking I/O on the un-pumped loop; an in-process store just
 * freezes the worker for the transfer). The HTTP read plane therefore probes
 * whether an inline open would block, runs the fill on the thread pool, and
 * re-enters. These three entrypoints expose exactly that - without making the
 * SD open() contract asynchronous. See src/shared/http_cache_fill.c. */

/* Would a read-open of `key` block the calling thread on slow (remote) I/O? 1
 * only for a cache MISS whose whole-file fill would touch a non-local tier - the
 * source exposes no local fd (a remote read: xroot/http/s3/ceph) or the cache
 * store is not a local POSIX dir (a remote write: e.g. a rados store). A COMPLETE
 * hit, a slice-mode object (open returns without filling), a local->local copy,
 * or a non-cache instance all return 0 (serve inline). No blocking call - the
 * cinfo probe hits the per-worker L1 / a local sidecar. */
int
brix_sd_cache_fill_needs_offload(brix_sd_instance_t *inst, const char *key)
{
    sd_cache_inst_state  *st;
    brix_cache_cinfo_t  ci;
    int                   src_slow;
    int                   store_slow;

    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        return 0;
    }
    st = SD_CACHE_ST(inst);

    /* A COMPLETE cached object is served from the store with no fill —
     * unless its phase-68 TTL has passed (an expired manifest refills; the
     * failed-refill path serves it stale within the 10x-TTL bound). */
    if (brix_cstore_cinfo_load(&st->cstore, key, &ci) == NGX_OK
        && (ci.flags & BRIX_CINFO_F_COMPLETE))
    {
        if (!(st->policy.cvmfs_manifest_ttl > 0
              && brix_cache_cinfo_expired(&ci, time(NULL)) == 1))
        {
            return 0;
        }
        /* expired: fall through to the miss logic (refill if a slow tier) */
    }
    /* Slice/partial mode (LOCAL store): open() returns a partial object without a
     * whole-file fill, so the open call itself does not block. */
    if (st->policy.slice_size > 0
        && st->cstore.meta_mode == BRIX_CMETA_LOCAL)
    {
        return 0;
    }
    /* A miss: the inline open would run the whole-file fill. Offload iff a slow
     * tier is involved - a remote source read or a remote store write. */
    src_slow   = (brix_sd_caps(st->source) & BRIX_SD_CAP_FD) == 0;
    store_slow = (st->cstore.meta_mode != BRIX_CMETA_LOCAL);
    return (src_slow || store_slow) ? 1 : 0;
}

/* Run the whole-file fill for `key` (source -> cache store + cinfo) on the
 * CALLING thread - the worker-thread half of the offload. NGX_OK (cached),
 * NGX_DECLINED (admission declined - not cached), NGX_ERROR (fill failure).
 * Safe off the event loop: pure driver pread/pwrite + cstore ops, no nginx pool. */
ngx_int_t
brix_sd_cache_fill_key(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred)
{
    return brix_sd_cache_fill_key_ex(inst, key, cred, 0, NULL);
}

/* As brix_sd_cache_fill_key, but with the phase-92 store-then-evict passthrough
 * opt-in threaded through (see sd_cache_fill / sd_cache.h). When *out_pt is set
 * to 1 on an NGX_OK return, the object was filled ONLY under the passthrough
 * policy: the caller must evict `key` (brix_sd_cache_evict) after serving it. */
ngx_int_t
brix_sd_cache_fill_key_ex(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, int allow_pt, int *out_pt)
{
    if (out_pt != NULL) {
        *out_pt = 0;
    }
    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return sd_cache_fill(SD_CACHE_ST(inst), key, cred, allow_pt, out_pt);
}
