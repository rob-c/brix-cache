/*
 * sd_cache.c - the generic read-cache decorator (section 12.1). See header.
 *
 * The decorator forwards every write / namespace / xattr / dir / staged op to the
 * wrapped `source` and interposes only the READ-open path: a COMPLETE cached
 * object is served from the cache store (cstore), a miss is filled from the source
 * into the store and recorded in a cinfo, and a write invalidates the cached copy.
 * Served read objects are the store's own objects, so byte I/O bypasses the
 * decorator. A sick cache degrades to a source read - it never fails a read or
 * serves wrong bytes (section 16).
 *
 * This file owns the interposed read-open decision tree, the driver vtable, the
 * create/destroy lifecycle, and the async-fill offload seam. The pieces it drives
 * live in three siblings after the phase-79 size split (all reached through
 * sd_cache_internal.h): the whole-file fill spine (sd_cache_fill.c), the
 * slice/partial machinery + partial byte slots (sd_cache_partial.c), and the
 * namespace/xattr/dir/staged-write forwarders (sd_cache_forward.c).
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "sd_cache_policy.h"      /* admission + repo-metrics (split out) */
#include "protocols/cvmfs/classify.h"   /* phase-68 manifest-TTL stamping */
#include "observability/metrics/metrics.h"        /* phase-68 T16 counters */
#include "observability/metrics/metrics_macros.h"
#include "fs/cache/cstore.h"
#include "fs/backend/http/sd_http.h"    /* per-upstream fill attribution     */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* ---- the interposed read/write open --------------------------------------- */

/* The caller's open request, packed so the shared open path and its helpers
 * take one descriptor instead of a flags/mode/cred parameter triple. */
typedef struct {
    int                    sd_flags;
    mode_t                 mode;
    const brix_sd_cred_t  *cred;      /* NULL = service-credential path */
} sd_cache_open_req_t;

/* Serve a COMPLETE cached object for `path`, if one exists.
 *
 * WHAT: The authoritative-hit fast path — a COMPLETE cinfo serves straight
 *       from the cache store (freshness is checked at fill time via verify,
 *       not on every read - section 6.4).
 *
 * WHY:  Splitting the hit decision from the miss machinery keeps the open
 *       decision tree flat: the caller falls through to the miss path on any
 *       NULL (no cinfo, not COMPLETE, or the object vanished under us).
 *
 * HOW:  cinfo load + COMPLETE check, then brix_cstore_serve_open. Presents the
 *       ORIGIN perms recorded in the cinfo, not the physical store object's
 *       bits (which are forced owner-writable so the cinfo xattr can be
 *       maintained). A cached object is a regular file; 0 = pre-mode cinfo →
 *       keep the store bits (snap left untouched). */
static brix_sd_obj_t *
cache_open_serve_hit(sd_cache_inst_state *st, const char *path, int *err_out)
{
    brix_cache_cinfo_t  ci;
    brix_sd_obj_t      *obj;

    if (brix_cstore_cinfo_load(&st->cstore, path, &ci) != NGX_OK
        || !(ci.flags & BRIX_CINFO_F_COMPLETE))
    {
        return NULL;
    }
    /* §4.3 uvkeep (upstream pfc.uvkeep): don't trust a NEVER-verified entry
     * forever. When armed, a COMPLETE entry whose contents were never checked
     * against the origin digest (F_VERIFIED clear — e.g. a TLS-trusted fill with
     * no checksum to compare) and that is older than the keep window is treated
     * as a MISS, so the next open revalidates it against the origin. A verified
     * entry, one still inside the window, or one with no recorded fill time
     * (legacy, filled_at == 0) serves normally. This only ADDS revalidation — it
     * never serves anything it would not already serve. */
    if (st->policy.uvkeep > 0
        && !(ci.flags & BRIX_CINFO_F_VERIFIED)
        && ci.filled_at != 0
        && (uint64_t) time(NULL) >= ci.filled_at + (uint64_t) st->policy.uvkeep)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
            "sd_cache: uvkeep revalidate — unverified aged entry \"%s\"", path);
        return NULL;
    }
    obj = brix_cstore_serve_open(&st->cstore, path, err_out);
    if (obj == NULL) {
        return NULL;   /* the cached object vanished under us - refill */
    }
    if (ci.mode != 0) {
        obj->snap.mode = (mode_t) S_IFREG | (mode_t) (ci.mode & 0777);
    }
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
        "sd_cache: hit \"%s\"", path);
    return obj;
}

/* Park the open on an in-flight nearline (tape) recall.
 *
 * WHAT: For a NEARLINE source, kicks the async recall for `path` and reports
 *       whether the open should park (fail soft with EAGAIN).
 *
 * WHY:  A nearline miss is an async recall the open must not block on
 *       (section 9.2): the recall runs through the stage engine, and the
 *       open fails soft with EAGAIN so the protocol plane can answer
 *       "staging, retry later" instead of stalling a worker.
 *
 * HOW:  Returns 1 (recall in flight — *err_out = EAGAIN; the HTTP plane
 *       answers 202 "staging" + Retry-After; a retry re-polls the recall and,
 *       once the MSS brings the object online, takes the normal miss-fill and
 *       serves, SP5 §9.2) or 0 (not nearline, or already online — proceed to
 *       a normal fill). */
static int
cache_open_recall_parked(sd_cache_inst_state *st, brix_sd_instance_t *src,
    const char *path, int *err_out)
{
    char      reqid[40];
    ngx_int_t rr;

    if ((brix_sd_caps(src) & BRIX_SD_CAP_NEARLINE) == 0
        || src->driver->recall == NULL)
    {
        return 0;
    }
    rr = src->driver->recall(src, path, reqid);
    if (rr != NGX_AGAIN) {
        return 0;      /* NGX_OK: already online - a normal fill follows */
    }
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
        "sd_cache: nearline recall of \"%s\" in flight (staging)", path);
    if (err_out != NULL) {
        *err_out = EAGAIN;
    }
    return 1;
}

/* Serve a cache MISS: partial-serve when slice mode applies, else fill+serve.
 *
 * WHAT: The miss half of the read-open decision — build a partial (on-demand
 *       block-fill) object in slice mode, or run the whole-file fill and serve
 *       the cached copy.
 *
 * WHY:  A miss or a PARTIAL cinfo both take the slice path (a COMPLETE object
 *       was already served by the hit helper); a non-default slice_size on a
 *       LOCAL cache store fills on demand (section 6.5) instead of pulling the
 *       whole object.
 *
 * HOW:  Each strategy falls through to the next on failure; NULL means the
 *       caller degrades to a plain source read (a sick cache never fails a
 *       read, section 16). */
static brix_sd_obj_t *
cache_open_miss_serve(brix_sd_instance_t *inst, sd_cache_inst_state *st,
    const char *path, const brix_sd_cred_t *cred, int *err_out)
{
    brix_sd_obj_t *obj;

    if (st->policy.slice_size > 0
        && st->cstore.meta_mode == BRIX_CMETA_LOCAL)
    {
        obj = sd_cache_partial_open(inst, st, path, cred, err_out);
        if (obj != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: partial-serve \"%s\"", path);
            return obj;
        }
        /* partial open failed - fall through to a whole-file fill / source read */
    }

    if (sd_cache_fill(st, path, cred, 0, NULL) == NGX_OK) {
        obj = brix_cstore_serve_open(&st->cstore, path, err_out);
        if (obj != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: filled \"%s\"", path);
            return obj;
        }
    }
    return NULL;
}

/* Common open implementation shared by sd_cache_open (no cred) and
 * sd_cache_open_cred (with cred).
 *
 * WHAT: The interposed read-open decision tree for the cache decorator.
 *
 * WHY:  Extracting the body into a common helper avoids duplicating the entire
 *       open logic across two vtable slots (plain and cred-scoped).
 *
 * HOW:  Write/create/trunc → passthrough + evict.  A COMPLETE hit → serve from
 *       the store (cache_open_serve_hit).  A miss → partial-serve or fill+serve
 *       (cache_open_miss_serve, cred threaded through to the source open).
 *       Failed or declined → degrade to the source.  rq->cred may be NULL
 *       (service-credential path). */
static brix_sd_obj_t *
sd_cache_open_common(brix_sd_instance_t *inst, const char *path,
    const sd_cache_open_req_t *rq, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t   *src = st->source;
    brix_sd_obj_t        *obj;

    /* A composed source always defines .open (brix_tier_build never yields a
     * driver without it), but guard uniformly with the fill/partial-open paths
     * (sd_cache_fill, sd_cache_partial_open) rather than relying on that alone. */
    if (src->driver->open == NULL) {
        if (err_out != NULL) { *err_out = ENOSYS; }
        errno = ENOSYS;
        return NULL;
    }

    /* WRITE / CREATE / TRUNC: pass through and invalidate the cached copy.
     * The evicted size is stamped on the obj so the protocol adopt site can
     * account it (the decorator has no request context here). */
    if (rq->sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC)) {
        obj = brix_sd_open_maybe_cred(src, path, rq->sd_flags, rq->mode,
                                      rq->cred, err_out);
        if (obj != NULL) {
            obj->cache_evicted_bytes =
                brix_cstore_evict_sized(&st->cstore, path);
        }
        return obj;
    }

    /* READ: a COMPLETE cinfo is an authoritative hit. */
    obj = cache_open_serve_hit(st, path, err_out);
    if (obj != NULL) {
        obj->cache_outcome = BRIX_SD_CACHE_OUTCOME_HIT;
        return obj;
    }

    /* Cache-only serving (audit §4.4, upstream pfc.onlyifcached): the hit test
     * above already failed, so this read would have to reach the origin. Refuse
     * it as ENOENT instead — a client seeing "not here" fails over to another
     * replica, which is the whole point of the mode: this node contributes only
     * what it already holds and never becomes an origin puller.
     *
     * Placed AFTER the hit test (a cached object still serves) and BEFORE both
     * the admission filter and the fill paths — otherwise an admission-declined
     * or nearline path would quietly reach the source anyway, which is the exact
     * bypass the mode exists to prevent. */
    if (st->policy.only_if_cached) {
        if (err_out != NULL) { *err_out = ENOENT; }
        errno = ENOENT;
        return NULL;
    }

    /* Path-filtered out: serve straight from the source, never cache. */
    if (!sd_cache_admit(&st->policy, path, -1)) {
        return brix_sd_open_maybe_cred(src, path, rq->sd_flags, rq->mode,
                                       rq->cred, err_out);
    }

    /* Nearline (tape) source: park the open on an in-flight recall (§9.2). */
    if (cache_open_recall_parked(st, src, path, err_out)) {
        return NULL;
    }

    /* MISS: partial-serve (slice mode) or fill from the source + serve. */
    obj = cache_open_miss_serve(inst, st, path, rq->cred, err_out);
    if (obj != NULL) {
        obj->cache_outcome = BRIX_SD_CACHE_OUTCOME_MISS;
        return obj;
    }

    /* Declined or failed: serve from the source (a sick cache never fails a read,
     * section 16).  Still a MISS — the cache was consulted and could not serve. */
    obj = brix_sd_open_maybe_cred(src, path, rq->sd_flags, rq->mode,
                                  rq->cred, err_out);
    if (obj != NULL) {
        obj->cache_outcome = BRIX_SD_CACHE_OUTCOME_MISS;
    }
    return obj;
}

/* Plain open slot (service credential / no per-user cred). */
static brix_sd_obj_t *
sd_cache_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_cache_open_req_t rq = { sd_flags, mode, NULL };

    return sd_cache_open_common(inst, path, &rq, err_out);
}

/* Credential-scoped open slot (per-user backend auth).
 *
 * WHAT: Forwards the caller's per-user brix_sd_cred_t into sd_cache_open_common
 *       so all source opens within the cache decorator (fill, partial-fill, and
 *       passthrough) authenticate as the requesting user.
 *
 * WHY:  Without this slot the cache decorator silently drops the credential
 *       on the floor and opens the source under the service identity, breaking
 *       per-user quota and audit on credential-aware backends.
 *
 * HOW:  Delegates entirely to sd_cache_open_common with the supplied cred. */
static brix_sd_obj_t *
sd_cache_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_cache_open_req_t rq = { sd_flags, mode, cred };

    return sd_cache_open_common(inst, path, &rq, err_out);
}

/* The decorator advertises the namespace/write cap set; the served read object
 * carries the cache store's own byte caps (sendfile/fd), and write/namespace ops
 * forward to the source - so the cache is transport-transparent above the seam. */
static const brix_sd_driver_t brix_sd_cache_driver = {
    .name        = "cache",
    .caps        = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_XATTR_WRITE
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY
                 | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE,
    .open             = sd_cache_open,
    .open_cred        = sd_cache_open_cred,
    .close            = sd_cache_close,
    .pread            = sd_cache_pread,
    .read_advise      = sd_cache_read_advise,
    .fstat            = sd_cache_fstat,
    .read_sendfile_fd = sd_cache_read_sendfile_fd,
    .stat          = sd_cache_stat,
    .unlink        = sd_cache_unlink,
    .mkdir         = sd_cache_mkdir,
    .rename        = sd_cache_rename,
    .server_copy   = sd_cache_server_copy,
    .setattr       = sd_cache_setattr,
    .truncate_path = sd_cache_truncate_path,
    .space         = sd_cache_space,
    .opendir       = sd_cache_opendir,
    .readdir       = sd_cache_readdir,
    .closedir      = sd_cache_closedir,
    .getxattr      = sd_cache_getxattr,
    .listxattr     = sd_cache_listxattr,
    .setxattr      = sd_cache_setxattr,
    .removexattr   = sd_cache_removexattr,
    /* Credential-scoped twins: without them this decorator LOOKS like a driver
     * with no per-user support, and the tier above either refuses (deny mode) or
     * silently signs as the export. They add no policy of their own — each
     * re-dispatches through the source's own brix_sd_<op>_maybe_cred. */
    .stat_cred        = sd_cache_stat_cred,
    .unlink_cred      = sd_cache_unlink_cred,
    .mkdir_cred       = sd_cache_mkdir_cred,
    .rename_cred      = sd_cache_rename_cred,
    .server_copy_cred = sd_cache_server_copy_cred,
    .setattr_cred     = sd_cache_setattr_cred,
    .truncate_path_cred = sd_cache_truncate_path_cred,
    .opendir_cred     = sd_cache_opendir_cred,
    .getxattr_cred    = sd_cache_getxattr_cred,
    .listxattr_cred   = sd_cache_listxattr_cred,
    .setxattr_cred    = sd_cache_setxattr_cred,
    .removexattr_cred = sd_cache_removexattr_cred,
    .staged_open      = sd_cache_staged_open,
    .staged_open_cred = sd_cache_staged_open_cred,
    .staged_write     = sd_cache_staged_write,
    .staged_commit    = sd_cache_staged_commit,
    .staged_abort     = sd_cache_staged_abort,
};

brix_sd_instance_t *
brix_sd_cache_create(brix_sd_instance_t *source, brix_sd_instance_t *store,
    const brix_cache_policy_t *policy, const char *store_local_root,
    ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_cache_inst_state  *st;

    if (source == NULL || store == NULL || policy == NULL) {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    st   = calloc(1, sizeof(*st));
    if (inst == NULL || st == NULL) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    st->source = source;
    st->policy = *policy;
    st->log    = log;

    if (brix_cstore_init(&st->cstore, store, store_local_root,
                           policy->meta_mode, policy->l1_entries,
                           policy->batch_cinfo, log) != NGX_OK)
    {
        int e = errno;
        free(inst);
        free(st);
        errno = e ? e : EINVAL;
        return NULL;
    }

    if (policy->global_cas) {
        brix_cstore_enable_gcas(&st->cstore);   /* phase-87 G13 */
    }

    inst->driver = &brix_sd_cache_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = st;
    return inst;
}

void
brix_sd_cache_destroy(brix_sd_instance_t *inst)
{
    sd_cache_inst_state *st;

    if (inst == NULL) {
        return;
    }
    st = inst->state;
    if (st != NULL) {
        brix_cstore_cleanup(&st->cstore);
        free(st);
    }
    free(inst);
}

/* The identity predicate lives here because the driver vtable is static to
 * this TU; the caller-driven evict/cached-bytes probes and the SP2 async-fill
 * offload trio it gates live in sd_cache_maint.c. */
int
brix_sd_cache_instance_is(const brix_sd_instance_t *inst)
{
    return (inst != NULL && inst->driver == &brix_sd_cache_driver) ? 1 : 0;
}

/* The cache STORE instance (where served objects live), or NULL for a non-cache
 * instance. A read SERVE reads from the store, so the serve-locality predicate
 * (http_serve_offload.c) recurses into it. */
brix_sd_instance_t *
brix_sd_cache_store_instance(const brix_sd_instance_t *inst)
{
    return brix_sd_cache_instance_is(inst) ? SD_CACHE_ST(inst)->cstore.store
                                             : NULL;
}

/* The cache SOURCE instance (the tier BELOW the cache - a stage decorator or the
 * backend), or NULL for a non-cache instance. Lets a caller unwrap the composed
 * stack to reach the stage decorator (SP4 reconcile). */
brix_sd_instance_t *
brix_sd_cache_source_instance(const brix_sd_instance_t *inst)
{
    return brix_sd_cache_instance_is(inst) ? SD_CACHE_SRC(inst) : NULL;
}

/* The decorator's own cstore — the eviction/reaper enumerates + removes cached
 * objects through the SAME store adapter the read path fills into (§14a). Returned
 * void* (cast to brix_cstore_t* by the caller) to keep sd_cache.h off cstore.h. */
void *
brix_sd_cache_cstore(const brix_sd_instance_t *inst)
{
    return brix_sd_cache_instance_is(inst) ? &SD_CACHE_ST(inst)->cstore : NULL;
}

/* Attach/detach the OPTIONAL cold store tier (phase-85 F7). `cold` is BORROWED
 * (registry-owned, worker lifetime) so brix_sd_cache_destroy never frees it.
 * No-op for a non-cache instance. With a cold tier set, sd_cache_fill tries a
 * verified promote from it before the origin, and brix_sd_cache_demote (the
 * eviction seam) copies victims into it. */
void
brix_sd_cache_set_cold(brix_sd_instance_t *inst, brix_sd_instance_t *cold)
{
    if (brix_sd_cache_instance_is(inst)) {
        SD_CACHE_ST(inst)->cold = cold;
    }
}

/* Attach/detach the sibling-mesh ring (phase-85 F8). The member instances are
 * BORROWED (registry-owned, worker lifetime) so brix_sd_cache_destroy never
 * frees them. No-op for a non-cache instance; n == 0 (or an out-of-range self)
 * detaches. With a ring set, sd_cache_fill tries one verified fill from the
 * key's rendezvous-owning sibling before the origin. */
void
brix_sd_cache_set_peers(brix_sd_instance_t *inst,
    const brix_sd_cache_peer_t *peers, int n, int self)
{
    sd_cache_inst_state *st;
    int                  i;

    if (!brix_sd_cache_instance_is(inst)) {
        return;
    }
    st = SD_CACHE_ST(inst);
    if (peers == NULL || n <= 0 || n > BRIX_SD_CACHE_MAX_PEERS
        || self < 0 || self >= n)
    {
        st->n_peers = 0;
        return;
    }
    for (i = 0; i < n; i++) {
        st->peers[i] = peers[i];
    }
    st->n_peers   = n;
    st->peer_self = self;
}

/* Publish a swarm-built ring (phase-87 G12). Event loop only; the barrier
 * orders the ring's contents before the pointer store so a worker-thread
 * fill that loads the new pointer sees a fully built ring. */
void
brix_sd_cache_ring_swap(brix_sd_instance_t *inst,
    const brix_sd_cache_ring_t *ring)
{
    sd_cache_inst_state *st;

    if (!brix_sd_cache_instance_is(inst)) {
        return;
    }
    if (ring != NULL
        && (ring->n <= 0 || ring->n > BRIX_SD_CACHE_MAX_PEERS
            || ring->self < 0 || ring->self >= ring->n))
    {
        return;
    }
    st = SD_CACHE_ST(inst);
    ngx_memory_barrier();
    st->dyn_ring = ring;
}

int
brix_sd_cache_get_peers(const brix_sd_instance_t *inst,
    brix_sd_cache_peer_t *out, int *self)
{
    const sd_cache_inst_state *st;
    int                        i;

    if (!brix_sd_cache_instance_is(inst) || out == NULL || self == NULL) {
        return 0;
    }
    st = SD_CACHE_ST(inst);
    if (st->n_peers <= 0) {
        return 0;
    }
    for (i = 0; i < st->n_peers; i++) {
        out[i] = st->peers[i];
    }
    *self = st->peer_self;
    return st->n_peers;
}
