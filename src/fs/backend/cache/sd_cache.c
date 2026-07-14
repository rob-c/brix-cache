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
 * WHY:  A nearline miss is an async recall the open parks on (section 9.2).
 *       The waiter that parks/wakes the open lands with the frm driver
 *       (SP4/SP5); until then a NEARLINE source cannot be served here, so
 *       fail soft with EAGAIN rather than block.
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

    if (sd_cache_fill(st, path, cred) == NGX_OK) {
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

    /* WRITE / CREATE / TRUNC: pass through and invalidate the cached copy. */
    if (rq->sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC)) {
        obj = brix_sd_open_maybe_cred(src, path, rq->sd_flags, rq->mode,
                                      rq->cred, err_out);
        if (obj != NULL) {
            (void) brix_cstore_evict(&st->cstore, path);
        }
        return obj;
    }

    /* READ: a COMPLETE cinfo is an authoritative hit. */
    obj = cache_open_serve_hit(st, path, err_out);
    if (obj != NULL) {
        return obj;
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
        return obj;
    }

    /* Declined or failed: serve from the source (a sick cache never fails a read,
     * section 16). */
    return brix_sd_open_maybe_cred(src, path, rq->sd_flags, rq->mode,
                                   rq->cred, err_out);
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
    .fstat            = sd_cache_fstat,
    .read_sendfile_fd = sd_cache_read_sendfile_fd,
    .stat          = sd_cache_stat,
    .unlink        = sd_cache_unlink,
    .mkdir         = sd_cache_mkdir,
    .rename        = sd_cache_rename,
    .server_copy   = sd_cache_server_copy,
    .setattr       = sd_cache_setattr,
    .opendir       = sd_cache_opendir,
    .readdir       = sd_cache_readdir,
    .closedir      = sd_cache_closedir,
    .getxattr      = sd_cache_getxattr,
    .listxattr     = sd_cache_listxattr,
    .setxattr      = sd_cache_setxattr,
    .removexattr   = sd_cache_removexattr,
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

/* ---- async-fill seam (SP2 "shell -> full") --------------------------------
 * The decorator's open() runs the miss-fill INLINE - correct on a worker thread
 * (the stream fill task, a WebDAV/S3 PUT worker) but a stall on the event loop
 * when the fill reads a remote source or writes a remote store (a socket wire
 * client cannot do blocking I/O on the un-pumped loop; an in-process store just
 * freezes the worker for the transfer). The HTTP read plane therefore probes
 * whether an inline open would block, runs the fill on the thread pool, and
 * re-enters. These three entrypoints expose exactly that - without making the
 * SD open() contract asynchronous. See src/shared/http_cache_fill.c. */

int
brix_sd_cache_instance_is(const brix_sd_instance_t *inst)
{
    return (inst != NULL && inst->driver == &brix_sd_cache_driver) ? 1 : 0;
}

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
brix_sd_cache_fill_key(brix_sd_instance_t *inst, const char *key)
{
    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return sd_cache_fill(SD_CACHE_ST(inst), key, NULL);
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
