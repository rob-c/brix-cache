/*
 * sd_cache_fill.c — the whole-file fill spine of the read-through cache.
 *
 * WHAT: Pulls a COMPLETE object from the wrapped source into the cache store and
 *       records its cinfo. Owns the four fill phases (acquire -> pump -> verify
 *       -> commit) and the sd_cache_fill orchestrator the interposed read-open
 *       and the async-offload entrypoint both drive.
 *
 * WHY:  Split from sd_cache.c (phase-79) to keep every cache file under the
 *       ~500-line, one-concept-per-file cap. The fill spine is the single path
 *       that populates the cache; isolating it keeps the origin-read / stale-serve
 *       / verify / cinfo-publish logic reviewable apart from the vtable adapters
 *       (sd_cache.c), the slice/partial machinery (sd_cache_partial.c), and the
 *       namespace/staged forwarders (sd_cache_forward.c).
 *
 * HOW:  cache_fill_acquire (source open + admission + staged fill-open) -> pump
 *       (origin read loop) -> verify (phase-68 cvmfs-cas) -> commit (publish +
 *       cinfo). sd_cache_fill is the only non-static symbol here; sd_cache.c
 *       reaches it (miss-serve and the async fill-key) through
 *       sd_cache_internal.h. The admission/policy + repo-metrics helpers it calls
 *       live in sd_cache_policy.c. ZERO behaviour change from the pre-split file.
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


/* Move granule for a miss-fill (driver-mediated pread/staged_write). */
#define SD_CACHE_CHUNK (1u << 20)


/* ---- the fill spine (source -> cache store) ------------------------------- */

/* Transient state threaded through the fill phases (acquire -> pump ->
 * verify -> commit). Owned by sd_cache_fill; each phase helper consumes or
 * releases the resources it is documented to on its own failure paths. */
typedef struct {
    brix_sd_obj_t      *so;        /* the open source object                  */
    brix_sd_staged_t   *staged;    /* the staged (uncommitted) store object   */
    brix_sd_stat_t      snap;      /* source size/mtime/mode snapshot         */
    u_char             *buf;       /* SD_CACHE_CHUNK move buffer              */
    off_t               off;       /* bytes pumped so far                     */
    int                 verified;  /* cvmfs-cas digest verified (phase-68)    */
    struct timespec     t0;        /* T16: per-upstream fill duration         */
} sd_cache_fill_state_t;

/* Acquire everything a fill needs: source object, stat snapshot, staged store
 * object, and the move buffer.
 *
 * WHAT: Opens the source for `key`, snapshots its stat, checks admission, and
 *       opens the staged cache-store object (which takes the fill lock — the
 *       O_EXCL + dead-owner-reclaim logic lives in the cstore layer, frozen).
 *
 * WHY:  The acquire phase concentrates all the "can this fill happen at all?"
 *       decisions so the pump/commit phases run against a fully-provisioned
 *       state and can stay linear.
 *
 * HOW:  brix_sd_open_maybe_cred so drivers with an open_cred slot use the
 *       per-user proxy. Returns NGX_OK (fs populated), NGX_DONE (stale copy
 *       served — caller reports success without filling), NGX_DECLINED
 *       (admission declined), or NGX_ERROR with errno set; every failure path
 *       releases whatever it had already acquired. */
static ngx_int_t
cache_fill_acquire(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, sd_cache_fill_state_t *fs)
{
    brix_sd_instance_t *src = st->source;
    mode_t              fmode;
    int                 err = 0;

    if (src->driver->open == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    fs->so = brix_sd_open_maybe_cred(src, key, BRIX_SD_O_READ, 0, cred, &err);
    if (fs->so == NULL) {
        if (sd_cache_stale_serve_ok(st, key)) {
            return NGX_DONE;            /* bounded stale-if-error (phase-68) */
        }
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    /* Every op on the OPEN OBJECT dispatches through so->driver, NOT src->driver:
     * a decorator source (sd_stage) legitimately returns the tier-below's object
     * from a read open ("read byte-I/O bypasses the decorator"), so the object's
     * vtable can differ from the instance's — dispatching object ops through the
     * instance vtable reinterprets a foreign object state (type confusion). */
    if (fs->so->driver->pread == NULL) {
        if (fs->so->driver->close != NULL) { fs->so->driver->close(fs->so); }
        errno = ENOSYS;
        return NGX_ERROR;
    }
    /* open() does not guarantee a populated snap (the posix driver fstats lazily),
     * so fstat the object for an accurate size/mtime/mode - the cinfo validity and
     * the cached file's permission bits both depend on it. */
    fs->snap = fs->so->snap;
    if (fs->so->driver->fstat != NULL) {
        (void) fs->so->driver->fstat(fs->so, &fs->snap);
    }
    /* SECURITY + correctness: the physical cache-store object is a svc-owned
     * artifact that aggregates MANY users' bytes under one tree. Per-user
     * authorization is enforced at the protocol gate (open_cache.c), and the
     * CLIENT-FACING mode is carried in the cinfo record and served by
     * sd_cache_stat() — decoupled from this physical mode. So force 0600:
     *   - owner rw is REQUIRED (XATTR meta_mode stores user.xrd.cinfo ON this
     *     object; Linux refuses user.* xattrs on a non-writable inode — a
     *     read-only 0444 source would otherwise block cinfo persistence, G3);
     *   - NO group/other bits, so a mapped low-priv uid cannot read another
     *     user's cached bytes by direct filesystem access (the source mode's
     *     0644 previously leaked here). snap.mode still reaches clients via the
     *     cinfo record (ci.mode below, served by sd_cache_stat). */
    fmode = S_IRUSR | S_IWUSR;          /* 0600 — svc-owned cache artifact */

    if (!sd_cache_admit(&st->policy, key, fs->snap.size)) {
        fs->so->driver->close(fs->so);
        return NGX_DECLINED;            /* too big / filtered - do not cache */
    }

    fs->staged = brix_cstore_fill_open(&st->cstore, key, fmode);
    if (fs->staged == NULL) {
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: fill_open on the cache store failed for \"%s\" - not cached",
            key);
        fs->so->driver->close(fs->so);
        return NGX_ERROR;
    }
    fs->buf = malloc(SD_CACHE_CHUNK);
    if (fs->buf == NULL) {
        brix_cstore_fill_abort(fs->staged);
        fs->so->driver->close(fs->so);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Pump the source object's bytes into the staged store object.
 *
 * WHAT: The origin read loop — pread from the source, fill_write to the staged
 *       object, chunk by chunk, advancing fs->off.
 *
 * WHY:  The pump is the fill's only long-running phase; isolating it keeps the
 *       read-error / stale-serve / errno-preservation logic in one place.
 *
 * HOW:  On success frees the move buffer and closes the source (the staged
 *       object stays open for verify/commit) and returns NGX_OK. On a read or
 *       write failure it releases EVERYTHING (buffer, staged fill, source) and
 *       returns NGX_DONE if a bounded stale copy can be served, else NGX_ERROR
 *       with the READ's errno preserved. */
static ngx_int_t
cache_fill_pump(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    for ( ;; ) {
        ssize_t r = fs->so->driver->pread(fs->so, fs->buf, SD_CACHE_CHUNK,
                                          fs->off);

        if (r < 0) {
            int read_err = errno;      /* capture BEFORE any cleanup call */

            if (read_err == EINTR) {
                continue;
            }
            free(fs->buf);
            brix_cstore_fill_abort(fs->staged);
            fs->so->driver->close(fs->so);
            if (sd_cache_stale_serve_ok(st, key)) {
                return NGX_DONE;        /* bounded stale-if-error (phase-68) */
            }
            /* Restore the READ's errno. sd_cache_stale_serve_ok() (and the
             * cleanup calls) stat the absent cache entry and leave errno
             * ENOENT — propagating that would make the fill layer classify a
             * merely-broken origin connection (EIO/ETIMEDOUT) as the origin's
             * definitive 404, turning a transient network fault into a
             * cached, client-poisoning "not found" instead of a retry. */
            errno = read_err;
            return NGX_ERROR;
        }
        if (r == 0) {
            break;
        }
        if (brix_cstore_fill_write(fs->staged, fs->buf, (size_t) r,
                                   fs->off) < 0)
        {
            free(fs->buf);
            brix_cstore_fill_abort(fs->staged);
            fs->so->driver->close(fs->so);
            return NGX_ERROR;
        }
        fs->off += r;
        if (fs->snap.size > 0 && fs->off >= fs->snap.size) {
            break;               /* size known: skip the EOF-probe round-trip */
        }
    }
    free(fs->buf);
    fs->buf = NULL;
    fs->so->driver->close(fs->so);
    fs->so = NULL;
    return NGX_OK;
}

/* Digest-verify the staged bytes before the commit publishes them.
 *
 * WHAT: phase-68 cvmfs-cas verification — the key names its own sha1, so the
 *       staged part can be checked with no origin digest.
 *
 * WHY:  A MISMATCH is quarantined for evidence and the fill fails (the client
 *       sees a gateway error and retries); an ERROR fails closed. Non-CAS keys
 *       (manifests) come back UNVERIFIED and commit as before.
 *
 * HOW:  No-op (NGX_OK) unless policy.verify is CVMFS_CAS. Sets fs->verified on
 *       a VERIFIED result. On failure aborts the staged fill and returns
 *       NGX_ERROR with errno EBADMSG (mismatch — T20 budgets retries) or EIO
 *       (verify could not run). */
static ngx_int_t
cache_fill_verify(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    const char                  *pp;
    brix_cache_verify_result_e   vr;

    fs->verified = 0;
    if (st->policy.verify != BRIX_CACHE_VERIFY_CVMFS_CAS) {
        return NGX_OK;
    }
    pp = (fs->staged->inst->driver->staged_path != NULL)
       ? fs->staged->inst->driver->staged_path(fs->staged) : NULL;
    vr = (pp != NULL)
       ? brix_cache_verify_cvmfs_cas(pp, key, st->log, NULL, NULL)
       : BRIX_CACHE_VERIFY_ERROR;
    if (vr == BRIX_CACHE_VERIFY_MISMATCH) {
        ngx_brix_cvmfs_repo_metrics_t *rm = sd_cache_repo_metrics(st, key);

        BRIX_CVMFS_METRIC_INC(verify_failures_total);
        if (rm != NULL) {
            BRIX_ATOMIC_INC(&rm->verify_failures_total);
        }
        sd_cache_note_origin_bytes(st, key, fs->off); /* WAN cost is WAN cost */
        /* a verify mismatch IS an upstream fill failure — the bytes came
         * from the origin but did not publish. */
        sd_cache_note_upstream(st, 0, fs->off, sd_cache_ms_since(&fs->t0));
        brix_cache_quarantine_part(pp, st->policy.quarantine_dir, st->log);
        brix_cstore_fill_abort(fs->staged);   /* part already renamed away */
        errno = EBADMSG;        /* digest mismatch — T20 budgets retries */
        return NGX_ERROR;
    }
    if (vr == BRIX_CACHE_VERIFY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, st->log, errno,
            "sd_cache: cvmfs-cas verify could not run for \"%s\" - "
            "failing the fill closed", key);
        brix_cstore_fill_abort(fs->staged);
        errno = EIO;
        return NGX_ERROR;
    }
    fs->verified = (vr == BRIX_CACHE_VERIFY_VERIFIED);
    return NGX_OK;
}

/* Publish the staged object and record its cinfo.
 *
 * WHAT: Accounts the upstream fill, commits (renames) the staged object into
 *       the store, and stores the whole-file COMPLETE cinfo built from the
 *       source stat snapshot (the fstat mode fix — origin perms in ci.mode).
 *
 * WHY:  The commit phase is the fill's publication point; everything before it
 *       is invisible to readers, so all bookkeeping that describes a
 *       SUCCESSFUL fill belongs here.
 *
 * HOW:  Whole-file COMPLETE cinfo (the 1 MiB granule keys validity; the present
 *       bitmap is all-set). A partial/slice fill is section 6.5 / SP2. A failed
 *       cinfo store is only a WARN — the object is cached but unrecorded, a
 *       safe miss (refill) next time. */
static ngx_int_t
cache_fill_commit(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    brix_cache_cinfo_t  ci;

    sd_cache_note_origin_bytes(st, key, fs->off);  /* WAN in, this attempt */
    sd_cache_note_upstream(st, 1, fs->off, sd_cache_ms_since(&fs->t0));

    if (brix_cstore_fill_commit(fs->staged) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&ci, sizeof(ci));
    ci.magic      = BRIX_CACHE_CINFO_MAGIC;
    ci.version    = BRIX_CACHE_CINFO_VERSION;
    ci.block_size = BRIX_CACHE_DIRTY_BLOCK;
    ci.size       = (uint64_t) fs->off;
    ci.mtime      = (uint64_t) fs->snap.mtime;
    ci.mode       = (uint32_t) (fs->snap.mode & 0777); /* origin perms — served back
                                                        * so a read-only source is not
                                                        * masked by the owner-writable
                                                        * physical store object. */
    ci.nblocks    = brix_cache_cinfo_nblocks((uint64_t) fs->off, ci.block_size);
    ci.flags      = BRIX_CINFO_F_COMPLETE
                  | (fs->verified ? BRIX_CINFO_F_VERIFIED : 0);
    ci.filled_at  = (uint64_t) time(NULL);
    if (st->policy.cvmfs_manifest_ttl > 0 && sd_cache_is_manifest_key(key)) {
        brix_cache_cinfo_set_expires(&ci,
            (time_t) ci.filled_at + st->policy.cvmfs_manifest_ttl);
    }

    if (brix_cstore_cinfo_store(&st->cstore, key, &ci) != NGX_OK) {
        /* The object is cached but unrecorded - a safe miss (refill) next time. */
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: cinfo store failed for \"%s\" - will refill on next read",
            key);
    }
    return NGX_OK;
}

/* Fill `key` from the source into the cache store and record its cinfo.
 *
 * WHAT: Pulls the object `key` from `st->source` into the cache store,
 *       building a whole-file cinfo on success.
 *
 * WHY:  The fill spine is the single path that populates the cache; threading
 *       the caller's per-user `cred` here ensures the source open uses the
 *       correct identity rather than the service credential.
 *
 * HOW:  acquire (source open + admission + staged fill-open) -> pump (origin
 *       read loop) -> verify (phase-68 cvmfs-cas) -> commit (publish + cinfo).
 *       NGX_DONE from acquire/pump means a bounded stale copy was served —
 *       reported as NGX_OK without caching. Returns NGX_OK (object cached +
 *       cinfo stored, or stale-served), NGX_DECLINED (policy declined), or
 *       NGX_ERROR (failure). */
ngx_int_t
sd_cache_fill(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred)
{
    sd_cache_fill_state_t  fs;
    ngx_int_t              rc;

    ngx_memzero(&fs, sizeof(fs));
    (void) clock_gettime(CLOCK_MONOTONIC, &fs.t0);

    rc = cache_fill_acquire(st, key, cred, &fs);
    if (rc == NGX_DONE) {
        return NGX_OK;                  /* bounded stale-if-error (phase-68) */
    }
    if (rc != NGX_OK) {
        return rc;                      /* NGX_DECLINED or NGX_ERROR */
    }

    rc = cache_fill_pump(st, key, &fs);
    if (rc == NGX_DONE) {
        return NGX_OK;                  /* bounded stale-if-error (phase-68) */
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (cache_fill_verify(st, key, &fs) != NGX_OK) {
        return NGX_ERROR;
    }
    return cache_fill_commit(st, key, &fs);
}
