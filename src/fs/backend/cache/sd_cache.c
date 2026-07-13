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
static ngx_int_t
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

/* ---- slice/partial caching (section 6.5) ----------------------------------
 * When policy.slice_size > 0 on a LOCAL posix cache store, an object is cached in
 * fixed-size BLOCKS filled on demand: a read range-fills only the blocks it
 * touches (source pread -> cache pwrite -> cinfo present-bit), so a Range request
 * never pulls the whole object. The served object carries this state and ranges-
 * fill on pread; it is never sendfiled (it may have holes). A fully-filled object's
 * cinfo becomes COMPLETE and subsequent opens take the whole-file hit fast path. */

typedef struct {
    brix_sd_instance_t *source;
    brix_sd_obj_t      *src_obj;          /* lazily opened on the first miss   */
    int                   cache_fd;         /* the RW (sparse) cache object      */
    off_t                 size;
    uint32_t              block_size;
    uint32_t              mode;             /* origin perm bits recorded in cinfo */
    uint64_t              mtime;
    uint64_t              nblocks;
    uint8_t              *bitmap;           /* present blocks (in-memory mirror) */
    size_t                bitmap_len;
    ngx_log_t            *log;
    char                  key[1024];
    char                  cache_path[PATH_MAX];   /* for cinfo record_block      */
    /* Per-user credential copies for deferred (range-fill) source opens.
     * A partial-fill block may be filled on a later pread after the request
     * context — and its brix_sd_cred_t — is gone; embedding NUL-terminated
     * copies here ensures later opens can still authenticate as the owner.
     * cred_proxy[0] == '\0' means no per-user credential (service cred). */
    char                  cred_proxy[1024];     /* x509_proxy path, or "" */
    char                  cred_key[128];        /* ucred key stem, or ""  */
    char                  cred_principal[512];  /* principal string, or "" */
} sd_cache_partial_t;

/* Lazily open the partial object's source for a deferred range-fill.
 *
 * WHAT: Ensures p->src_obj is an open, pread-capable source object, opening it
 *       on the first missing-block fill.
 *
 * WHY:  Block fills occur on pread calls after the request context is gone;
 *       the open must happen against the credential captured at partial-open
 *       time so the fill still authenticates as the original user.
 *
 * HOW:  Authenticate as the original user when a credential was captured at
 *       partial-open time; otherwise fall back to the service credential.
 *       The stack brix_sd_cred_t only needs x509_proxy/key/principal — the
 *       cred_dir/fallback_deny fields are not needed for a range-fill re-open
 *       (the proxy path was already resolved at object-open time).
 *       Returns 0 (src_obj usable) or -1 with errno set. */
static int
partial_source_ensure(sd_cache_partial_t *p)
{
    int e = 0;

    if (p->src_obj != NULL) {
        return 0;
    }
    if (p->source->driver->open == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (p->cred_proxy[0] != '\0') {
        brix_sd_cred_t rc;

        ngx_memzero(&rc, sizeof(rc));
        rc.x509_proxy = p->cred_proxy;
        rc.key        = p->cred_key;
        rc.principal  = p->cred_principal;
        p->src_obj = brix_sd_open_maybe_cred(p->source, p->key,
                                              BRIX_SD_O_READ, 0, &rc, &e);
    } else {
        p->src_obj = p->source->driver->open(p->source, p->key,
                                              BRIX_SD_O_READ, 0, &e);
    }
    if (p->src_obj == NULL) {
        errno = e ? e : EIO;
        return -1;
    }
    /* Object ops dispatch through the OBJECT's driver (a decorator source
     * returns the tier-below's object from a read open — see sd_cache_fill). */
    if (p->src_obj->driver->pread == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return 0;
}

/* Copy one block's bytes source -> sparse cache object.
 *
 * WHAT: preads [bstart, bstart+blen) from the open source object into a heap
 *       buffer and pwrites the bytes into the cache fd at the same offset.
 *
 * WHY:  The read and write retry loops (EINTR, short reads against a stale
 *       stat) are pure byte plumbing — separated from the block bookkeeping
 *       (cinfo record + bitmap mark) that publishes the block as present.
 *
 * HOW:  A short source read (r == 0 before blen) stops early and writes what
 *       was read — the block is still recorded present by the caller, matching
 *       the "short source vs stat" doctrine. Returns 0 or -1 with errno set. */
static int
partial_block_copy(sd_cache_partial_t *p, off_t bstart, size_t blen)
{
    u_char *bbuf;
    off_t   got = 0;
    off_t   w = 0;

    bbuf = malloc(blen);
    if (bbuf == NULL) {
        errno = ENOMEM;
        return -1;
    }
    while ((size_t) got < blen) {
        ssize_t r = p->src_obj->driver->pread(p->src_obj, bbuf + got,
                                              blen - (size_t) got, bstart + got);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            free(bbuf);
            return -1;
        }
        if (r == 0) {
            break;                          /* short source vs stat - stop */
        }
        got += r;
    }
    while (w < got) {
        ssize_t n = pwrite(p->cache_fd, bbuf + w, (size_t) (got - w),
                           bstart + w);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            free(bbuf);
            return -1;
        }
        w += n;
    }
    free(bbuf);
    return 0;
}

/* Fetch block `blk` from the source into the cache object + mark it present. */
static int
sd_cache_fill_block(sd_cache_partial_t *p, uint64_t blk)
{
    off_t   bstart = (off_t) blk * p->block_size;
    size_t  blen;

    if (bstart >= p->size) {
        return 0;
    }
    blen = (size_t) ((bstart + (off_t) p->block_size <= p->size)
                     ? p->block_size : (p->size - bstart));

    if (partial_source_ensure(p) != 0) {
        return -1;
    }
    if (partial_block_copy(p, bstart, blen) != 0) {
        return -1;
    }

    (void) brix_cache_cinfo_record_block(p->cache_path, (uint64_t) p->size,
                                           p->block_size, p->mtime, p->mode, blk,
                                           p->log);
    if (p->bitmap != NULL && blk < p->nblocks) {
        brix_cache_cinfo_mark_block(p->bitmap, blk);
    }
    return 0;
}

/* Capture the per-user credential for deferred block fills.
 *
 * WHAT: Copies x509_proxy/key/principal from `cred` into the partial state's
 *       embedded NUL-terminated buffers.
 *
 * WHY:  Block fills occur on pread calls after the request context — and its
 *       brix_sd_cred_t — is gone; capturing the resolved credential at open
 *       time ensures later fills authenticate as the original user rather
 *       than the service account.
 *
 * HOW:  Only copies when the proxy path is non-empty; otherwise cred_proxy
 *       stays '\0' (which triggers the service-credential path in
 *       partial_source_ensure). */
static void
partial_capture_cred(sd_cache_partial_t *p, const brix_sd_cred_t *cred)
{
    if (cred == NULL || cred->x509_proxy == NULL || cred->x509_proxy[0] == '\0') {
        return;
    }
    ngx_cpystrn((u_char *) p->cred_proxy, (u_char *) cred->x509_proxy,
                sizeof(p->cred_proxy));
    ngx_cpystrn((u_char *) p->cred_key,
                (u_char *) (cred->key ? cred->key : ""),
                sizeof(p->cred_key));
    ngx_cpystrn((u_char *) p->cred_principal,
                (u_char *) (cred->principal ? cred->principal : ""),
                sizeof(p->cred_principal));
}

/* Adopt or initialize the partial object's present bitmap.
 *
 * WHAT: Loads a previously-recorded present bitmap (an earlier partial fill)
 *       into p->bitmap when it matches this object's geometry; otherwise
 *       starts all-absent.
 *
 * WHY:  Re-opening a partially-filled object must not forget which blocks are
 *       already present — but a stale bitmap (size or block-size changed)
 *       would serve wrong bytes, so geometry mismatch discards it.
 *
 * HOW:  brix_cache_cinfo_load from the cache path; adopt only when the bitmap
 *       length, recorded size, and block size all match; otherwise free the
 *       loaded bitmap and calloc a zeroed one (NULL for an empty object). */
static void
partial_adopt_bitmap(sd_cache_partial_t *p, const char *cpath)
{
    brix_cache_cinfo_t  hdr;
    uint8_t            *bm = NULL;
    size_t              bl = 0;

    if (brix_cache_cinfo_load(cpath, &hdr, &bm, &bl) == NGX_OK
        && bl == p->bitmap_len && hdr.size == (uint64_t) p->size
        && hdr.block_size == p->block_size)
    {
        p->bitmap = bm;
        return;
    }
    free(bm);
    p->bitmap = (p->bitmap_len > 0) ? calloc(1, p->bitmap_len) : NULL;
}

/* Open a partial-serve object for `key` (slice mode).
 *
 * WHAT: Allocates and wires a sd_cache_partial_t for on-demand block fills from
 *       the source, recording the per-user credential for deferred re-opens.
 *
 * WHY:  Block fills occur on pread calls after the request context is gone;
 *       capturing the resolved credential at open time ensures later fills
 *       authenticate as the original user rather than the service account.
 *
 * HOW:  Stats the source, opens the sparse cache object (0600, see below),
 *       wires the partial state (geometry + credential + present bitmap via
 *       partial_capture_cred / partial_adopt_bitmap), and returns a heap
 *       object shell whose driver is this decorator (range-fill pread).
 *       Returns the new object, or NULL with *err_out set on failure. */
static brix_sd_obj_t *
sd_cache_partial_open(brix_sd_instance_t *inst, sd_cache_inst_state *st,
    const char *key, const brix_sd_cred_t *cred, int *err_out)
{
    brix_sd_instance_t *src = st->source;
    brix_sd_stat_t      snap;
    sd_cache_partial_t   *p;
    brix_sd_obj_t      *o;
    char                  cpath[PATH_MAX];
    uint32_t              bs;
    int                   fd;

    if (src->driver->stat == NULL
        || src->driver->stat(src, key, &snap) != NGX_OK)
    {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    bs = (uint32_t) st->policy.slice_size;
    /* Force owner rw ONLY (0600): the partial object is re-opened O_RDWR for every
     * incremental block fill (a read-only 0444 source would EACCES the second open
     * and silently fall back to a whole-file fill, §6.5). SECURITY: no group/other
     * bits — this svc-owned cache artifact must not be directly readable by a mapped
     * low-priv uid. The origin perms are carried in the cinfo and served back to
     * clients (see sd_cache_stat / the READ hit), decoupled from this physical mode. */
    fd = brix_cstore_partial_open(&st->cstore, key,
                                   (mode_t) (S_IRUSR | S_IWUSR),
                                   snap.size, cpath, sizeof(cpath));
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    p = calloc(1, sizeof(*p));
    o = calloc(1, sizeof(*o));
    if (p == NULL || o == NULL) {
        (void) close(fd);
        free(p);
        free(o);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    p->source     = src;
    p->cache_fd   = fd;
    p->size       = snap.size;
    p->block_size = bs;
    p->mode       = (uint32_t) (snap.mode & 0777);   /* origin perms → cinfo */
    p->mtime      = (uint64_t) snap.mtime;
    p->nblocks    = brix_cache_cinfo_nblocks((uint64_t) snap.size, bs);
    p->bitmap_len = brix_cache_cinfo_bitmap_len(p->nblocks);
    p->log        = st->log;
    ngx_cpystrn((u_char *) p->key, (u_char *) key, sizeof(p->key));
    ngx_cpystrn((u_char *) p->cache_path, (u_char *) cpath, sizeof(p->cache_path));

    partial_capture_cred(p, cred);
    partial_adopt_bitmap(p, cpath);

    o->driver     = inst->driver;       /* our pread/close/fstat range-fill */
    o->inst       = inst;
    o->fd         = NGX_INVALID_FILE;    /* a partial object is never sendfiled */
    o->snap       = snap;
    o->state      = p;
    o->heap_shell = 1;
    return o;
}

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

/* ---- namespace / xattr / dir forwarders (delegate to the source) ---------- */

static ngx_int_t
sd_cache_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s  = SD_CACHE_SRC(inst);
    brix_cache_cinfo_t  ci;

    /* A COMPLETE cached object answers stat from its cinfo — the same
     * authoritative-hit doctrine as open() (section 6.4), and it keeps a stat of
     * a warm object off the source (a remote source would otherwise take a
     * blocking wire round-trip on the caller's thread — the event loop for the
     * kXR_open pre-flight probe). A miss/partial falls through to the source. */
    if (brix_cstore_cinfo_load(&st->cstore, path, &ci) == NGX_OK
        && (ci.flags & BRIX_CINFO_F_COMPLETE))
    {
        ngx_memzero(out, sizeof(*out));
        out->size   = (off_t) ci.size;
        out->mtime  = (time_t) ci.mtime;
        out->ctime  = (time_t) ci.mtime;
        out->mode   = (mode_t) S_IFREG
                    | (mode_t) ((ci.mode != 0) ? (ci.mode & 0777) : 0644);
        out->is_reg = 1;
        return NGX_OK;
    }

    return s->driver->stat ? s->driver->stat(s, path, out) : NGX_ERROR;
}

static ngx_int_t
sd_cache_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;
    ngx_int_t             rc;

    rc = s->driver->unlink ? s->driver->unlink(s, path, is_dir) : NGX_ERROR;
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, path);
    }
    return rc;
}

static ngx_int_t
sd_cache_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->mkdir ? s->driver->mkdir(s, path, mode) : NGX_ERROR;
}

static ngx_int_t
sd_cache_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;
    ngx_int_t             rc;

    rc = s->driver->rename ? s->driver->rename(s, src, dst, noreplace)
                           : NGX_ERROR;
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, src);
        (void) brix_cstore_evict(&st->cstore, dst);
    }
    return rc;
}

static ngx_int_t
sd_cache_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->server_copy ? s->driver->server_copy(s, src, dst, bytes_out)
                                  : NGX_ERROR;
}

static ngx_int_t
sd_cache_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->setattr ? s->driver->setattr(s, path, attr) : NGX_OK;
}

static brix_sd_dir_t *
sd_cache_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->opendir == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    return s->driver->opendir(s, path, err_out);    /* dir->inst = the source */
}

static ngx_int_t
sd_cache_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    /* The dir handle carries its owning (source) instance; dispatch through it. */
    return d->inst->driver->readdir ? d->inst->driver->readdir(d, out)
                                    : NGX_ERROR;
}

static ngx_int_t
sd_cache_closedir(brix_sd_dir_t *d)
{
    return d->inst->driver->closedir ? d->inst->driver->closedir(d) : NGX_ERROR;
}

static ssize_t
sd_cache_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->getxattr == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    return s->driver->getxattr(s, path, name, buf, cap);
}

static ssize_t
sd_cache_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->listxattr == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    return s->driver->listxattr(s, path, buf, cap);
}

static ngx_int_t
sd_cache_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->setxattr == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return s->driver->setxattr(s, path, name, val, len, flags);
}

static ngx_int_t
sd_cache_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->removexattr == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return s->driver->removexattr(s, path, name);
}

/* ---- staged write forwarders (the write path runs through the source) ----- */

static brix_sd_staged_t *
sd_cache_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;

    if (s->driver->staged_open == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    /* A staged publish replaces the object; drop any cached copy now. */
    (void) brix_cstore_evict(&st->cstore, final_path);
    return s->driver->staged_open(s, final_path, mode, err_out);
}

/* Credential-scoped staged_open: forwards the per-user cred into the source's
 * staged_open_cred slot when the source driver implements it.
 *
 * WHAT: Evicts any cached copy (a staged write is a replacement) and delegates
 *       to the source via brix_sd_staged_open_maybe_cred so the backend driver
 *       can authenticate as the requesting user for the staged upload.
 *
 * WHY:  Without this slot the cache decorator drops the credential on the floor
 *       when a caller uses brix_sd_staged_open_maybe_cred against it.
 *
 * HOW:  Evict → brix_sd_staged_open_maybe_cred (cred forwarded to source). */
static brix_sd_staged_t *
sd_cache_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;

    if (s->driver->staged_open == NULL && s->driver->staged_open_cred == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    (void) brix_cstore_evict(&st->cstore, final_path);
    return brix_sd_staged_open_maybe_cred(s, final_path, mode, cred, err_out);
}

static ssize_t
sd_cache_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    return st->inst->driver->staged_write
         ? st->inst->driver->staged_write(st, buf, len, off) : -1;
}

static ngx_int_t
sd_cache_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    return st->inst->driver->staged_commit
         ? st->inst->driver->staged_commit(st, noreplace) : NGX_ERROR;
}

static void
sd_cache_staged_abort(brix_sd_staged_t *st)
{
    if (st->inst->driver->staged_abort != NULL) {
        st->inst->driver->staged_abort(st);
    }
}

/* ---- partial-object byte slots (reached only for a slice partial object, whose
 * driver is this decorator; whole-file hits return store/source objects that carry
 * their own driver, so these are never called for them) ---- */

/* cstore fill callback: fill one missing block of this partial object from the
 * source. The decorator owns the source, so cstore's serve loop calls back here. */
static int
sd_cache_fill_block_cb(void *ctx, uint64_t blk)
{
    return sd_cache_fill_block((sd_cache_partial_t *) ctx, blk);
}

static ssize_t
sd_cache_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_cache_partial_t *p = obj->state;

    if (p == NULL) {
        errno = EBADF;
        return -1;
    }
    /* The bitmap-consult + range-serve loop lives in cstore (section 6.5); this
     * decorator only supplies the source-fill callback for a missing block. */
    return brix_cstore_serve_pread(p->cache_fd, p->bitmap, p->nblocks,
        p->block_size, (off_t) p->size, buf, len, off, sd_cache_fill_block_cb, p);
}

static ngx_int_t
sd_cache_close(brix_sd_obj_t *obj)
{
    sd_cache_partial_t *p = (obj != NULL) ? obj->state : NULL;

    if (p != NULL) {
        if (p->src_obj != NULL && p->src_obj->driver->close != NULL) {
            p->src_obj->driver->close(p->src_obj);   /* object's own vtable */
        }
        if (p->cache_fd >= 0) {
            (void) close(p->cache_fd);
        }
        free(p->bitmap);
        free(p);
    }
    if (obj != NULL && obj->heap_shell) {
        free(obj);
    }
    return NGX_OK;
}

static ngx_int_t
sd_cache_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_cache_partial_t *p = obj->state;

    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = p->size;
    out->mtime  = (time_t) p->mtime;
    out->mode   = obj->snap.mode ? obj->snap.mode : (S_IFREG | 0644);
    out->is_reg = 1;
    return NGX_OK;
}

static ngx_fd_t
sd_cache_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) obj;
    (void) off;
    (void) len;
    (void) want_zerocopy;
    return NGX_INVALID_FILE;            /* a partial object is served via pread */
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
