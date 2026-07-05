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

/* Fill `key` from the source into the cache store and record its cinfo. Returns
 * NGX_OK (object cached + cinfo stored), NGX_DECLINED (policy declined to cache it
 * - serve from source), or NGX_ERROR (a fill failure - serve from source). */
static ngx_int_t
sd_cache_fill(sd_cache_inst_state *st, const char *key)
{
    brix_sd_instance_t *src = st->source;
    brix_sd_obj_t      *so;
    brix_sd_staged_t   *staged;
    brix_sd_stat_t      snap;
    u_char               *buf;
    off_t                 off = 0;
    int                   err = 0;
    int                   verified;
    mode_t                fmode;
    brix_cache_cinfo_t  ci;
    struct timespec       fill_t0;       /* T16: per-upstream fill duration    */

    (void) clock_gettime(CLOCK_MONOTONIC, &fill_t0);

    if (src->driver->open == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    so = src->driver->open(src, key, BRIX_SD_O_READ, 0, &err);
    if (so == NULL) {
        if (sd_cache_stale_serve_ok(st, key)) {
            return NGX_OK;              /* bounded stale-if-error (phase-68) */
        }
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    /* Every op on the OPEN OBJECT dispatches through so->driver, NOT src->driver:
     * a decorator source (sd_stage) legitimately returns the tier-below's object
     * from a read open ("read byte-I/O bypasses the decorator"), so the object's
     * vtable can differ from the instance's — dispatching object ops through the
     * instance vtable reinterprets a foreign object state (type confusion). */
    if (so->driver->pread == NULL) {
        if (so->driver->close != NULL) { so->driver->close(so); }
        errno = ENOSYS;
        return NGX_ERROR;
    }
    /* open() does not guarantee a populated snap (the posix driver fstats lazily),
     * so fstat the object for an accurate size/mtime/mode - the cinfo validity and
     * the cached file's permission bits both depend on it. */
    snap = so->snap;
    if (so->driver->fstat != NULL) {
        (void) so->driver->fstat(so, &snap);
    }
    /* The cache STORE object must stay owner-writable: in XATTR meta_mode the
     * cinfo record lives as a user.xrd.cinfo xattr ON this object, and Linux
     * refuses to set/update a user.* xattr on a non-writable inode — so a
     * read-only (e.g. 0444) source mode would block cinfo persistence entirely
     * (the remote-store restart-survival path, G3). The physical store mode is a
     * cache-implementation detail; force owner rw and keep the rest of the source
     * bits. (Client-facing mode fidelity for a read-only source is a follow-up:
     * carry the mode in the cinfo record and serve that.) */
    fmode = ((mode_t) (snap.mode & 0777)) | S_IRUSR | S_IWUSR;
    if (fmode == 0) {
        fmode = 0644;                   /* backend reported none - sane default */
    }

    if (!sd_cache_admit(&st->policy, key, snap.size)) {
        so->driver->close(so);
        return NGX_DECLINED;            /* too big / filtered - do not cache */
    }

    staged = brix_cstore_fill_open(&st->cstore, key, fmode);
    if (staged == NULL) {
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: fill_open on the cache store failed for \"%s\" - not cached",
            key);
        so->driver->close(so);
        return NGX_ERROR;
    }
    buf = malloc(SD_CACHE_CHUNK);
    if (buf == NULL) {
        brix_cstore_fill_abort(staged);
        so->driver->close(so);
        errno = ENOMEM;
        return NGX_ERROR;
    }

    for ( ;; ) {
        ssize_t r = so->driver->pread(so, buf, SD_CACHE_CHUNK, off);

        if (r < 0) {
            int read_err = errno;      /* capture BEFORE any cleanup call */

            if (read_err == EINTR) {
                continue;
            }
            free(buf);
            brix_cstore_fill_abort(staged);
            so->driver->close(so);
            if (sd_cache_stale_serve_ok(st, key)) {
                return NGX_OK;          /* bounded stale-if-error (phase-68) */
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
        if (brix_cstore_fill_write(staged, buf, (size_t) r, off) < 0) {
            free(buf);
            brix_cstore_fill_abort(staged);
            so->driver->close(so);
            return NGX_ERROR;
        }
        off += r;
        if (snap.size > 0 && off >= snap.size) {
            break;               /* size known: skip the EOF-probe round-trip */
        }
    }
    free(buf);
    so->driver->close(so);

    /* phase-68: digest-verify the staged bytes BEFORE the commit publishes
     * them (cvmfs-cas: the key names its own sha1 — no origin digest). A
     * MISMATCH is quarantined for evidence and the fill fails (the client
     * sees a gateway error and retries); an ERROR fails closed. Non-CAS keys
     * (manifests) come back UNVERIFIED and commit as before. */
    verified = 0;
    if (st->policy.verify == BRIX_CACHE_VERIFY_CVMFS_CAS) {
        const char *pp = (staged->inst->driver->staged_path != NULL)
                       ? staged->inst->driver->staged_path(staged) : NULL;
        brix_cache_verify_result_e vr;

        vr = (pp != NULL)
           ? brix_cache_verify_cvmfs_cas(pp, key, st->log, NULL, NULL)
           : BRIX_CACHE_VERIFY_ERROR;
        if (vr == BRIX_CACHE_VERIFY_MISMATCH) {
            ngx_brix_cvmfs_repo_metrics_t *rm = sd_cache_repo_metrics(st,
                                                                        key);

            BRIX_CVMFS_METRIC_INC(verify_failures_total);
            if (rm != NULL) {
                BRIX_ATOMIC_INC(&rm->verify_failures_total);
            }
            sd_cache_note_origin_bytes(st, key, off); /* WAN cost is WAN cost */
            /* a verify mismatch IS an upstream fill failure — the bytes came
             * from the origin but did not publish. */
            sd_cache_note_upstream(st, 0, off, sd_cache_ms_since(&fill_t0));
            brix_cache_quarantine_part(pp, st->policy.quarantine_dir,
                                         st->log);
            brix_cstore_fill_abort(staged);   /* part already renamed away */
            errno = EBADMSG;        /* digest mismatch — T20 budgets retries */
            return NGX_ERROR;
        }
        if (vr == BRIX_CACHE_VERIFY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, st->log, errno,
                "sd_cache: cvmfs-cas verify could not run for \"%s\" - "
                "failing the fill closed", key);
            brix_cstore_fill_abort(staged);
            errno = EIO;
            return NGX_ERROR;
        }
        verified = (vr == BRIX_CACHE_VERIFY_VERIFIED);
    }

    sd_cache_note_origin_bytes(st, key, off);  /* WAN in, this attempt */
    sd_cache_note_upstream(st, 1, off, sd_cache_ms_since(&fill_t0));

    if (brix_cstore_fill_commit(staged) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Whole-file COMPLETE cinfo (the 1 MiB granule keys validity; the present
     * bitmap is all-set). A partial/slice fill is section 6.5 / SP2. */
    ngx_memzero(&ci, sizeof(ci));
    ci.magic      = BRIX_CACHE_CINFO_MAGIC;
    ci.version    = BRIX_CACHE_CINFO_VERSION;
    ci.block_size = BRIX_CACHE_DIRTY_BLOCK;
    ci.size       = (uint64_t) off;
    ci.mtime      = (uint64_t) snap.mtime;
    ci.mode       = (uint32_t) (snap.mode & 0777);   /* origin perms — served back
                                                      * so a read-only source is not
                                                      * masked by the owner-writable
                                                      * physical store object. */
    ci.nblocks    = brix_cache_cinfo_nblocks((uint64_t) off, ci.block_size);
    ci.flags      = BRIX_CINFO_F_COMPLETE
                  | (verified ? BRIX_CINFO_F_VERIFIED : 0);
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
} sd_cache_partial_t;

/* Fetch block `blk` from the source into the cache object + mark it present. */
static int
sd_cache_fill_block(sd_cache_partial_t *p, uint64_t blk)
{
    off_t   bstart = (off_t) blk * p->block_size;
    size_t  blen;
    u_char *bbuf;
    off_t   got = 0;
    int     e = 0;

    if (bstart >= p->size) {
        return 0;
    }
    blen = (size_t) ((bstart + (off_t) p->block_size <= p->size)
                     ? p->block_size : (p->size - bstart));

    if (p->src_obj == NULL) {
        if (p->source->driver->open == NULL) {
            errno = ENOSYS;
            return -1;
        }
        p->src_obj = p->source->driver->open(p->source, p->key, BRIX_SD_O_READ,
                                             0, &e);
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
    }
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
    {
        off_t w = 0;

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
    }
    free(bbuf);

    (void) brix_cache_cinfo_record_block(p->cache_path, (uint64_t) p->size,
                                           p->block_size, p->mtime, p->mode, blk,
                                           p->log);
    if (p->bitmap != NULL && blk < p->nblocks) {
        brix_cache_cinfo_mark_block(p->bitmap, blk);
    }
    return 0;
}

/* Open a partial-serve object for `key` (slice mode). NULL + *err_out on failure. */
static brix_sd_obj_t *
sd_cache_partial_open(brix_sd_instance_t *inst, sd_cache_inst_state *st,
    const char *key, int *err_out)
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
    /* Force owner rw: the partial object is re-opened O_RDWR for every incremental
     * block fill, so a read-only (0444) source mode would make the SECOND open fail
     * EACCES and silently fall back to a whole-file fill (§6.5 sparse lost). The
     * origin perms are carried in the cinfo and served back (see the READ hit). */
    fd = brix_cstore_partial_open(&st->cstore, key,
                                   ((mode_t) (snap.mode & 0777)) | S_IRUSR | S_IWUSR,
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

    /* Adopt a previously-recorded present bitmap (an earlier partial fill) when it
     * matches this object's geometry; otherwise start all-absent. */
    {
        brix_cache_cinfo_t  hdr;
        uint8_t              *bm = NULL;
        size_t                bl = 0;

        if (brix_cache_cinfo_load(cpath, &hdr, &bm, &bl) == NGX_OK
            && bl == p->bitmap_len && hdr.size == (uint64_t) snap.size
            && hdr.block_size == bs)
        {
            p->bitmap = bm;
        } else {
            free(bm);
            p->bitmap = (p->bitmap_len > 0) ? calloc(1, p->bitmap_len) : NULL;
        }
    }

    o->driver     = inst->driver;       /* our pread/close/fstat range-fill */
    o->inst       = inst;
    o->fd         = NGX_INVALID_FILE;    /* a partial object is never sendfiled */
    o->snap       = snap;
    o->state      = p;
    o->heap_shell = 1;
    return o;
}

/* ---- the interposed read/write open --------------------------------------- */

static brix_sd_obj_t *
sd_cache_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *src = st->source;
    brix_cache_cinfo_t  ci;
    brix_sd_obj_t      *obj;

    /* WRITE / CREATE / TRUNC: pass through and invalidate the cached copy. */
    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC)) {
        obj = src->driver->open(src, path, sd_flags, mode, err_out);
        if (obj != NULL) {
            (void) brix_cstore_evict(&st->cstore, path);
        }
        return obj;
    }

    /* READ: a COMPLETE cinfo is an authoritative hit (freshness is checked at fill
     * time via verify, not on every read - section 6.4). */
    if (brix_cstore_cinfo_load(&st->cstore, path, &ci) == NGX_OK
        && (ci.flags & BRIX_CINFO_F_COMPLETE))
    {
        obj = brix_cstore_serve_open(&st->cstore, path, err_out);
        if (obj != NULL) {
            /* Present the ORIGIN perms recorded in the cinfo, not the physical
             * store object's bits (which are forced owner-writable so the cinfo
             * xattr can be maintained). A cached object is a regular file; 0 =
             * pre-mode cinfo → keep the store bits (snap left untouched). */
            if (ci.mode != 0) {
                obj->snap.mode = (mode_t) S_IFREG | (mode_t) (ci.mode & 0777);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: hit \"%s\"", path);
            return obj;
        }
        /* the cached object vanished under us - fall through to refill */
    }

    /* Path-filtered out: serve straight from the source, never cache. */
    if (!sd_cache_admit(&st->policy, path, -1)) {
        return src->driver->open(src, path, sd_flags, mode, err_out);
    }

    /* Nearline (tape) source: a miss is an async recall the open parks on
     * (section 9.2). The waiter that parks/wakes the open lands with the frm
     * driver (SP4/SP5); until then a NEARLINE source cannot be served here, so
     * fail soft with EAGAIN rather than block. */
    if ((brix_sd_caps(src) & BRIX_SD_CAP_NEARLINE) != 0
        && src->driver->recall != NULL)
    {
        char      reqid[40];
        ngx_int_t rr = src->driver->recall(src, path, reqid);

        if (rr == NGX_AGAIN) {
            /* Recall in flight: the open "parks" as EAGAIN. The HTTP plane answers
             * 202 "staging" + Retry-After; a retry re-polls the recall and, once
             * the MSS brings the object online, takes the normal miss-fill below
             * (tape -> cache store) and serves (SP5 §9.2). */
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: nearline recall of \"%s\" in flight (staging)", path);
            if (err_out != NULL) {
                *err_out = EAGAIN;
            }
            return NULL;
        }
        /* NGX_OK: already online - fall through to a normal fill. */
    }

    /* Slice/partial caching: a non-default slice_size on a LOCAL cache store fills
     * on demand (section 6.5) instead of pulling the whole object. A miss or a
     * PARTIAL cinfo both take this path; a COMPLETE object was already served above. */
    if (st->policy.slice_size > 0
        && st->cstore.meta_mode == BRIX_CMETA_LOCAL)
    {
        obj = sd_cache_partial_open(inst, st, path, err_out);
        if (obj != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: partial-serve \"%s\"", path);
            return obj;
        }
        /* partial open failed - fall through to a whole-file fill / source read */
    }

    /* MISS: fill from the source, then serve the cached copy. */
    if (sd_cache_fill(st, path) == NGX_OK) {
        obj = brix_cstore_serve_open(&st->cstore, path, err_out);
        if (obj != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                "sd_cache: filled \"%s\"", path);
            return obj;
        }
    }

    /* Declined or failed: serve from the source (a sick cache never fails a read,
     * section 16). */
    return src->driver->open(src, path, sd_flags, mode, err_out);
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
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY
                 | BRIX_SD_CAP_DIRS,
    .open             = sd_cache_open,
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
    .staged_open   = sd_cache_staged_open,
    .staged_write  = sd_cache_staged_write,
    .staged_commit = sd_cache_staged_commit,
    .staged_abort  = sd_cache_staged_abort,
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
    return sd_cache_fill(SD_CACHE_ST(inst), key);
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
