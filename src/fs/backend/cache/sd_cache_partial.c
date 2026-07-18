/*
 * sd_cache_partial.c — slice / partial-object caching (section 6.5).
 *
 * WHAT: The on-demand block-fill path: when policy.slice_size > 0 on a LOCAL
 *       posix cache store, an object is cached in fixed-size BLOCKS filled as
 *       reads touch them. Owns sd_cache_partial_open (build the partial-serve
 *       object) and the decorator's own byte slots reached only for such an
 *       object (pread range-fill, close, fstat, and the never-sendfile slot).
 *
 * WHY:  Split from sd_cache.c (phase-79) to keep every cache file under the
 *       ~500-line, one-concept-per-file cap. Slice mode is a self-contained
 *       strategy — a sparse cache fd, a present bitmap, and per-user credentials
 *       captured for deferred fills — reviewable apart from the whole-file fill
 *       spine (sd_cache_fill.c) and the vtable adapters (sd_cache.c).
 *
 * HOW:  A read range-fills only the blocks it touches (source pread -> cache
 *       pwrite -> cinfo present-bit) via brix_cstore_serve_pread's callback, so
 *       a Range request never pulls the whole object. The served object carries
 *       this state and ranges-fill on pread; it is never sendfiled (it may have
 *       holes). A fully-filled object's cinfo becomes COMPLETE and subsequent
 *       opens take the whole-file hit fast path. The five cross-called symbols
 *       (sd_cache_partial_open + the four byte slots) are non-static and reach
 *       sd_cache.c through sd_cache_internal.h. ZERO behaviour change.
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
brix_sd_obj_t *
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

ssize_t
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

ngx_int_t
sd_cache_close(brix_sd_obj_t *obj)
{
    sd_cache_partial_t *p = (obj != NULL) ? obj->state : NULL;

    if (p != NULL) {
        brix_sd_obj_release(p->src_obj);   /* close + free heap shell if any */
        if (p->cache_fd >= 0) {
            (void) close(p->cache_fd);
        }
        free(p->bitmap);
        free(p);
    }
    /* The shell is NOT freed here. driver->close releases the decorator state
     * (source obj + cache fd + bitmap) only; the malloc'd shell (heap_shell) is
     * owned by the caller that holds the object by pointer — brix_sd_obj_release()
     * and the VFS adopt-fail path both do `close(o); if (o->heap_shell) free(o);`,
     * and brix_vfs_adopt_obj() frees the original after copying it by value (and
     * zeroes heap_shell on the embedded copy). Freeing it here double-frees the
     * shell the moment this object is released by pointer or an adopt fails.
     */
    return NGX_OK;
}

ngx_int_t
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

ngx_fd_t
sd_cache_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) obj;
    (void) off;
    (void) len;
    (void) want_zerocopy;
    return NGX_INVALID_FILE;            /* a partial object is served via pread */
}
