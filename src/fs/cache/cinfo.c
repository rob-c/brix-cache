/*
 * cinfo.c — block-present bitmap sidecar ("<cachefile>.cinfo"). See cinfo.h.
 *
 * The header is written/read verbatim (native byte order on the x86-64 target,
 * matching meta.c); the bitmap follows it on disk.  Block recording serialises
 * its read-modify-write with flock(2) so that concurrent slice-fill workers —
 * each completing a different window of the same file — never lose one another's
 * bits.  A torn or inconsistent sidecar is treated by the loader as "nothing
 * recorded" (NGX_DECLINED), so a crash mid-write is always safe: the affected
 * blocks merely look absent and are refetched.
 */

#include "cinfo.h"
#include "fs/meta/xmeta_path.h"      /* the shared raw-path record carrier */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/* pure helpers */
uint64_t
xrootd_cache_cinfo_nblocks(uint64_t size, uint32_t block_size)
{
    if (size == 0 || block_size == 0) {
        return 0;
    }
    return (size + block_size - 1) / block_size;
}

size_t
xrootd_cache_cinfo_bitmap_len(uint64_t nblocks)
{
    return (size_t) ((nblocks + 7) / 8);
}

void
xrootd_cache_cinfo_mark_block(uint8_t *bitmap, uint64_t blk)
{
    bitmap[blk >> 3] |= (uint8_t) (1u << (blk & 7u));
}

int
xrootd_cache_cinfo_block_present(const uint8_t *bitmap, uint64_t blk)
{
    return (bitmap[blk >> 3] >> (blk & 7u)) & 1u;
}

uint64_t
xrootd_cache_cinfo_present_count(const uint8_t *bitmap, uint64_t nblocks)
{
    uint64_t count = 0;
    uint64_t blk;

    for (blk = 0; blk < nblocks; blk++) {
        if (xrootd_cache_cinfo_block_present(bitmap, blk)) {
            count++;
        }
    }
    return count;
}

void
xrootd_cache_cinfo_refresh_flags(xrootd_cache_cinfo_t *hdr, const uint8_t *bitmap)
{
    uint64_t present;

    hdr->flags &= (uint16_t) ~(XROOTD_CINFO_F_COMPLETE | XROOTD_CINFO_F_PARTIAL);

    if (hdr->nblocks == 0) {
        hdr->flags |= XROOTD_CINFO_F_COMPLETE;   /* an empty file is trivially whole */
        return;
    }
    present = xrootd_cache_cinfo_present_count(bitmap, hdr->nblocks);
    if (present == hdr->nblocks) {
        hdr->flags |= XROOTD_CINFO_F_COMPLETE;
    } else if (present > 0) {
        hdr->flags |= XROOTD_CINFO_F_PARTIAL;
    }
}

/* sidecar path */
int
xrootd_cache_cinfo_path(char *dst, size_t dstsz, const char *cache_path)
{
    int n = snprintf(dst, dstsz, "%s.cinfo", cache_path);
    return (n < 0 || (size_t) n >= dstsz) ? -1 : 0;
}

/* ---- xmeta mapping (the cinfo struct stays the in-memory model) --------- */

ngx_int_t
xrootd_cache_cinfo_to_xmeta(const xrootd_cache_cinfo_t *hdr,
    const uint8_t *bitmap, size_t bitmap_len, xrootd_xmeta_t *m)
{
    uint32_t bs = hdr->block_size ? hdr->block_size : XROOTD_CACHE_DIRTY_BLOCK;
    size_t   need;

    if (xrootd_xmeta_init(m, (int64_t) hdr->size, (int64_t) bs)
        != XROOTD_XMETA_OK)
    {
        return NGX_ERROR;
    }
    m->have_blockcrc = 0;              /* block CRCs are CSI state (P3) */
    m->access_cnt    = hdr->access_count;
    if (hdr->last_access != 0 || hdr->bytes_served != 0) {
        m->astat_count       = 1;
        m->astat.attach_time = (int64_t) hdr->last_access;
        m->astat.detach_time = (int64_t) hdr->last_access;
        m->astat.bytes_hit   = (int64_t) hdr->bytes_served;
    }
    m->origin_mtime  = hdr->mtime;
    m->dirty_lo      = hdr->dirty_lo;
    m->dirty_hi      = hdr->dirty_hi;
    m->dirty_since   = hdr->dirty_since;
    m->flush_gen     = hdr->flush_gen;
    m->last_flush    = hdr->last_flush;
    m->bytes_flushed = hdr->bytes_flushed;
    m->expires_at    = hdr->expires_at;
    m->filled_at     = hdr->filled_at;
    m->mode          = hdr->mode;
    m->state_flags   =
        ((hdr->flags & XROOTD_CINFO_F_VERIFIED) ? XROOTD_XMETA_F_VERIFIED : 0u)
      | ((hdr->flags & XROOTD_CINFO_F_EXPIRES)  ? XROOTD_XMETA_F_EXPIRES  : 0u);
    /* Clamp the validity-string lengths at this boundary: a hand-built or
     * corrupted header must not be able to drive an over-long encode. */
    m->etag_len = (hdr->etag_len <= sizeof(hdr->etag)) ? hdr->etag_len : 0;
    ngx_memcpy(m->etag, hdr->etag, m->etag_len);
    m->cks_alg_len = (hdr->cks_alg_len <= sizeof(hdr->cks_alg))
                     ? hdr->cks_alg_len : 0;
    ngx_memcpy(m->cks_alg, hdr->cks_alg, m->cks_alg_len);
    m->cks_len = (hdr->cks_len <= sizeof(hdr->cks_hex)) ? hdr->cks_len : 0;
    ngx_memcpy(m->cks_hex, hdr->cks_hex, m->cks_len);

    /* Present bitmap: adopt the caller's when it covers this geometry;
     * otherwise synthesize whole-file state from the COMPLETE flag. */
    need = xrootd_cache_cinfo_bitmap_len(m->nblocks);
    if (bitmap != NULL && bitmap_len >= need && need > 0) {
        ngx_memcpy(m->bitmap, bitmap, need);
    } else if ((hdr->flags & XROOTD_CINFO_F_COMPLETE) && need > 0) {
        ngx_memset(m->bitmap, 0xFF, need);
    }
    return NGX_OK;
}

void
xrootd_cache_cinfo_from_xmeta(const xrootd_xmeta_t *m,
    xrootd_cache_cinfo_t *hdr)
{
    ngx_memzero(hdr, sizeof(*hdr));
    hdr->magic         = XROOTD_CACHE_CINFO_MAGIC;
    hdr->version       = XROOTD_CACHE_CINFO_VERSION;
    hdr->block_size    = (uint32_t) m->buffer_size;
    hdr->size          = (uint64_t) m->file_size;
    hdr->mtime         = m->origin_mtime;
    hdr->nblocks       = m->nblocks;
    hdr->access_count  = m->access_cnt;
    hdr->bytes_served  = (uint64_t) m->astat.bytes_hit;
    hdr->last_access   = (uint64_t) m->astat.detach_time;
    hdr->dirty_lo      = m->dirty_lo;
    hdr->dirty_hi      = m->dirty_hi;
    hdr->dirty_since   = m->dirty_since;
    hdr->flush_gen     = m->flush_gen;
    hdr->last_flush    = m->last_flush;
    hdr->bytes_flushed = m->bytes_flushed;
    hdr->expires_at    = m->expires_at;
    hdr->filled_at     = m->filled_at;
    hdr->mode          = m->mode;

    hdr->etag_len = m->etag_len <= sizeof(hdr->etag) ? m->etag_len : 0;
    ngx_memcpy(hdr->etag, m->etag, hdr->etag_len);
    hdr->cks_alg_len = m->cks_alg_len <= sizeof(hdr->cks_alg)
                       ? m->cks_alg_len : 0;
    ngx_memcpy(hdr->cks_alg, m->cks_alg, hdr->cks_alg_len);
    hdr->cks_len = m->cks_len <= sizeof(hdr->cks_hex) ? m->cks_len : 0;
    ngx_memcpy(hdr->cks_hex, m->cks_hex, hdr->cks_len);

    if (m->bitmap != NULL) {
        xrootd_cache_cinfo_refresh_flags(hdr, m->bitmap);
    }
    if (m->state_flags & XROOTD_XMETA_F_VERIFIED) {
        hdr->flags |= XROOTD_CINFO_F_VERIFIED;
    }
    if (m->state_flags & XROOTD_XMETA_F_EXPIRES) {
        hdr->flags |= XROOTD_CINFO_F_EXPIRES;
    }
    if (m->dirty_lo < m->dirty_hi) {
        hdr->flags |= XROOTD_CINFO_F_DIRTY;
    }
}

/* ---- raw path carrier (shared: fs/meta/xmeta_path.c) -----------------------
 * The record rides in the data file's user.xrd.cinfo xattr when it fits, else
 * as the stock-readable "<path>.cinfo" sidecar; CSI and the cache persist into
 * the SAME record under the SAME per-file lock. Thin NGX-return wrappers. */

static ngx_int_t
cinfo_xmeta_read(const char *cache_path, xrootd_xmeta_t *xm)
{
    int rc = xrootd_xmeta_path_load(cache_path, xm);

    if (rc == XROOTD_XMETA_OK) {
        return NGX_OK;
    }
    return (rc == XROOTD_XMETA_FOREIGN) ? NGX_DECLINED : NGX_ERROR;
}

static ngx_int_t
cinfo_xmeta_write(const char *cache_path, const xrootd_xmeta_t *xm)
{
    return (xrootd_xmeta_path_save(cache_path, xm) == XROOTD_XMETA_OK)
           ? NGX_OK : NGX_ERROR;
}

static int
cinfo_rmw_lock(const char *cache_path)
{
    return xrootd_xmeta_path_lock(cache_path);
}

static void
cinfo_rmw_unlock(int fd)
{
    xrootd_xmeta_path_unlock(fd);
}

ngx_int_t
xrootd_cache_cinfo_load(const char *cache_path, xrootd_cache_cinfo_t *hdr,
    uint8_t **bitmap, size_t *bitmap_len)
{
    xrootd_xmeta_t xm;
    size_t         blen;
    ngx_int_t      rc;

    if (cache_path == NULL || hdr == NULL || bitmap == NULL
        || bitmap_len == NULL)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *bitmap = NULL;
    *bitmap_len = 0;

    rc = cinfo_xmeta_read(cache_path, &xm);
    if (rc != NGX_OK) {
        return rc;
    }
    xrootd_cache_cinfo_from_xmeta(&xm, hdr);

    blen = xrootd_cache_cinfo_bitmap_len(hdr->nblocks);
    if (blen > 0) {
        uint8_t *bits = malloc(blen);

        if (bits == NULL) {
            xrootd_xmeta_free(&xm);
            errno = ENOMEM;
            return NGX_ERROR;
        }
        ngx_memcpy(bits, xm.bitmap, blen);
        *bitmap = bits;
        *bitmap_len = blen;
    }
    xrootd_xmeta_free(&xm);
    return NGX_OK;
}

ngx_int_t
xrootd_cache_cinfo_store(const char *cache_path,
    const xrootd_cache_cinfo_t *hdr, const uint8_t *bitmap, size_t bitmap_len)
{
    xrootd_xmeta_t xm;
    ngx_int_t      rc;

    if (cache_path == NULL || hdr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_cache_cinfo_to_xmeta(hdr, bitmap, bitmap_len, &xm) != NGX_OK) {
        return NGX_ERROR;
    }
    rc = cinfo_xmeta_write(cache_path, &xm);
    xrootd_xmeta_free(&xm);
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_from_meta(const xrootd_cache_meta_t *m, uint32_t block_size,
    xrootd_cache_cinfo_t *out)
{
    if (m == NULL || out == NULL || block_size == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));
    out->magic = XROOTD_CACHE_CINFO_MAGIC;
    out->version = XROOTD_CACHE_CINFO_VERSION;
    out->flags = XROOTD_CINFO_F_COMPLETE;   /* a legacy .meta means a whole file */
    out->block_size = block_size;
    out->size = m->size;
    out->mtime = m->mtime;
    out->nblocks = xrootd_cache_cinfo_nblocks(m->size, block_size);
    out->access_count = m->access_count;
    out->bytes_served = m->bytes_served;
    out->last_access = m->last_access;

    out->etag_len = m->etag_len;
    ngx_memcpy(out->etag, m->etag, sizeof(out->etag));
    out->cks_alg_len = m->cks_alg_len;
    ngx_memcpy(out->cks_alg, m->cks_alg, sizeof(out->cks_alg));
    out->cks_len = m->cks_len;
    ngx_memcpy(out->cks_hex, m->cks_hex, sizeof(out->cks_hex));
    return NGX_OK;
}

/* record-keeping entry point */
/*
 * Initialise a fresh, all-absent header for a file of `size` bytes recorded at
 * `block_size`/`mtime`. *out is zeroed; the caller marks bits + writes.
 */
static void
cinfo_init(xrootd_cache_cinfo_t *out, uint64_t size, uint32_t block_size,
    uint64_t mtime)
{
    ngx_memzero(out, sizeof(*out));
    out->magic = XROOTD_CACHE_CINFO_MAGIC;
    out->version = XROOTD_CACHE_CINFO_VERSION;
    out->block_size = block_size;
    out->size = size;
    out->mtime = mtime;
    out->nblocks = xrootd_cache_cinfo_nblocks(size, block_size);
}

ngx_int_t
xrootd_cache_cinfo_record_block(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint32_t mode, uint64_t blk,
    ngx_log_t *log)
{
    xrootd_cache_cinfo_t hdr;
    xrootd_xmeta_t       xm;
    uint64_t             nblocks;
    int                  lfd;
    ngx_int_t            rc;

    (void) log;

    if (cache_path == NULL || block_size == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    nblocks = xrootd_cache_cinfo_nblocks(size, block_size);
    if (blk >= nblocks) {
        errno = ERANGE;
        return NGX_ERROR;            /* block out of range for this size */
    }

    lfd = cinfo_rmw_lock(cache_path);
    if (lfd < 0) {
        return NGX_ERROR;
    }

    /* Adopt the recorded state only if it describes the SAME origin file; an
     * absent/garbage/stale (changed origin) record starts the bitmap fresh. */
    if (cinfo_xmeta_read(cache_path, &xm) == NGX_OK) {
        if ((uint64_t) xm.file_size == size
            && (uint64_t) xm.buffer_size == block_size
            && xm.origin_mtime == mtime)
        {
            xrootd_cache_cinfo_from_xmeta(&xm, &hdr);
        } else {
            xrootd_xmeta_free(&xm);
            cinfo_init(&hdr, size, block_size, mtime);
            if (xrootd_cache_cinfo_to_xmeta(&hdr, NULL, 0, &xm) != NGX_OK) {
                cinfo_rmw_unlock(lfd);
                return NGX_ERROR;
            }
        }
    } else {
        cinfo_init(&hdr, size, block_size, mtime);
        if (xrootd_cache_cinfo_to_xmeta(&hdr, NULL, 0, &xm) != NGX_OK) {
            cinfo_rmw_unlock(lfd);
            return NGX_ERROR;
        }
    }

    if (mode != 0) {
        xm.mode = mode;              /* origin perms (0 = caller has none) */
    }
    xrootd_xmeta_block_set(&xm, blk);

    rc = cinfo_xmeta_write(cache_path, &xm);
    xrootd_xmeta_free(&xm);
    cinfo_rmw_unlock(lfd);
    return rc;
}

/* ---- write-back (dirty) record-keeping --------------------------------- */

/* Under the per-file RMW lock, load the record describing the SAME origin
 * file (size/mtime/block_size) into *xm; an absent/garbage/stale record
 * starts fresh (clean dirty state, empty bitmap). NGX_OK / NGX_ERROR. */
static ngx_int_t
cinfo_rmw_load(const char *cache_path, uint64_t size, uint32_t block_size,
    uint64_t mtime, xrootd_xmeta_t *xm)
{
    xrootd_cache_cinfo_t fresh;

    if (cinfo_xmeta_read(cache_path, xm) == NGX_OK) {
        if ((uint64_t) xm->file_size == size
            && (uint64_t) xm->buffer_size == block_size
            && xm->origin_mtime == mtime)
        {
            return NGX_OK;
        }
        xrootd_xmeta_free(xm);
    }
    cinfo_init(&fresh, size, block_size, mtime);
    return xrootd_cache_cinfo_to_xmeta(&fresh, NULL, 0, xm);
}

ngx_int_t
xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len,
    ngx_log_t *log)
{
    xrootd_xmeta_t xm;
    int            lfd;
    ngx_int_t      rc;

    (void) log;

    if (cache_path == NULL || block_size == 0 || len == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lfd = cinfo_rmw_lock(cache_path);
    if (lfd < 0) {
        return NGX_ERROR;
    }
    if (cinfo_rmw_load(cache_path, size, block_size, mtime, &xm) != NGX_OK) {
        cinfo_rmw_unlock(lfd);
        return NGX_ERROR;
    }

    if (xm.dirty_lo >= xm.dirty_hi) {              /* clean -> dirty */
        xm.dirty_lo = off;
        xm.dirty_hi = off + len;
        xm.dirty_since = (uint64_t) time(NULL);
    } else {                                       /* widen; keep dirty_since */
        if (off < xm.dirty_lo) {
            xm.dirty_lo = off;
        }
        if (off + len > xm.dirty_hi) {
            xm.dirty_hi = off + len;
        }
    }

    rc = cinfo_xmeta_write(cache_path, &xm);
    xrootd_xmeta_free(&xm);
    cinfo_rmw_unlock(lfd);
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
    ngx_log_t *log)
{
    xrootd_xmeta_t xm;
    int            lfd;
    ngx_int_t      rc;

    (void) log;

    if (cache_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lfd = cinfo_rmw_lock(cache_path);
    if (lfd < 0) {
        return NGX_ERROR;
    }
    rc = cinfo_xmeta_read(cache_path, &xm);
    if (rc != NGX_OK) {
        cinfo_rmw_unlock(lfd);
        return (rc == NGX_DECLINED) ? NGX_DECLINED : NGX_ERROR;
    }

    xm.dirty_lo = 0;
    xm.dirty_hi = 0;
    xm.dirty_since = 0;
    xm.flush_gen += 1;
    xm.last_flush = (uint64_t) time(NULL);
    xm.bytes_flushed += bytes;

    rc = cinfo_xmeta_write(cache_path, &xm);
    xrootd_xmeta_free(&xm);
    cinfo_rmw_unlock(lfd);
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
    uint64_t *hi, uint64_t *dirty_since)
{
    xrootd_cache_cinfo_t h;
    uint8_t             *bm = NULL;
    size_t               bl = 0;
    ngx_int_t            rc;

    rc = xrootd_cache_cinfo_load(cache_path, &h, &bm, &bl);
    if (rc != NGX_OK) {
        return rc;                          /* DECLINED (no record) or ERROR */
    }
    free(bm);

    if (!(h.flags & XROOTD_CINFO_F_DIRTY) || h.dirty_lo >= h.dirty_hi) {
        return NGX_DECLINED;                /* clean */
    }
    if (lo != NULL) {
        *lo = h.dirty_lo;
    }
    if (hi != NULL) {
        *hi = h.dirty_hi;
    }
    if (dirty_since != NULL) {
        *dirty_since = h.dirty_since;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_cache_cinfo_state(const char *cache_path, xrootd_cache_cinfo_state_t *out)
{
    xrootd_cache_cinfo_t h;
    uint8_t             *bm = NULL;
    size_t               bl = 0;
    ngx_int_t            rc;

    if (out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    rc = xrootd_cache_cinfo_load(cache_path, &h, &bm, &bl);
    if (rc != NGX_OK) {
        return rc;                          /* DECLINED (no record) or ERROR */
    }
    free(bm);

    out->is_dirty    = ((h.flags & XROOTD_CINFO_F_DIRTY)
                        && h.dirty_lo < h.dirty_hi) ? 1 : 0;
    out->dirty_lo    = h.dirty_lo;
    out->dirty_hi    = h.dirty_hi;
    out->dirty_since = h.dirty_since;
    out->flush_gen   = h.flush_gen;
    out->last_flush  = h.last_flush;
    return NGX_OK;
}

/* ---- phase-68 manifest TTL (pure helpers on the in-memory header) -------- */

void
xrootd_cache_cinfo_set_expires(xrootd_cache_cinfo_t *ci, time_t when)
{
    ci->expires_at = (uint64_t) when;
    ci->flags |= XROOTD_CINFO_F_EXPIRES;
}

int
xrootd_cache_cinfo_expired(const xrootd_cache_cinfo_t *ci, time_t now)
{
    if ((ci->flags & XROOTD_CINFO_F_EXPIRES) == 0) {
        return -1;                          /* immutable entry: never expires */
    }
    return ((uint64_t) now >= ci->expires_at) ? 1 : 0;
}
