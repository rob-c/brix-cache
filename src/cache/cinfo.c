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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
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

/* short-safe positional read/write */
/* Transfer exactly len bytes at offset off. Returns NGX_OK, NGX_DECLINED on a
 * short read (premature EOF), or NGX_ERROR (errno set). */
static ngx_int_t
cinfo_pio(int fd, void *buf, size_t len, off_t off, unsigned write_op)
{
    u_char *p = buf;

    while (len > 0) {
        ssize_t n = write_op ? pwrite(fd, p, len, off)
                             : pread(fd, p, len, off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }
        if (n == 0) {
            return NGX_DECLINED;   /* short file */
        }
        p += (size_t) n;
        len -= (size_t) n;
        off += n;
    }
    return NGX_OK;
}

/*
 * Validate a just-read header against its own internal invariants. NGX_OK if it
 * is a well-formed cinfo, NGX_DECLINED otherwise (treat as no record).
 */
static ngx_int_t
cinfo_header_ok(const xrootd_cache_cinfo_t *hdr)
{
    if (hdr->magic != XROOTD_CACHE_CINFO_MAGIC
        || hdr->version != XROOTD_CACHE_CINFO_VERSION
        || hdr->block_size == 0
        || hdr->etag_len > XROOTD_CACHE_META_ETAG_MAX
        || hdr->cks_alg_len > sizeof(hdr->cks_alg)
        || hdr->cks_len > sizeof(hdr->cks_hex)
        || hdr->nblocks != xrootd_cache_cinfo_nblocks(hdr->size, hdr->block_size))
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/* load / store */
ngx_int_t
xrootd_cache_cinfo_load(const char *cache_path, xrootd_cache_cinfo_t *hdr,
    uint8_t **bitmap, size_t *bitmap_len)
{
    char      path[PATH_MAX];
    int       fd;
    size_t    blen;
    uint8_t  *bits;
    ngx_int_t rc;

    if (cache_path == NULL || hdr == NULL || bitmap == NULL || bitmap_len == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *bitmap = NULL;
    *bitmap_len = 0;

    if (xrootd_cache_cinfo_path(path, sizeof(path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return (errno == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }

    rc = cinfo_pio(fd, hdr, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
    if (rc != NGX_OK) {
        close(fd);
        return rc;                 /* short header → DECLINED, I/O error → ERROR */
    }
    if (cinfo_header_ok(hdr) != NGX_OK) {
        close(fd);
        return NGX_DECLINED;       /* garbage / wrong version / inconsistent */
    }

    blen = xrootd_cache_cinfo_bitmap_len(hdr->nblocks);
    if (blen == 0) {
        close(fd);
        return NGX_OK;             /* 0-block file: header only, no bitmap */
    }

    bits = malloc(blen);
    if (bits == NULL) {
        close(fd);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    rc = cinfo_pio(fd, bits, blen, (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0);
    close(fd);
    if (rc != NGX_OK) {
        free(bits);
        return (rc == NGX_DECLINED) ? NGX_DECLINED : NGX_ERROR;
    }

    *bitmap = bits;
    *bitmap_len = blen;
    return NGX_OK;
}

/*
 * Write *src + bitmap to an already-open fd at offset 0 and trim to that exact
 * length. The magic/version are forced so every persisted record self-identifies.
 */
static ngx_int_t
cinfo_write_fd(int fd, const xrootd_cache_cinfo_t *src,
    const uint8_t *bitmap, size_t bitmap_len)
{
    xrootd_cache_cinfo_t disk;

    disk = *src;
    disk.magic = XROOTD_CACHE_CINFO_MAGIC;
    disk.version = XROOTD_CACHE_CINFO_VERSION;

    if (cinfo_pio(fd, &disk, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 1) != NGX_OK) {
        return NGX_ERROR;
    }
    if (bitmap_len > 0
        && cinfo_pio(fd, (void *) bitmap, bitmap_len,
                     (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (ftruncate(fd, (off_t) (XROOTD_CACHE_CINFO_HDR_SIZE + bitmap_len)) != 0) {
        return NGX_ERROR;
    }
    if (fdatasync(fd) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_cache_cinfo_store(const char *cache_path, const xrootd_cache_cinfo_t *hdr,
    const uint8_t *bitmap, size_t bitmap_len)
{
    char      path[PATH_MAX];
    int       fd;
    ngx_int_t rc;

    if (cache_path == NULL || hdr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_cache_cinfo_path(path, sizeof(path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return NGX_ERROR;
    }
    rc = cinfo_write_fd(fd, hdr, bitmap, bitmap_len);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }
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
    uint32_t block_size, uint64_t mtime, uint64_t blk, ngx_log_t *log)
{
    char                 path[PATH_MAX];
    xrootd_cache_cinfo_t hdr;
    uint8_t             *bits = NULL;
    size_t               blen;
    uint64_t             nblocks;
    int                  fd;
    ngx_int_t            rc = NGX_ERROR;

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
    blen = xrootd_cache_cinfo_bitmap_len(nblocks);

    if (xrootd_cache_cinfo_path(path, sizeof(path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    fd = open(path, O_RDWR | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return NGX_ERROR;
    }
    /* Serialise the read-modify-write so two workers filling different windows
     * of the same file cannot clobber each other's bits.  flock is per-open-fd,
     * advisory, and auto-released on close/crash (no orphan-lock reclaim). */
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            close(fd);
            return NGX_ERROR;
        }
    }

    bits = malloc(blen ? blen : 1);
    if (bits == NULL) {
        flock(fd, LOCK_UN);
        close(fd);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memzero(bits, blen ? blen : 1);

    /* Adopt the on-disk bitmap only if it describes the SAME origin file; an
     * absent/garbage/stale (changed origin) record starts the bitmap fresh. */
    {
        xrootd_cache_cinfo_t cur;
        ngx_int_t lrc = cinfo_pio(fd, &cur, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
        int reuse = (lrc == NGX_OK
                     && cinfo_header_ok(&cur) == NGX_OK
                     && cur.size == size
                     && cur.block_size == block_size
                     && cur.mtime == mtime);
        if (reuse) {
            hdr = cur;
            if (blen > 0
                && cinfo_pio(fd, bits, blen,
                             (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0) != NGX_OK)
            {
                ngx_memzero(bits, blen);   /* unreadable tail → start fresh */
            }
        } else {
            cinfo_init(&hdr, size, block_size, mtime);
        }
    }

    xrootd_cache_cinfo_mark_block(bits, blk);
    xrootd_cache_cinfo_refresh_flags(&hdr, bits);

    rc = cinfo_write_fd(fd, &hdr, bits, blen);

    free(bits);
    flock(fd, LOCK_UN);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }
    return rc;
}
