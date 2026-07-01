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

/* short-safe positional read/write */
/* Transfer exactly len bytes at offset off. Returns NGX_OK, NGX_DECLINED on a
 * short read (premature EOF), or NGX_ERROR (errno set). */
static ngx_int_t
cinfo_pio(int fd, void *buf, size_t len, off_t off, unsigned write_op)
{
    u_char *p = buf;

    /* The .cinfo sidecar is cache METADATA (the block-present bitmap), not user
     * file data, so the data-plane "byte I/O only via the SD backend" invariant
     * does not apply — and keeping raw pread/pwrite here preserves cinfo.c's
     * standalone (nginx-free) unit test (tests/c/run_cinfo_tests.sh). */
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

/*
 * Frozen v2 on-disk header (pre-write-back layout). A v2 sidecar predates the
 * dirty/write-back fields; reading it lets a populated cache survive the upgrade
 * to v3 — the present bitmap is preserved and the dirty state starts clean. The
 * field order is byte-identical to the v2 xrootd_cache_cinfo_t.
 */
#define XROOTD_CACHE_CINFO_V2_VERSION 2
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t block_size;
    uint32_t reserved;
    uint64_t size;
    uint64_t mtime;
    uint64_t nblocks;
    uint64_t access_count;
    uint64_t bytes_served;
    uint64_t last_access;
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];
    uint8_t  cks_alg_len;
    char     cks_alg[16];
    uint8_t  cks_len;
    char     cks_hex[129];
} xrootd_cache_cinfo_v2_t;
#define XROOTD_CACHE_CINFO_V2_HDR_SIZE (sizeof(xrootd_cache_cinfo_v2_t))

/* Promote a v2 header into a zero-initialised v3 header (the dirty/write-back
 * fields stay 0 ⇒ the upgraded record reads as clean). */
static void
cinfo_v2_to_v3(const xrootd_cache_cinfo_v2_t *v2, xrootd_cache_cinfo_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->magic        = v2->magic;
    out->version      = XROOTD_CACHE_CINFO_VERSION;
    out->flags        = v2->flags;
    out->block_size   = v2->block_size;
    out->size         = v2->size;
    out->mtime        = v2->mtime;
    out->nblocks      = v2->nblocks;
    out->access_count = v2->access_count;
    out->bytes_served = v2->bytes_served;
    out->last_access  = v2->last_access;
    out->etag_len     = v2->etag_len;
    ngx_memcpy(out->etag, v2->etag, sizeof(out->etag));
    out->cks_alg_len  = v2->cks_alg_len;
    ngx_memcpy(out->cks_alg, v2->cks_alg, sizeof(out->cks_alg));
    out->cks_len      = v2->cks_len;
    ngx_memcpy(out->cks_hex, v2->cks_hex, sizeof(out->cks_hex));
}

/* Read a legacy v2 sidecar (header@v2 size + bitmap@v2 offset) into the v3 hdr +
 * a freshly malloc'd bitmap. fd is positioned anywhere (pread is used). Returns
 * NGX_OK with the bitmap out-params set (NULL/0 for a 0-block file), or a
 * NGX_DECLINED/NGX_ERROR the caller propagates. */
static ngx_int_t
cinfo_load_v2(int fd, xrootd_cache_cinfo_t *hdr, uint8_t **bitmap,
    size_t *bitmap_len)
{
    xrootd_cache_cinfo_v2_t v2;
    size_t                  blen;
    uint8_t                *bits;
    ngx_int_t               rc;

    if (cinfo_pio(fd, &v2, XROOTD_CACHE_CINFO_V2_HDR_SIZE, 0, 0) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (v2.block_size == 0
        || v2.nblocks != xrootd_cache_cinfo_nblocks(v2.size, v2.block_size))
    {
        return NGX_DECLINED;                 /* garbage v2 → nothing recorded */
    }
    cinfo_v2_to_v3(&v2, hdr);

    blen = xrootd_cache_cinfo_bitmap_len(hdr->nblocks);
    if (blen == 0) {
        return NGX_OK;                       /* 0-block file: header only */
    }
    bits = malloc(blen);
    if (bits == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    rc = cinfo_pio(fd, bits, blen, (off_t) XROOTD_CACHE_CINFO_V2_HDR_SIZE, 0);
    if (rc != NGX_OK) {
        free(bits);
        return (rc == NGX_DECLINED) ? NGX_DECLINED : NGX_ERROR;
    }
    *bitmap = bits;
    *bitmap_len = blen;
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

    /* Peek magic+version first: a v2 sidecar is SHORTER than the v3 header, so a
     * full v3-sized read would short-read before we could detect the version.
     * magic (u32 @0) + version (u16 @4) sit at the same offset in v2 and v3. */
    {
        unsigned char peek[8];

        if (cinfo_pio(fd, peek, sizeof(peek), 0, 0) == NGX_OK) {
            uint32_t pmagic;
            uint16_t pver;

            ngx_memcpy(&pmagic, peek, sizeof(pmagic));
            ngx_memcpy(&pver, peek + 4, sizeof(pver));
            if (pmagic == XROOTD_CACHE_CINFO_MAGIC
                && pver == XROOTD_CACHE_CINFO_V2_VERSION)
            {
                rc = cinfo_load_v2(fd, hdr, bitmap, bitmap_len);
                close(fd);
                return rc;
            }
        }
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
    uint32_t block_size, uint64_t mtime, uint32_t mode, uint64_t blk,
    ngx_log_t *log)
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

    if (mode != 0) {
        hdr.mode = mode;                 /* origin perms (0 = caller has none) */
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

/* ---- write-back (dirty) record-keeping (v3) ---------------------------- */

/*
 * Under an flock'd fd, load the current header + present bitmap describing the
 * SAME origin file (size/mtime/block_size); an absent/garbage/stale record
 * starts fresh (cinfo_init zeroes the dirty fields too). *bits is malloc'd
 * (caller frees); *blen_out is its length. Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
cinfo_rmw_load(int fd, uint64_t size, uint32_t block_size, uint64_t mtime,
    xrootd_cache_cinfo_t *hdr, uint8_t **bits, size_t *blen_out)
{
    uint64_t nblocks = xrootd_cache_cinfo_nblocks(size, block_size);
    size_t   blen = xrootd_cache_cinfo_bitmap_len(nblocks);
    uint8_t *b = malloc(blen ? blen : 1);
    xrootd_cache_cinfo_t cur;
    ngx_int_t lrc;
    int reuse;

    if (b == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memzero(b, blen ? blen : 1);

    lrc = cinfo_pio(fd, &cur, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0);
    reuse = (lrc == NGX_OK
             && cinfo_header_ok(&cur) == NGX_OK
             && cur.size == size
             && cur.block_size == block_size
             && cur.mtime == mtime);
    if (reuse) {
        *hdr = cur;
        if (blen > 0
            && cinfo_pio(fd, b, blen, (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0)
               != NGX_OK)
        {
            ngx_memzero(b, blen);          /* unreadable tail → start fresh bits */
        }
    } else {
        cinfo_init(hdr, size, block_size, mtime);
    }
    *bits = b;
    *blen_out = blen;
    return NGX_OK;
}

ngx_int_t
xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len,
    ngx_log_t *log)
{
    char                 path[PATH_MAX];
    xrootd_cache_cinfo_t hdr;
    uint8_t             *bits = NULL;
    size_t               blen;
    int                  fd;
    ngx_int_t            rc;

    (void) log;

    if (cache_path == NULL || block_size == 0 || len == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_cache_cinfo_path(path, sizeof(path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    fd = open(path, O_RDWR | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return NGX_ERROR;
    }
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            close(fd);
            return NGX_ERROR;
        }
    }

    if (cinfo_rmw_load(fd, size, block_size, mtime, &hdr, &bits, &blen)
        != NGX_OK)
    {
        flock(fd, LOCK_UN);
        close(fd);
        return NGX_ERROR;
    }

    if (!(hdr.flags & XROOTD_CINFO_F_DIRTY)) {     /* clean → dirty transition */
        hdr.flags |= XROOTD_CINFO_F_DIRTY;
        hdr.dirty_lo = off;
        hdr.dirty_hi = off + len;
        hdr.dirty_since = (uint64_t) time(NULL);
    } else {                                       /* widen; keep dirty_since */
        if (off < hdr.dirty_lo) {
            hdr.dirty_lo = off;
        }
        if (off + len > hdr.dirty_hi) {
            hdr.dirty_hi = off + len;
        }
    }

    rc = cinfo_write_fd(fd, &hdr, bits, blen);

    free(bits);
    flock(fd, LOCK_UN);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }
    return rc;
}

ngx_int_t
xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
    ngx_log_t *log)
{
    char                 path[PATH_MAX];
    xrootd_cache_cinfo_t hdr;
    uint8_t             *bits = NULL;
    size_t               blen;
    int                  fd;
    ngx_int_t            rc;

    (void) log;

    if (cache_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_cache_cinfo_path(path, sizeof(path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return (errno == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            close(fd);
            return NGX_ERROR;
        }
    }

    {
        xrootd_cache_cinfo_t cur;

        if (cinfo_pio(fd, &cur, XROOTD_CACHE_CINFO_HDR_SIZE, 0, 0) != NGX_OK
            || cinfo_header_ok(&cur) != NGX_OK)
        {
            flock(fd, LOCK_UN);
            close(fd);
            return NGX_DECLINED;               /* no usable record → nothing to do */
        }
        blen = xrootd_cache_cinfo_bitmap_len(cur.nblocks);
        bits = malloc(blen ? blen : 1);
        if (bits == NULL) {
            flock(fd, LOCK_UN);
            close(fd);
            errno = ENOMEM;
            return NGX_ERROR;
        }
        ngx_memzero(bits, blen ? blen : 1);
        if (blen > 0) {
            (void) cinfo_pio(fd, bits, blen,
                             (off_t) XROOTD_CACHE_CINFO_HDR_SIZE, 0);
        }
        hdr = cur;
    }

    hdr.flags &= (uint16_t) ~XROOTD_CINFO_F_DIRTY;
    hdr.dirty_lo = 0;
    hdr.dirty_hi = 0;
    hdr.dirty_since = 0;
    hdr.flush_gen += 1;
    hdr.last_flush = (uint64_t) time(NULL);
    hdr.bytes_flushed += bytes;

    rc = cinfo_write_fd(fd, &hdr, bits, blen);

    free(bits);
    flock(fd, LOCK_UN);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }
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
