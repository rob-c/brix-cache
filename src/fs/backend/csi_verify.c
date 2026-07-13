/*
 * fs/backend/csi_verify.c — CSI block-granule verify / fold / flush on the
 * unified metadata record (xmeta P3).
 *
 * WHAT: Read-verify fully-spanned blocks against the record's BLOCKCRC table;
 *       fold write CRCs into the handle-local table as bytes stream through;
 *       merge everything into the record once at flush. WHY: at-rest
 *       corruption detection with ONE metadata record per file and zero
 *       record I/O on the write hot path. HOW: the record's own buffer_size
 *       is the verify granule; a slot of 0 means "not computed" and never
 *       fails a read; flush recomputes bounded unaligned edges from disk and
 *       zeroes anything it cannot vouch for (fail-open on coverage,
 *       fail-closed on mismatch).
 */

#include "csi_tagstore.h"
#include "fs/meta/xmeta_path.h"
#include "core/compat/crc32c.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- read verify ----------------------------------------------------------- */

/* Verify the bytes in [off, off+len) against the block CRCs in *xm. Pure: no
 * I/O, no allocation — the record is supplied by the caller (cached snapshot on
 * the read hot path, or a one-off load on the write read-after-write path). */
static int
csi_verify_against(const brix_csi_t *c, const brix_xmeta_t *xm,
    const unsigned char *buf, off_t off, size_t len)
{
    int64_t   g;
    uint64_t  b, b0;

    if (!xm->have_blockcrc || xm->blockcrc == NULL || xm->buffer_size <= 0) {
        return BRIX_CSI_NOTAGS;
    }

    /* Verify every block the buffer FULLY covers (the last file block is
     * short: it ends at file_size). Slot 0 = not computed -> skipped. */
    g  = xm->buffer_size;
    b0 = ((uint64_t) off + (uint64_t) g - 1) / (uint64_t) g;
    for (b = b0; b < xm->nblocks; b++) {
        int64_t bstart = (int64_t) b * g;
        int64_t bend   = bstart + g;

        if (bend > xm->file_size) {
            bend = xm->file_size;
        }
        if (bend > off + (int64_t) len) {
            break;                      /* not fully covered by this read */
        }
        /* A block written through THIS handle since open has a stale on-disk CRC
         * (the record is only recomputed at flush/close). Skip it: the bytes we
         * serve are the ones just written, so there is no disk-corruption risk to
         * catch here, and verifying against the pre-write CRC would spuriously
         * fail every read-after-write on an integrity-tracked file (e.g. kXR_write
         * / kXR_clone / a ckpXeq write followed by a read on the same handle). */
        if (c->dirty && bstart < c->dirty_hi && bend > c->dirty_lo) {
            continue;
        }
        if (xm->blockcrc[b] == BRIX_XMETA_CRC_UNSET) {
            continue;
        }
        if (brix_crc32c_value(buf + (bstart - off),
                                (size_t) (bend - bstart)) != xm->blockcrc[b])
        {
            return BRIX_CSI_MISMATCH;
        }
    }
    return BRIX_CSI_OK;
}

int
brix_csi_verify_read(brix_csi_t *c, const unsigned char *buf, off_t off,
    size_t len)
{
    brix_xmeta_t xm;
    int          rc;

    if (c == NULL || buf == NULL || off < 0) {
        errno = EINVAL;
        return BRIX_CSI_ERR;
    }
    if (len == 0 || c->trust_fs) {
        return BRIX_CSI_OK;   /* nothing to check / self-checksumming fs */
    }

    /* Read hot path: verify against the snapshot taken once at open. No
     * getxattr / parse / malloc per read — the record cannot change under a
     * read handle, so the at-open copy is authoritative for at-rest checking. */
    if (c->record != NULL) {
        return csi_verify_against(c, c->record, buf, off, len);
    }

    /* Fallback: a handle with no cached record (a write handle serving a
     * read-after-write) loads the record for this call. Rare and not the
     * throughput hot path. */
    switch (brix_xmeta_path_load(c->path, &xm)) {
    case BRIX_XMETA_OK:
        break;
    case BRIX_XMETA_FOREIGN:
        return BRIX_CSI_NOTAGS;
    default:
        return BRIX_CSI_ERR;
    }
    rc = csi_verify_against(c, &xm, buf, off, len);
    brix_xmeta_free(&xm);
    return rc;
}

/* ---- write fold ------------------------------------------------------------- */

/* Grow the handle-local table to hold block index b. 0 / -1 (cap/OOM). */
static int
csi_local_reserve(brix_csi_t *c, uint64_t b)
{
    uint64_t  want;
    uint32_t *grown;

    if (b >= BRIX_CSI_LOCAL_MAX) {
        c->overflow = 1;
        return -1;
    }
    if (b < c->local_n) {
        return 0;
    }
    want = c->local_n ? c->local_n : 64;
    while (want <= b) {
        want *= 2;
    }
    if (want > BRIX_CSI_LOCAL_MAX) {
        want = BRIX_CSI_LOCAL_MAX;
    }
    grown = realloc(c->local, (size_t) want * sizeof(uint32_t));
    if (grown == NULL) {
        c->overflow = 1;
        return -1;
    }
    memset(grown + c->local_n, 0,
           (size_t) (want - c->local_n) * sizeof(uint32_t));
    c->local = grown;
    c->local_n = want;
    return 0;
}

int
brix_csi_write_update(brix_csi_t *c, const unsigned char *buf, off_t off,
    size_t len)
{
    uint64_t b, b0;
    int64_t  g;

    if (c == NULL || off < 0 || (buf == NULL && len != 0)) {
        errno = EINVAL;
        return BRIX_CSI_ERR;
    }
    if (len == 0) {
        return BRIX_CSI_OK;
    }

    if (!c->dirty) {
        c->dirty = 1;
        c->dirty_lo = off;
        c->dirty_hi = off + (int64_t) len;
    } else {
        if (off < c->dirty_lo) {
            c->dirty_lo = off;
        }
        if (off + (int64_t) len > c->dirty_hi) {
            c->dirty_hi = off + (int64_t) len;
        }
    }

    /* Fold the CRCs of fully covered blocks (at the CONFIGURED granule; if
     * the record turns out to use a different one, flush drops the fold and
     * falls back to its bounded recompute). */
    g  = (int64_t) c->granule;
    b0 = ((uint64_t) off + (uint64_t) g - 1) / (uint64_t) g;
    for (b = b0; ; b++) {
        int64_t bstart = (int64_t) b * g;

        if (bstart + g > off + (int64_t) len) {
            break;
        }
        if (csi_local_reserve(c, b) != 0) {
            break;                      /* cap/OOM: flush covers what it can */
        }
        c->local[b] = brix_crc32c_value(buf + (bstart - off), (size_t) g);
    }
    return BRIX_CSI_OK;
}

/* ---- flush ------------------------------------------------------------------ */

/* Rebuild *xm for a new geometry, preserving scalar state. The write handle
 * rewrote the file, so the local bytes are authoritative: the present bitmap
 * is fully set. 0 / -1. */
static int
csi_record_regeom(brix_xmeta_t *xm, int64_t new_size, int64_t granule)
{
    brix_xmeta_t nu;

    if (brix_xmeta_init(&nu, new_size, granule) != BRIX_XMETA_OK) {
        return -1;
    }
    nu.creation_time = xm->creation_time ? xm->creation_time
                                         : nu.creation_time;
    nu.access_cnt    = xm->access_cnt;
    nu.status_raw    = xm->status_raw;
    nu.astat         = xm->astat;
    nu.astat_count   = xm->astat_count;
    nu.have_state    = 1;
    nu.origin_mtime  = xm->origin_mtime;
    nu.dirty_lo      = xm->dirty_lo;
    nu.dirty_hi      = xm->dirty_hi;
    nu.flush_gen     = xm->flush_gen;
    nu.dirty_since   = xm->dirty_since;
    nu.last_flush    = xm->last_flush;
    nu.bytes_flushed = xm->bytes_flushed;
    nu.expires_at    = xm->expires_at;
    nu.filled_at     = xm->filled_at;
    nu.mode          = xm->mode;
    nu.state_flags   = xm->state_flags;
    nu.etag_len      = xm->etag_len;
    memcpy(nu.etag, xm->etag, sizeof(nu.etag));
    nu.cks_alg_len   = xm->cks_alg_len;
    memcpy(nu.cks_alg, xm->cks_alg, sizeof(nu.cks_alg));
    nu.cks_len       = xm->cks_len;
    memcpy(nu.cks_hex, xm->cks_hex, sizeof(nu.cks_hex));
    if (nu.nblocks > 0) {
        memset(nu.bitmap, 0xFF,
               (size_t) ((nu.nblocks + 7) / 8));       /* file is the data */
    }
    brix_xmeta_free(xm);
    *xm = nu;
    return 0;
}

/* Open the file's own O_RDONLY fd for read-back and stat it. WHAT: flush reads
 * the just-written bytes to recompute unaligned edges, so it needs a fresh read
 * fd — the handle's data fd may already be closed or write-only. WHY: the
 * recompute path (pread) and the geometry decision (st_size) both need a live,
 * regular-file descriptor. HOW: open with the hardened flag set used elsewhere
 * on this carrier, fstat, and reject anything that is not a regular file;
 * returns the fd (>= 0) and fills *st, or -1 (fd closed) on any failure. */
static int
csi_flush_open_file(const brix_csi_t *c, struct stat *st)
{
    int fd = open(c->path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Load, create, or re-geometry the record so it matches the file on disk.
 * WHAT: bring *xm into a state whose geometry (nblocks/buffer_size) and present
 * bitmap describe the current file, and guarantee a non-NULL blockcrc table.
 * WHY: the write handle may have grown/replaced the file, and a foreign/absent
 * record must become a fresh, fully-present one this handle owns. HOW: load;
 * on FOREIGN init a fresh fully-present record; on a size/geometry drift
 * re-geometry (present bitmap set — the file is authoritative); then allocate
 * the CRC table if missing. Returns BRIX_CSI_OK with *xm live (caller frees) or
 * BRIX_CSI_ERR with *xm already released. */
static int
csi_flush_load_record(const brix_csi_t *c, const struct stat *st,
    brix_xmeta_t *xm)
{
    int rc = brix_xmeta_path_load(c->path, xm);

    if (rc == BRIX_XMETA_ERR
        || (rc == BRIX_XMETA_FOREIGN
            && brix_xmeta_init(xm, st->st_size,
                                 (int64_t) c->granule) != BRIX_XMETA_OK))
    {
        return BRIX_CSI_ERR;
    }

    if (rc == BRIX_XMETA_FOREIGN) {
        /* Fresh record for a file this handle wrote: fully present. */
        xm->origin_mtime = (uint64_t) st->st_mtime;
        if (xm->nblocks > 0) {
            memset(xm->bitmap, 0xFF, (size_t) ((xm->nblocks + 7) / 8));
        }
    } else if (xm->file_size != st->st_size || xm->buffer_size <= 0) {
        if (csi_record_regeom(xm, st->st_size,
                              xm->buffer_size > 0 ? xm->buffer_size
                                                  : (int64_t) c->granule) != 0)
        {
            brix_xmeta_free(xm);
            return BRIX_CSI_ERR;
        }
        xm->origin_mtime = (uint64_t) st->st_mtime;
    }

    if (xm->blockcrc == NULL) {
        xm->blockcrc = calloc(xm->nblocks ? (size_t) xm->nblocks : 1,
                              sizeof(uint32_t));
        if (xm->blockcrc == NULL) {
            brix_xmeta_free(xm);
            errno = ENOMEM;
            return BRIX_CSI_ERR;
        }
    }
    xm->have_blockcrc = 1;
    return BRIX_CSI_OK;
}

/* Recompute one block's CRC by reading it back from disk. WHAT: pread block b
 * (bounded by file_size) into *blockbuf and CRC it. WHY: a dirty-edge block
 * with no folded CRC (misaligned write or geometry mismatch) must be recomputed
 * from the authoritative on-disk bytes. HOW: allocate blockbuf lazily on first
 * use (granule-sized, reused across blocks), EINTR-retry the pread, and on a
 * full read store the CRC into xm->blockcrc[b]; returns 1 when the slot was
 * filled, 0 on a short read / alloc failure (caller marks it UNSET). */
static int
csi_flush_recompute_block(int fd, brix_xmeta_t *xm, int64_t g, uint64_t b,
    unsigned char **blockbuf)
{
    int64_t bstart = (int64_t) b * g;
    int64_t bend   = bstart + g;
    size_t  got = 0;

    if (bend > xm->file_size) {
        bend = xm->file_size;
    }
    if (*blockbuf == NULL) {
        *blockbuf = malloc((size_t) g);
    }
    if (*blockbuf == NULL) {
        return 0;
    }
    while (got < (size_t) (bend - bstart)) {
        ssize_t n = pread(fd, *blockbuf + got,
                          (size_t) (bend - bstart) - got,
                          bstart + (off_t) got);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return 0;                   /* short read: cannot vouch for it */
        }
        got += (size_t) n;
    }
    xm->blockcrc[b] = brix_crc32c_value(*blockbuf, got);
    return 1;
}

/* Give every block the dirty write extent touched a fresh CRC truth. WHAT: for
 * each block in the dirty [lo,hi) block range, store the folded CRC when we
 * trust it, else a bounded on-disk recompute, else UNSET. WHY: only the written
 * extent can have stale CRCs; blocks outside it keep their recorded truth. HOW:
 * derive the block range from the byte extent; fold when the granule matches and
 * the local table did not overflow; otherwise recompute within a per-flush read
 * budget (BRIX_CSI_FLUSH_READ blocks); anything unread is UNSET. Owns and frees
 * the recompute scratch buffer. */
static void
csi_flush_rebuild_crcs(brix_csi_t *c, brix_xmeta_t *xm, int fd, int64_t g)
{
    unsigned char *blockbuf = NULL;
    int            budget = BRIX_CSI_FLUSH_READ;
    int            fold_ok = (g == (int64_t) c->granule && !c->overflow);
    uint64_t       b;
    uint64_t       b_lo = (uint64_t) (c->dirty_lo / g);
    uint64_t       b_hi = (uint64_t) ((c->dirty_hi + g - 1) / g);

    if (b_hi > xm->nblocks) {
        b_hi = xm->nblocks;
    }
    for (b = b_lo; b < b_hi; b++) {
        if (fold_ok && b < c->local_n
            && c->local[b] != BRIX_XMETA_CRC_UNSET)
        {
            xm->blockcrc[b] = c->local[b];
            continue;
        }
        if (budget > 0) {
            budget--;
            if (csi_flush_recompute_block(fd, xm, g, b, &blockbuf)) {
                continue;
            }
        }
        xm->blockcrc[b] = BRIX_XMETA_CRC_UNSET;    /* cannot vouch for it */
    }
    free(blockbuf);
}

/* Stamp the record's whole-file coverage timestamp. WHAT: set/clear
 * no_cksum_time from whether any block CRC is still UNSET. WHY: the record
 * tracks how long a file has lacked full checksum coverage (scrub / reporting);
 * a first gap starts the clock, full coverage clears it. HOW: scan the CRC
 * table for any UNSET slot; on a gap set no_cksum_time once (preserve an
 * existing start), otherwise zero it. Pure record bookkeeping, no I/O. */
static void
csi_flush_mark_coverage(brix_xmeta_t *xm)
{
    uint64_t b;
    int      any_unset = 0;

    for (b = 0; b < xm->nblocks; b++) {
        if (xm->blockcrc[b] == BRIX_XMETA_CRC_UNSET) {
            any_unset = 1;
            break;
        }
    }
    if (any_unset) {
        if (xm->no_cksum_time == 0) {
            xm->no_cksum_time = (int64_t) time(NULL);
        }
    } else {
        xm->no_cksum_time = 0;
    }
}

int
brix_csi_flush(brix_csi_t *c)
{
    brix_xmeta_t xm;
    struct stat  st;
    int          fd, lockfd, rc;

    if (c == NULL || !c->writable) {
        errno = EINVAL;
        return BRIX_CSI_ERR;
    }
    if (!c->dirty) {
        return BRIX_CSI_OK;
    }

    fd = csi_flush_open_file(c, &st);
    if (fd < 0) {
        return BRIX_CSI_ERR;
    }

    lockfd = brix_xmeta_path_lock(c->path);
    if (lockfd < 0) {
        close(fd);
        return BRIX_CSI_ERR;
    }

    if (csi_flush_load_record(c, &st, &xm) != BRIX_CSI_OK) {
        brix_xmeta_path_unlock(lockfd);
        close(fd);
        return BRIX_CSI_ERR;
    }

    csi_flush_rebuild_crcs(c, &xm, fd, xm.buffer_size);
    csi_flush_mark_coverage(&xm);

    rc = (brix_xmeta_path_save(c->path, &xm) == BRIX_XMETA_OK)
         ? BRIX_CSI_OK : BRIX_CSI_ERR;
    brix_xmeta_free(&xm);
    brix_xmeta_path_unlock(lockfd);
    close(fd);
    if (rc == BRIX_CSI_OK) {
        c->dirty = 0;
    }
    return rc;
}
