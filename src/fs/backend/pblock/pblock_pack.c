/*
 * pblock_pack.c — phase-88 W2: the packed small-blob arena. See pblock_pack.h.
 *
 * WHAT: Implements the arena: catalog `pack` table (blob_id → seg/off/len),
 *       flock-serialised record appends into <root>/pack/seg-<n>.dat, memfd
 *       read-serving, materialise-back, and row/segment reaping.
 *
 * HOW:  Records are the shared "BXS1" layout (shared/cache/cas_pack_format.h),
 *       keyed by blob_id, always fmt 0 (raw — a packed blob requires xform
 *       NONE). The append protocol under pack/.lock is: resolve the active
 *       segment (highest seg-<n>.dat, rolling at PBLOCK_PACK_SEG_BYTES) →
 *       pwrite header+key+data at its tail → fdatasync → INSERT the pack row →
 *       unlock. Because the row lands before the lock releases, the reap check
 *       (count(seg)==0, also under the lock) can never unlink a segment an
 *       in-flight append is targeting. Whole-record crc32 is verified on every
 *       decode (memfd open / materialise) — damage is EIO, never wrong bytes.
 *       ngx-free (libc + sqlite3 + zlib); BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* memfd_create, F_ADD_SEALS */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"
#include "pblock_pack.h"
#include "pblock_pack_internal.h"          /* pack_seg_path / pack_lock / … */
#include "sd_pblock_catalog_internal.h"   /* cat_exec / cat_prepare / cat_fail */
#include "cache/cas_pack_format.h"        /* the shared "BXS1" record layout */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ---- small file helpers --------------------------------------------------- */

/* pack_pread_full / pack_pwrite_full / pack_seg_path / pack_lock /
 * pack_active_seg live in pblock_pack_seg.c (file-size split); declared in
 * pblock_pack_internal.h. */

/* ---- catalog rows --------------------------------------------------------- */

int
pblock_pack_arm(pblock_state_t *st)
{
    char dirp[PATH_MAX];

    if (cat_exec(st->cat,
            "CREATE TABLE IF NOT EXISTS pack("
            "  blob_id TEXT PRIMARY KEY,"
            "  seg INTEGER NOT NULL,"
            "  off INTEGER NOT NULL,"
            "  len INTEGER NOT NULL);") != 0
        || cat_exec(st->cat,
            "CREATE INDEX IF NOT EXISTS pack_seg ON pack(seg);") != 0)
    {
        return -1;
    }
    if (snprintf(dirp, sizeof(dirp), "%s/pack", st->root) >= (int) sizeof(dirp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return pblock_mkdir_p(dirp);
}

int
pblock_pack_find(const pblock_state_t *st, const char *blob_id,
    pblock_pack_loc_t *out)
{
    sqlite3_stmt *q;
    int           rc;

    q = cat_prepare(st->cat,
        "SELECT seg, off, len FROM pack WHERE blob_id = ?1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    if (rc == SQLITE_ROW) {
        out->seg = sqlite3_column_int64(q, 0);
        out->off = sqlite3_column_int64(q, 1);
        out->len = sqlite3_column_int64(q, 2);
        sqlite3_finalize(q);
        return 0;
    }
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 1 : cat_fail(EIO);
}

/* pack_row_insert / pack_row_delete / pack_seg_live — tiny row CRUD. */
static int
pack_row_insert(const pblock_state_t *st, const char *blob_id, int64_t seg,
    int64_t off, int64_t len)
{
    sqlite3_stmt *q = cat_prepare(st->cat,
        "INSERT OR REPLACE INTO pack(blob_id, seg, off, len)"
        " VALUES(?1, ?2, ?3, ?4);");
    int           rc;

    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, seg);
    sqlite3_bind_int64(q, 3, off);
    sqlite3_bind_int64(q, 4, len);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

static void
pack_row_delete(const pblock_state_t *st, const char *blob_id)
{
    sqlite3_stmt *q = cat_prepare(st->cat,
        "DELETE FROM pack WHERE blob_id = ?1;");

    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

/* Rows still referencing `seg` (-1 on a catalog error — treated as "live" so
 * a reap can never race a failing count into data loss). */
static int64_t
pack_seg_live(const pblock_state_t *st, int64_t seg)
{
    sqlite3_stmt *q = cat_prepare(st->cat,
        "SELECT COUNT(*) FROM pack WHERE seg = ?1;");
    int64_t       live = -1;

    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_int64(q, 1, seg);
    if (sqlite3_step(q) == SQLITE_ROW) {
        live = sqlite3_column_int64(q, 0);
    }
    sqlite3_finalize(q);
    return live;
}

/* pack_seg_reap — under the arena lock, unlink `seg` once no rows reference
 * it. Safe against appends: they insert their row before unlocking. */
static void
pack_seg_reap(const pblock_state_t *st, int64_t seg)
{
    char segp[PATH_MAX];
    int  lockfd = pack_lock(st);

    if (lockfd < 0) {
        return;
    }
    if (pack_seg_live(st, seg) == 0
        && pack_seg_path(st, seg, segp, sizeof(segp)) == 0)
    {
        (void) unlink(segp);
    }
    close(lockfd);          /* closing releases the flock */
}

/* ---- record decode (shared by memfd-open and materialise) ----------------- */

/* pack_hdr_check — decode a just-read record header and shape-check it against
 * the expected blob (fmt 0, matching klen, raw==stored==expect_len, key match);
 * fills *rec. 0 when sound, -1 on any mismatch (caller maps to EIO). */
static int
pack_hdr_check(const unsigned char *hdr, const char *blob_id, size_t klen,
    int64_t expect_len, brix_pack_rec_t *rec)
{
    if (brix_pack_seg_decode(hdr, rec) != 0
        || rec->klen != klen
        || rec->fmt != 0
        || rec->stored != rec->raw
        || (int64_t) rec->raw != expect_len
        || memcmp(hdr + SEG_HDR, blob_id, klen) != 0)
    {
        return -1;
    }
    return 0;
}

/* pack_read_record — open the record's segment, decode + shape-check its
 * header against the expected blob, then read + crc-verify the data into a
 * malloc'd buffer. Returns the buffer (caller frees) or NULL/errno (EIO for
 * any damage — a packed record is served verified or not at all). */
static unsigned char *
pack_read_record(const pblock_state_t *st, const char *blob_id,
    const pblock_pack_loc_t *loc, int64_t expect_len)
{
    char             segp[PATH_MAX];
    unsigned char    hdr[SEG_HDR + PACK_KMAX];
    brix_pack_rec_t  rec;
    unsigned char   *data;
    size_t           klen = strlen(blob_id);
    int              segfd;

    if (klen == 0 || klen > PACK_KMAX
        || pack_seg_path(st, loc->seg, segp, sizeof(segp)) != 0)
    {
        errno = EINVAL;
        return NULL;
    }
    segfd = open(segp, O_RDONLY | O_CLOEXEC);
    if (segfd < 0) {
        errno = EIO;            /* row without a segment = damage, not ENOENT */
        return NULL;
    }
    if (pack_pread_full(segfd, hdr, SEG_HDR + klen, (off_t) loc->off) != 0
        || pack_hdr_check(hdr, blob_id, klen, expect_len, &rec) != 0)
    {
        close(segfd);
        errno = EIO;
        return NULL;
    }

    data = malloc(rec.stored ? (size_t) rec.stored : 1);
    if (data == NULL) {
        close(segfd);
        errno = ENOMEM;
        return NULL;
    }
    if (pack_pread_full(segfd, data, (size_t) rec.stored,
                        (off_t) (loc->off + SEG_HDR + (int64_t) klen)) != 0
        || crc_of(data, (size_t) rec.stored) != rec.crc)
    {
        close(segfd);
        free(data);
        errno = EIO;
        return NULL;
    }
    close(segfd);
    return data;
}

/* ---- the public verbs ----------------------------------------------------- */

/* pack_open_admit_seg — open the segment that will receive a `size`-byte record
 * for a `klen`-byte key, first rolling to the next segment when appending here
 * would push it past PBLOCK_PACK_SEG_BYTES. On success returns the open (O_RDWR)
 * segfd, writing the chosen segment number to *seg and its tail offset to *off;
 * -1/errno on failure. Caller holds the arena lock (active seg is stable). */
static int
pack_open_admit_seg(const pblock_state_t *st, size_t klen, int64_t size,
    int64_t *seg, off_t *off)
{
    char        segp[PATH_MAX];
    struct stat segst;
    int64_t     s = pack_active_seg(st);
    int         segfd;

    if (s == 0) {
        s = 1;
    }
    if (pack_seg_path(st, s, segp, sizeof(segp)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    segfd = open(segp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (segfd >= 0 && fstat(segfd, &segst) == 0
        && segst.st_size > 0
        && segst.st_size + (off_t) (SEG_HDR + klen) + (off_t) size
           > (off_t) PBLOCK_PACK_SEG_BYTES)
    {
        /* Roll to the next segment before this record would overgrow it. */
        close(segfd);
        segfd = -1;
        s++;
        if (pack_seg_path(st, s, segp, sizeof(segp)) == 0) {
            segfd = open(segp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        }
    }
    if (segfd < 0 || fstat(segfd, &segst) != 0) {
        int err = errno;

        if (segfd >= 0) { close(segfd); }
        errno = err;
        return -1;
    }
    *seg = s;
    *off = segst.st_size;
    return segfd;
}

/* pack_write_record — encode and durably append one record (header+key+data) at
 * `off` in segfd, retracting a torn tail on failure. 0 on success, -1/errno.
 * Caller holds the arena lock. */
static int
pack_write_record(int segfd, const char *blob_id, const unsigned char *data,
    int64_t size, size_t klen, off_t off)
{
    unsigned char   hdr[SEG_HDR + PACK_KMAX];
    brix_pack_rec_t rec;

    rec.klen   = klen;
    rec.fmt    = 0;
    rec.crc    = crc_of(data, (size_t) size);
    rec.stored = (uint64_t) size;
    rec.raw    = (uint64_t) size;
    brix_pack_seg_encode(hdr, blob_id, &rec);

    if (pack_pwrite_full(segfd, hdr, SEG_HDR + klen, off) != 0
        || pack_pwrite_full(segfd, data, (size_t) size,
                            off + (off_t) (SEG_HDR + klen)) != 0
        || fdatasync(segfd) != 0)
    {
        int err = errno;

        if (ftruncate(segfd, off) != 0) {
            /* best-effort retract of the torn tail — the original pwrite/sync
             * error verdict (err) stands either way */
        }
        errno = err;
        return -1;
    }
    return 0;
}

int
pblock_pack_admit(pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs)
{
    unsigned char   *data;
    size_t           klen = strlen(blob_id);
    int64_t          seg;
    off_t            off;
    ssize_t          got;
    int              lockfd, segfd;

    if (size <= 0 || klen == 0 || klen > PACK_KMAX) {
        errno = EINVAL;
        return -1;
    }
    data = malloc((size_t) size);
    if (data == NULL) {
        errno = ENOMEM;
        return -1;
    }
    /* Read through the block engine (holes read as zeros), never raw off the
     * block-0 file — the blob's logical bytes are what the record must carry. */
    got = pblock_read_blocks(st, blob_id, bs, -1, data, (size_t) size, 0);
    if (got != (ssize_t) size) {
        free(data);
        errno = got < 0 ? errno : EIO;
        return -1;
    }

    lockfd = pack_lock(st);
    if (lockfd < 0) {
        free(data);
        return -1;
    }

    segfd = pack_open_admit_seg(st, klen, size, &seg, &off);
    if (segfd < 0) {
        int err = errno;

        close(lockfd);
        free(data);
        errno = err;
        return -1;
    }

    if (pack_write_record(segfd, blob_id, data, size, klen, off) != 0) {
        int err = errno;

        close(segfd);
        close(lockfd);
        free(data);
        errno = err;
        return -1;
    }
    close(segfd);
    free(data);

    if (pack_row_insert(st, blob_id, seg, (int64_t) off, size) != 0) {
        close(lockfd);
        return -1;                        /* record is an fsck-collectable orphan */
    }
    close(lockfd);

    /* The record is durable and indexed — the striped copy is now redundant. */
    pblock_remove_blocks(st, blob_id, size, bs);
    return 0;
}

int
pblock_pack_open_memfd(const pblock_state_t *st, const pblock_meta *meta)
{
    pblock_pack_loc_t loc;
    unsigned char    *data;
    int               fd, rc;

    rc = pblock_pack_find(st, meta->blob_id, &loc);
    if (rc != 0) {
        errno = rc > 0 ? ENOENT : EIO;
        return -1;
    }
    data = pack_read_record(st, meta->blob_id, &loc, meta->size);
    if (data == NULL) {
        return -1;                        /* errno set (EIO family) */
    }

    fd = memfd_create(meta->blob_id, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        free(data);
        return -1;
    }
    if (pack_pwrite_full(fd, data, (size_t) meta->size, 0) != 0) {
        int err = errno;

        close(fd);
        free(data);
        errno = err;
        return -1;
    }
    free(data);
    /* Best-effort seals: the handle is read-intent, so freezing the bytes is
     * pure hardening — never a functional dependency. */
    (void) fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE);
    return fd;
}

int
pblock_pack_materialize(pblock_state_t *st, const pblock_meta *meta)
{
    pblock_pack_loc_t loc;
    unsigned char    *data;
    ssize_t           put;
    int               rc;

    if (!st->pack) {
        return 0;
    }
    rc = pblock_pack_find(st, meta->blob_id, &loc);
    if (rc != 0) {
        if (rc > 0) {
            return 0;                     /* not packed — nothing to do */
        }
        errno = EIO;
        return -1;
    }
    data = pack_read_record(st, meta->blob_id, &loc, meta->size);
    if (data == NULL) {
        return -1;
    }
    if (pblock_ensure_obj_dir(st, meta->blob_id) != 0) {
        free(data);
        return -1;
    }
    put = pblock_write_blocks(st, meta->blob_id, meta->block_size, -1, data,
                              (size_t) meta->size, 0);
    free(data);
    if (put != (ssize_t) meta->size) {
        errno = put < 0 ? errno : EIO;
        return -1;
    }
    pack_row_delete(st, meta->blob_id);
    pack_seg_reap(st, loc.seg);
    return 0;
}

void
pblock_pack_del(const pblock_state_t *st, const char *blob_id)
{
    pblock_pack_loc_t loc;

    if (!st->pack || pblock_pack_find(st, blob_id, &loc) != 0) {
        return;
    }
    pack_row_delete(st, blob_id);
    pack_seg_reap(st, loc.seg);
}

ssize_t
pblock_pack_or_block_read(const pblock_state_t *st, const char *blob_id,
    int64_t bs, void *buf, size_t len, off_t off)
{
    pblock_pack_loc_t loc;
    char              segp[PATH_MAX];
    size_t            klen = strlen(blob_id);
    size_t            want = len;
    int               segfd, rc;

    if (!st->pack || (rc = pblock_pack_find(st, blob_id, &loc)) > 0) {
        return pblock_read_blocks(st, blob_id, bs, -1, buf, len, off);
    }
    if (rc < 0) {
        errno = EIO;
        return -1;
    }
    if (off >= (off_t) loc.len) {
        return 0;
    }
    if ((off_t) want > (off_t) loc.len - off) {
        want = (size_t) ((off_t) loc.len - off);
    }
    if (pack_seg_path(st, loc.seg, segp, sizeof(segp)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    segfd = open(segp, O_RDONLY | O_CLOEXEC);
    if (segfd < 0) {
        errno = EIO;
        return -1;
    }
    if (pack_pread_full(segfd, buf, want,
            (off_t) (loc.off + SEG_HDR + (int64_t) klen) + off) != 0)
    {
        int err = errno;

        close(segfd);
        errno = err;
        return -1;
    }
    close(segfd);
    return (ssize_t) want;
}

#endif /* BRIX_HAVE_SQLITE */
