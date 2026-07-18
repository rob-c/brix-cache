/*
 * pblock_refs.c — F10 refcounted blobs + content-addressed dedup for pblock.
 *
 * WHAT: Implements pblock_refs.h: the `blobs` refcount table, reference
 *       bookkeeping (track/bump/count/release), publish-time dedup with a
 *       mandatory byte-verify, and the copy-on-write share-break.
 *
 * HOW:  Row absence = implicit refcount 1 (legacy blobs), so every reader
 *       treats "no row" and "refcount 1" identically. A hash match is never
 *       trusted on its own: dedup byte-compares both blobs through the block
 *       engine before linking. Release fails CLOSED on a DB error — blocks are
 *       kept (an fsck-collectable orphan at worst), never removed while a
 *       sibling row may still reference them. ngx-free (libc + sqlite3);
 *       BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_csi.h"
#include "sd_pblock_internal.h"
#include "pblock_refs.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec/cat_prepare, nscache_inval */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

int
pblock_refs_init(pblock_state_t *st)
{
    if (cat_exec(st->cat,
            "CREATE TABLE IF NOT EXISTS blobs("
            "  blob_id TEXT PRIMARY KEY,"
            "  refcount INTEGER NOT NULL DEFAULT 1,"
            "  size INTEGER NOT NULL DEFAULT 0,"
            "  block_size INTEGER NOT NULL DEFAULT 0,"
            "  content_hash TEXT NOT NULL DEFAULT '');") != 0)
    {
        return -1;
    }
    return cat_exec(st->cat,
        "CREATE INDEX IF NOT EXISTS blobs_hash ON blobs(content_hash);");
}

int
pblock_refs_track(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs, uint32_t crc, int crc_ok)
{
    sqlite3_stmt *q;
    char          hash[24];
    int           rc;

    if (crc_ok) {
        snprintf(hash, sizeof(hash), "crc32:%08x", crc);
    } else {
        hash[0] = '\0';
    }
    q = cat_prepare(st->cat,
        "INSERT INTO blobs(blob_id, refcount, size, block_size, content_hash)"
        " VALUES(?1, 1, ?2, ?3, ?4)"
        " ON CONFLICT(blob_id) DO UPDATE SET"
        "  size = excluded.size, block_size = excluded.block_size,"
        "  content_hash = excluded.content_hash;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, size);
    sqlite3_bind_int64(q, 3, bs);
    sqlite3_bind_text(q, 4, hash, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

int
pblock_refs_bump(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs)
{
    sqlite3_stmt *q;
    int           rc;

    /* A missing row carries the implicit legacy reference — created here as 2:
     * that reference plus the new one. */
    q = cat_prepare(st->cat,
        "INSERT INTO blobs(blob_id, refcount, size, block_size, content_hash)"
        " VALUES(?1, 2, ?2, ?3, '')"
        " ON CONFLICT(blob_id) DO UPDATE SET refcount = refcount + 1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, size);
    sqlite3_bind_int64(q, 3, bs);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

int
pblock_refs_count(const pblock_state_t *st, const char *blob_id)
{
    sqlite3_stmt *q;
    int           n = 1;                  /* absent row = implicit single ref */
    int           rc;

    q = cat_prepare(st->cat,
        "SELECT refcount FROM blobs WHERE blob_id = ?1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    if (rc == SQLITE_ROW) {
        n = sqlite3_column_int(q, 0);
        if (n < 1) {
            n = 1;
        }
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(q);
        return cat_fail(EIO);
    }
    sqlite3_finalize(q);
    return n;
}

/* refs_drop_row — delete a blob's tracking row (last reference gone). */
static void
refs_drop_row(const pblock_state_t *st, const char *blob_id)
{
    sqlite3_stmt *q;

    q = cat_prepare(st->cat, "DELETE FROM blobs WHERE blob_id = ?1;");
    if (q == NULL) {
        return;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    (void) sqlite3_step(q);
    sqlite3_finalize(q);
}

/* refs_remove — physically remove a blob: block files + csi rows. */
static void
refs_remove(const pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs)
{
    pblock_remove_blocks(st, blob_id, size, bs);
    if (st->csi) {
        pblock_csi_drop(st->cat, blob_id);
    }
}

void
pblock_refs_release(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs)
{
    int n;

    if (!st->refs) {                     /* gate off: the pre-F10 removal */
        refs_remove(st, blob_id, size, bs);
        return;
    }
    n = pblock_refs_count(st, blob_id);
    if (n < 0) {
        return;                          /* fail closed: keep the blocks — an
                                          * fsck orphan beats removing bytes a
                                          * sibling row may still reference */
    }
    if (n <= 1) {
        refs_drop_row(st, blob_id);
        refs_remove(st, blob_id, size, bs);
        return;
    }
    {
        sqlite3_stmt *q = cat_prepare(st->cat,
            "UPDATE blobs SET refcount = refcount - 1 WHERE blob_id = ?1;");

        if (q != NULL) {
            sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
            (void) sqlite3_step(q);
            sqlite3_finalize(q);
        }
    }
}

/* refs_repoint — point the object row for `path` at a different blob. The
 * nscache holds the old row, so it must be invalidated. 0 or -1/errno. */
static int
refs_repoint(pblock_state_t *st, const char *path, const char *blob_id)
{
    sqlite3_stmt *q;
    int           rc;

    q = cat_prepare(st->cat,
        "UPDATE objects SET blob_id = ?2 WHERE path = ?1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(q, 2, blob_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    nscache_inval(st->cat, path);
    return 0;
}

/* refs_same_bytes — full byte compare of two blobs over [0, size) through the
 * block engine (transient block fds). 1 identical, 0 different, -1/errno. */
static int
refs_same_bytes(const pblock_state_t *st, const char *a, const char *b,
    int64_t size, int64_t bs)
{
    char    ba[32768], bb[32768];
    int64_t off = 0;

    while (off < size) {
        size_t  chunk = (size_t) (size - off) < sizeof(ba)
                            ? (size_t) (size - off) : sizeof(ba);
        ssize_t ra = pblock_read_blocks(st, a, bs, -1, ba, chunk, (off_t) off);
        ssize_t rb = pblock_read_blocks(st, b, bs, -1, bb, chunk, (off_t) off);

        if (ra < 0 || rb < 0) {
            return -1;
        }
        if (ra != rb || memcmp(ba, bb, (size_t) ra) != 0) {
            return 0;
        }
        if (ra == 0) {                   /* both short (hole tail): equal so far */
            break;
        }
        off += ra;
    }
    return 1;
}

int
pblock_refs_dedup_publish(pblock_state_t *st, const char *path,
    pblock_meta *meta, uint32_t crc, int crc_ok)
{
    sqlite3_stmt *q;
    char          hash[24];
    char          match[PBLOCK_BLOB_ID_CAP];
    int           found = 0;

    /* No trustworthy whole-object hash, an empty object, or a blob that is
     * already shared (folding it would strand the sibling): just (re)track. */
    if (!crc_ok || meta->size <= 0
        || pblock_refs_count(st, meta->blob_id) != 1)
    {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, crc, crc_ok);
    }

    snprintf(hash, sizeof(hash), "crc32:%08x", crc);
    q = cat_prepare(st->cat,
        "SELECT blob_id FROM blobs"
        " WHERE content_hash = ?1 AND size = ?2 AND block_size = ?3"
        "   AND blob_id != ?4 AND refcount >= 1;");
    if (q == NULL) {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, crc, crc_ok);
    }
    sqlite3_bind_text(q, 1, hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, meta->size);
    sqlite3_bind_int64(q, 3, meta->block_size);
    sqlite3_bind_text(q, 4, meta->blob_id, -1, SQLITE_STATIC);
    while (!found && sqlite3_step(q) == SQLITE_ROW) {
        const unsigned char *id = sqlite3_column_text(q, 0);

        if (id == NULL) {
            continue;
        }
        snprintf(match, sizeof(match), "%s", (const char *) id);
        /* The hash only nominates: a CRC collision (or a forged row) must
         * never alias content, so every candidate is byte-verified. */
        if (refs_same_bytes(st, meta->blob_id, match, meta->size,
                            meta->block_size) == 1)
        {
            found = 1;
        }
    }
    sqlite3_finalize(q);

    if (!found) {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, crc, crc_ok);
    }

    if (pblock_refs_bump(st, match, meta->size, meta->block_size) != 0) {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, crc, crc_ok);
    }
    if (refs_repoint(st, path, match) != 0) {
        pblock_refs_release(st, match, meta->size, meta->block_size);
        return -1;
    }
    pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
    snprintf(meta->blob_id, sizeof(meta->blob_id), "%s", match);
    return 1;
}

int
pblock_refs_break_share(pblock_state_t *st, const char *path,
    pblock_meta *meta, int trunc)
{
    char    fresh[PBLOCK_BLOB_ID_CAP];
    int64_t last, i;
    int     n;

    n = pblock_refs_count(st, meta->blob_id);
    if (n < 0) {
        errno = EIO;                     /* can't prove the blob is private —
                                          * refuse the write open, never write
                                          * through a possibly-shared blob */
        return -1;
    }
    if (n <= 1) {
        return 0;                        /* already private */
    }

    if (pblock_gen_blob_id(fresh) != 0
        || pblock_ensure_obj_dir(st, fresh) != 0)
    {
        return -1;
    }

    if (trunc) {
        /* Content is being replaced: start from an empty block 0 (the open
         * path expects the file to exist) instead of copying doomed bytes. */
        char bp[PATH_MAX];
        int  fd;

        if (pblock_block_path(st, fresh, 0, bp, sizeof(bp)) != 0) {
            return -1;
        }
        fd = open(bp, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            return -1;
        }
        close(fd);
    } else {
        last = pblock_last_block(meta->size, meta->block_size);
        for (i = 0; i <= last; i++) {
            char sp[PATH_MAX], dp[PATH_MAX];

            if (pblock_block_path(st, meta->blob_id, i, sp, sizeof(sp)) != 0
                || pblock_block_path(st, fresh, i, dp, sizeof(dp)) != 0
                || pblock_copy_one_block(sp, dp) < 0)
            {
                int err = errno;

                pblock_remove_blocks(st, fresh, meta->size, meta->block_size);
                errno = err;
                return -1;
            }
        }
    }

    if (refs_repoint(st, path, fresh) != 0) {
        int err = errno;

        pblock_remove_blocks(st, fresh, meta->size, meta->block_size);
        errno = err;
        return -1;
    }
    if (st->csi && !trunc) {
        /* Carry the at-rest CRCs to the private copy (same bytes, same tags);
         * best-effort — missing tags read as "unset", never as corruption. */
        sqlite3_stmt *q = cat_prepare(st->cat,
            "INSERT OR REPLACE INTO csi(blob_id, block_no, crc)"
            " SELECT ?2, block_no, crc FROM csi WHERE blob_id = ?1;");

        if (q != NULL) {
            sqlite3_bind_text(q, 1, meta->blob_id, -1, SQLITE_STATIC);
            sqlite3_bind_text(q, 2, fresh, -1, SQLITE_STATIC);
            (void) sqlite3_step(q);
            sqlite3_finalize(q);
        }
    }
    (void) pblock_refs_track(st, fresh, meta->size, meta->block_size, 0, 0);
    pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
    snprintf(meta->blob_id, sizeof(meta->blob_id), "%s", fresh);
    return 0;
}

#endif /* BRIX_HAVE_SQLITE */
