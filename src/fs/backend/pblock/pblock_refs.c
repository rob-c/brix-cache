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
#include "pblock_pack.h"                  /* W2: pack-aware reads + record del */
#include "core/compat/wverify.h"          /* on-demand whole-object CRC (W1) */

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

void
pblock_refs_wv_hash(const brix_wverify_t *wv, int64_t size, char *out,
    size_t cap)
{
    unsigned char sha[32];
    uint32_t      crc = 0;
    off_t         total = 0;

    out[0] = '\0';
    if (wv == NULL
        || brix_wverify_expected(wv, &crc, &total) != 0
        || (int64_t) total != size)
    {
        return;                     /* incomplete/degraded — no hash at all */
    }
    if (brix_wverify_expected_sha256(wv, sha) == 0) {
        size_t i;
        int    n = snprintf(out, cap, "sha256:");

        if (n < 0 || (size_t) n + 64 >= cap) {
            out[0] = '\0';
            return;
        }
        for (i = 0; i < 32; i++) {
            snprintf(out + n + i * 2, 3, "%02x", sha[i]);
        }
        return;
    }
    snprintf(out, cap, "crc32:%08x", crc);
}

int
pblock_refs_track(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs, const char *hash)
{
    sqlite3_stmt *q;
    int           rc;

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
    sqlite3_bind_text(q, 4, hash != NULL ? hash : "", -1, SQLITE_STATIC);
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

/* refs_remove — physically remove a blob: block files, any packed-arena
 * record (phase-88 W2), and csi rows. */
static void
refs_remove(const pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs)
{
    pblock_remove_blocks(st, blob_id, size, bs);
    pblock_pack_del(st, blob_id);
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

/* refs_same_bytes — full byte compare of two blobs over [0, size), each read
 * from whichever layout holds it (striped blocks or a packed-arena record —
 * phase-88 W2: dedup candidates may rest packed). 1 identical, 0 different,
 * -1/errno. */
static int
refs_same_bytes(const pblock_state_t *st, const char *a, const char *b,
    int64_t size, int64_t bs)
{
    char    ba[32768], bb[32768];
    int64_t off = 0;

    while (off < size) {
        size_t  chunk = (size_t) (size - off) < sizeof(ba)
                            ? (size_t) (size - off) : sizeof(ba);
        ssize_t ra = pblock_pack_or_block_read(st, a, bs, ba, chunk,
                                               (off_t) off);
        ssize_t rb = pblock_pack_or_block_read(st, b, bs, bb, chunk,
                                               (off_t) off);

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

/* refs_fold_by_hash — fold `path`'s (private) blob onto an identical
 * candidate nominated by the content-hash string `hash`. Returns 1 (folded —
 * meta->blob_id updated to the survivor), 0 (no candidate survived / the
 * bookkeeping declined — caller keeps its blob), or -1/errno on a hard
 * failure mid-fold (the object row may already point at the survivor).
 * W3 trust split: a "sha256:" hash IS the content identity — the first
 * candidate folds outright (forging a row means writing catalog.db, i.e.
 * owning the store); any other prefix ("crc32:" legacy) only NOMINATES and
 * every candidate is byte-verified, so a CRC collision can never alias. */
static int
refs_fold_by_hash(pblock_state_t *st, const char *path, pblock_meta *meta,
    const char *hash)
{
    sqlite3_stmt *q;
    char          match[PBLOCK_BLOB_ID_CAP];
    int           trusted = strncmp(hash, "sha256:", 7) == 0;
    int           found = 0;

    q = cat_prepare(st->cat,
        "SELECT blob_id FROM blobs"
        " WHERE content_hash = ?1 AND size = ?2 AND block_size = ?3"
        "   AND blob_id != ?4 AND refcount >= 1;");
    if (q == NULL) {
        return 0;
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
        if (trusted
            || refs_same_bytes(st, meta->blob_id, match, meta->size,
                               meta->block_size) == 1)
        {
            found = 1;
        }
    }
    sqlite3_finalize(q);

    if (!found) {
        return 0;
    }

    if (pblock_refs_bump(st, match, meta->size, meta->block_size) != 0) {
        return 0;
    }
    if (refs_repoint(st, path, match) != 0) {
        pblock_refs_release(st, match, meta->size, meta->block_size);
        return -1;
    }
    pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
    snprintf(meta->blob_id, sizeof(meta->blob_id), "%s", match);
    return 1;
}

/*
 * WHAT: Populate a fresh private blob for a copy-on-write break.
 * WHY:  Truncation needs one empty block while ordinary writes clone all blocks.
 * HOW:  Create the object directory, then initialize or copy with rollback.
 */
static int
refs_populate_private(pblock_state_t *st, const pblock_meta *meta,
    const char *fresh, int trunc)
{
    if (pblock_ensure_obj_dir(st, fresh) != 0)
        return -1;
    if (trunc) {
        char path[PATH_MAX];
        int  fd;

        if (pblock_block_path(st, fresh, 0, path, sizeof(path)) != 0)
            return -1;
        fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            return -1;
        close(fd);
        return 0;
    }
    for (int64_t block = 0;
         block <= pblock_last_block(meta->size, meta->block_size); block++) {
        char source[PATH_MAX], destination[PATH_MAX];

        if (pblock_block_path(st, meta->blob_id, block, source,
                             sizeof(source)) != 0 ||
            pblock_block_path(st, fresh, block, destination,
                             sizeof(destination)) != 0 ||
            pblock_copy_one_block(source, destination) < 0) {
            int err = errno;

            pblock_remove_blocks(st, fresh, meta->size, meta->block_size);
            errno = err;
            return -1;
        }
    }
    return 0;
}

/*
 * WHAT: Copy at-rest CRC rows from a shared blob to its byte-identical clone.
 * WHY:  A private copy retains the same integrity tags when CSI is enabled.
 * HOW:  Insert-select all source rows under the fresh blob id, best effort.
 */
static void
refs_copy_csi(pblock_state_t *st, const char *source, const char *fresh)
{
    sqlite3_stmt *query = cat_prepare(st->cat,
        "INSERT OR REPLACE INTO csi(blob_id, block_no, crc)"
        " SELECT ?2, block_no, crc FROM csi WHERE blob_id = ?1;");

    if (query == NULL)
        return;
    sqlite3_bind_text(query, 1, source, -1, SQLITE_STATIC);
    sqlite3_bind_text(query, 2, fresh, -1, SQLITE_STATIC);
    (void) sqlite3_step(query);
    sqlite3_finalize(query);
}

int
pblock_refs_dedup_publish(pblock_state_t *st, const char *path,
    pblock_meta *meta, const char *hash)
{
    int rc;

    if (hash == NULL) {
        hash = "";
    }
    /* No trustworthy whole-object hash, an empty object, or a blob that is
     * already shared (folding it would strand the sibling): just (re)track. */
    if (hash[0] == '\0' || meta->size <= 0
        || pblock_refs_count(st, meta->blob_id) != 1)
    {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, hash);
    }

    rc = refs_fold_by_hash(st, path, meta, hash);
    if (rc == 0) {
        return pblock_refs_track(st, meta->blob_id, meta->size,
                                 meta->block_size, hash);
    }
    return rc;
}

/* refs_stored_hash — read the recorded content-hash string of a blob into
 * out[cap]. Returns 1 (a non-empty hash was recorded), 0 (no row / empty hash
 * — the blob is out of the candidate pool), or -1/errno on a DB error. */
static int
refs_stored_hash(const pblock_state_t *st, const char *blob_id, char *out,
    size_t cap)
{
    sqlite3_stmt *q;
    int           rc;
    int           have = 0;

    out[0] = '\0';
    q = cat_prepare(st->cat,
        "SELECT content_hash FROM blobs WHERE blob_id = ?1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, blob_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    if (rc == SQLITE_ROW) {
        const unsigned char *h = sqlite3_column_text(q, 0);

        if (h != NULL && h[0] != '\0') {
            snprintf(out, cap, "%s", (const char *) h);
            have = 1;
        }
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(q);
        return cat_fail(EIO);
    }
    sqlite3_finalize(q);
    return have;
}

/* refs_compute_hash — the "sha256:<hex>" identity of a blob read back through
 * whichever layout holds it: the on-demand twin of the write path's in-order
 * accumulator, so a computed hash lands in the same candidate pool the
 * commit-time hashes live in. Fills out[cap] (cap >= PBLOCK_REFS_HASH_CAP);
 * 0 or -1/errno (a short read fails closed). */
static int
refs_compute_hash(const pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs, char *out, size_t cap)
{
    brix_wverify_t *wv;
    char             buf[32768];
    int64_t          off = 0;

    wv = brix_wverify_begin();
    if (wv == NULL) {
        errno = ENOMEM;
        return -1;
    }
    while (off < size) {
        size_t  chunk = (size_t) (size - off) < sizeof(buf)
                            ? (size_t) (size - off) : sizeof(buf);
        ssize_t n = pblock_pack_or_block_read(st, blob_id, bs, buf, chunk,
                                              (off_t) off);

        if (n <= 0 || brix_wverify_update(wv, buf, (off_t) off, (size_t) n) != 0) {
            brix_wverify_free(wv);
            errno = n < 0 ? errno : EIO;
            return -1;
        }
        off += n;
    }
    pblock_refs_wv_hash(wv, size, out, cap);
    brix_wverify_free(wv);
    if (out[0] == '\0') {
        errno = EIO;
        return -1;
    }
    return 0;
}

int
pblock_refs_dedup_existing(pblock_state_t *st, const char *path)
{
    pblock_meta meta;
    char        hash[PBLOCK_REFS_HASH_CAP];
    int         rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc != 0) {
        errno = rc > 0 ? ENOENT : errno;
        return -1;
    }
    if (meta.is_dir || meta.size <= 0) {
        return 0;
    }
    /* Fold only a provably-private blob: an already-shared blob is dedup'd by
     * definition, and a count error must never nominate a fold. */
    if (pblock_refs_count(st, meta.blob_id) != 1) {
        return 0;
    }
    rc = refs_stored_hash(st, meta.blob_id, hash, sizeof(hash));
    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        /* No trustworthy hash recorded (a legacy blob, or an out-of-order
         * write history forfeited it): compute the sha256 identity from the
         * stored bytes so the caller's verified object can still join the
         * candidate pool. Recording it also lets FUTURE commits nominate
         * this blob. */
        if (refs_compute_hash(st, meta.blob_id, meta.size, meta.block_size,
                              hash, sizeof(hash)) != 0
            || pblock_refs_track(st, meta.blob_id, meta.size,
                                 meta.block_size, hash) != 0)
        {
            return -1;
        }
    }
    return refs_fold_by_hash(st, path, &meta, hash);
}

int
pblock_refs_break_share(pblock_state_t *st, const char *path,
    pblock_meta *meta, int trunc)
{
    char fresh[PBLOCK_BLOB_ID_CAP];
    int  count;

    /* phase-88 W2: the copy loop below walks block files — a packed shared
     * blob must come back to the striped layout first (its other sharers are
     * unaffected: same blob_id, same bytes). */
    if (st->pack && pblock_pack_materialize(st, meta) != 0) {
        return -1;
    }

    count = pblock_refs_count(st, meta->blob_id);
    if (count < 0) {
        errno = EIO;                     /* can't prove the blob is private —
                                          * refuse the write open, never write
                                          * through a possibly-shared blob */
        return -1;
    }
    if (count <= 1)
        return 0;
    if (pblock_gen_blob_id(fresh) != 0 ||
        refs_populate_private(st, meta, fresh, trunc) != 0)
        return -1;

    if (refs_repoint(st, path, fresh) != 0) {
        int err = errno;

        pblock_remove_blocks(st, fresh, meta->size, meta->block_size);
        errno = err;
        return -1;
    }
    if (st->csi && !trunc)
        refs_copy_csi(st, meta->blob_id, fresh);
    (void) pblock_refs_track(st, fresh, meta->size, meta->block_size, NULL);
    pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
    snprintf(meta->blob_id, sizeof(meta->blob_id), "%s", fresh);
    return 0;
}

#endif /* BRIX_HAVE_SQLITE */
