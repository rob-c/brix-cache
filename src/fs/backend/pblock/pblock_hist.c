/*
 * pblock_hist.c — F11 versioning + trash/undelete for the pblock driver.
 *
 * WHAT: Implements pblock_hist.h — the `versions`/`trash` tables, the push
 *       (capture) primitives called on overwrite/unlink, version trimming, the
 *       undelete pop, and the reserved-namespace control dispatch.
 *
 * HOW:  Held blobs use the F10 explicit refcount arithmetic. push bumps the blob
 *       BEFORE the caller's release so the reference is transferred (copy-on-
 *       write) from the live object to the history row without the refcount ever
 *       reaching 0 — the blocks are never freed mid-move. trim/undelete release
 *       symmetrically. Paths are only ever bound column values, so a hostile
 *       name can neither inject nor traverse. ngx-free (libc + sqlite3);
 *       BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_hist.h"
#include "pblock_refs.h"                 /* F10 explicit bump/release */
#include "sd_pblock_catalog_internal.h"  /* cat_exec/cat_prepare/cat_fail */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

int
pblock_hist_init(pblock_state_t *st)
{
    return cat_exec(st->cat,
        "CREATE TABLE IF NOT EXISTS versions("
        "  path TEXT NOT NULL,"
        "  gen INTEGER NOT NULL,"
        "  blob_id TEXT NOT NULL DEFAULT '',"
        "  size INTEGER NOT NULL DEFAULT 0,"
        "  block_size INTEGER NOT NULL DEFAULT 0,"
        "  mtime INTEGER NOT NULL DEFAULT 0,"
        "  ctime INTEGER NOT NULL DEFAULT 0,"
        "  mode INTEGER NOT NULL DEFAULT 0,"
        "  uid INTEGER NOT NULL DEFAULT 0,"
        "  gid INTEGER NOT NULL DEFAULT 0,"
        "  saved_at INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(path, gen));"
        "CREATE INDEX IF NOT EXISTS versions_blob ON versions(blob_id);"
        "CREATE TABLE IF NOT EXISTS trash("
        "  trash_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  path TEXT NOT NULL,"
        "  blob_id TEXT NOT NULL DEFAULT '',"
        "  size INTEGER NOT NULL DEFAULT 0,"
        "  block_size INTEGER NOT NULL DEFAULT 0,"
        "  mtime INTEGER NOT NULL DEFAULT 0,"
        "  ctime INTEGER NOT NULL DEFAULT 0,"
        "  mode INTEGER NOT NULL DEFAULT 0,"
        "  uid INTEGER NOT NULL DEFAULT 0,"
        "  gid INTEGER NOT NULL DEFAULT 0,"
        "  deleted_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS trash_path ON trash(path);"
        "CREATE INDEX IF NOT EXISTS trash_blob ON trash(blob_id);");
}

/* hist_next_gen — the next (monotonically increasing) version number for `path`:
 * MAX(gen)+1, or 1 for the first version. -1/EIO on a DB error. */
static int64_t
hist_next_gen(pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q = cat_prepare(st->cat,
        "SELECT COALESCE(MAX(gen), 0) + 1 FROM versions WHERE path = ?1;");
    int64_t       gen;
    int           rc;

    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    gen = (rc == SQLITE_ROW) ? sqlite3_column_int64(q, 0) : -1;
    sqlite3_finalize(q);
    if (rc != SQLITE_ROW) {
        return cat_fail(EIO);
    }
    return gen;
}

/* hist_bind_meta — bind the ten metadata columns shared by the versions and
 * trash INSERTs starting at parameter `base` (blob_id, size, block_size, mtime,
 * ctime, mode, uid, gid). The path/gen (or trash timestamp) are bound by the
 * caller before this. */
static void
hist_bind_meta(sqlite3_stmt *q, int base, const pblock_meta *m)
{
    sqlite3_bind_text (q, base + 0, m->blob_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(q, base + 1, m->size);
    sqlite3_bind_int64(q, base + 2, m->block_size);
    sqlite3_bind_int64(q, base + 3, m->mtime);
    sqlite3_bind_int64(q, base + 4, m->ctime);
    sqlite3_bind_int64(q, base + 5, m->mode);
    sqlite3_bind_int64(q, base + 6, m->uid);
    sqlite3_bind_int64(q, base + 7, m->gid);
}

/* hist_version_trim — release generations beyond the newest `keep` for `path`,
 * oldest (lowest gen) first, releasing each trimmed blob. 0 or -1/errno. */
static int
hist_version_trim(pblock_state_t *st, const char *path, int keep)
{
    for (;;) {
        sqlite3_stmt *q = cat_prepare(st->cat,
            "SELECT gen, blob_id, size, block_size FROM versions"
            " WHERE path = ?1"
            "   AND (SELECT COUNT(*) FROM versions WHERE path = ?1) > ?2"
            " ORDER BY gen ASC LIMIT 1;");
        char          blob[PBLOCK_BLOB_ID_CAP];
        int64_t       gen, size, bs;
        int           rc;

        if (q == NULL) {
            return -1;
        }
        sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_int (q, 2, keep);
        rc = sqlite3_step(q);
        if (rc == SQLITE_DONE) {
            sqlite3_finalize(q);
            return 0;                         /* within budget — nothing to trim */
        }
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(q);
            return cat_fail(EIO);
        }
        gen  = sqlite3_column_int64(q, 0);
        snprintf(blob, sizeof(blob), "%s", (const char *) sqlite3_column_text(q, 1));
        size = sqlite3_column_int64(q, 2);
        bs   = sqlite3_column_int64(q, 3);
        sqlite3_finalize(q);

        q = cat_prepare(st->cat,
            "DELETE FROM versions WHERE path = ?1 AND gen = ?2;");
        if (q == NULL) {
            return -1;
        }
        sqlite3_bind_text (q, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_int64(q, 2, gen);
        rc = sqlite3_step(q);
        sqlite3_finalize(q);
        if (rc != SQLITE_DONE) {
            return cat_fail(EIO);
        }
        pblock_refs_release(st, blob, size, bs);   /* the version's held blob */
    }
}

int
pblock_hist_version_push(pblock_state_t *st, const char *path,
    const pblock_meta *meta)
{
    sqlite3_stmt *q;
    int64_t       gen;
    int           rc;

    if (meta->is_dir) {
        return 0;                             /* directories have no blob */
    }
    gen = hist_next_gen(st, path);
    if (gen < 0) {
        return -1;
    }
    /* Hold the blob first: the caller's subsequent release then only decrements,
     * transferring the reference from the live object to this version row. */
    if (pblock_refs_bump(st, meta->blob_id, meta->size, meta->block_size) != 0) {
        return -1;
    }
    q = cat_prepare(st->cat,
        "INSERT INTO versions(path, gen, blob_id, size, block_size, mtime,"
        "  ctime, mode, uid, gid, saved_at)"
        " VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);");
    if (q == NULL) {
        pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
        return -1;
    }
    sqlite3_bind_text (q, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, gen);
    hist_bind_meta(q, 3, meta);               /* ?3..?10 */
    sqlite3_bind_int64(q, 11, pblock_now());
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    if (rc != SQLITE_DONE) {
        pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
        return cat_fail(EIO);
    }
    return hist_version_trim(st, path, st->versions);
}

int
pblock_hist_trash_push(pblock_state_t *st, const char *path,
    const pblock_meta *meta)
{
    sqlite3_stmt *q;
    int           rc;

    if (meta->is_dir) {
        return 0;
    }
    if (pblock_refs_bump(st, meta->blob_id, meta->size, meta->block_size) != 0) {
        return -1;
    }
    q = cat_prepare(st->cat,
        "INSERT INTO trash(path, blob_id, size, block_size, mtime, ctime,"
        "  mode, uid, gid, deleted_at)"
        " VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);");
    if (q == NULL) {
        pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
        return -1;
    }
    sqlite3_bind_text (q, 1, path, -1, SQLITE_STATIC);
    hist_bind_meta(q, 2, meta);               /* ?2..?9 */
    sqlite3_bind_int64(q, 10, pblock_now());
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    if (rc != SQLITE_DONE) {
        pblock_refs_release(st, meta->blob_id, meta->size, meta->block_size);
        return cat_fail(EIO);
    }
    return 0;
}

int
pblock_hist_undelete(pblock_state_t *st, const char *path)
{
    sqlite3_stmt *q;
    pblock_meta   meta;
    int64_t       trash_id, size, bs;
    char          blob[PBLOCK_BLOB_ID_CAP];
    int           rc;

    /* Never clobber a live object: a name currently in use is EEXIST. */
    rc = pblock_catalog_lookup(st->cat, path, NULL);
    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        errno = EEXIST;
        return -1;
    }

    q = cat_prepare(st->cat,
        "SELECT trash_id, blob_id, size, block_size, mtime, ctime, mode,"
        "  uid, gid FROM trash WHERE path = ?1"
        " ORDER BY deleted_at DESC, trash_id DESC LIMIT 1;");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, path, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(q);
        errno = ENOENT;
        return -1;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(q);
        return cat_fail(EIO);
    }
    memset(&meta, 0, sizeof(meta));
    trash_id = sqlite3_column_int64(q, 0);
    snprintf(blob, sizeof(blob), "%s", (const char *) sqlite3_column_text(q, 1));
    snprintf(meta.blob_id, sizeof(meta.blob_id), "%s", blob);
    size = meta.size = sqlite3_column_int64(q, 2);
    bs   = meta.block_size = sqlite3_column_int64(q, 3);
    meta.mtime = sqlite3_column_int64(q, 4);
    meta.ctime = sqlite3_column_int64(q, 5);
    meta.mode  = (mode_t) sqlite3_column_int64(q, 6);
    meta.uid   = (uint32_t) sqlite3_column_int64(q, 7);
    meta.gid   = (uint32_t) sqlite3_column_int64(q, 8);
    meta.is_dir = 0;
    sqlite3_finalize(q);

    /* Transfer the held reference to the restored object: bump for the new row,
     * then release once the trash row (its prior holder) is gone. */
    if (pblock_refs_bump(st, blob, size, bs) != 0) {
        return -1;
    }
    if (pblock_catalog_create(st->cat, path, &meta) != 0) {
        int err = errno;

        pblock_refs_release(st, blob, size, bs);
        errno = err;
        return -1;
    }
    q = cat_prepare(st->cat, "DELETE FROM trash WHERE trash_id = ?1;");
    if (q != NULL) {
        sqlite3_bind_int64(q, 1, trash_id);
        (void) sqlite3_step(q);
        sqlite3_finalize(q);
    }
    pblock_refs_release(st, blob, size, bs);   /* the trash row's held blob */
    return 0;
}

/* ---- reserved-namespace control dispatch -------------------------------- */

#define HIST_UNDELETE_PREFIX     "/.pblock/undelete/"
#define HIST_UNDELETE_PREFIX_LEN 18

int
pblock_hist_ctl_mkdir_match(const char *path)
{
    return path != NULL
        && strncmp(path, HIST_UNDELETE_PREFIX, HIST_UNDELETE_PREFIX_LEN) == 0;
}

int
pblock_hist_ctl_mkdir(pblock_state_t *st, const char *path)
{
    const char *rest = path + HIST_UNDELETE_PREFIX_LEN;
    char        target[PATH_MAX];

    if (rest[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    /* The wire path is absolute; `rest` is the target minus its leading slash. */
    snprintf(target, sizeof(target), "/%s", rest);
    return pblock_hist_undelete(st, target);
}

#endif /* BRIX_HAVE_SQLITE */
