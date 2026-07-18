/*
 * pblock_snap.c — F6 snapshots / instant fixture reset for the pblock driver.
 *
 * WHAT: Implements pblock_snap.h — the `snapshots`/`snap_objects`/`snap_xattrs`
 *       tables, take/restore/drop, name validation, and the reserved-namespace
 *       control dispatch.
 *
 * HOW:  Every mutator runs inside BEGIN IMMEDIATE and finishes by recomputing
 *       each blob's refcount from live objects + all snapshot copies, so the F10
 *       release path (which removes blocks only at the last reference) stays
 *       exact across take/restore/drop. The snapshot name is only ever a bound
 *       column value — never interpolated into SQL — and is separately validated
 *       to a strict charset, so a hostile name can neither inject nor traverse.
 *       ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_snap.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec/cat_prepare, nscache_clear */

#include <errno.h>
#include <string.h>

#include <sqlite3.h>

int
pblock_snap_init(pblock_state_t *st)
{
    return cat_exec(st->cat,
        "CREATE TABLE IF NOT EXISTS snapshots("
        "  name TEXT PRIMARY KEY,"
        "  created_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS snap_objects("
        "  snap TEXT NOT NULL,"
        "  path TEXT NOT NULL,"
        "  parent TEXT NOT NULL,"
        "  is_dir INTEGER NOT NULL,"
        "  blob_id TEXT NOT NULL DEFAULT '',"
        "  size INTEGER NOT NULL DEFAULT 0,"
        "  block_size INTEGER NOT NULL DEFAULT 0,"
        "  mtime INTEGER NOT NULL DEFAULT 0,"
        "  ctime INTEGER NOT NULL DEFAULT 0,"
        "  mode INTEGER NOT NULL DEFAULT 0,"
        "  uid INTEGER NOT NULL DEFAULT 0,"
        "  gid INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(snap, path));"
        "CREATE INDEX IF NOT EXISTS snap_objects_blob"
        "  ON snap_objects(blob_id);"
        "CREATE TABLE IF NOT EXISTS snap_xattrs("
        "  snap TEXT NOT NULL,"
        "  path TEXT NOT NULL,"
        "  name TEXT NOT NULL,"
        "  value BLOB NOT NULL,"
        "  PRIMARY KEY(snap, path, name));");
}

int
pblock_snap_valid_name(const char *name)
{
    size_t n;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    for (n = 0; name[n] != '\0'; n++) {
        char c = name[n];

        if (n >= 64) {
            return 0;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
            return 0;
        }
    }
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return 0;
    }
    return 1;
}

/* snap_run1 — prepare `sql`, bind ?1 = `name`, step to completion. 0 or -1/EIO. */
static int
snap_run1(pblock_state_t *st, const char *sql, const char *name)
{
    sqlite3_stmt *q = cat_prepare(st->cat, sql);
    int           rc;

    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

/* snap_recount — recompute every blob's refcount from (live objects + every
 * snapshot copy). Called at the end of take/restore/drop so the F10 release path
 * stays exact: a blob no longer referenced anywhere falls to 0 (its blocks
 * become an fsck --gc-collectable orphan — fail-safe, never removed mid-txn). A
 * referenced legacy blob with no row is materialised first (seed 0, then set). */
static int
snap_recount(pblock_state_t *st)
{
    if (cat_exec(st->cat,
            "INSERT OR IGNORE INTO blobs(blob_id, refcount, size, block_size,"
            "  content_hash)"
            " SELECT DISTINCT blob_id, 0, size, block_size, ''"
            "   FROM objects WHERE is_dir = 0 AND blob_id != '';") != 0)
    {
        return -1;
    }
    return cat_exec(st->cat,
        "UPDATE blobs SET refcount = "
        "  (SELECT COUNT(*) FROM objects o"
        "     WHERE o.blob_id = blobs.blob_id AND o.is_dir = 0)"
        " + (SELECT COUNT(*) FROM snap_objects s"
        "     WHERE s.blob_id = blobs.blob_id AND s.is_dir = 0);");
}

/* snap_take_body — the copy work inside the open transaction (name already
 * validated). 0 on success; -1 with errno set (EEXIST for a duplicate name). */
static int
snap_take_body(pblock_state_t *st, const char *name)
{
    sqlite3_stmt *q;
    int           rc;

    /* The PRIMARY KEY is the existence check — a duplicate name is EEXIST. */
    q = cat_prepare(st->cat,
        "INSERT INTO snapshots(name, created_at) VALUES(?1, ?2);");
    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(q, 2, pblock_now());
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    if (rc != SQLITE_DONE) {
        errno = (rc == SQLITE_CONSTRAINT) ? EEXIST : EIO;
        return -1;
    }

    if (snap_run1(st,
            "INSERT INTO snap_objects(snap, path, parent, is_dir, blob_id, size,"
            "  block_size, mtime, ctime, mode, uid, gid)"
            " SELECT ?1, path, parent, is_dir, blob_id, size, block_size, mtime,"
            "  ctime, mode, uid, gid FROM objects;", name) != 0
        || snap_run1(st,
            "INSERT INTO snap_xattrs(snap, path, name, value)"
            " SELECT ?1, path, name, value FROM xattrs;", name) != 0
        || snap_recount(st) != 0)
    {
        return -1;
    }
    return 0;
}

int
pblock_snap_take(pblock_state_t *st, const char *name)
{
    if (!pblock_snap_valid_name(name)) {
        errno = EINVAL;
        return -1;
    }
    if (cat_exec(st->cat, "BEGIN IMMEDIATE;") != 0) {
        return -1;
    }
    if (snap_take_body(st, name) != 0) {
        int err = errno;

        (void) cat_exec(st->cat, "ROLLBACK;");
        errno = err ? err : EIO;
        return -1;
    }
    return cat_exec(st->cat, "COMMIT;");
}

/* snap_exists — 1 present, 0 absent, -1/EIO. */
static int
snap_exists(pblock_state_t *st, const char *name)
{
    sqlite3_stmt *q = cat_prepare(st->cat,
        "SELECT 1 FROM snapshots WHERE name = ?1;");
    int           rc;

    if (q == NULL) {
        return -1;
    }
    sqlite3_bind_text(q, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    if (rc == SQLITE_ROW) {
        return 1;
    }
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

int
pblock_snap_restore(pblock_state_t *st, const char *name)
{
    int rc;

    if (!pblock_snap_valid_name(name)) {
        errno = EINVAL;
        return -1;
    }
    /* Never swap the namespace out from under a live handle: EBUSY (not
     * corruption) while any regular-file handle is open on the export. */
    if (__atomic_load_n(&st->open_files, __ATOMIC_ACQUIRE) > 0) {
        errno = EBUSY;
        return -1;
    }
    rc = snap_exists(st, name);
    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        errno = ENOENT;
        return -1;
    }

    if (cat_exec(st->cat, "BEGIN IMMEDIATE;") != 0) {
        return -1;
    }
    if (cat_exec(st->cat, "DELETE FROM objects;") != 0
        || cat_exec(st->cat, "DELETE FROM xattrs;") != 0
        || snap_run1(st,
            "INSERT INTO objects(path, parent, is_dir, blob_id, size,"
            "  block_size, mtime, ctime, mode, uid, gid)"
            " SELECT path, parent, is_dir, blob_id, size, block_size, mtime,"
            "  ctime, mode, uid, gid FROM snap_objects WHERE snap = ?1;",
            name) != 0
        || snap_run1(st,
            "INSERT INTO xattrs(path, name, value)"
            " SELECT path, name, value FROM snap_xattrs WHERE snap = ?1;",
            name) != 0
        || snap_recount(st) != 0)
    {
        int err = errno;

        (void) cat_exec(st->cat, "ROLLBACK;");
        errno = err ? err : EIO;
        return -1;
    }
    if (cat_exec(st->cat, "COMMIT;") != 0) {
        return -1;
    }
    /* The whole namespace changed — every cached row is now stale. */
    nscache_clear(st->cat);
    return 0;
}

int
pblock_snap_drop(pblock_state_t *st, const char *name)
{
    int rc;

    if (!pblock_snap_valid_name(name)) {
        errno = EINVAL;
        return -1;
    }
    rc = snap_exists(st, name);
    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        errno = ENOENT;
        return -1;
    }

    if (cat_exec(st->cat, "BEGIN IMMEDIATE;") != 0) {
        return -1;
    }
    if (snap_run1(st, "DELETE FROM snapshots WHERE name = ?1;", name) != 0
        || snap_run1(st, "DELETE FROM snap_objects WHERE snap = ?1;", name) != 0
        || snap_run1(st, "DELETE FROM snap_xattrs WHERE snap = ?1;", name) != 0
        || snap_recount(st) != 0)
    {
        int err = errno;

        (void) cat_exec(st->cat, "ROLLBACK;");
        errno = err ? err : EIO;
        return -1;
    }
    return cat_exec(st->cat, "COMMIT;");
}

/* ---- reserved-namespace control dispatch -------------------------------- */

#define SNAP_CTL_PREFIX     "/.pblock/"
#define SNAP_CTL_PREFIX_LEN 9

int
pblock_snap_ctl_path(const char *path)
{
    return path != NULL
        && strncmp(path, SNAP_CTL_PREFIX, SNAP_CTL_PREFIX_LEN) == 0;
}

int
pblock_snap_ctl_mkdir(pblock_state_t *st, const char *path)
{
    const char *rest = path + SNAP_CTL_PREFIX_LEN;

    if (strncmp(rest, "snap/", 5) == 0) {
        return pblock_snap_take(st, rest + 5);
    }
    if (strncmp(rest, "restore/", 8) == 0) {
        return pblock_snap_restore(st, rest + 8);
    }
    errno = EINVAL;
    return -1;
}

int
pblock_snap_ctl_rmdir(pblock_state_t *st, const char *path)
{
    const char *rest = path + SNAP_CTL_PREFIX_LEN;

    if (strncmp(rest, "snap/", 5) == 0) {
        return pblock_snap_drop(st, rest + 5);
    }
    errno = EINVAL;
    return -1;
}

#endif /* BRIX_HAVE_SQLITE */
