/*
 * sd_pblock_catalog_objects.c — objects-table row CRUD for the pblock catalog.
 *
 * WHAT: Implements the single-path operations over the `objects` table declared
 *       in sd_pblock_catalog.h: lookup, parent_ok, put, create, setattr, touch,
 *       remove, and child_count, plus the `ids` identity registry (id_map). Each
 *       is one prepared statement (creates and puts gate the parent first); the
 *       namespace cache is consulted on read and invalidated/installed on write.
 *
 * WHY:  Split from sd_pblock_catalog.c (phase-79) to keep every file under the
 *       ~500-line cap with one concept per file. These are the per-row namespace
 *       mutations and reads; the connection lifecycle, the cache itself, and the
 *       shared SQL primitives live in sd_pblock_catalog.c; subtree rename,
 *       directory iteration, and xattrs live in sd_pblock_catalog_ns.c.
 *
 * HOW:  Reaches the sqlite3 connection and the namespace cache through the
 *       primitives in sd_pblock_catalog_internal.h (cat_prepare/cat_exec/cat_fail,
 *       parent_of/cat_parent_gate, nscache_*). All paths are bound parameters —
 *       never string-formatted into SQL. Gated by BRIX_HAVE_SQLITE like the rest
 *       of the catalog so a no-sqlite build stays byte-for-byte unchanged.
 */
#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "sd_pblock_catalog_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>
#include <stdint.h>

int
pblock_catalog_lookup(pblock_catalog *cat, const char *path, pblock_meta *out)
{
    sqlite3_stmt        *stmt;
    pblock_meta          m;
    const unsigned char *blob;
    uint64_t             gen;
    int                  rc;

    /* Fast path: a positive cache hit answers without touching SQLite. */
    if (nscache_get(cat, path, out)) {
        return 0;
    }
    gen = nscache_gen(cat);     /* snapshot before the read we may cache */

    stmt = cat_prepare(cat,
        "SELECT is_dir, blob_id, size, block_size, mtime, ctime, mode, uid, gid"
        "  FROM objects WHERE path = ?1;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;                 /* no such row (absent — not cached) */
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return cat_fail(EIO);
    }

    /* Always materialise the full row so the cache holds a complete meta even
     * for existence-only probes (out == NULL). */
    blob = sqlite3_column_text(stmt, 1);
    memset(&m, 0, sizeof(m));
    m.is_dir = sqlite3_column_int(stmt, 0);
    snprintf(m.blob_id, sizeof(m.blob_id), "%s",
             blob != NULL ? (const char *) blob : "");
    m.size       = sqlite3_column_int64(stmt, 2);
    m.block_size = sqlite3_column_int64(stmt, 3);
    m.mtime      = sqlite3_column_int64(stmt, 4);
    m.ctime      = sqlite3_column_int64(stmt, 5);
    m.mode       = (uint32_t) sqlite3_column_int64(stmt, 6);
    m.uid        = (uint32_t) sqlite3_column_int64(stmt, 7);
    m.gid        = (uint32_t) sqlite3_column_int64(stmt, 8);
    sqlite3_finalize(stmt);

    nscache_store(cat, path, &m, gen);
    if (out != NULL) {
        *out = m;
    }
    return 0;
}

int
pblock_catalog_parent_ok(pblock_catalog *cat, const char *path)
{
    return cat_parent_gate(cat, path);
}

/* ---- Fetch the metadata row of a path's immediate parent directory ----
 *
 * WHAT: Fills *out with the parent directory's row. 0 on success; -1/errno
 *       (EINVAL for the root, ENOENT absent parent, ENOTDIR non-directory).
 *
 * WHY: The driver's identity-enforcement wrappers need the parent's mode/owner
 *      to answer "may this principal create/remove entries here?" — the boolean
 *      cat_parent_gate cannot carry that.
 *
 * HOW: 1. Derive the parent path (parent_of; "" means `path` is the root).
 *      2. Look it up (nscache-backed). 3. Demand it is a directory.
 */
int
pblock_catalog_parent_lookup(pblock_catalog *cat, const char *path,
    pblock_meta *out)
{
    char parent[1024];
    int  rc;

    parent_of(path, parent, sizeof(parent));
    if (parent[0] == '\0') {
        return cat_fail(EINVAL);          /* the root has no parent */
    }
    rc = pblock_catalog_lookup(cat, parent, out);
    if (rc > 0) {
        return cat_fail(ENOENT);
    }
    if (rc < 0) {
        return -1;
    }
    if (!out->is_dir) {
        return cat_fail(ENOTDIR);
    }
    return 0;
}

int
pblock_catalog_put(pblock_catalog *cat, const char *path,
    const pblock_meta *meta)
{
    sqlite3_stmt *stmt;
    char          parent[1024];
    int           rc;

    if (path == NULL || meta == NULL) {
        return cat_fail(EINVAL);
    }
    if (cat_parent_gate(cat, path) != 0) {
        return -1;                       /* errno = ENOENT / ENOTDIR */
    }
    parent_of(path, parent, sizeof(parent));

    stmt = cat_prepare(cat,
        "INSERT OR REPLACE INTO objects"
        "  (path, parent, is_dir, blob_id, size, block_size, mtime, ctime,"
        "   mode, uid, gid)"
        "  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, parent, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, meta->is_dir ? 1 : 0);
    sqlite3_bind_text(stmt, 4, meta->blob_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, meta->size);
    sqlite3_bind_int64(stmt, 6, meta->block_size);
    sqlite3_bind_int64(stmt, 7, meta->mtime);
    sqlite3_bind_int64(stmt, 8, meta->ctime);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64) meta->mode);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64) meta->uid);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64) meta->gid);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    nscache_put(cat, path, meta);
    return 0;
}

/* Insert a new row, failing on a pre-existing path — one statement, no upfront
 * existence lookup (the PRIMARY KEY constraint is the check). */
int
pblock_catalog_create(pblock_catalog *cat, const char *path,
    const pblock_meta *meta)
{
    sqlite3_stmt *stmt;
    char          parent[1024];
    int           rc;

    if (path == NULL || meta == NULL) {
        return cat_fail(EINVAL);
    }
    if (cat_parent_gate(cat, path) != 0) {
        return -1;                       /* errno = ENOENT / ENOTDIR */
    }
    parent_of(path, parent, sizeof(parent));

    stmt = cat_prepare(cat,
        "INSERT INTO objects"
        "  (path, parent, is_dir, blob_id, size, block_size, mtime, ctime,"
        "   mode, uid, gid)"
        "  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, parent, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, meta->is_dir ? 1 : 0);
    sqlite3_bind_text(stmt, 4, meta->blob_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, meta->size);
    sqlite3_bind_int64(stmt, 6, meta->block_size);
    sqlite3_bind_int64(stmt, 7, meta->mtime);
    sqlite3_bind_int64(stmt, 8, meta->ctime);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64) meta->mode);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64) meta->uid);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64) meta->gid);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        nscache_put(cat, path, meta);
        return 0;
    }
    if (rc == SQLITE_CONSTRAINT) {
        return cat_fail(EEXIST);
    }
    return cat_fail(EIO);
}

/* Apply mode/owner/mtime changes in a single UPDATE (no read-modify-write). The
 * cached entry is dropped since the new full meta is not re-read here. */
int
pblock_catalog_setattr(pblock_catalog *cat, const char *path,
    int set_mode, uint32_t perm, int set_owner, int64_t uid, int64_t gid,
    int set_mtime, int64_t mtime, int64_t now)
{
    sqlite3_stmt *stmt;
    int           rc, changed;

    /* ?1=now ?2=set_mode ?3=perm ?4=set_mtime ?5=mtime ?6=set_owner ?7=uid
     * ?8=gid ?9=path. 61440 == S_IFMT and 511 == 0777, so the new mode keeps
     * only the type bits and replaces the permission triad — matching the prior
     * read-modify-write exactly. A negative uid/gid keeps the current value
     * (POSIX chown's (uid_t)-1 convention). */
    stmt = cat_prepare(cat,
        "UPDATE objects SET"
        "  ctime = ?1,"
        "  mode  = CASE WHEN ?2 THEN (mode & 61440) | (?3 & 511) ELSE mode END,"
        "  mtime = CASE WHEN ?4 THEN ?5 ELSE mtime END,"
        "  uid   = CASE WHEN ?6 AND ?7 >= 0 THEN ?7 ELSE uid END,"
        "  gid   = CASE WHEN ?6 AND ?8 >= 0 THEN ?8 ELSE gid END"
        "  WHERE path = ?9;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_int(stmt, 2, set_mode ? 1 : 0);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) perm);
    sqlite3_bind_int(stmt, 4, set_mtime ? 1 : 0);
    sqlite3_bind_int64(stmt, 5, mtime);
    sqlite3_bind_int(stmt, 6, set_owner ? 1 : 0);
    sqlite3_bind_int64(stmt, 7, uid);
    sqlite3_bind_int64(stmt, 8, gid);
    sqlite3_bind_text(stmt, 9, path, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    changed = sqlite3_changes(cat->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    if (changed > 0) {
        nscache_inval(cat, path);
        return 0;
    }
    return cat_fail(ENOENT);
}

int
pblock_catalog_touch(pblock_catalog *cat, const char *path, int64_t size,
    int64_t mtime)
{
    sqlite3_stmt *stmt;
    int           rc, changed;

    stmt = cat_prepare(cat,
        "UPDATE objects SET size = ?2, mtime = ?3"
        "  WHERE path = ?1 AND is_dir = 0;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, size);
    sqlite3_bind_int64(stmt, 3, mtime);

    rc = sqlite3_step(stmt);
    changed = sqlite3_changes(cat->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    if (changed > 0) {
        nscache_inval(cat, path);   /* cached size/mtime now stale */
        return 0;
    }
    return cat_fail(ENOENT);
}

int
pblock_catalog_remove(pblock_catalog *cat, const char *path)
{
    sqlite3_stmt *stmt;
    int           rc;

    stmt = cat_prepare(cat, "DELETE FROM objects WHERE path = ?1;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    nscache_inval(cat, path);

    stmt = cat_prepare(cat, "DELETE FROM xattrs WHERE path = ?1;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

/* ---- identity registry ----------------------------------------------------- */

/* ---- Probe the ids table for (kind, name) ----
 *
 * WHAT: Looks up the synthetic id already assigned to (kind, name). Returns 0
 *       and fills *id_out on a hit, 1 when no row exists, -1/errno on error.
 *
 * WHY: pblock_catalog_id_map needs a read-then-assign loop; keeping the read a
 *      pure helper keeps that loop flat.
 *
 * HOW: 1. Prepare the point SELECT. 2. Bind kind+name. 3. Step and map
 *      ROW/DONE/other to 0/1/-1.
 */
static int
id_select(pblock_catalog *cat, int kind, const char *name, int64_t *id_out)
{
    sqlite3_stmt *stmt;
    int           rc;

    stmt = cat_prepare(cat,
        "SELECT id FROM ids WHERE kind = ?1 AND name = ?2;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, kind);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *id_out = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 1 : cat_fail(EIO);
}

/* ---- Map a principal/VO name to its stable synthetic id, assigning on first sight ----
 *
 * WHAT: Returns 0 and fills *id_out with the id registered for (kind, name),
 *       inserting the next free id (max(id)+1, floor PBLOCK_ID_BASE) when the
 *       name is new. -1/errno on failure. Ids are immutable once assigned.
 *
 * WHY: The catalog is pblock's identity authority (no unix accounts): object
 *      ownership needs stable numeric uids/gids for principals and VO groups
 *      that exist nowhere else. Assignment must be safe across worker
 *      processes sharing the database.
 *
 * HOW: 1. SELECT the existing row — the common case after first sight.
 *      2. On a miss, INSERT OR IGNORE a row whose id is computed inside the
 *         same statement (coalesce(max(id), BASE-1) + 1) — SQLite serializes
 *         writers, so the subquery and insert are atomic; OR IGNORE absorbs a
 *         concurrent insert of the same name AND an id collision under the
 *         unique index (another worker won the max+1 race with a different
 *         name).
 *      3. Re-SELECT; loop covers the ignored-collision case. Bounded retries —
 *         a persistent failure is EIO, never an infinite loop.
 */
int
pblock_catalog_id_map(pblock_catalog *cat, int kind, const char *name,
    int64_t *id_out)
{
    sqlite3_stmt *stmt;
    int           attempt, rc;

    if (cat == NULL || name == NULL || name[0] == '\0' || id_out == NULL) {
        return cat_fail(EINVAL);
    }

    for (attempt = 0; attempt < 8; attempt++) {
        rc = id_select(cat, kind, name, id_out);
        if (rc <= 0) {
            return rc;                    /* found (0) or hard error (-1) */
        }

        stmt = cat_prepare(cat,
            "INSERT OR IGNORE INTO ids (kind, name, id)"
            "  SELECT ?1, ?2, coalesce(max(id), ?3 - 1) + 1 FROM ids;");
        if (stmt == NULL) {
            return -1;
        }
        sqlite3_bind_int(stmt, 1, kind);
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, PBLOCK_ID_BASE);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            return cat_fail(EIO);
        }
    }
    return cat_fail(EIO);
}

int
pblock_catalog_child_count(pblock_catalog *cat, const char *path)
{
    sqlite3_stmt *stmt;
    int           rc, count;

    stmt = cat_prepare(cat,
        "SELECT count(*) FROM objects WHERE parent = ?1;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return cat_fail(EIO);
    }
    count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

#else

/* ISO C forbids an empty translation unit; a no-sqlite build compiles this
 * file to nothing but this placeholder (same contract as sd_pblock.c). */
typedef int brix_sd_pblock_catalog_objects_disabled_t;

#endif /* BRIX_HAVE_SQLITE */
