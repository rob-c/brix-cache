/*
 * sd_pblock_catalog_ns.c — namespace-tree operations for the pblock catalog.
 *
 * WHAT: Implements the catalog operations that go beyond single-row objects CRUD:
 *       subtree-aware rename (collect every descendant, then reparent each in one
 *       transaction), directory iteration (opendir/readdir/closedir over the
 *       parent index), and the xattr CRUD (get/list/set/remove over the `xattrs`
 *       table). All declared in sd_pblock_catalog.h.
 *
 * WHY:  Split from sd_pblock_catalog.c (phase-79) to keep every file under the
 *       ~500-line cap with one concept per file. Rename spans many rows and its
 *       own transaction, directory iteration owns the cursor handle, and xattrs
 *       are a second table — none of which belong in the single-row objects file
 *       (sd_pblock_catalog_objects.c) or the connection/cache core
 *       (sd_pblock_catalog.c).
 *
 * HOW:  Reaches the sqlite3 connection and namespace cache through the primitives
 *       in sd_pblock_catalog_internal.h (cat_prepare/cat_exec/cat_fail,
 *       parent_of/cat_parent_gate, nscache_clear). All paths are bound
 *       parameters; the rename prefix test uses substr() to avoid LIKE wildcard
 *       escaping on user-controlled paths. Gated by BRIX_HAVE_SQLITE like the
 *       rest of the catalog so a no-sqlite build stays byte-for-byte unchanged.
 */
#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "sd_pblock_catalog_internal.h"
#include "core/compat/snprintf_check.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sqlite3.h>

struct pblock_catalog_iter {
    sqlite3_stmt *stmt;
};

/* basename_of — the final path component (pointer into `path`). */
static const char *
basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

/* ---- rename (subtree-aware) ----------------------------------------------- */

/* path_list — a small growable vector of owned path strings, used to snapshot the
 * rows a directory rename must reparent before any are mutated. */
typedef struct {
    char   **items;
    size_t   len;
    size_t   cap;
} path_list;

static int
path_list_push(path_list *pl, const char *s)
{
    char *dup;

    if (pl->len == pl->cap) {
        size_t  ncap = pl->cap ? pl->cap * 2 : 16;
        char  **ni   = realloc(pl->items, ncap * sizeof(*ni));

        if (ni == NULL) {
            return -1;
        }
        pl->items = ni;
        pl->cap   = ncap;
    }
    /* Ownership transfers INTO the list; path_list_free releases every entry.
     * (gcc -fanalyzer reports the strdup as leaking — it does not track
     * ownership through the container, known false positive in the fanalyzer
     * baseline.) */
    dup = strdup(s);
    if (dup == NULL) {
        return -1;
    }
    /* phase79-fp: ownership of dup transfers into pl->items; every entry is
     * released by path_list_free — analyzer does not track container ownership */
    pl->items[pl->len++] = dup;
    return 0;
}

static void
path_list_free(path_list *pl)
{
    size_t i;

    for (i = 0; i < pl->len; i++) {
        free(pl->items[i]);
    }
    free(pl->items);
    pl->items = NULL;
    pl->len = pl->cap = 0;
}

/* rename_collect — snapshot `src` and every descendant ("src/...") into *pl.
 * Returns 0, or -1 with errno set (and *pl already freed by the caller). The
 * substr() prefix test avoids LIKE wildcard escaping on user-controlled paths. */
static int
rename_collect(pblock_catalog *cat, const char *src, path_list *pl)
{
    sqlite3_stmt *stmt;
    int           rc;

    stmt = cat_prepare(cat,
        "SELECT path FROM objects"
        "  WHERE path = ?1 OR substr(path, 1, length(?1) + 1) = ?1 || '/';");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, src, -1, SQLITE_STATIC);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (path_list_push(pl, (const char *) sqlite3_column_text(stmt, 0))
            != 0)
        {
            sqlite3_finalize(stmt);
            return cat_fail(ENOMEM);
        }
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

/* rename_one — move a single row (and its xattrs) from old_path to its rewritten
 * destination, recomputing the parent column. Returns 0 or -1/errno. */
static int
rename_one(pblock_catalog *cat, const char *old_path, const char *src,
    const char *dst)
{
    char          new_path[2048];
    char          new_parent[1024];
    const char   *tail = old_path + strlen(src);   /* "" or "/sub/..." */
    sqlite3_stmt *stmt;
    int           rc, i;
    const char   *objects_sql =
        "UPDATE objects SET path = ?2, parent = ?3 WHERE path = ?1;";
    const char   *xattrs_sql =
        "UPDATE xattrs SET path = ?2 WHERE path = ?1;";
    const char   *sqls[2];

    /* A truncated destination would rebind the row to a different (shorter) path
     * and silently corrupt the catalog — reject rather than truncate. */
    if (!brix_snprintf_ok(new_path, sizeof(new_path), "%s%s", dst, tail)) {
        return cat_fail(ENAMETOOLONG);
    }
    parent_of(new_path, new_parent, sizeof(new_parent));

    sqls[0] = objects_sql;
    sqls[1] = xattrs_sql;
    for (i = 0; i < 2; i++) {
        stmt = cat_prepare(cat, sqls[i]);
        if (stmt == NULL) {
            return -1;
        }
        sqlite3_bind_text(stmt, 1, old_path, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, new_path, -1, SQLITE_STATIC);
        if (i == 0) {
            sqlite3_bind_text(stmt, 3, new_parent, -1, SQLITE_STATIC);
        }
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            return cat_fail(EIO);
        }
    }
    return 0;
}

int
pblock_catalog_rename(pblock_catalog *cat, const char *src, const char *dst)
{
    path_list pl = {0};
    size_t    i;

    if (src == NULL || dst == NULL) {
        return cat_fail(EINVAL);
    }
    if (cat_parent_gate(cat, dst) != 0) {
        return -1;                       /* errno = ENOENT / ENOTDIR */
    }

    if (cat_exec(cat, "BEGIN IMMEDIATE;") != 0) {
        return -1;
    }

    if (rename_collect(cat, src, &pl) != 0) {
        int err = errno;

        path_list_free(&pl);
        cat_exec(cat, "ROLLBACK;");
        return cat_fail(err);
    }
    if (pl.len == 0) {
        path_list_free(&pl);
        cat_exec(cat, "ROLLBACK;");
        return cat_fail(ENOENT);
    }

    for (i = 0; i < pl.len; i++) {
        if (rename_one(cat, pl.items[i], src, dst) != 0) {
            int err = errno;

            path_list_free(&pl);
            cat_exec(cat, "ROLLBACK;");
            return cat_fail(err);
        }
    }

    path_list_free(&pl);
    {
        int crc = cat_exec(cat, "COMMIT;");
        if (crc == 0) {
            /* a rename reparents whole subtrees — drop every cached path. */
            nscache_clear(cat);
        }
        return crc;
    }
}

/* ---- directory iteration -------------------------------------------------- */

pblock_catalog_iter *
pblock_catalog_opendir(pblock_catalog *cat, const char *parent)
{
    pblock_catalog_iter *it;

    it = calloc(1, sizeof(*it));
    if (it == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    it->stmt = cat_prepare(cat,
        "SELECT path FROM objects WHERE parent = ?1 ORDER BY path;");
    if (it->stmt == NULL) {
        free(it);
        return NULL;
    }
    sqlite3_bind_text(it->stmt, 1, parent, -1, SQLITE_TRANSIENT);
    return it;
}

int
pblock_catalog_readdir(pblock_catalog_iter *it, char *name, size_t cap)
{
    int rc = sqlite3_step(it->stmt);

    if (rc == SQLITE_DONE) {
        return 1;
    }
    if (rc != SQLITE_ROW) {
        return cat_fail(EIO);
    }
    if (!brix_snprintf_ok(name, cap, "%s",
            basename_of((const char *) sqlite3_column_text(it->stmt, 0)))) {
        return cat_fail(ENAMETOOLONG);
    }
    return 0;
}

void
pblock_catalog_closedir(pblock_catalog_iter *it)
{
    if (it == NULL) {
        return;
    }
    sqlite3_finalize(it->stmt);
    free(it);
}

/* ---- xattrs --------------------------------------------------------------- */

ssize_t
pblock_catalog_getxattr(pblock_catalog *cat, const char *path,
    const char *name, void *buf, size_t cap)
{
    sqlite3_stmt *stmt;
    int           rc;
    ssize_t       len;

    stmt = cat_prepare(cat,
        "SELECT value FROM xattrs WHERE path = ?1 AND name = ?2;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return cat_fail(ENODATA);
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return cat_fail(EIO);
    }

    len = sqlite3_column_bytes(stmt, 0);
    if (cap == 0) {
        sqlite3_finalize(stmt);
        return len;               /* size probe */
    }
    if ((size_t) len > cap) {
        sqlite3_finalize(stmt);
        return cat_fail(ERANGE);
    }
    memcpy(buf, sqlite3_column_blob(stmt, 0), (size_t) len);
    sqlite3_finalize(stmt);
    return len;
}

ssize_t
pblock_catalog_listxattr(pblock_catalog *cat, const char *path, void *buf,
    size_t cap)
{
    sqlite3_stmt *stmt;
    int           rc;
    size_t        total = 0;
    char         *out = buf;

    stmt = cat_prepare(cat,
        "SELECT name FROM xattrs WHERE path = ?1 ORDER BY name;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *nm  = (const char *) sqlite3_column_text(stmt, 0);
        size_t      nlen = strlen(nm) + 1;   /* include the NUL separator */

        if (cap != 0) {
            if (total + nlen > cap) {
                sqlite3_finalize(stmt);
                return cat_fail(ERANGE);
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    return (ssize_t) total;
}

int
pblock_catalog_setxattr(pblock_catalog *cat, const char *path,
    const char *name, const void *val, size_t len)
{
    sqlite3_stmt *stmt;
    int           rc;

    stmt = cat_prepare(cat,
        "INSERT OR REPLACE INTO xattrs (path, name, value)"
        "  VALUES (?1, ?2, ?3);");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, val, (int) len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : cat_fail(EIO);
}

int
pblock_catalog_removexattr(pblock_catalog *cat, const char *path,
    const char *name)
{
    sqlite3_stmt *stmt;
    int           rc, changed;

    stmt = cat_prepare(cat,
        "DELETE FROM xattrs WHERE path = ?1 AND name = ?2;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    changed = sqlite3_changes(cat->db);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return cat_fail(EIO);
    }
    return changed > 0 ? 0 : cat_fail(ENODATA);
}

#else

/* ISO C forbids an empty translation unit; a no-sqlite build compiles this
 * file to nothing but this placeholder (same contract as sd_pblock.c). */
typedef int brix_sd_pblock_catalog_ns_disabled_t;

#endif /* BRIX_HAVE_SQLITE */
