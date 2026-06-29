/*
 * sd_pblock_catalog.h — SQLite metadata catalog for the pblock backend.
 *
 * WHAT: The namespace + metadata half of the pblock ("pseudo-block") storage
 *       driver. Owns one SQLite connection per instance and exposes typed CRUD
 *       over two tables: `objects` (one row per logical path: dir flag, blob id,
 *       size, mtime, ctime, mode) and `xattrs` (one row per (path, name)). The
 *       catalog holds the entire logical namespace and the path->blob mapping;
 *       the opaque blob bytes live in plain POSIX files keyed by blob id.
 *
 * WHY:  Splitting metadata (here) from bulk content (blob files) is what lets
 *       pblock be a full-capability drop-in for POSIX while keeping the hot
 *       data path (pread/pwrite/sendfile on a blob fd) free of any database
 *       work. Keeping this layer pure libc + sqlite3 — no nginx types — makes it
 *       independently unit-testable (sd_pblock_catalog_unittest.c) and reusable
 *       from the driver vtable above it (sd_pblock.c).
 *
 * HOW:  An opaque handle wraps the sqlite3* and its prepared statements. All
 *       calls return 0 / a count on success and -1 with errno set on failure
 *       (lookup uses +1 for "no such row"). Directory rename reparents every
 *       descendant in one transaction. Concurrency across nginx worker processes
 *       is handled by WAL journal mode + a busy timeout, set at open.
 */
#ifndef XROOTD_SD_PBLOCK_CATALOG_H
#define XROOTD_SD_PBLOCK_CATALOG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Width of a blob id: 128 bits rendered as lowercase hex, plus the NUL. */
#define PBLOCK_BLOB_ID_HEX 32
#define PBLOCK_BLOB_ID_CAP (PBLOCK_BLOB_ID_HEX + 1)

/* Default object block size (64 MiB) when an export configures none. A file's
 * data is striped across fixed-size block files of this size; the value is fixed
 * per file at creation, so retuning the default only affects newer files. */
#define PBLOCK_DEFAULT_BLOCK_SIZE (64LL * 1024 * 1024)

/* Opaque per-instance catalog handle: one sqlite3 connection + prepared stmts. */
typedef struct pblock_catalog pblock_catalog;

/* A namespace entry's metadata. blob_id is the empty string for directories;
 * block_size is the per-file stripe size (0 for directories). */
typedef struct {
    int      is_dir;
    char     blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t  size;
    int64_t  block_size;
    int64_t  mtime;
    int64_t  ctime;
    uint32_t mode;
} pblock_meta;

/* Open (creating the file + schema if needed) the catalog at db_path.
 * busy_timeout_ms arms SQLite's busy handler so a writer blocked by another
 * worker process retries rather than failing. Returns a handle, or NULL/errno. */
pblock_catalog *pblock_catalog_open(const char *db_path, int busy_timeout_ms);

/* Finalize statements + close the connection. NULL-safe. */
void pblock_catalog_close(pblock_catalog *cat);

/* Look up `path`: 0 and fill *out when present, 1 when absent, -1/errno on error.
 * *out may be NULL to probe existence only. */
int pblock_catalog_lookup(pblock_catalog *cat, const char *path,
    pblock_meta *out);

/* Insert-or-replace the row for `path` (its parent path is derived internally).
 * 0, or -1/errno. */
int pblock_catalog_put(pblock_catalog *cat, const char *path,
    const pblock_meta *meta);

/* Insert a NEW row (fails if `path` already exists). 0, -1/errno (EEXIST on a
 * pre-existing path). Single statement — no separate existence lookup. */
int pblock_catalog_create(pblock_catalog *cat, const char *path,
    const pblock_meta *meta);

/* Apply a metadata change to an existing row in ONE UPDATE (no read-modify-write):
 * always bumps ctime to `now`; when set_mode, replaces the low 9 permission bits
 * with `perm` (preserving the type bits); when set_mtime, sets mtime. 0, or
 * -1/errno (ENOENT if the path is absent). */
int pblock_catalog_setattr(pblock_catalog *cat, const char *path,
    int set_mode, uint32_t perm, int set_mtime, int64_t mtime, int64_t now);

/* Update only size+mtime of an existing row. 0, or -1/errno (ENOENT if absent). */
int pblock_catalog_touch(pblock_catalog *cat, const char *path, int64_t size,
    int64_t mtime);

/* Remove the row for `path` (its xattrs too). 0, or -1/errno. */
int pblock_catalog_remove(pblock_catalog *cat, const char *path);

/* Number of direct children of `path` (directory-emptiness checks). >=0, -1/errno. */
int pblock_catalog_child_count(pblock_catalog *cat, const char *path);

/* Rename src->dst; a directory reparents every descendant in one transaction.
 * 0, or -1/errno. */
int pblock_catalog_rename(pblock_catalog *cat, const char *src, const char *dst);

/* Direct-children iteration over `parent`. */
typedef struct pblock_catalog_iter pblock_catalog_iter;
pblock_catalog_iter *pblock_catalog_opendir(pblock_catalog *cat,
    const char *parent);
/* Write the next child's basename into name[cap]: 0 = filled, 1 = end, -1/errno. */
int pblock_catalog_readdir(pblock_catalog_iter *it, char *name, size_t cap);
void pblock_catalog_closedir(pblock_catalog_iter *it);

/* xattr CRUD keyed by (path, name). get/list return the byte length (or the
 * needed length when cap is too small, like the POSIX *xattr family), -1/errno
 * on error; ENODATA when the name is absent. list emits NUL-separated names. */
ssize_t pblock_catalog_getxattr(pblock_catalog *cat, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t pblock_catalog_listxattr(pblock_catalog *cat, const char *path,
    void *buf, size_t cap);
int pblock_catalog_setxattr(pblock_catalog *cat, const char *path,
    const char *name, const void *val, size_t len);
int pblock_catalog_removexattr(pblock_catalog *cat, const char *path,
    const char *name);

#endif /* XROOTD_SD_PBLOCK_CATALOG_H */
