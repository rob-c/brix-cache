/* catalog.h — CVMFS SQLite catalog reader (pure C; links libsqlite3 + libcrypto).
 *
 * WHAT: open a decompressed CVMFS catalog (a SQLite DB) and answer the questions
 *       a read-only FUSE layer asks — lookup(path), readdir(dir), the nested
 *       catalog covering a path, and the chunk list of a chunked file.
 * WHY:  catalogs ARE the CVMFS namespace + metadata; the client resolves every
 *       path through them before it ever fetches content.
 * HOW:  rows are keyed by md5path_{1,2} = the two little-endian int64 halves of
 *       MD5(path) (CVMFS `Md5::ToIntPair`), and a directory's children carry that
 *       md5 in parent_{1,2}. `flags` bits classify the entry and mark nested-catalog
 *       transition points. Paths are repo-root-relative, no trailing slash; the
 *       catalog root entry is the empty path "". libsqlite3 read-only, prepared
 *       statements, no allocation beyond fixed dirent buffers.
 */
#ifndef BRIX_CVMFS_CATALOG_H
#define BRIX_CVMFS_CATALOG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "cvmfs/grammar/hash.h"

/* CVMFS catalog `flags` bits (subset; see cvmfs catalog_sql.h). */
#define CVMFS_FLAG_DIR                 1u
#define CVMFS_FLAG_DIR_NESTED_MOUNT    2u    /* transition point to a nested catalog */
#define CVMFS_FLAG_FILE                4u
#define CVMFS_FLAG_LINK                8u    /* symlink */
#define CVMFS_FLAG_DIR_NESTED_ROOT    32u    /* root entry of a nested catalog */
#define CVMFS_FLAG_FILE_CHUNK         64u    /* file is split into chunks */

typedef struct {
    char         name[256];
    uint32_t     flags;
    uint32_t     mode;          /* unix st_mode */
    uint64_t     size;
    int64_t      mtime;
    uint32_t     uid, gid;
    uint32_t     linkcount;
    char         symlink[1024]; /* target when CVMFS_FLAG_LINK */
    int          has_hash;
    cvmfs_hash_t hash;          /* content hash for regular files */
} cvmfs_dirent_t;

typedef struct cvmfs_catalog_s cvmfs_catalog_t;

/* Open a decompressed catalog SQLite file read-only. NULL on error. */
cvmfs_catalog_t *cvmfs_catalog_open(const char *db_path);
void             cvmfs_catalog_close(cvmfs_catalog_t *c);

/* Compute the md5-path key halves for a repo-root-relative path. */
void cvmfs_catalog_md5path(const char *path, int64_t *m1, int64_t *m2);

/* Look up `path`; fill *out. Returns 1 if found, 0 if absent, -1 on error. */
int cvmfs_catalog_lookup(cvmfs_catalog_t *c, const char *path, cvmfs_dirent_t *out);

/* Invoke `cb` for each direct child of directory `path`. Returns the child count
 * or -1 on error. */
typedef void (*cvmfs_readdir_cb)(const cvmfs_dirent_t *e, void *ud);
int cvmfs_catalog_readdir(cvmfs_catalog_t *c, const char *path, cvmfs_readdir_cb cb, void *ud);

/* If `path` is a nested-catalog mountpoint, return its catalog hash + size.
 * Returns 1 if found, 0 if `path` is not a mountpoint, -1 on error. */
int cvmfs_catalog_nested(cvmfs_catalog_t *c, const char *path, cvmfs_hash_t *hash, uint64_t *size);

/* Emit each chunk (offset,size,hash) of a chunked file `path` in offset order.
 * Returns the chunk count or -1 on error. */
typedef void (*cvmfs_chunk_cb)(uint64_t offset, uint64_t size, const cvmfs_hash_t *hash, void *ud);
int cvmfs_catalog_chunks(cvmfs_catalog_t *c, const char *path, cvmfs_chunk_cb cb, void *ud);

/* Read a properties(key)→value string (e.g. "revision"). 1 if found. */
int cvmfs_catalog_property(cvmfs_catalog_t *c, const char *key, char *out, size_t outlen);

#endif /* BRIX_CVMFS_CATALOG_H */
