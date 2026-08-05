/* catalog_write.h — CVMFS SQLite catalog WRITER (pure C; phase-96 S1/S5/S8).
 *
 * WHAT: create a catalog from the pinned DDL (or open a working copy of an
 *       existing one), upsert/delete dirent rows, nested-catalog rows, chunk
 *       rows, properties, and the statistics counters — everything a publish
 *       needs to mint or mutate a catalog the reader (catalog.c) accepts.
 * WHY:  catalog.c is read-only by design; the release-manager plane needs the
 *       write half, unit-tested against that reader in the same directory.
 * HOW:  rows keyed by md5path int64 pairs (cvmfs_catalog_md5path); hardlinks
 *       column encodes (group << 32) | linkcount; explicit transaction per
 *       catalog (mirroring sd_pblock_catalog.c conventions), committed on
 *       cvmfs_catwriter_commit. The committed DB file is then compressed and
 *       CAS-stored with the 'C' suffix by the object writer.
 */
#ifndef BRIX_CVMFS_CATALOG_WRITE_H
#define BRIX_CVMFS_CATALOG_WRITE_H

#include <stddef.h>
#include <stdint.h>
#include "cvmfs/grammar/hash.h"
#include "cvmfs/catalog/catalog.h"

typedef struct cvmfs_catwriter_s cvmfs_catwriter_t;

/* One dirent row to upsert. `path` is repo-root-relative ("" = catalog root;
 * for a nested catalog the root path is the mountpoint path). */
typedef struct {
    const char          *path;
    uint32_t             flags;          /* CVMFS_FLAG_* */
    uint32_t             mode;           /* full st_mode (type bits included) */
    uint64_t             size;
    int64_t              mtime;
    uint32_t             uid, gid;
    uint32_t             linkcount;      /* 0 → stored as 1 */
    uint32_t             hardlink_group; /* 0 = not in a group */
    const char          *symlink;        /* target when CVMFS_FLAG_LINK, else NULL */
    const cvmfs_hash_t  *hash;           /* content hash, NULL for dirs/chunked */
    const unsigned char *xattr;          /* packed xattr BLOB or NULL */
    size_t               xattr_len;
} cvmfs_catrow_t;

/* Create a fresh catalog DB at `db_path` (fails if the file exists), or open
 * an existing working copy read-write. Both begin a transaction. */
cvmfs_catwriter_t *cvmfs_catwriter_create(const char *db_path);
cvmfs_catwriter_t *cvmfs_catwriter_open(const char *db_path);

/* Commit the transaction and close; the DB file at db_path is complete.
 * cvmfs_catwriter_abort rolls back and closes. 0 on success. */
int  cvmfs_catwriter_commit(cvmfs_catwriter_t *w);
void cvmfs_catwriter_abort(cvmfs_catwriter_t *w);

/* Insert or replace one dirent row. Duplicate paths REPLACE (upsert);
 * use cvmfs_catwriter_insert for a duplicate-refusing plain INSERT. */
int cvmfs_catwriter_upsert(cvmfs_catwriter_t *w, const cvmfs_catrow_t *r);
int cvmfs_catwriter_insert(cvmfs_catwriter_t *w, const cvmfs_catrow_t *r);

/* Delete the row for `path` plus its chunk rows. 0 even if absent. */
int cvmfs_catwriter_delete(cvmfs_catwriter_t *w, const char *path);

/* Recursively delete `path` and everything under it owned by THIS catalog:
 * dirent rows, chunk rows, and nested_catalogs rows at/under the path.
 * Returns the number of dirent rows removed, or -1. */
int cvmfs_catwriter_delete_subtree(cvmfs_catwriter_t *w, const char *path);

/* chunks row for a chunked file (dirent must carry CVMFS_FLAG_FILE_CHUNK). */
int cvmfs_catwriter_add_chunk(cvmfs_catwriter_t *w, const char *path,
                              uint64_t offset, uint64_t size, const cvmfs_hash_t *hash);
/* Drop all chunk rows of `path` (before re-emitting on modify). */
int cvmfs_catwriter_clear_chunks(cvmfs_catwriter_t *w, const char *path);

/* nested_catalogs row upsert / delete. `sha1_hex` is the child catalog hash. */
int cvmfs_catwriter_set_nested(cvmfs_catwriter_t *w, const char *path,
                               const char *sha1_hex, uint64_t size);
int cvmfs_catwriter_del_nested(cvmfs_catwriter_t *w, const char *path);

/* properties upsert. */
int cvmfs_catwriter_set_property(cvmfs_catwriter_t *w, const char *key, const char *value);

/* Recompute the statistics table (self_* counters) from the current rows:
 * self_regular/self_dir/self_symlink/self_nested/self_chunked/self_chunks/
 * self_file_size/self_chunked_size/self_xattr — plus the matching subtree_*
 * counters seeded to 0 (the publisher overwrites them with the aggregated
 * child totals via cvmfs_catwriter_set_counter). 0 on success. */
int cvmfs_catwriter_update_counters(cvmfs_catwriter_t *w);

/* Upsert / read back a single statistics counter. set: 0 on success.
 * get: 1 found, 0 absent (*out untouched), -1 error. */
int cvmfs_catwriter_set_counter(cvmfs_catwriter_t *w, const char *name, int64_t value);
int cvmfs_catwriter_get_counter(cvmfs_catwriter_t *w, const char *name, int64_t *out);

/* ---- read-backs publish needs on its own working copy ------------------- */

/* Look up `path` in the working copy (same semantics as cvmfs_catalog_lookup). */
int cvmfs_catwriter_lookup(cvmfs_catwriter_t *w, const char *path, cvmfs_dirent_t *out);

/* Invoke `cb` for each nested_catalogs row. Returns row count or -1. */
typedef void (*cvmfs_nested_cb)(const char *path, const char *sha1_hex,
                                uint64_t size, void *ud);
int cvmfs_catwriter_list_nested(cvmfs_catwriter_t *w, cvmfs_nested_cb cb, void *ud);

/* ---- xattr BLOB packing (upstream XattrList serialization) --------------- */

/* Pack N (key,value) pairs into the catalog xattr BLOB form:
 * u8 version(1), u8 count, then per entry u8 key_len, u16le value_len,
 * key bytes, value bytes. Bounds: key ≤ 255, value ≤ 65535, count ≤ 255.
 * Returns packed length or -1 on bound/overflow violation. */
int cvmfs_xattr_pack(const char *const *keys, const unsigned char *const *vals,
                     const size_t *val_lens, size_t n, unsigned char *out, size_t cap);

/* Unpack entry `i` of a packed BLOB. 0 on success, -1 out of range/malformed. */
int cvmfs_xattr_unpack(const unsigned char *blob, size_t blob_len, size_t i,
                       const char **key, size_t *key_len,
                       const unsigned char **val, size_t *val_len);

/* Entry count of a packed BLOB, or -1 if malformed. */
int cvmfs_xattr_count(const unsigned char *blob, size_t blob_len);

#endif /* BRIX_CVMFS_CATALOG_WRITE_H */
