/* pathidx.h — G6 mmap path index (phase-87; pure C, no ngx/FUSE).
 *
 * WHAT: a pinned-revision, memory-mapped index of the ENTIRE merged namespace
 *       — path → full dirent (mode, size, mtime, owner, symlink target,
 *       content hash) — answering resolve() and readdir() with zero SQLite
 *       opens.
 * WHY:  metadata-heavy workloads (`find`, build-system stats) pay a catalog
 *       round-trip per lookup; one flat mmap'd table answers them at memory
 *       speed and pages lazily.
 * HOW:  built from the same VERIFIED walk as the G1 negative filter, so every
 *       entry came out of a hash-checked catalog. On-disk sidecar =
 *       host-ABI structs (hash_sz/ent_sz header guards refuse a foreign
 *       layout), entries sorted by (dirname, name) so a directory's children
 *       are one contiguous run, plus an FNV-1a-64 open-addressing bucket
 *       table for point lookups. (The phase-87 doc sketches CHD/FST; this
 *       lands the simpler sorted-run + hash-table layout with the same
 *       contract — divergence recorded in the doc's LANDED block.)
 *
 * Integrity: the header carries a crc32 (build-time corruption of the GEOMETRY
 * is refused at open) and the root-catalog hash (an index for revision A is
 * never consulted for revision B). Entry payloads are NOT crc'd by design —
 * the file pages lazily and every content read is still CAS-verified, so a
 * tampered entry is caught at first read and the client drops the index.
 */
#ifndef BRIX_CVMFS_PATHIDX_H
#define BRIX_CVMFS_PATHIDX_H

#include <stddef.h>
#include <stdint.h>
#include "cvmfs/grammar/hash.h"
#include "cvmfs/catalog/catalog.h"

#define CVMFS_PATHIDX_MAGIC   0x49505842u   /* "BXPI" little-endian */
#define CVMFS_PATHIDX_VERSION 1u

typedef struct {
    uint32_t     magic;
    uint32_t     version;
    uint32_t     hash_sz;      /* sizeof(cvmfs_hash_t) — host-ABI guard */
    uint32_t     ent_sz;       /* sizeof(cvmfs_pathidx_ent_t) — host-ABI guard */
    cvmfs_hash_t root;         /* root catalog this index was built from */
    uint64_t     count;        /* entries (includes the "" root entry) */
    uint64_t     nbuckets;     /* power of two */
    uint64_t     ents_off;     /* all offsets are from file start */
    uint64_t     buckets_off;
    uint64_t     blob_off;
    uint64_t     blob_len;
    uint64_t     file_len;
    uint32_t     hdr_crc;      /* crc32 of this header with hdr_crc zeroed */
    uint32_t     rsvd;
} cvmfs_pathidx_hdr_t;

/* One namespace entry. Strings live in the blob, NUL-terminated. The path is
 * repo-root-relative ("/a/b"; "" = repo root) and splits as
 * dirname = path[0..dlen), name = path + dlen + 1 (path[dlen] == '/'). */
typedef struct {
    uint64_t     path_off;
    uint32_t     path_len;
    uint32_t     dlen;
    uint64_t     size;
    int64_t      mtime;
    uint32_t     mode;
    uint32_t     flags;        /* CVMFS_FLAG_* */
    uint64_t     link_off;     /* symlink target; link_len 0 = none */
    uint32_t     link_len;
    uint32_t     has_hash;
    uint32_t     uid, gid;
    uint32_t     linkcount;
    uint32_t     rsvd;
    cvmfs_hash_t hash;
} cvmfs_pathidx_ent_t;

/* ---- builder (accumulate dirents, then write the sidecar) ---------------- */

typedef struct {
    char         *path;        /* heap copies, owned by the builder */
    char         *link;        /* symlink target or NULL */
    uint64_t      size;
    int64_t       mtime;
    uint32_t      mode, flags, uid, gid, linkcount, has_hash;
    cvmfs_hash_t  hash;
} cvmfs_pathidx_bent_t;

typedef struct {
    cvmfs_pathidx_bent_t *v;
    size_t                n, cap;
    int                   oom;   /* any failed add poisons the build */
} cvmfs_pathidx_build_t;

void cvmfs_pathidx_build_init(cvmfs_pathidx_build_t *b);
int  cvmfs_pathidx_build_add(cvmfs_pathidx_build_t *b, const char *path,
                             const cvmfs_dirent_t *e);
void cvmfs_pathidx_build_free(cvmfs_pathidx_build_t *b);

/* Sort, lay out and atomically write the sidecar `name` under `dfd`
 * (tmp + renameat). Returns 0, or -1 (oom flag set, I/O error). */
int cvmfs_pathidx_write(cvmfs_pathidx_build_t *b, const cvmfs_hash_t *root,
                        int dfd, const char *name);

/* ---- mmap reader --------------------------------------------------------- */

typedef struct {
    void                       *map;
    size_t                      maplen;
    const cvmfs_pathidx_hdr_t  *hdr;
    const cvmfs_pathidx_ent_t  *ents;
    const uint32_t             *buckets;   /* entry_idx + 1; 0 = empty */
    const char                 *blob;
} cvmfs_pathidx_t;

/* Map + validate sidecar `name` under `dfd` (magic, version, ABI sizes,
 * header crc, every section inside the file). 0 on success, -1 refused. */
int  cvmfs_pathidx_open(cvmfs_pathidx_t *ix, int dfd, const char *name);
void cvmfs_pathidx_close(cvmfs_pathidx_t *ix);

/* Root catalog hash the index was built from. */
const cvmfs_hash_t *cvmfs_pathidx_root(const cvmfs_pathidx_t *ix);

/* Look up `path`. The index covers the COMPLETE namespace, so the answer is
 * authoritative both ways: 1 found (*out filled), 0 absent, -1 internal
 * defect (corrupt entry/bucket — caller should stop trusting the index). */
int cvmfs_pathidx_lookup(const cvmfs_pathidx_t *ix, const char *path,
                         cvmfs_dirent_t *out);

/* Enumerate the direct children of directory `dir` in name order. Returns the
 * child count, or -1 when `dir` is not an indexed directory (or an entry is
 * corrupt) — the caller falls back to the catalogs. */
int cvmfs_pathidx_readdir(const cvmfs_pathidx_t *ix, const char *dir,
                          cvmfs_readdir_cb cb, void *ud);

#endif /* BRIX_CVMFS_PATHIDX_H */
