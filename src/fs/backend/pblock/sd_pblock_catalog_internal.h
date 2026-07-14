/*
 * sd_pblock_catalog_internal.h — cross-file declarations shared between the three
 * translation units of the pblock SQLite catalog after the phase-79 size split.
 *
 * WHAT: Publishes the private catalog handle layout (the sqlite3 connection plus
 *       the namespace lookup cache) and the small set of internal helpers that
 *       are called across the file boundary: the SQL primitives
 *       (cat_fail/cat_prepare/cat_exec), the path helpers (parent_of /
 *       cat_parent_gate), and the namespace-cache mutators (nscache_*).
 *
 * WHY:  sd_pblock_catalog.c was one 1054-line file. It is split by concept into
 *       the core (connection lifecycle, the namespace cache, the shared SQL
 *       primitives — stays in sd_pblock_catalog.c), the objects-table row CRUD
 *       (sd_pblock_catalog_objects.c), and the namespace-tree operations —
 *       subtree rename, directory iteration, xattrs (sd_pblock_catalog_ns.c).
 *       The CRUD and namespace files reach the connection and the cache through
 *       the primitives declared here, so exactly those helpers become non-static.
 *       Nothing here is exported beyond the pblock backend — the public surface
 *       remains sd_pblock_catalog.h.
 *
 * HOW:  All three translation units include this header (in addition to the
 *       public sd_pblock_catalog.h). It is gated by BRIX_HAVE_SQLITE exactly like
 *       its includers, so a no-sqlite build stays byte-for-byte unchanged.
 *
 * Requires: sd_pblock_catalog.h (pblock_meta), <sqlite3.h>, <pthread.h>,
 *           <stdint.h>, <stddef.h> before inclusion.
 */
#ifndef BRIX_SD_PBLOCK_CATALOG_INTERNAL_H
#define BRIX_SD_PBLOCK_CATALOG_INTERNAL_H

#include "sd_pblock_catalog.h"

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <sqlite3.h>

/* ---- namespace lookup cache --------------------------------------------- *
 * A direct-mapped path->meta cache in front of SQLite. It collapses the
 * redundant per-op lookups the storage path makes — the existence gate's probe
 * plus the operation's own lookup, stat-after-write, and the shared-parent probe
 * every sibling create repeats — into a memory hit, skipping both the SQL
 * compile and the B-tree descent. POSITIVE entries only: an absent path always
 * falls through to SQL, so a create immediately following a miss stays correct.
 * Invalidated on every write to a path (put/touch/remove) and fully cleared on
 * rename (which reparents whole subtrees). A monotonically-bumped generation
 * makes the fill-after-miss coherent: if any write lands during the SQL window
 * the store is skipped, so a stale row can never be cached. Worker-local and
 * mutex-guarded (the catalog is shared across a worker's threads via FULLMUTEX).
 */
#define PBLOCK_NSCACHE_BUCKETS  8192u           /* power of two */
#define PBLOCK_NSCACHE_PATHMAX  256

typedef struct {
    char        path[PBLOCK_NSCACHE_PATHMAX];
    pblock_meta meta;
    uint8_t     valid;
} pblock_nscache_ent;

struct pblock_catalog {
    sqlite3            *db;
    pthread_mutex_t     cache_mtx;
    uint64_t            cache_gen;     /* bumped on any invalidation/clear */
    pblock_nscache_ent *cache;         /* BUCKETS entries, or NULL = disabled */
};

/* ---- shared SQL primitives (defined in sd_pblock_catalog.c) -------------- */

/* Set errno and return -1 — the uniform error exit for int-returning calls. */
int cat_fail(int err);

/* Prepare `sql` on the connection; NULL with errno=EIO on failure. */
sqlite3_stmt *cat_prepare(pblock_catalog *cat, const char *sql);

/* Run a parameterless statement (PRAGMA/DDL/transaction control). 0 or -1/EIO. */
int cat_exec(pblock_catalog *cat, const char *sql);

/* Write the parent directory path of `path` into out[cap]. */
void parent_of(const char *path, char *out, size_t cap);

/* POSIX parent gate for a NEW namespace row: 0 when the immediate parent exists
 * and is a directory; else -1 with errno ENOENT/ENOTDIR. */
int cat_parent_gate(pblock_catalog *cat, const char *path);

/* ---- namespace-cache mutators (defined in sd_pblock_catalog.c) ----------- */

/* Positive hit -> 1 and fills *out (when non-NULL); miss -> 0. */
int nscache_get(pblock_catalog *cat, const char *path, pblock_meta *out);

/* Snapshot the generation (call before a SQL read whose result may be cached). */
uint64_t nscache_gen(pblock_catalog *cat);

/* Store a positive entry, but only if no invalidation happened since `gen`. */
void nscache_store(pblock_catalog *cat, const char *path,
    const pblock_meta *meta, uint64_t gen);

/* Authoritative install after a write: bump the generation and cache `meta`. */
void nscache_put(pblock_catalog *cat, const char *path, const pblock_meta *meta);

/* Drop the entry for `path` and bump the generation. */
void nscache_inval(pblock_catalog *cat, const char *path);

/* Invalidate everything (used by rename, which reparents whole subtrees). */
void nscache_clear(pblock_catalog *cat);

#endif /* BRIX_SD_PBLOCK_CATALOG_INTERNAL_H */
