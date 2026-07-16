/*
 * sd_pblock_catalog.c — connection/cache core of the pblock SQLite catalog.
 *
 * WHAT: Owns the catalog's lifecycle and the machinery its two sibling files
 *       build on: opening the sqlite3 connection (schema bootstrap, WAL + sync
 *       tunables), closing it, the direct-mapped namespace lookup cache
 *       (nscache_*), and the shared SQL primitives (cat_prepare/cat_exec/cat_fail,
 *       parent_of/cat_parent_gate). The single-row objects CRUD lives in
 *       sd_pblock_catalog_objects.c and the namespace-tree operations (rename,
 *       directory iteration, xattrs) in sd_pblock_catalog_ns.c; both reach this
 *       core through sd_pblock_catalog_internal.h.
 *
 * WHY:  See the header. This layer is pure libc + sqlite3 so it is independently
 *       unit-testable and carries none of the data-plane cost — the driver above
 *       it touches it only at metadata boundaries (open, fsync, close, namespace).
 *       Split from a single 1054-line file (phase-79) to hold every catalog file
 *       under the ~500-line, one-concept-per-file cap.
 *
 * HOW:  One sqlite3 connection per handle, opened SERIALIZED (SQLITE_OPEN_FULLMUTEX)
 *       so a single per-export instance can be shared across a worker's thread
 *       pool, and in WAL mode with a busy timeout so separate worker *processes*
 *       contend safely. Statements are prepared per call (no cached cursors to
 *       race between threads) and finalized immediately. All paths are bound
 *       parameters — never string-formatted into SQL.
 *
 * Compiled only when the build found libsqlite3 (BRIX_HAVE_SQLITE), the
 * same gate as sd_pblock.c — a no-sqlite build must stay byte-for-byte
 * unchanged (see ./config).
 */
#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "sd_pblock_catalog_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>
#include <pthread.h>
#include <stdint.h>

/* ---- namespace lookup cache ---------------------------------------------- *
 * The cache layout (struct pblock_catalog, pblock_nscache_ent, the bucket/path
 * limits) and the design rationale live in sd_pblock_catalog_internal.h so the
 * objects/namespace files can consult and invalidate it. The mutators below are
 * non-static (declared there) except the two purely local helpers. */

/* FNV-1a of `path`, masked to the bucket count (power of two). */
static uint32_t
nscache_hash(const char *p)
{
    uint32_t h = 2166136261u;

    for (; *p != '\0'; p++) {
        h = (h ^ (unsigned char) *p) * 16777619u;
    }
    return h & (PBLOCK_NSCACHE_BUCKETS - 1u);
}

static int
nscache_ok(const char *p)
{
    return p != NULL && strlen(p) < PBLOCK_NSCACHE_PATHMAX;
}

/* Positive hit → 1 and fills *out (when non-NULL); miss → 0. */
int
nscache_get(pblock_catalog *cat, const char *path, pblock_meta *out)
{
    pblock_nscache_ent *e;
    int                 hit = 0;

    if (cat->cache == NULL || !nscache_ok(path)) {
        return 0;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    e = &cat->cache[nscache_hash(path)];
    if (e->valid && strcmp(e->path, path) == 0) {
        if (out != NULL) {
            *out = e->meta;
        }
        hit = 1;
    }
    pthread_mutex_unlock(&cat->cache_mtx);
    return hit;
}

/* Snapshot the generation (call before the SQL read whose result may be cached). */
uint64_t
nscache_gen(pblock_catalog *cat)
{
    uint64_t g;

    if (cat->cache == NULL) {
        return 0;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    g = cat->cache_gen;
    pthread_mutex_unlock(&cat->cache_mtx);
    return g;
}

/* Store a positive entry, but only if no invalidation happened since `gen` was
 * snapshotted (else the row we read may already be stale → drop it). */
void
nscache_store(pblock_catalog *cat, const char *path, const pblock_meta *meta,
    uint64_t gen)
{
    pblock_nscache_ent *e;

    if (cat->cache == NULL || !nscache_ok(path)) {
        return;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    if (cat->cache_gen == gen) {
        e = &cat->cache[nscache_hash(path)];
        memcpy(e->path, path, strlen(path) + 1);
        e->meta = *meta;
        e->valid = 1;
    }
    pthread_mutex_unlock(&cat->cache_mtx);
}

/* Authoritative install after a write (put): bump the generation (discarding any
 * concurrent lookup-fill for this path) and store the just-written meta, so the
 * common write-then-read sequence (create → chmod → stat) serves the reads from
 * memory. Assumes a path is not written concurrently from two threads (true on
 * the worker event loop; the SQL write remains the source of truth regardless). */
void
nscache_put(pblock_catalog *cat, const char *path, const pblock_meta *meta)
{
    pblock_nscache_ent *e;

    if (cat->cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    cat->cache_gen++;
    if (nscache_ok(path)) {
        e = &cat->cache[nscache_hash(path)];
        memcpy(e->path, path, strlen(path) + 1);
        e->meta = *meta;
        e->valid = 1;
    }
    pthread_mutex_unlock(&cat->cache_mtx);
}

/* Drop the entry for `path` (if present) and bump the generation so any
 * in-flight fill for a now-stale read is discarded. */
void
nscache_inval(pblock_catalog *cat, const char *path)
{
    pblock_nscache_ent *e;

    if (cat->cache == NULL || !nscache_ok(path)) {
        return;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    cat->cache_gen++;
    e = &cat->cache[nscache_hash(path)];
    if (e->valid && strcmp(e->path, path) == 0) {
        e->valid = 0;
    }
    pthread_mutex_unlock(&cat->cache_mtx);
}

/* Invalidate everything (used by rename, which reparents whole subtrees). */
void
nscache_clear(pblock_catalog *cat)
{
    if (cat->cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cat->cache_mtx);
    cat->cache_gen++;
    memset(cat->cache, 0,
           (size_t) PBLOCK_NSCACHE_BUCKETS * sizeof(cat->cache[0]));
    pthread_mutex_unlock(&cat->cache_mtx);
}

/* ---- small helpers -------------------------------------------------------- */

/* cat_fail — set errno and return -1 (the uniform error exit for int returns). */
int
cat_fail(int err)
{
    errno = err;
    return -1;
}

/* cat_prepare — prepare `sql` on the connection; NULL with errno=EIO on failure. */
sqlite3_stmt *
cat_prepare(pblock_catalog *cat, const char *sql)
{
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(cat->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        errno = EIO;
        return NULL;
    }
    return stmt;
}

/* cat_exec — run a parameterless statement (PRAGMA/DDL/transaction control).
 * Returns 0 or -1 with errno=EIO. */
int
cat_exec(pblock_catalog *cat, const char *sql)
{
    if (sqlite3_exec(cat->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        return cat_fail(EIO);
    }
    return 0;
}

/* parent_of — write the parent directory path of `path` into out[cap]. An
 * absolute child of the root ("/x") and the root itself both yield "/". */
void
parent_of(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    size_t      len;

    /* The root has no parent ("" — not "/", which would make it its own child in
     * a parent= listing). A direct child of the root has parent "/". */
    if (path[0] == '/' && path[1] == '\0') {
        out[0] = '\0';
        return;
    }
    if (slash == NULL || slash == path) {
        snprintf(out, cap, "/");
        return;
    }
    len = (size_t) (slash - path);
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(out, path, len);
    out[len] = '\0';
}

/* cat_parent_gate — POSIX parent gate for a NEW namespace row: the immediate
 * parent must exist and be a directory. "/" exists implicitly (flat exports
 * never pay a lookup), and the root row itself (parent "") always passes.
 * Without this gate a create with missing parents inserted an ORPHAN: the key
 * resolved (GET worked) but no parent= listing could ever reach it — readdir of
 * an ancestor showed nothing and stat of the missing parent said ENOENT. Costs
 * one indexed lookup per NEW row — creates only, never the byte path — and the
 * nscache usually answers it. */
int
cat_parent_gate(pblock_catalog *cat, const char *path)
{
    char         parent[1024];
    pblock_meta  pm;

    parent_of(path, parent, sizeof(parent));
    if (parent[0] == '\0'                                /* the root row    */
        || (parent[0] == '/' && parent[1] == '\0'))      /* child of "/"    */
    {
        return 0;
    }
    if (pblock_catalog_lookup(cat, parent, &pm) != 0) {
        return cat_fail(ENOENT);
    }
    if (!pm.is_dir) {
        return cat_fail(ENOTDIR);
    }
    return 0;
}

/* ---- open / close --------------------------------------------------------- */

pblock_catalog *
pblock_catalog_open(const char *db_path, int busy_timeout_ms)
{
    pblock_catalog *cat;
    int             flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                            | SQLITE_OPEN_FULLMUTEX;

    if (db_path == NULL) {
        errno = EINVAL;
        return NULL;
    }

    cat = calloc(1, sizeof(*cat));
    if (cat == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    if (sqlite3_open_v2(db_path, &cat->db, flags, NULL) != SQLITE_OK) {
        sqlite3_close(cat->db);   /* close is NULL/partial-open safe */
        free(cat);
        errno = EIO;
        return NULL;
    }

    sqlite3_busy_timeout(cat->db, busy_timeout_ms > 0 ? busy_timeout_ms : 0);

    /* Durability/throughput tunables (env): PBLOCK_SYNC ∈ {OFF,NORMAL,FULL}
     * (default NORMAL) selects the WAL fsync discipline; PBLOCK_WAL_AUTOCKPT sets
     * the WAL auto-checkpoint threshold in pages (default SQLite's 1000; 0 disables
     * auto-checkpoint). Used to characterise the metadata-throughput trade-off. */
    {
        const char *sync_env = getenv("PBLOCK_SYNC");
        const char *ck_env   = getenv("PBLOCK_WAL_AUTOCKPT");
        char        pragma[64];

        if (sync_env == NULL
            || (strcmp(sync_env, "OFF") != 0 && strcmp(sync_env, "NORMAL") != 0
                && strcmp(sync_env, "FULL") != 0)) {
            sync_env = "NORMAL";
        }
        snprintf(pragma, sizeof(pragma), "PRAGMA synchronous=%s;", sync_env);
        if (cat_exec(cat, "PRAGMA journal_mode=WAL;") != 0
            || cat_exec(cat, pragma) != 0) {
            int err = errno;
            sqlite3_close(cat->db);
            free(cat);
            errno = err;
            return NULL;
        }
        if (ck_env != NULL) {
            snprintf(pragma, sizeof(pragma),
                     "PRAGMA wal_autocheckpoint=%d;", atoi(ck_env));
            (void) cat_exec(cat, pragma);   /* best-effort */
        }
    }

    if (cat_exec(cat,
               "CREATE TABLE IF NOT EXISTS objects("
               "  path TEXT PRIMARY KEY,"
               "  parent TEXT NOT NULL,"
               "  is_dir INTEGER NOT NULL,"
               "  blob_id TEXT NOT NULL DEFAULT '',"
               "  size INTEGER NOT NULL DEFAULT 0,"
               "  block_size INTEGER NOT NULL DEFAULT 0,"
               "  mtime INTEGER NOT NULL DEFAULT 0,"
               "  ctime INTEGER NOT NULL DEFAULT 0,"
               "  mode INTEGER NOT NULL DEFAULT 0,"
               "  uid INTEGER NOT NULL DEFAULT 0,"
               "  gid INTEGER NOT NULL DEFAULT 0);") != 0
        || cat_exec(cat,
               "CREATE INDEX IF NOT EXISTS objects_parent"
               "  ON objects(parent);") != 0
        || cat_exec(cat,
               "CREATE TABLE IF NOT EXISTS xattrs("
               "  path TEXT NOT NULL,"
               "  name TEXT NOT NULL,"
               "  value BLOB NOT NULL,"
               "  PRIMARY KEY(path, name));") != 0
        || cat_exec(cat,
               /* Identity registry: catalog-internal synthetic uid/gid
                * assignment (kind 0 = principal/uid, 1 = VO-group/gid). The
                * UNIQUE index makes an id collision from a concurrent
                * assignment a constraint failure, not silent aliasing. */
               "CREATE TABLE IF NOT EXISTS ids("
               "  kind INTEGER NOT NULL,"
               "  name TEXT NOT NULL,"
               "  id INTEGER NOT NULL,"
               "  PRIMARY KEY(kind, name));") != 0
        || cat_exec(cat,
               "CREATE UNIQUE INDEX IF NOT EXISTS ids_id ON ids(id);") != 0)
    {
        int err = errno;

        sqlite3_close(cat->db);
        free(cat);
        errno = err;
        return NULL;
    }

    /* Forward-compat: add columns to an `objects` table created before they
     * existed. Best-effort — a "duplicate column" error on an up-to-date
     * schema is expected and ignored. Pre-migration rows keep uid/gid 0
     * (service-owned), matching their pre-identity behaviour. */
    sqlite3_exec(cat->db,
        "ALTER TABLE objects ADD COLUMN block_size INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    sqlite3_exec(cat->db,
        "ALTER TABLE objects ADD COLUMN uid INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    sqlite3_exec(cat->db,
        "ALTER TABLE objects ADD COLUMN gid INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);

    /* Namespace lookup cache (best-effort: a calloc failure just disables it —
     * lookups still work, only slower). */
    pthread_mutex_init(&cat->cache_mtx, NULL);
    cat->cache_gen = 0;
    cat->cache = calloc((size_t) PBLOCK_NSCACHE_BUCKETS, sizeof(*cat->cache));

    return cat;
}

void
pblock_catalog_close(pblock_catalog *cat)
{
    if (cat == NULL) {
        return;
    }
    if (cat->cache != NULL) {
        free(cat->cache);
    }
    pthread_mutex_destroy(&cat->cache_mtx);
    sqlite3_close(cat->db);
    free(cat);
}

#else

/* ISO C forbids an empty translation unit; a no-sqlite build compiles this
 * file to nothing but this placeholder (same contract as sd_pblock.c). */
typedef int brix_sd_pblock_catalog_disabled_t;

#endif /* BRIX_HAVE_SQLITE */
