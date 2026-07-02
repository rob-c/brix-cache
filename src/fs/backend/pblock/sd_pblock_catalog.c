/*
 * sd_pblock_catalog.c — SQLite metadata catalog for the pblock backend.
 *
 * WHAT: Implements sd_pblock_catalog.h: schema bootstrap and typed CRUD over the
 *       `objects` (namespace + stat + path->blob map) and `xattrs` tables.
 *
 * WHY:  See the header. This layer is pure libc + sqlite3 so it is independently
 *       unit-testable and carries none of the data-plane cost — the driver above
 *       touches it only at metadata boundaries (open, fsync, close, namespace).
 *
 * HOW:  One sqlite3 connection per handle, opened SERIALIZED (SQLITE_OPEN_FULLMUTEX)
 *       so a single per-export instance can be shared across a worker's thread
 *       pool, and in WAL mode with a busy timeout so separate worker *processes*
 *       contend safely. Statements are prepared per call (no cached cursors to
 *       race between threads) and finalized immediately. All paths are bound
 *       parameters — never string-formatted into SQL. Directory rename collects
 *       the affected paths first, then reparents each in one transaction.
 */
#include "sd_pblock_catalog.h"
#include "compat/snprintf_check.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>
#include <pthread.h>
#include <stdint.h>

/* ---- namespace lookup cache --------------------------------------------- *
 * A direct-mapped path→meta cache in front of SQLite. It collapses the
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
static int
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
static uint64_t
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
static void
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
static void
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
static void
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
static void
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

struct pblock_catalog_iter {
    sqlite3_stmt *stmt;
};

/* ---- small helpers -------------------------------------------------------- */

/* cat_fail — set errno and return -1 (the uniform error exit for int returns). */
static int
cat_fail(int err)
{
    errno = err;
    return -1;
}

/* cat_prepare — prepare `sql` on the connection; NULL with errno=EIO on failure. */
static sqlite3_stmt *
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
static int
cat_exec(pblock_catalog *cat, const char *sql)
{
    if (sqlite3_exec(cat->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        return cat_fail(EIO);
    }
    return 0;
}

/* parent_of — write the parent directory path of `path` into out[cap]. An
 * absolute child of the root ("/x") and the root itself both yield "/". */
static void
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

/* basename_of — the final path component (pointer into `path`). */
static const char *
basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
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
               "  mode INTEGER NOT NULL DEFAULT 0);") != 0
        || cat_exec(cat,
               "CREATE INDEX IF NOT EXISTS objects_parent"
               "  ON objects(parent);") != 0
        || cat_exec(cat,
               "CREATE TABLE IF NOT EXISTS xattrs("
               "  path TEXT NOT NULL,"
               "  name TEXT NOT NULL,"
               "  value BLOB NOT NULL,"
               "  PRIMARY KEY(path, name));") != 0)
    {
        int err = errno;

        sqlite3_close(cat->db);
        free(cat);
        errno = err;
        return NULL;
    }

    /* Forward-compat: add block_size to an `objects` table created before the
     * column existed. Best-effort — a "duplicate column" error on an up-to-date
     * schema is expected and ignored. */
    sqlite3_exec(cat->db,
        "ALTER TABLE objects ADD COLUMN block_size INTEGER NOT NULL DEFAULT 0;",
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

/* ---- objects -------------------------------------------------------------- */

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
        "SELECT is_dir, blob_id, size, block_size, mtime, ctime, mode"
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
    sqlite3_finalize(stmt);

    nscache_store(cat, path, &m, gen);
    if (out != NULL) {
        *out = m;
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
    parent_of(path, parent, sizeof(parent));

    stmt = cat_prepare(cat,
        "INSERT OR REPLACE INTO objects"
        "  (path, parent, is_dir, blob_id, size, block_size, mtime, ctime, mode)"
        "  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);");
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
    parent_of(path, parent, sizeof(parent));

    stmt = cat_prepare(cat,
        "INSERT INTO objects"
        "  (path, parent, is_dir, blob_id, size, block_size, mtime, ctime, mode)"
        "  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);");
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

/* Apply mode/mtime changes in a single UPDATE (no read-modify-write). The cached
 * entry is dropped since the new full meta is not re-read here. */
int
pblock_catalog_setattr(pblock_catalog *cat, const char *path,
    int set_mode, uint32_t perm, int set_mtime, int64_t mtime, int64_t now)
{
    sqlite3_stmt *stmt;
    int           rc, changed;

    /* ?1=now ?2=set_mode ?3=perm ?4=set_mtime ?5=mtime ?6=path. 61440 == S_IFMT
     * and 511 == 0777, so the new mode keeps only the type bits and replaces the
     * permission triad — matching the prior read-modify-write exactly. */
    stmt = cat_prepare(cat,
        "UPDATE objects SET"
        "  ctime = ?1,"
        "  mode  = CASE WHEN ?2 THEN (mode & 61440) | (?3 & 511) ELSE mode END,"
        "  mtime = CASE WHEN ?4 THEN ?5 ELSE mtime END"
        "  WHERE path = ?6;");
    if (stmt == NULL) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_int(stmt, 2, set_mode ? 1 : 0);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) perm);
    sqlite3_bind_int(stmt, 4, set_mtime ? 1 : 0);
    sqlite3_bind_int64(stmt, 5, mtime);
    sqlite3_bind_text(stmt, 6, path, -1, SQLITE_STATIC);

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
    dup = strdup(s);
    if (dup == NULL) {
        return -1;
    }
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
    if (!xrootd_snprintf_ok(new_path, sizeof(new_path), "%s%s", dst, tail)) {
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
    if (!xrootd_snprintf_ok(name, cap, "%s",
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
