/*
 * pblock-fsck — Phase-83 F7 consistency oracle for a pblock export.
 *
 * WHAT: Cross-checks the pblock catalog (<root>/catalog.db, objects table)
 *       against the on-disk block files (<root>/data/<b0b1>/<b2b3>/<blob>/<idx>)
 *       and reports the divergence classes the driver's own "known limits" call
 *       out as THE pblock hazard:
 *         ORPHAN <blob>            — blob dir on disk with no catalog row
 *         DANGLING <path>          — file row whose blob dir / blocks are absent
 *         SIZE <path> cat=N disk=M — catalog size disagrees with block extent
 *         CSI <path> block=K       — block bytes disagree with the csi table CRC
 *                                    (--verify-csi only; F3 at-rest integrity)
 *         USAGE <scope> id=N stored=B/I actual=B/I — quota rollup diverges from
 *                                    a recompute (--verify-usage only; F5)
 *         REFS <blob> refcount=R referrers=N — tracked refcount disagrees with
 *                                    the referring-row count (--verify-refs; F10)
 *       Exit status is the finding-count class so pytest can assert on it:
 *         0 clean · 1 findings present · 2 usage/IO error · 3 refused (schema).
 *
 * WHY:  F7's crash points kill a worker mid-operation; on restart this tool is
 *       the assertion oracle — "kill between block write and catalog commit,
 *       restart, fsck shows exactly one orphan, --gc converges to zero". Every
 *       other lab feature's error-leg test reuses it as "and the store is still
 *       consistent".
 *
 * HOW:  Fully self-contained (libc + sqlite3) — it re-derives the trivial blob
 *       fan-out path math rather than linking the ngx-adjacent driver, so it
 *       builds with `cc pblock-fsck.c -lsqlite3`. Read-only by default; --gc
 *       removes orphan blob dirs + dangling rows, --repair rewrites a row's size
 *       to the block truth. Mutating modes refuse to run against a catalog whose
 *       PRAGMA user_version this build does not know (fail-closed on schema).
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#define PBLOCK_FSCK_SCHEMA 0        /* highest catalog user_version we understand */

struct opts {
    const char *root;
    int         gc;
    int         repair;
    int         verify_csi;         /* F3 — re-CRC each block file vs csi table */
    int         verify_usage;       /* F5 — usage rollup vs recompute from rows */
    int         verify_refs;        /* F10 — blobs.refcount vs referring rows   */
    const char *snapshot;           /* F6 — take a named snapshot then exit     */
    const char *restore;            /* F6 — restore a named snapshot then exit  */
    const char *list_versions;      /* F11 — list a path's retained versions    */
    int         list_trash;         /* F11 — list the trash ledger then exit    */
    const char *undelete;           /* F11 — pop a path out of the trash        */
    long long   trash_ttl;          /* F11 — --gc purge age in secs; -1 = off   */
};

static int g_findings;              /* total divergences reported this run */

#define PBLOCK_FSCK_CRC_POLY 0x82F63B78u   /* Castagnoli, reflected (INVARIANT 9) */

/* crc32c — standard CRC-32c, bit-by-bit, matching brix_crc32c_value()
 * (init 0xFFFFFFFF, reflected in/out, final XOR 0xFFFFFFFF). Kept local so the
 * tool stays `cc pblock-fsck.c -lsqlite3` self-contained like the rest of it. */
static uint32_t
crc32c(const unsigned char *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    int      k;

    while (n--) {
        crc ^= *p++;
        for (k = 0; k < 8; k++) {
            crc = (crc >> 1)
                ^ (PBLOCK_FSCK_CRC_POLY & (uint32_t) -(int) (crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ---- on-disk layout helpers (mirror pblock_store.c, kept trivial) ------- */

static void
blob_dir(const char *root, const char *blob, char *out, size_t cap)
{
    snprintf(out, cap, "%s/data/%c%c/%c%c/%s", root,
             blob[0], blob[1], blob[2], blob[3], blob);
}

static void
block_path(const char *root, const char *blob, long long idx, char *out,
    size_t cap)
{
    snprintf(out, cap, "%s/data/%c%c/%c%c/%s/%lld", root,
             blob[0], blob[1], blob[2], blob[3], blob, idx);
}

static int
is_dir(const char *p)
{
    struct stat sb;

    return stat(p, &sb) == 0 && S_ISDIR(sb.st_mode);
}

/* Actual on-disk byte extent of a blob: max present block index → its offset
 * plus that block's own byte length. Returns -1 if the blob dir is absent. */
static long long
disk_size(const char *root, const char *blob, long long block_size)
{
    char        dir[PATH_MAX], bp[PATH_MAX];
    long long   max_idx = -1, i;
    struct stat sb;

    blob_dir(root, blob, dir, sizeof(dir));
    if (!is_dir(dir)) {
        return -1;
    }
    for (i = 0;; i++) {                        /* blocks are dense from 0 */
        block_path(root, blob, i, bp, sizeof(bp));
        if (stat(bp, &sb) != 0) {
            break;
        }
        max_idx = i;
    }
    if (max_idx < 0) {
        return 0;                              /* empty blob dir */
    }
    block_path(root, blob, max_idx, bp, sizeof(bp));
    if (stat(bp, &sb) != 0) {
        return 0;
    }
    if (block_size <= 0) {
        return (long long) sb.st_size;
    }
    return max_idx * block_size + (long long) sb.st_size;
}

/* ---- catalog side ------------------------------------------------------- */

static int
schema_known(sqlite3 *db)
{
    sqlite3_stmt *st;
    int           ver = 0;

    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &st, NULL) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        ver = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return ver <= PBLOCK_FSCK_SCHEMA;
}

/* Collect the set of blob ids the catalog references (files only). Linear scan
 * membership is fine — export sizes here are test-scale. */
struct blobset {
    char   (*ids)[64];
    size_t   n, cap;
};

static void
blobset_add(struct blobset *bs, const char *id)
{
    if (bs->n == bs->cap) {
        size_t ncap = bs->cap ? bs->cap * 2 : 64;
        void  *p = realloc(bs->ids, ncap * sizeof(bs->ids[0]));

        if (p == NULL) {
            return;
        }
        bs->ids = p;
        bs->cap = ncap;
    }
    snprintf(bs->ids[bs->n++], 64, "%s", id);
}

static int
blobset_has(const struct blobset *bs, const char *id)
{
    size_t i;

    for (i = 0; i < bs->n; i++) {
        if (strcmp(bs->ids[i], id) == 0) {
            return 1;
        }
    }
    return 0;
}

/* table_present — forward declaration (defined below). */
static int table_present(sqlite3 *db, const char *name);

/* blobset_collect — add every non-empty blob_id yielded by `sql` to `bs`. Used to
 * fold the F6 snapshot + F11 versions/trash referrers into the referenced set so
 * a blob pinned ONLY by history (its live `objects` row already gone) is not
 * mis-reported as an ORPHAN — and never freed by --gc. No-op on an absent table. */
static void
blobset_collect(sqlite3 *db, struct blobset *bs, const char *table,
    const char *sql)
{
    sqlite3_stmt *st;

    if (!table_present(db, table)) {
        return;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        return;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *blob = (const char *) sqlite3_column_text(st, 0);

        if (blob != NULL && blob[0] != '\0' && strlen(blob) >= 4) {
            blobset_add(bs, blob);
        }
    }
    sqlite3_finalize(st);
}

/* Pass 1: each file row → check its blob dir + block extent. */
static int
check_rows(sqlite3 *db, const struct opts *o, struct blobset *bs)
{
    sqlite3_stmt *st;
    int           rc;

    rc = sqlite3_prepare_v2(db,
        "SELECT path, blob_id, size, block_size FROM objects "
        "WHERE is_dir = 0 AND blob_id <> '';", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: query objects: %s\n", sqlite3_errmsg(db));
        return 2;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *path = (const char *) sqlite3_column_text(st, 0);
        const char *blob = (const char *) sqlite3_column_text(st, 1);
        long long   csize = sqlite3_column_int64(st, 2);
        long long   bsz   = sqlite3_column_int64(st, 3);
        long long   dsize;

        if (blob == NULL || blob[0] == '\0' || strlen(blob) < 4) {
            continue;
        }
        blobset_add(bs, blob);
        dsize = disk_size(o->root, blob, bsz);
        if (dsize < 0) {
            printf("DANGLING %s\n", path ? path : "?");
            g_findings++;
            if (o->gc) {
                char *ds = sqlite3_mprintf(
                    "DELETE FROM objects WHERE path = %Q;", path);
                sqlite3_exec(db, ds, NULL, NULL, NULL);
                sqlite3_free(ds);
            }
            continue;
        }
        if (dsize != csize) {
            printf("SIZE %s cat=%lld disk=%lld\n", path ? path : "?",
                   csize, dsize);
            g_findings++;
            if (o->repair) {
                char *rs = sqlite3_mprintf(
                    "UPDATE objects SET size = %lld WHERE path = %Q;",
                    dsize, path);
                sqlite3_exec(db, rs, NULL, NULL, NULL);
                sqlite3_free(rs);
            }
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        return 2;
    }
    /* Fold history referrers into the referenced set (snapshot copies, retained
     * versions, trashed-but-recoverable objects) so check_orphans spares them. */
    blobset_collect(db, bs, "snap_objects",
        "SELECT blob_id FROM snap_objects WHERE is_dir = 0 AND blob_id <> '';");
    blobset_collect(db, bs, "versions",
        "SELECT blob_id FROM versions WHERE blob_id <> '';");
    blobset_collect(db, bs, "trash",
        "SELECT blob_id FROM trash WHERE blob_id <> '';");
    return 0;
}

/* Pass 2: each on-disk blob dir → orphan if no row references it. */
static int
check_orphans(const struct opts *o, const struct blobset *bs)
{
    char data[PATH_MAX], l1[PATH_MAX], l2[PATH_MAX];
    DIR *d1, *d2, *d3;
    struct dirent *e1, *e2, *e3;

    snprintf(data, sizeof(data), "%s/data", o->root);
    d1 = opendir(data);
    if (d1 == NULL) {
        return 0;                              /* no data dir yet ⇒ nothing */
    }
    while ((e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.') {
            continue;
        }
        if (snprintf(l1, sizeof(l1), "%s/%s", data, e1->d_name) >= (int) sizeof(l1)
            || !is_dir(l1))
        {
            continue;
        }
        d2 = opendir(l1);
        if (d2 == NULL) {
            continue;
        }
        while ((e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.') {
                continue;
            }
            if (snprintf(l2, sizeof(l2), "%s/%s", l1, e2->d_name) >= (int) sizeof(l2)
                || !is_dir(l2))
            {
                continue;
            }
            d3 = opendir(l2);
            if (d3 == NULL) {
                continue;
            }
            while ((e3 = readdir(d3)) != NULL) {
                char leaf[PATH_MAX];

                if (e3->d_name[0] == '.') {
                    continue;
                }
                if (snprintf(leaf, sizeof(leaf), "%s/%s", l2, e3->d_name)
                        >= (int) sizeof(leaf)
                    || !is_dir(leaf))
                {
                    continue;
                }
                if (blobset_has(bs, e3->d_name)) {
                    continue;
                }
                printf("ORPHAN %s\n", e3->d_name);
                g_findings++;
                if (o->gc) {
                    char cmd[PATH_MAX + 264];
                    /* leaf dir + its blocks; blocks are plain files inside. */
                    DIR *bd = opendir(leaf);
                    struct dirent *be;
                    if (bd != NULL) {
                        while ((be = readdir(bd)) != NULL) {
                            if (be->d_name[0] == '.') { continue; }
                            if (snprintf(cmd, sizeof(cmd), "%s/%s", leaf,
                                         be->d_name) < (int) sizeof(cmd)) {
                                unlink(cmd);
                            }
                        }
                        closedir(bd);
                    }
                    rmdir(leaf);
                }
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
    return 0;
}

/* table_present — opt-in tables (csi, usage) only exist on exports that armed
 * the matching feature; absence is not a finding, just "nothing to verify". */
static int
table_present(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st;
    int           found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    found = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return found;
}

/* verify_csi — F3 oracle: for every file row that has csi rows, re-CRC each
 * recorded block file on disk and compare to its stored CRC. A mismatch (or a
 * missing block file for a recorded CRC) is a CSI finding. The 0 sentinel
 * ("unset", the driver skips it) is skipped here too. */
static int
verify_csi(sqlite3 *db, const struct opts *o)
{
    sqlite3_stmt *rows, *cst;
    int           rc;

    if (!table_present(db, "csi")) {
        return 0;                              /* not a csi export ⇒ nothing */
    }
    rc = sqlite3_prepare_v2(db,
        "SELECT path, blob_id FROM objects "
        "WHERE is_dir = 0 AND blob_id <> '';", -1, &rows, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: query objects: %s\n", sqlite3_errmsg(db));
        return 2;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT block_no, crc FROM csi WHERE blob_id = ?1;",
            -1, &cst, NULL) != SQLITE_OK) {
        sqlite3_finalize(rows);
        return 2;
    }
    while ((rc = sqlite3_step(rows)) == SQLITE_ROW) {
        const char *path = (const char *) sqlite3_column_text(rows, 0);
        const char *blob = (const char *) sqlite3_column_text(rows, 1);

        if (blob == NULL || strlen(blob) < 4) {
            continue;
        }
        sqlite3_reset(cst);
        sqlite3_bind_text(cst, 1, blob, -1, SQLITE_STATIC);
        while (sqlite3_step(cst) == SQLITE_ROW) {
            long long      bno = sqlite3_column_int64(cst, 0);
            uint32_t       want = (uint32_t) sqlite3_column_int64(cst, 1);
            char           bp[PATH_MAX];
            struct stat    sb;
            unsigned char *buf;
            int            fd;
            ssize_t        got;

            if (want == 0) {
                continue;                      /* unset sentinel — driver skips */
            }
            block_path(o->root, blob, bno, bp, sizeof(bp));
            fd = open(bp, O_RDONLY);
            if (fd < 0 || fstat(fd, &sb) != 0) {
                if (fd >= 0) { close(fd); }
                printf("CSI %s block=%lld missing\n", path ? path : "?", bno);
                g_findings++;
                continue;
            }
            buf = malloc(sb.st_size ? (size_t) sb.st_size : 1);
            if (buf == NULL) {
                close(fd);
                sqlite3_finalize(cst);
                sqlite3_finalize(rows);
                return 2;
            }
            got = read(fd, buf, (size_t) sb.st_size);
            close(fd);
            if (got != (ssize_t) sb.st_size
                || crc32c(buf, (size_t) sb.st_size) != want) {
                printf("CSI %s block=%lld\n", path ? path : "?", bno);
                g_findings++;
            }
            free(buf);
        }
    }
    sqlite3_finalize(cst);
    sqlite3_finalize(rows);
    return (rc == SQLITE_DONE) ? 0 : 2;
}

/* verify_usage — F5 oracle: every trigger-maintained `usage` rollup row must
 * equal a fresh recompute from `objects` (and no scope/id may exist in one
 * side only). Any divergence is a USAGE finding — it means a catalog write
 * path bypassed the triggers. */
static int
verify_usage(sqlite3 *db)
{
    static const char *q =
        "WITH fresh AS ("
        "  SELECT 'total' scope, 0 id,"
        "    COALESCE(SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END),0) bytes,"
        "    COUNT(*) inodes FROM objects"
        "  UNION ALL SELECT 'uid', uid,"
        "    SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END), COUNT(*)"
        "    FROM objects GROUP BY uid"
        "  UNION ALL SELECT 'gid', gid,"
        "    SUM(CASE WHEN is_dir=0 THEN size ELSE 0 END), COUNT(*)"
        "    FROM objects GROUP BY gid)"
        /* both directions via LEFT JOIN (portable — no FULL OUTER JOIN,
         * which needs sqlite >= 3.39) */
        " SELECT u.scope, u.id, u.bytes, u.inodes,"
        "        COALESCE(f.bytes, -1), COALESCE(f.inodes, -1)"
        " FROM usage u LEFT JOIN fresh f ON u.scope=f.scope AND u.id=f.id"
        " WHERE f.bytes IS NOT u.bytes OR f.inodes IS NOT u.inodes"
        " UNION ALL"
        " SELECT f.scope, f.id, -1, -1, f.bytes, f.inodes"
        " FROM fresh f LEFT JOIN usage u ON u.scope=f.scope AND u.id=f.id"
        " WHERE u.scope IS NULL;";
    sqlite3_stmt *st;
    int           rc;

    if (!table_present(db, "usage")) {
        return 0;                          /* not a quota export ⇒ nothing */
    }
    if (sqlite3_prepare_v2(db, q, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: query usage: %s\n", sqlite3_errmsg(db));
        return 2;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        printf("USAGE %s id=%lld stored=%lld/%lld actual=%lld/%lld\n",
               sqlite3_column_text(st, 0),
               (long long) sqlite3_column_int64(st, 1),
               (long long) sqlite3_column_int64(st, 2),
               (long long) sqlite3_column_int64(st, 3),
               (long long) sqlite3_column_int64(st, 4),
               (long long) sqlite3_column_int64(st, 5));
        g_findings++;
    }
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : 2;
}

/* verify_refs — F10 oracle: every tracked blob's refcount must equal the number
 * of file `objects` rows that point at it. A drift means a copy/unlink path
 * failed to bump/release — a leaked blob (refcount too high, never reclaimed) or
 * a premature free candidate (too low). Blobs with no tracking row carry the
 * implicit single reference and are checked by the row/orphan passes, not here.
 * The 0-sentinel LEFT JOIN handles a blob with zero referencing rows. */
static int
verify_refs(sqlite3 *db)
{
    /* Referrers = live objects + every history copy that pins the blob: F6
     * snapshot rows + F11 retained versions + F11 trashed objects — the exact
     * union the driver's explicit bump/release maintains. Each term is added
     * only when its table exists on this export (a term against an absent table
     * would fail to parse), so the formula is assembled at runtime. */
    char          q[1024];
    int           n;
    sqlite3_stmt *st;
    int           rc;

    if (!table_present(db, "blobs")) {
        return 0;                          /* not a dedup export ⇒ nothing */
    }
    n = snprintf(q, sizeof(q),
        "SELECT b.blob_id, b.refcount,"
        "  (SELECT COUNT(*) FROM objects o"
        "     WHERE o.blob_id = b.blob_id AND o.is_dir = 0)");
    if (table_present(db, "snap_objects")) {
        n += snprintf(q + n, sizeof(q) - n,
            "  + (SELECT COUNT(*) FROM snap_objects s"
            "     WHERE s.blob_id = b.blob_id AND s.is_dir = 0)");
    }
    if (table_present(db, "versions")) {
        n += snprintf(q + n, sizeof(q) - n,
            "  + (SELECT COUNT(*) FROM versions v WHERE v.blob_id = b.blob_id)");
    }
    if (table_present(db, "trash")) {
        n += snprintf(q + n, sizeof(q) - n,
            "  + (SELECT COUNT(*) FROM trash t WHERE t.blob_id = b.blob_id)");
    }
    (void) snprintf(q + n, sizeof(q) - n,
        " AS refs FROM blobs b WHERE b.refcount != refs;");
    if (sqlite3_prepare_v2(db, q, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: query blobs: %s\n", sqlite3_errmsg(db));
        return 2;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        printf("REFS %s refcount=%lld referrers=%lld\n",
               sqlite3_column_text(st, 0),
               (long long) sqlite3_column_int64(st, 1),
               (long long) sqlite3_column_int64(st, 2));
        g_findings++;
    }
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : 2;
}

/* ---- F6 offline snapshot / restore -------------------------------------- */

/* snap_valid_name — identical charset to the driver's pblock_snap_valid_name:
 * [A-Za-z0-9_.-], 1..64, and not "." / "..". The offline oracle applies the
 * exact same gate so a hostile snapshot name is refused here too — and the name
 * is only ever bound (never interpolated), so injection is structurally out. */
static int
snap_valid_name(const char *name)
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
    return !(strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

/* snap_init_tables — mirror pblock_snap_init so a first offline snapshot on an
 * export that never armed F6 at runtime still works (same DDL, IF NOT EXISTS). */
static int
snap_init_tables(sqlite3 *db)
{
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS snapshots("
        "  name TEXT PRIMARY KEY, created_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS snap_objects("
        "  snap TEXT NOT NULL, path TEXT NOT NULL, parent TEXT NOT NULL,"
        "  is_dir INTEGER NOT NULL, blob_id TEXT NOT NULL DEFAULT '',"
        "  size INTEGER NOT NULL DEFAULT 0, block_size INTEGER NOT NULL DEFAULT 0,"
        "  mtime INTEGER NOT NULL DEFAULT 0, ctime INTEGER NOT NULL DEFAULT 0,"
        "  mode INTEGER NOT NULL DEFAULT 0, uid INTEGER NOT NULL DEFAULT 0,"
        "  gid INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(snap, path));"
        "CREATE INDEX IF NOT EXISTS snap_objects_blob ON snap_objects(blob_id);"
        "CREATE TABLE IF NOT EXISTS snap_xattrs("
        "  snap TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL,"
        "  value BLOB NOT NULL, PRIMARY KEY(snap, path, name));",
        NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* snap_run1 — prepare, bind ?1=name, step to DONE. 0 / -1. */
static int
snap_run1(sqlite3 *db, const char *sql, const char *name)
{
    sqlite3_stmt *st;
    int           rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* snap_recount — same blob-refcount recompute as the driver, only when a blobs
 * table exists (F10 armed). Keeps the release path exact after take/restore. */
static int
snap_recount(sqlite3 *db)
{
    char q[1024];
    int  n;

    if (!table_present(db, "blobs")) {
        return 0;
    }
    if (sqlite3_exec(db,
            "INSERT OR IGNORE INTO blobs(blob_id, refcount, size, block_size,"
            "  content_hash)"
            " SELECT DISTINCT blob_id, 0, size, block_size, ''"
            "   FROM objects WHERE is_dir = 0 AND blob_id != '';",
            NULL, NULL, NULL) != SQLITE_OK) {
        return -1;
    }
    /* refcount = live objects + all history referrers (snapshot/version/trash),
     * each term added only for a table that exists — mirrors verify_refs. */
    n = snprintf(q, sizeof(q),
        "UPDATE blobs SET refcount = "
        "  (SELECT COUNT(*) FROM objects o"
        "     WHERE o.blob_id = blobs.blob_id AND o.is_dir = 0)");
    if (table_present(db, "snap_objects")) {
        n += snprintf(q + n, sizeof(q) - n,
            " + (SELECT COUNT(*) FROM snap_objects s"
            "     WHERE s.blob_id = blobs.blob_id AND s.is_dir = 0)");
    }
    if (table_present(db, "versions")) {
        n += snprintf(q + n, sizeof(q) - n,
            " + (SELECT COUNT(*) FROM versions v WHERE v.blob_id = blobs.blob_id)");
    }
    if (table_present(db, "trash")) {
        n += snprintf(q + n, sizeof(q) - n,
            " + (SELECT COUNT(*) FROM trash t WHERE t.blob_id = blobs.blob_id)");
    }
    (void) snprintf(q + n, sizeof(q) - n, ";");
    return sqlite3_exec(db, q, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* do_snapshot — take a named snapshot (INSERT + copy objects/xattrs + recount)
 * inside one transaction. A duplicate name reports and returns 1 (a finding). */
static int
do_snapshot(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st;
    int           rc;

    if (!snap_valid_name(name)) {
        fprintf(stderr, "pblock-fsck: invalid snapshot name\n");
        return 3;
    }
    if (snap_init_tables(db) != 0
        || sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    if (sqlite3_prepare_v2(db,
            "INSERT INTO snapshots(name, created_at) VALUES(?1, 0);",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        fprintf(stderr, "pblock-fsck: snapshot %s already exists\n", name);
        return 1;
    }
    if (snap_run1(db,
            "INSERT INTO snap_objects(snap, path, parent, is_dir, blob_id, size,"
            "  block_size, mtime, ctime, mode, uid, gid)"
            " SELECT ?1, path, parent, is_dir, blob_id, size, block_size, mtime,"
            "  ctime, mode, uid, gid FROM objects;", name) != 0
        || snap_run1(db,
            "INSERT INTO snap_xattrs(snap, path, name, value)"
            " SELECT ?1, path, name, value FROM xattrs;", name) != 0
        || snap_recount(db) != 0) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    printf("SNAPSHOT %s\n", name);
    return 0;
}

/* do_restore — replace the live namespace with a named snapshot (byte-identical
 * blob ids, so reads return identical bytes) inside one transaction. Absent name
 * → refused (exit 1). Offline, so there is no open-handle EBUSY guard here. */
static int
do_restore(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st;
    int           rc;

    if (!snap_valid_name(name)) {
        fprintf(stderr, "pblock-fsck: invalid snapshot name\n");
        return 3;
    }
    if (!table_present(db, "snapshots")) {
        fprintf(stderr, "pblock-fsck: no snapshots on this export\n");
        return 1;
    }
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM snapshots WHERE name = ?1;",
            -1, &st, NULL) != SQLITE_OK) {
        return 2;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "pblock-fsck: snapshot %s not found\n", name);
        return 1;
    }
    if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    if (sqlite3_exec(db, "DELETE FROM objects;", NULL, NULL, NULL) != SQLITE_OK
        || sqlite3_exec(db, "DELETE FROM xattrs;", NULL, NULL, NULL) != SQLITE_OK
        || snap_run1(db,
            "INSERT INTO objects(path, parent, is_dir, blob_id, size,"
            "  block_size, mtime, ctime, mode, uid, gid)"
            " SELECT path, parent, is_dir, blob_id, size, block_size, mtime,"
            "  ctime, mode, uid, gid FROM snap_objects WHERE snap = ?1;",
            name) != 0
        || snap_run1(db,
            "INSERT INTO xattrs(path, name, value)"
            " SELECT path, name, value FROM snap_xattrs WHERE snap = ?1;",
            name) != 0
        || snap_recount(db) != 0) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    printf("RESTORE %s\n", name);
    return 0;
}

/* ---- F11 offline versions / trash / undelete ---------------------------- */

/* fsck_parent_of — offline mirror of the driver's parent_of: the parent dir of
 * an absolute path. Root/"" and a direct child of "/" both derive "/". */
static void
fsck_parent_of(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    size_t      len;

    if ((path[0] == '/' && path[1] == '\0') || slash == NULL || slash == path) {
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

/* do_list_versions — read-only dump of a path's retained F11 versions, newest
 * gen last. Absent table ⇒ no output (clean). Ends with a VERSIONS count line. */
static int
do_list_versions(sqlite3 *db, const char *path)
{
    sqlite3_stmt *st;
    long long     n = 0;

    if (!table_present(db, "versions")) {
        printf("VERSIONS %s n=0\n", path);
        return 0;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT gen, size, blob_id FROM versions WHERE path = ?1"
            " ORDER BY gen ASC;", -1, &st, NULL) != SQLITE_OK) {
        return 2;
    }
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    while (sqlite3_step(st) == SQLITE_ROW) {
        printf("VERSION gen=%lld size=%lld blob=%s\n",
               (long long) sqlite3_column_int64(st, 0),
               (long long) sqlite3_column_int64(st, 1),
               sqlite3_column_text(st, 2));
        n++;
    }
    sqlite3_finalize(st);
    printf("VERSIONS %s n=%lld\n", path, n);
    return 0;
}

/* do_list_trash — read-only dump of the trash ledger, oldest first. Absent
 * table ⇒ no output. Ends with a TRASH count line. */
static int
do_list_trash(sqlite3 *db)
{
    sqlite3_stmt *st;
    long long     n = 0;

    if (!table_present(db, "trash")) {
        printf("TRASH n=0\n");
        return 0;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT trash_id, path, size, blob_id FROM trash"
            " ORDER BY trash_id ASC;", -1, &st, NULL) != SQLITE_OK) {
        return 2;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        printf("TRASHED id=%lld path=%s size=%lld blob=%s\n",
               (long long) sqlite3_column_int64(st, 0),
               sqlite3_column_text(st, 1),
               (long long) sqlite3_column_int64(st, 2),
               sqlite3_column_text(st, 3));
        n++;
    }
    sqlite3_finalize(st);
    printf("TRASH n=%lld\n", n);
    return 0;
}

/* do_undelete — offline mirror of pblock_hist_undelete: pop the most-recently
 * trashed instance of `path` back into the live namespace inside one
 * transaction, then reconcile refcounts (snap_recount folds the now-removed
 * trash row and the new objects row — a net-zero transfer). A live name is
 * refused (EEXIST); no trashed instance is a finding (exit 1). */
static int
do_undelete(sqlite3 *db, const char *path)
{
    sqlite3_stmt *st;
    char          parent[PATH_MAX];
    long long     trash_id, size, bsz, mtime, ctime, mode, uid, gid;
    char          blob[64];
    int           rc;

    if (!table_present(db, "trash")) {
        fprintf(stderr, "pblock-fsck: no trash on this export\n");
        return 1;
    }
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM objects WHERE path = ?1;",
            -1, &st, NULL) != SQLITE_OK) {
        return 2;
    }
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) {
        fprintf(stderr, "pblock-fsck: %s already exists (EEXIST)\n", path);
        return 1;
    }
    if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT trash_id, blob_id, size, block_size, mtime, ctime, mode,"
            "  uid, gid FROM trash WHERE path = ?1"
            " ORDER BY deleted_at DESC, trash_id DESC LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        fprintf(stderr, "pblock-fsck: %s not in trash\n", path);
        return 1;
    }
    trash_id = sqlite3_column_int64(st, 0);
    snprintf(blob, sizeof(blob), "%s", (const char *) sqlite3_column_text(st, 1));
    size  = sqlite3_column_int64(st, 2);
    bsz   = sqlite3_column_int64(st, 3);
    mtime = sqlite3_column_int64(st, 4);
    ctime = sqlite3_column_int64(st, 5);
    mode  = sqlite3_column_int64(st, 6);
    uid   = sqlite3_column_int64(st, 7);
    gid   = sqlite3_column_int64(st, 8);
    sqlite3_finalize(st);

    fsck_parent_of(path, parent, sizeof(parent));
    if (sqlite3_prepare_v2(db,
            "INSERT INTO objects(path, parent, is_dir, blob_id, size,"
            "  block_size, mtime, ctime, mode, uid, gid)"
            " VALUES(?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    sqlite3_bind_text (st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text (st, 2, parent, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 3, blob, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, size);
    sqlite3_bind_int64(st, 5, bsz);
    sqlite3_bind_int64(st, 6, mtime);
    sqlite3_bind_int64(st, 7, ctime);
    sqlite3_bind_int64(st, 8, mode);
    sqlite3_bind_int64(st, 9, uid);
    sqlite3_bind_int64(st, 10, gid);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    if (sqlite3_prepare_v2(db, "DELETE FROM trash WHERE trash_id = ?1;",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    sqlite3_bind_int64(st, 1, trash_id);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || snap_recount(db) != 0) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return 2;
    }
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        return 2;
    }
    printf("UNDELETE %s\n", path);
    return 0;
}

/* trash_purge — --gc purge of trash rows deleted more than `ttl` seconds ago
 * (ttl 0 = purge all). Each purged row releases its held blob via snap_recount +
 * the row/orphan pass; here we just drop the ledger rows and let the standard
 * orphan pass reclaim any now-unreferenced blocks. Findings-neutral (a purge is
 * expected cleanup, not a divergence). */
static int
trash_purge(sqlite3 *db, long long ttl)
{
    sqlite3_stmt *st;
    long long     cutoff = (long long) time(NULL) - ttl;
    int           rc;

    if (!table_present(db, "trash")) {
        return 0;
    }
    if (sqlite3_prepare_v2(db,
            "DELETE FROM trash WHERE deleted_at <= ?1;", -1, &st, NULL)
        != SQLITE_OK) {
        return 2;
    }
    sqlite3_bind_int64(st, 1, cutoff);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        return 2;
    }
    printf("TRASH-PURGED older=%llds\n", ttl);
    return snap_recount(db) == 0 ? 0 : 2;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage: pblock-fsck <export-root> [--gc [--trash-ttl <secs>]] [--repair]"
        " [--verify-csi] [--verify-usage] [--verify-refs]\n"
        "       pblock-fsck <export-root> --snapshot <name> | --restore <name>\n"
        "       pblock-fsck <export-root> --list-versions <path> | --list-trash"
        " | --undelete <path>\n"
        "  cross-check catalog.db against the block store, take/restore an F6"
        " snapshot, or inspect/recover F11 versions + trash.\n"
        "  --gc --trash-ttl <secs> also purges trash entries older than <secs>"
        " (0 = all).\n"
        "  exit: 0 clean, 1 findings, 2 error, 3 refused (unknown schema/name)\n");
}

int
main(int argc, char **argv)
{
    struct opts o;
    char        catpath[PATH_MAX];
    sqlite3    *db;
    struct blobset bs = { NULL, 0, 0 };
    int         i, rc;

    memset(&o, 0, sizeof(o));
    o.trash_ttl = -1;                        /* F11: --gc leaves trash alone   */
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            o.root = argv[i];
        } else if (strcmp(argv[i], "--gc") == 0) {
            o.gc = 1;
        } else if (strcmp(argv[i], "--repair") == 0) {
            o.repair = 1;
        } else if (strcmp(argv[i], "--verify-csi") == 0) {
            o.verify_csi = 1;
        } else if (strcmp(argv[i], "--verify-usage") == 0) {
            o.verify_usage = 1;
        } else if (strcmp(argv[i], "--verify-refs") == 0) {
            o.verify_refs = 1;
        } else if (strcmp(argv[i], "--snapshot") == 0 && i + 1 < argc) {
            o.snapshot = argv[++i];
        } else if (strcmp(argv[i], "--restore") == 0 && i + 1 < argc) {
            o.restore = argv[++i];
        } else if (strcmp(argv[i], "--list-versions") == 0 && i + 1 < argc) {
            o.list_versions = argv[++i];
        } else if (strcmp(argv[i], "--list-trash") == 0) {
            o.list_trash = 1;
        } else if (strcmp(argv[i], "--undelete") == 0 && i + 1 < argc) {
            o.undelete = argv[++i];
        } else if (strcmp(argv[i], "--trash-ttl") == 0 && i + 1 < argc) {
            o.trash_ttl = strtoll(argv[++i], NULL, 10);
        } else {
            usage();
            return 2;
        }
    }
    if (o.root == NULL) {
        usage();
        return 2;
    }

    snprintf(catpath, sizeof(catpath), "%s/catalog.db", o.root);
    if (sqlite3_open(catpath, &db) != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: open %s: %s\n", catpath,
                sqlite3_errmsg(db));
        sqlite3_close(db);
        return 2;
    }
    sqlite3_busy_timeout(db, 5000);

    if ((o.gc || o.repair || o.snapshot || o.restore || o.undelete)
        && !schema_known(db))
    {
        fprintf(stderr, "pblock-fsck: refusing a mutating op on an unknown "
                        "catalog schema version\n");
        sqlite3_close(db);
        return 3;
    }
    /* F6/F11: snapshot / restore / list / undelete short-circuit — they replace,
     * extend or report state and exit; the consistency passes below are the
     * read-only default. */
    if (o.snapshot != NULL) {
        rc = do_snapshot(db, o.snapshot);
        sqlite3_close(db);
        return rc;
    }
    if (o.restore != NULL) {
        rc = do_restore(db, o.restore);
        sqlite3_close(db);
        return rc;
    }
    if (o.list_versions != NULL) {
        rc = do_list_versions(db, o.list_versions);
        sqlite3_close(db);
        return rc;
    }
    if (o.list_trash) {
        rc = do_list_trash(db);
        sqlite3_close(db);
        return rc;
    }
    if (o.undelete != NULL) {
        rc = do_undelete(db, o.undelete);
        sqlite3_close(db);
        return rc;
    }
    /* F11: --gc --trash-ttl purges aged trash rows BEFORE the row/orphan passes
     * so a purged object's now-unreferenced blocks are reclaimed in this run. */
    if (o.gc && o.trash_ttl >= 0) {
        rc = trash_purge(db, o.trash_ttl);
        if (rc != 0) {
            sqlite3_close(db);
            return rc;
        }
    }
    rc = check_rows(db, &o, &bs);
    if (rc == 0) {
        rc = check_orphans(&o, &bs);
    }
    if (rc == 0 && o.verify_csi) {
        rc = verify_csi(db, &o);
    }
    if (rc == 0 && o.verify_usage) {
        rc = verify_usage(db);
    }
    if (rc == 0 && o.verify_refs) {
        rc = verify_refs(db);
    }
    free(bs.ids);
    sqlite3_close(db);

    if (rc != 0) {
        return rc;
    }
    printf("FINDINGS %d\n", g_findings);
    return g_findings > 0 ? 1 : 0;
}
