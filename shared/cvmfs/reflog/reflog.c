/* reflog.c — .cvmfsreflog reader + writer. See reflog.h. */
#include "cvmfs/reflog/reflog.h"
#include "cvmfs/object/object.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cvmfs_reflog_s {
    sqlite3 *db;
};

static const char REFLOG_DDL[] =
    "CREATE TABLE IF NOT EXISTS refs (hash TEXT,type INTEGER,timestamp INTEGER,"
    "PRIMARY KEY(hash,type));"
    "CREATE TABLE IF NOT EXISTS properties (key TEXT,value TEXT,PRIMARY KEY(key));"
    "INSERT OR IGNORE INTO properties VALUES('schema','1.0');";

cvmfs_reflog_t *cvmfs_reflog_open(const char *path) {
    cvmfs_reflog_t *r = calloc(1, sizeof(*r));
    if (r == NULL) return NULL;
    if (sqlite3_open_v2(path, &r->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK
        || sqlite3_exec(r->db, REFLOG_DDL, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(r->db);
        free(r);
        return NULL;
    }
    return r;
}

int cvmfs_reflog_close(cvmfs_reflog_t *r) {
    if (r == NULL) return -1;
    int rc = sqlite3_close(r->db) == SQLITE_OK ? 0 : -1;
    free(r);
    return rc;
}

static int ref_exec(cvmfs_reflog_t *r, const char *sql, const cvmfs_hash_t *hash,
                    cvmfs_reflog_type_e type, int64_t timestamp, int with_ts) {
    char hex[64];
    if (cvmfs_hash_to_hex(hash, 0, hex, sizeof(hex)) < 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, (int) type);
    if (with_ts) sqlite3_bind_int64(st, 3, timestamp);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_reflog_add(cvmfs_reflog_t *r, const cvmfs_hash_t *hash,
                     cvmfs_reflog_type_e type, int64_t timestamp) {
    return ref_exec(r, "INSERT OR REPLACE INTO refs VALUES(?,?,?)",
                    hash, type, timestamp, 1);
}

int cvmfs_reflog_del(cvmfs_reflog_t *r, const cvmfs_hash_t *hash,
                     cvmfs_reflog_type_e type) {
    return ref_exec(r, "DELETE FROM refs WHERE hash=? AND type=?", hash, type, 0, 0);
}

int cvmfs_reflog_list(cvmfs_reflog_t *r, int type, cvmfs_reflog_cb cb, void *ud) {
    sqlite3_stmt *st = NULL;
    /* rowid breaks same-second ties by insertion recency (INSERT OR REPLACE
     * re-inserts, so a refreshed ref really is the newest) — gc keep-N counts
     * on this ordering. */
    const char *sql = type < 0
        ? "SELECT hash, type, timestamp FROM refs "
          "ORDER BY timestamp DESC, rowid DESC"
        : "SELECT hash, type, timestamp FROM refs WHERE type=? "
          "ORDER BY timestamp DESC, rowid DESC";
    if (sqlite3_prepare_v2(r->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (type >= 0) sqlite3_bind_int(st, 1, type);

    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *hex = (const char *) sqlite3_column_text(st, 0);
        cvmfs_hash_t h;
        if (hex != NULL && cvmfs_hash_parse(hex, strlen(hex), &h) == 0) {
            if (cb)
                cb(&h, (cvmfs_reflog_type_e) sqlite3_column_int(st, 1),
                   sqlite3_column_int64(st, 2), ud);
            n++;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int cvmfs_reflog_checksum(const char *path, cvmfs_hash_t *out) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    rewind(f);

    unsigned char *buf = malloc(n > 0 ? (size_t) n : 1);
    if (buf == NULL) { fclose(f); return -1; }
    int ok = n == 0 || fread(buf, 1, (size_t) n, f) == (size_t) n;
    fclose(f);
    int rc = ok ? cvmfs_object_hash(CVMFS_HASH_SHA1, buf, (size_t) n, out) : -1;
    free(buf);
    return rc;
}
