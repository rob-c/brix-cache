/* history.c — CVMFS tag/history database. See history.h. */
#include "cvmfs/history/history.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cvmfs_history_s {
    sqlite3 *db;
};

static const char HISTORY_DDL[] =
    "CREATE TABLE IF NOT EXISTS tags (name TEXT,hash TEXT,revision INTEGER,"
    "timestamp INTEGER,channel INTEGER,description TEXT,size INTEGER,"
    "PRIMARY KEY(name));"
    "CREATE TABLE IF NOT EXISTS properties (key TEXT,value TEXT,PRIMARY KEY(key));"
    "INSERT OR IGNORE INTO properties VALUES('schema','1.0');";

cvmfs_history_t *cvmfs_history_open(const char *path, const char *fqrn) {
    cvmfs_history_t *h = calloc(1, sizeof(*h));
    if (h == NULL) return NULL;
    if (sqlite3_open_v2(path, &h->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK
        || sqlite3_exec(h->db, HISTORY_DDL, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(h->db);
        free(h);
        return NULL;
    }
    if (fqrn != NULL) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h->db,
                "INSERT OR REPLACE INTO properties VALUES('fqrn',?)", -1, &st, NULL)
            == SQLITE_OK) {
            sqlite3_bind_text(st, 1, fqrn, -1, SQLITE_STATIC);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    return h;
}

int cvmfs_history_close(cvmfs_history_t *h) {
    if (h == NULL) return -1;
    int rc = sqlite3_close(h->db) == SQLITE_OK ? 0 : -1;
    free(h);
    return rc;
}

int cvmfs_history_tag_add(cvmfs_history_t *h, const cvmfs_history_tag_t *tag) {
    char hex[64];
    if (cvmfs_hash_to_hex(&tag->root_hash, 0, hex, sizeof(hex)) < 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db,
            "INSERT OR REPLACE INTO tags VALUES(?,?,?,?,0,?,0)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, tag->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, tag->revision);
    sqlite3_bind_int64(st, 4, tag->timestamp);
    sqlite3_bind_text(st, 5, tag->description, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int row_to_tag(sqlite3_stmt *st, cvmfs_history_tag_t *out) {
    memset(out, 0, sizeof(*out));
    const char *name = (const char *) sqlite3_column_text(st, 0);
    const char *hex  = (const char *) sqlite3_column_text(st, 1);
    if (name == NULL || hex == NULL
        || cvmfs_hash_parse(hex, strlen(hex), &out->root_hash) != 0)
        return -1;
    snprintf(out->name, sizeof(out->name), "%s", name);
    out->revision  = (long) sqlite3_column_int64(st, 2);
    out->timestamp = sqlite3_column_int64(st, 3);
    const char *desc = (const char *) sqlite3_column_text(st, 4);
    if (desc != NULL) snprintf(out->description, sizeof(out->description), "%s", desc);
    return 0;
}

static const char TAG_COLS[] = "name, hash, revision, timestamp, description FROM tags";

int cvmfs_history_tag_get(cvmfs_history_t *h, const char *name, cvmfs_history_tag_t *out) {
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT %s WHERE name=?", TAG_COLS);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);

    int rc = sqlite3_step(st);
    int found = rc == SQLITE_ROW && row_to_tag(st, out) == 0;
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int cvmfs_history_tag_del(cvmfs_history_t *h, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, "DELETE FROM tags WHERE name=?", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_history_list(cvmfs_history_t *h, cvmfs_history_cb cb, void *ud) {
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT %s ORDER BY timestamp DESC, name", TAG_COLS);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        cvmfs_history_tag_t tag;
        if (row_to_tag(st, &tag) == 0) {
            if (cb) cb(&tag, ud);
            n++;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}
