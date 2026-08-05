/* catalog_write.c — CVMFS SQLite catalog writer. See catalog_write.h. */
#include "cvmfs/catalog/catalog_write.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cvmfs_catwriter_s {
    sqlite3 *db;
};

/* The pinned catalog DDL (schema 2.5 shape the reader + both reference
 * writers fix), plus the statistics counters table (S8). */
static const char CAT_DDL[] =
    "CREATE TABLE catalog (md5path_1 INTEGER,md5path_2 INTEGER,parent_1 INTEGER,parent_2 INTEGER,"
    "hardlinks INTEGER,hash BLOB,size INTEGER,mode INTEGER,mtime INTEGER,flags INTEGER,name TEXT,"
    "symlink TEXT,uid INTEGER,gid INTEGER,xattr BLOB,PRIMARY KEY(md5path_1,md5path_2));"
    "CREATE TABLE nested_catalogs (path TEXT,sha1 TEXT,size INTEGER,PRIMARY KEY(path));"
    "CREATE TABLE properties (key TEXT,value TEXT,PRIMARY KEY(key));"
    "CREATE TABLE chunks (md5path_1 INTEGER,md5path_2 INTEGER,offset INTEGER,size INTEGER,hash BLOB,"
    "PRIMARY KEY(md5path_1,md5path_2,offset));"
    "CREATE TABLE statistics (counter TEXT,value INTEGER,PRIMARY KEY(counter));";

/* Repo-root-relative parent; NULL cap-overflow. The root "" has NO parent —
 * stock catalogs store parent_{1,2} = 0 for it (self-parenting makes the
 * root list itself as an empty-named child; the official client SIGSEGVs). */
static const char *parent_of(const char *path, char *buf, size_t cap) {
    const char *slash = strrchr(path, '/');
    if (path[0] == '\0' || slash == NULL) return "";
    size_t n = (size_t) (slash - path);
    if (n >= cap) return NULL;
    memcpy(buf, path, n);
    buf[n] = '\0';
    return buf;
}

static const char *leaf_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

static int exec_sql(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static cvmfs_catwriter_t *open_common(const char *db_path, int create) {
    cvmfs_catwriter_t *w = calloc(1, sizeof(*w));
    if (w == NULL) return NULL;

    int flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0);
    if (sqlite3_open_v2(db_path, &w->db, flags, NULL) != SQLITE_OK
        || (create && exec_sql(w->db, CAT_DDL) != 0)
        || exec_sql(w->db, "BEGIN") != 0) {
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

cvmfs_catwriter_t *cvmfs_catwriter_create(const char *db_path) {
    FILE *f = fopen(db_path, "rb");          /* refuse an existing file */
    if (f != NULL) { fclose(f); return NULL; }
    return open_common(db_path, 1);
}

cvmfs_catwriter_t *cvmfs_catwriter_open(const char *db_path) {
    return open_common(db_path, 0);
}

int cvmfs_catwriter_commit(cvmfs_catwriter_t *w) {
    if (w == NULL) return -1;
    int rc = exec_sql(w->db, "COMMIT");
    sqlite3_close(w->db);
    free(w);
    return rc;
}

void cvmfs_catwriter_abort(cvmfs_catwriter_t *w) {
    if (w == NULL) return;
    exec_sql(w->db, "ROLLBACK");
    sqlite3_close(w->db);
    free(w);
}

static int row_write(cvmfs_catwriter_t *w, const cvmfs_catrow_t *r, int replace) {
    char    pbuf[4096];
    const char *parent = parent_of(r->path, pbuf, sizeof(pbuf));
    if (parent == NULL) return -1;

    int64_t m1, m2, p1 = 0, p2 = 0;
    cvmfs_catalog_md5path(r->path, &m1, &m2);
    if (r->path[0] != '\0')
        cvmfs_catalog_md5path(parent, &p1, &p2);

    const char *sql = replace
        ? "INSERT OR REPLACE INTO catalog VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        : "INSERT INTO catalog VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    int64_t hardlinks = ((int64_t) r->hardlink_group << 32)
                      | (int64_t) (r->linkcount != 0 ? r->linkcount : 1);
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);
    sqlite3_bind_int64(st, 3, p1);
    sqlite3_bind_int64(st, 4, p2);
    sqlite3_bind_int64(st, 5, hardlinks);
    if (r->hash != NULL && r->hash->len > 0)
        sqlite3_bind_blob(st, 6, r->hash->bytes, (int) r->hash->len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 6);
    sqlite3_bind_int64(st, 7, (int64_t) r->size);
    sqlite3_bind_int64(st, 8, (int64_t) r->mode);
    sqlite3_bind_int64(st, 9, r->mtime);
    sqlite3_bind_int64(st, 10, (int64_t) r->flags);
    sqlite3_bind_text(st, 11, leaf_of(r->path), -1, SQLITE_TRANSIENT);
    /* Stock stores '' (never NULL) for non-symlinks; the official client
     * string-retrieves the column unchecked and SIGSEGVs on NULL. */
    sqlite3_bind_text(st, 12, r->symlink != NULL ? r->symlink : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, (int64_t) r->uid);
    sqlite3_bind_int64(st, 14, (int64_t) r->gid);
    if (r->xattr != NULL && r->xattr_len > 0)
        sqlite3_bind_blob(st, 15, r->xattr, (int) r->xattr_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 15);

    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_upsert(cvmfs_catwriter_t *w, const cvmfs_catrow_t *r) {
    return row_write(w, r, 1);
}

int cvmfs_catwriter_insert(cvmfs_catwriter_t *w, const cvmfs_catrow_t *r) {
    return row_write(w, r, 0);
}

/* Run a "... WHERE md5path_1=? AND md5path_2=?" statement for `path`. */
static int exec_by_md5(cvmfs_catwriter_t *w, const char *sql, const char *path) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_delete(cvmfs_catwriter_t *w, const char *path) {
    if (exec_by_md5(w, "DELETE FROM chunks WHERE md5path_1=? AND md5path_2=?", path) != 0)
        return -1;
    return exec_by_md5(w, "DELETE FROM catalog WHERE md5path_1=? AND md5path_2=?", path);
}

/* Children names of `path` in this catalog, via parent_{1,2}. */
static int child_names(cvmfs_catwriter_t *w, const char *path,
                       char (**names)[256], int *count) {
    int64_t p1, p2;
    cvmfs_catalog_md5path(path, &p1, &p2);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM catalog WHERE parent_1=? AND parent_2=? AND name!=''",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, p1);
    sqlite3_bind_int64(st, 2, p2);

    int cap = 16, n = 0, rc;
    char (*list)[256] = malloc((size_t) cap * 256);
    if (list == NULL) { sqlite3_finalize(st); return -1; }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            char (*grown)[256] = realloc(list, (size_t) cap * 256);
            if (grown == NULL) { free(list); sqlite3_finalize(st); return -1; }
            list = grown;
        }
        snprintf(list[n++], 256, "%s", (const char *) sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) { free(list); return -1; }
    *names = list;
    *count = n;
    return 0;
}

static int delete_subtree_rec(cvmfs_catwriter_t *w, const char *path, int depth) {
    if (depth > 128) return -1;
    char (*names)[256] = NULL;
    int   n = 0, removed = 0;
    if (child_names(w, path, &names, &n) != 0) return -1;
    for (int i = 0; i < n; i++) {
        char child[4096];
        int  cw = snprintf(child, sizeof(child), "%s/%s", path, names[i]);
        if (cw < 0 || (size_t) cw >= sizeof(child)) { free(names); return -1; }
        int sub = delete_subtree_rec(w, child, depth + 1);
        if (sub < 0) { free(names); return -1; }
        removed += sub;
    }
    free(names);
    if (cvmfs_catwriter_delete(w, path) != 0) return -1;
    return removed + 1;
}

int cvmfs_catwriter_delete_subtree(cvmfs_catwriter_t *w, const char *path) {
    /* nested_catalogs rows at or under `path` go too. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "DELETE FROM nested_catalogs WHERE path=? OR path GLOB ?", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    char glob[4096];
    snprintf(glob, sizeof(glob), "%s/*", path);
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, glob, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    return delete_subtree_rec(w, path, 0);
}

int cvmfs_catwriter_add_chunk(cvmfs_catwriter_t *w, const char *path,
                              uint64_t offset, uint64_t size, const cvmfs_hash_t *hash) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chunks VALUES(?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);
    sqlite3_bind_int64(st, 3, (int64_t) offset);
    sqlite3_bind_int64(st, 4, (int64_t) size);
    sqlite3_bind_blob(st, 5, hash->bytes, (int) hash->len, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_clear_chunks(cvmfs_catwriter_t *w, const char *path) {
    return exec_by_md5(w, "DELETE FROM chunks WHERE md5path_1=? AND md5path_2=?", path);
}

int cvmfs_catwriter_set_nested(cvmfs_catwriter_t *w, const char *path,
                               const char *sha1_hex, uint64_t size) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO nested_catalogs VALUES(?,?,?)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, sha1_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (int64_t) size);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_del_nested(cvmfs_catwriter_t *w, const char *path) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "DELETE FROM nested_catalogs WHERE path=?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_set_property(cvmfs_catwriter_t *w, const char *key, const char *value) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO properties VALUES(?,?)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_update_counters(cvmfs_catwriter_t *w) {
    /* statistics recomputed wholesale from the row set — the fsck oracle. */
    static const char *const SQL[] = {
        "DELETE FROM statistics",
        "INSERT INTO statistics SELECT 'self_regular', COUNT(*) FROM catalog "
            "WHERE flags&4 AND NOT flags&64",
        "INSERT INTO statistics SELECT 'self_chunked', COUNT(*) FROM catalog WHERE flags&64",
        "INSERT INTO statistics SELECT 'self_chunks', COUNT(*) FROM chunks",
        "INSERT INTO statistics SELECT 'self_dir', COUNT(*) FROM catalog "
            "WHERE flags&1 AND name!=''",
        "INSERT INTO statistics SELECT 'self_symlink', COUNT(*) FROM catalog WHERE flags&8",
        "INSERT INTO statistics SELECT 'self_nested', COUNT(*) FROM nested_catalogs",
        "INSERT INTO statistics SELECT 'self_file_size', IFNULL(SUM(size),0) FROM catalog "
            "WHERE flags&4 AND NOT flags&64",
        "INSERT INTO statistics SELECT 'self_chunked_size', IFNULL(SUM(size),0) FROM catalog "
            "WHERE flags&64",
        "INSERT INTO statistics SELECT 'self_xattr', COUNT(*) FROM catalog "
            "WHERE xattr IS NOT NULL",
        /* subtree_* seeded to 0; the publisher aggregates child totals in. */
        "INSERT INTO statistics VALUES('subtree_regular',0),('subtree_chunked',0),"
            "('subtree_chunks',0),('subtree_dir',0),('subtree_symlink',0),"
            "('subtree_nested',0),('subtree_file_size',0),('subtree_chunked_size',0),"
            "('subtree_xattr',0)",
    };
    for (size_t i = 0; i < sizeof(SQL) / sizeof(SQL[0]); i++)
        if (exec_sql(w->db, SQL[i]) != 0) return -1;
    return 0;
}

int cvmfs_catwriter_set_counter(cvmfs_catwriter_t *w, const char *name, int64_t value) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO statistics VALUES(?,?)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, value);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int cvmfs_catwriter_get_counter(cvmfs_catwriter_t *w, const char *name, int64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT value FROM statistics WHERE counter=?", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(st, 0);
        found = 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int cvmfs_catwriter_lookup(cvmfs_catwriter_t *w, const char *path, cvmfs_dirent_t *out) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name, flags, mode, size, mtime, hardlinks, symlink, uid, gid, hash "
            "FROM catalog WHERE md5path_1=? AND md5path_2=?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);

    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        const unsigned char *name = sqlite3_column_text(st, 0);
        if (name) snprintf(out->name, sizeof(out->name), "%s", (const char *) name);
        out->flags = (uint32_t) sqlite3_column_int64(st, 1);
        out->mode  = (uint32_t) sqlite3_column_int64(st, 2);
        out->size  = (uint64_t) sqlite3_column_int64(st, 3);
        out->mtime = sqlite3_column_int64(st, 4);
        int64_t hardlinks = sqlite3_column_int64(st, 5);
        out->linkcount = (uint32_t) (hardlinks & 0xffffffffu);
        if (out->linkcount == 0) out->linkcount = 1;
        const unsigned char *sym = sqlite3_column_text(st, 6);
        if (sym && (out->flags & CVMFS_FLAG_LINK))
            snprintf(out->symlink, sizeof(out->symlink), "%s", (const char *) sym);
        out->uid = (uint32_t) sqlite3_column_int64(st, 7);
        out->gid = (uint32_t) sqlite3_column_int64(st, 8);
        if (sqlite3_column_type(st, 9) == SQLITE_BLOB) {
            const void *blob = sqlite3_column_blob(st, 9);
            int         blen = sqlite3_column_bytes(st, 9);
            if (blob && blen > 0 && blen <= 20) {
                cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, blob, (size_t) blen, &out->hash);
                out->has_hash = 1;
            }
        }
        found = 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int cvmfs_catwriter_list_nested(cvmfs_catwriter_t *w, cvmfs_nested_cb cb, void *ud) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT path, sha1, size FROM nested_catalogs", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (cb)
            cb((const char *) sqlite3_column_text(st, 0),
               (const char *) sqlite3_column_text(st, 1),
               (uint64_t) sqlite3_column_int64(st, 2), ud);
        n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

/* ---- xattr BLOB packing --------------------------------------------------- */

int cvmfs_xattr_pack(const char *const *keys, const unsigned char *const *vals,
                     const size_t *val_lens, size_t n, unsigned char *out, size_t cap) {
    if (n > 255 || cap < 2) return -1;
    out[0] = 1;                      /* version */
    out[1] = (unsigned char) n;
    size_t off = 2;
    for (size_t i = 0; i < n; i++) {
        size_t kl = strlen(keys[i]), vl = val_lens[i];
        if (kl == 0 || kl > 255 || vl > 65535) return -1;
        if (off + 3 + kl + vl > cap) return -1;
        out[off++] = (unsigned char) kl;
        out[off++] = (unsigned char) (vl & 0xff);
        out[off++] = (unsigned char) (vl >> 8);
        memcpy(out + off, keys[i], kl);
        off += kl;
        memcpy(out + off, vals[i], vl);
        off += vl;
    }
    return (int) off;
}

int cvmfs_xattr_count(const unsigned char *blob, size_t blob_len) {
    if (blob == NULL || blob_len < 2 || blob[0] != 1) return -1;
    return blob[1];
}

int cvmfs_xattr_unpack(const unsigned char *blob, size_t blob_len, size_t i,
                       const char **key, size_t *key_len,
                       const unsigned char **val, size_t *val_len) {
    int count = cvmfs_xattr_count(blob, blob_len);
    if (count < 0 || i >= (size_t) count) return -1;
    size_t off = 2;
    for (size_t e = 0; e <= i; e++) {
        if (off + 3 > blob_len) return -1;
        size_t kl = blob[off];
        size_t vl = (size_t) blob[off + 1] | ((size_t) blob[off + 2] << 8);
        off += 3;
        if (off + kl + vl > blob_len) return -1;
        if (e == i) {
            *key = (const char *) blob + off;
            *key_len = kl;
            *val = blob + off + kl;
            *val_len = vl;
            return 0;
        }
        off += kl + vl;
    }
    return -1;
}
