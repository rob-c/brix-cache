/* catalog.c — CVMFS SQLite catalog reader. See catalog.h. */
#include "cvmfs/catalog/catalog.h"

#include <openssl/evp.h>
#include <sqlite3.h>

#include <stdlib.h>
#include <string.h>

struct cvmfs_catalog_s {
    sqlite3 *db;
};

/* md5path_{1,2} = the two little-endian int64 halves of MD5(path)
 * (CVMFS Md5::ToIntPair). Path is repo-root-relative, no trailing slash. */
void cvmfs_catalog_md5path(const char *path, int64_t *m1, int64_t *m2) {
    unsigned char md[16];
    unsigned int  n = 0;
    EVP_MD_CTX   *c = EVP_MD_CTX_new();

    EVP_DigestInit_ex(c, EVP_md5(), NULL);
    EVP_DigestUpdate(c, path, strlen(path));
    EVP_DigestFinal_ex(c, md, &n);
    EVP_MD_CTX_free(c);

    int64_t hi = 0, lo = 0;
    memcpy(&hi, md, 8);          /* little-endian host interpretation */
    memcpy(&lo, md + 8, 8);
    *m1 = hi;
    *m2 = lo;
}

cvmfs_catalog_t *cvmfs_catalog_open(const char *db_path) {
    cvmfs_catalog_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;

    if (sqlite3_open_v2(db_path, &c->db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(c->db);
        free(c);
        return NULL;
    }
    return c;
}

void cvmfs_catalog_close(cvmfs_catalog_t *c) {
    if (c == NULL) return;
    sqlite3_close(c->db);
    free(c);
}

/* Fill a dirent from a `catalog` row selected with the standard column order. */
static void row_to_dirent(sqlite3_stmt *st, cvmfs_dirent_t *e) {
    memset(e, 0, sizeof(*e));
    const unsigned char *name = sqlite3_column_text(st, 0);
    if (name) { size_t n = strlen((const char *)name);
                if (n >= sizeof(e->name)) n = sizeof(e->name) - 1;
                memcpy(e->name, name, n); e->name[n] = '\0'; }
    e->flags = (uint32_t) sqlite3_column_int64(st, 1);
    e->mode  = (uint32_t) sqlite3_column_int64(st, 2);
    e->size  = (uint64_t) sqlite3_column_int64(st, 3);
    e->mtime = (int64_t)  sqlite3_column_int64(st, 4);

    int64_t hardlinks = sqlite3_column_int64(st, 5);
    e->linkcount = (uint32_t) (hardlinks & 0xffffffffu);   /* low 32 = linkcount */
    if (e->linkcount == 0) e->linkcount = 1;

    const unsigned char *sym = sqlite3_column_text(st, 6);
    if (sym && (e->flags & CVMFS_FLAG_LINK)) {
        size_t n = strlen((const char *)sym);
        if (n >= sizeof(e->symlink)) n = sizeof(e->symlink) - 1;
        memcpy(e->symlink, sym, n); e->symlink[n] = '\0';
    }
    e->uid = (uint32_t) sqlite3_column_int64(st, 7);
    e->gid = (uint32_t) sqlite3_column_int64(st, 8);

    if (sqlite3_column_type(st, 9) == SQLITE_BLOB) {
        const void *blob = sqlite3_column_blob(st, 9);
        int         blen = sqlite3_column_bytes(st, 9);
        if (blob && blen > 0 && blen <= 20) {
            cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, blob, (size_t) blen, &e->hash);
            e->has_hash = 1;
        }
    }
}

static const char SELECT_COLS[] =
    "name, flags, mode, size, mtime, hardlinks, symlink, uid, gid, hash FROM catalog ";

int cvmfs_catalog_lookup(cvmfs_catalog_t *c, const char *path, cvmfs_dirent_t *out) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT %s WHERE md5path_1=? AND md5path_2=?", SELECT_COLS);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);

    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW) { row_to_dirent(st, out); found = 1; }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int cvmfs_catalog_readdir(cvmfs_catalog_t *c, const char *path, cvmfs_readdir_cb cb, void *ud) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT %s WHERE parent_1=? AND parent_2=?", SELECT_COLS);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);

    int count = 0;
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            cvmfs_dirent_t e;
            row_to_dirent(st, &e);
            if (cb) cb(&e, ud);
            count++;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return count;
}

int cvmfs_catalog_nested(cvmfs_catalog_t *c, const char *path, cvmfs_hash_t *hash, uint64_t *size) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db,
            "SELECT sha1, size FROM nested_catalogs WHERE path=?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);

    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        const unsigned char *sha1 = sqlite3_column_text(st, 0);
        if (sha1 && cvmfs_hash_parse((const char *)sha1, strlen((const char *)sha1), hash) == 0) {
            if (size) *size = (uint64_t) sqlite3_column_int64(st, 1);
            found = 1;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int cvmfs_catalog_chunks(cvmfs_catalog_t *c, const char *path, cvmfs_chunk_cb cb, void *ud) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db,
            "SELECT offset, size, hash FROM chunks "
            "WHERE md5path_1=? AND md5path_2=? ORDER BY offset", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, m1);
    sqlite3_bind_int64(st, 2, m2);

    int count = 0;
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            uint64_t off = (uint64_t) sqlite3_column_int64(st, 0);
            uint64_t sz  = (uint64_t) sqlite3_column_int64(st, 1);
            cvmfs_hash_t h; memset(&h, 0, sizeof(h));
            if (sqlite3_column_type(st, 2) == SQLITE_BLOB) {
                const void *blob = sqlite3_column_blob(st, 2);
                int         blen = sqlite3_column_bytes(st, 2);
                if (blob && blen > 0 && blen <= 20)
                    cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, blob, (size_t) blen, &h);
            }
            if (cb) cb(off, sz, &h, ud);
            count++;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return count;
}

int cvmfs_catalog_property(cvmfs_catalog_t *c, const char *key, char *out, size_t outlen) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db,
            "SELECT value FROM properties WHERE key=?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);

    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        if (v) { snprintf(out, outlen, "%s", (const char *)v); found = 1; }
    }
    sqlite3_finalize(st);
    return found;
}
