/*
 * catalog_unittest.c — standalone tests for the CVMFS SQLite catalog reader.
 * Builds a fixture catalog in the real CVMFS schema, then exercises the reader.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_cat_ut \
 *       shared/cvmfs/catalog/catalog_unittest.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c -lsqlite3 -lcrypto && /tmp/cvmfs_cat_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/catalog/catalog.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static const unsigned char APP_HASH[20] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
    0xbb,0xcc,0xdd,0xee,0xff,0x00,0x12,0x34,0x56,0x78 };

/* Insert one catalog row. */
static void ins(sqlite3 *db, const char *path, const char *parent,
                const char *name, uint32_t flags, uint32_t mode, uint64_t size,
                const char *symlink, const unsigned char *hash) {
    int64_t m1, m2, p1, p2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    cvmfs_catalog_md5path(parent, &p1, &p2);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO catalog (md5path_1,md5path_2,parent_1,parent_2,hardlinks,"
        "hash,size,mode,mtime,flags,name,symlink,uid,gid,xattr) "
        "VALUES (?,?,?,?,1,?,?,?,1700000000,?,?,?,0,0,NULL)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, m1); sqlite3_bind_int64(st, 2, m2);
    sqlite3_bind_int64(st, 3, p1); sqlite3_bind_int64(st, 4, p2);
    if (hash) sqlite3_bind_blob(st, 5, hash, 20, SQLITE_STATIC);
    else      sqlite3_bind_null(st, 5);
    sqlite3_bind_int64(st, 6, (int64_t) size);
    sqlite3_bind_int64(st, 7, mode);
    sqlite3_bind_int64(st, 8, flags);
    sqlite3_bind_text(st, 9, name, -1, SQLITE_STATIC);
    if (symlink) sqlite3_bind_text(st, 10, symlink, -1, SQLITE_STATIC);
    else         sqlite3_bind_null(st, 10);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void build_fixture(const char *db_path) {
    sqlite3 *db;
    sqlite3_open(db_path, &db);
    sqlite3_exec(db,
        "CREATE TABLE catalog (md5path_1 INTEGER, md5path_2 INTEGER,"
        " parent_1 INTEGER, parent_2 INTEGER, hardlinks INTEGER, hash BLOB,"
        " size INTEGER, mode INTEGER, mtime INTEGER, flags INTEGER, name TEXT,"
        " symlink TEXT, uid INTEGER, gid INTEGER, xattr BLOB,"
        " PRIMARY KEY(md5path_1,md5path_2));"
        "CREATE TABLE nested_catalogs (path TEXT, sha1 TEXT, size INTEGER, PRIMARY KEY(path));"
        "CREATE TABLE properties (key TEXT, value TEXT, PRIMARY KEY(key));"
        "CREATE TABLE chunks (md5path_1 INTEGER, md5path_2 INTEGER, offset INTEGER,"
        " size INTEGER, hash BLOB, PRIMARY KEY(md5path_1,md5path_2,offset));",
        NULL, NULL, NULL);

    ins(db, "",           "",      "",       CVMFS_FLAG_DIR, 0040755, 0, NULL, NULL);
    ins(db, "/soft",      "",      "soft",   CVMFS_FLAG_DIR, 0040755, 0, NULL, NULL);
    ins(db, "/soft/app",  "/soft", "app",    CVMFS_FLAG_FILE, 0100644, 1234, NULL, APP_HASH);
    ins(db, "/soft/lnk",  "/soft", "lnk",    CVMFS_FLAG_LINK, 0120777, 0, "app", NULL);
    ins(db, "/soft/big",  "/soft", "big",
        CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK, 0100644, 8000000, NULL, NULL);
    ins(db, "/soft/nested", "/soft", "nested",
        CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT, 0040755, 0, NULL, NULL);

    /* nested catalog entry */
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO nested_catalogs (path,sha1,size) VALUES "
        "('/soft/nested','abcdef0123456789abcdef0123456789abcdef01',1234)", -1, &st, NULL);
    sqlite3_step(st); sqlite3_finalize(st);

    /* two chunks for /soft/big */
    int64_t bm1, bm2;
    cvmfs_catalog_md5path("/soft/big", &bm1, &bm2);
    sqlite3_prepare_v2(db,
        "INSERT INTO chunks (md5path_1,md5path_2,offset,size,hash) VALUES (?,?,?,?,?)",
        -1, &st, NULL);
    unsigned char ch0[20]; memset(ch0, 0xa0, 20);
    unsigned char ch1[20]; memset(ch1, 0xb1, 20);
    sqlite3_bind_int64(st,1,bm1); sqlite3_bind_int64(st,2,bm2);
    sqlite3_bind_int64(st,3,0);            sqlite3_bind_int64(st,4,4000000);
    sqlite3_bind_blob(st,5,ch0,20,SQLITE_STATIC); sqlite3_step(st); sqlite3_reset(st);
    sqlite3_bind_int64(st,1,bm1); sqlite3_bind_int64(st,2,bm2);
    sqlite3_bind_int64(st,3,4000000);      sqlite3_bind_int64(st,4,4000000);
    sqlite3_bind_blob(st,5,ch1,20,SQLITE_STATIC); sqlite3_step(st);
    sqlite3_finalize(st);

    sqlite3_exec(db, "INSERT INTO properties VALUES ('revision','42')", NULL, NULL, NULL);
    sqlite3_close(db);
}

typedef struct { int n; int saw_app, saw_lnk, saw_big, saw_nested; } dircnt_t;
static void dir_cb(const cvmfs_dirent_t *e, void *ud) {
    dircnt_t *d = ud; d->n++;
    if (!strcmp(e->name, "app"))    d->saw_app = 1;
    if (!strcmp(e->name, "lnk"))    d->saw_lnk = 1;
    if (!strcmp(e->name, "big"))    d->saw_big = 1;
    if (!strcmp(e->name, "nested")) d->saw_nested = 1;
}

typedef struct { int n; uint64_t last_off; int ordered; } chkcnt_t;
static void chk_cb(uint64_t off, uint64_t sz, const cvmfs_hash_t *h, void *ud) {
    (void) sz; (void) h;
    chkcnt_t *c = ud;
    if (c->n > 0 && off < c->last_off) c->ordered = 0;
    c->last_off = off; c->n++;
}

int main(void) {
    char db[] = "/tmp/brix_cat_ut.XXXXXX";
    int fd = mkstemp(db); if (fd >= 0) close(fd);
    unlink(db);                          /* let sqlite create it fresh */
    build_fixture(db);

    cvmfs_catalog_t *c = cvmfs_catalog_open(db);
    CHECK(c != NULL, "catalog opens");

    cvmfs_dirent_t e;
    CHECK(cvmfs_catalog_lookup(c, "/soft/app", &e) == 1, "lookup file found");
    CHECK((e.flags & CVMFS_FLAG_FILE) && e.size == 1234, "file flags+size");
    CHECK(e.has_hash && e.hash.len == 20 && memcmp(e.hash.bytes, APP_HASH, 20) == 0,
          "file content hash");

    CHECK(cvmfs_catalog_lookup(c, "/soft/lnk", &e) == 1
          && (e.flags & CVMFS_FLAG_LINK) && strcmp(e.symlink, "app") == 0,
          "symlink target");

    CHECK(cvmfs_catalog_lookup(c, "/does/not/exist", &e) == 0, "absent path"); /* neg */

    dircnt_t d; memset(&d, 0, sizeof(d));
    int n = cvmfs_catalog_readdir(c, "/soft", dir_cb, &d);
    CHECK(n == 4 && d.saw_app && d.saw_lnk && d.saw_big && d.saw_nested,
          "readdir lists all children");

    cvmfs_hash_t nh; uint64_t nsz = 0;
    CHECK(cvmfs_catalog_nested(c, "/soft/nested", &nh, &nsz) == 1
          && nh.bytes[0] == 0xab && nsz == 1234, "nested catalog descent");
    CHECK(cvmfs_catalog_nested(c, "/soft", &nh, &nsz) == 0, "non-mountpoint → no nested");

    chkcnt_t ck; memset(&ck, 0, sizeof(ck)); ck.ordered = 1;
    CHECK(cvmfs_catalog_chunks(c, "/soft/big", chk_cb, &ck) == 2 && ck.ordered,
          "chunk list ordered by offset");

    char rev[32];
    CHECK(cvmfs_catalog_property(c, "revision", rev, sizeof(rev)) == 1
          && strcmp(rev, "42") == 0, "property lookup");

    cvmfs_catalog_close(c);
    unlink(db);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
