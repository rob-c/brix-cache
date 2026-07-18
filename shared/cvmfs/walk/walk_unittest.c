/*
 * walk_unittest.c — test of the CVMFS content-aware core facade (phase-85 F0):
 * a genuine 3-catalog snapshot (root → nested A → nested B, with a whole file,
 * a plain subdirectory, a symlink, and a chunked file) built as real SQLite
 * catalogs, zlib-compressed and served through a mock transport. Proves
 * cvmfs_walk_catalog() enumerates the exact CAS reference set, honours depth /
 * early-stop, and aborts on a tampered catalog; and cvmfs_verify_blob()
 * verifies + decodes a stored object standalone.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_walk_ut \
 *       shared/cvmfs/walk/walk_unittest.c shared/cvmfs/walk/walk.c \
 *       shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
 *       shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c shared/cache/cas_store.c \
 *       -lsqlite3 -lcrypto -lz && /tmp/cvmfs_walk_ut
 * Exit 0 = all checks pass.
 */
#define _GNU_SOURCE
#include "cvmfs/walk/walk.h"
#include "cvmfs/catalog/catalog.h"
#include "cvmfs/object/object.h"

#include <sqlite3.h>
#include <zlib.h>

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

static void rm_rf(const char *p) {
    char cmd[600]; snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) {}
}

static unsigned char *zlib_of(const unsigned char *src, size_t n, size_t *outn) {
    uLongf cap = compressBound(n);
    unsigned char *buf = malloc(cap);
    compress(buf, &cap, src, n);
    *outn = cap;
    return buf;
}

/* ---- fixture: object registry for the mock transport -------------------- */
typedef struct { char rel[256]; unsigned char *bytes; size_t len; } mock_obj_t;
typedef struct { mock_obj_t obj[16]; int n; } mock_reg_t;

static void reg_add(mock_reg_t *r, const char *rel, unsigned char *bytes, size_t len) {
    snprintf(r->obj[r->n].rel, sizeof(r->obj[r->n].rel), "%s", rel);
    r->obj[r->n].bytes = bytes; r->obj[r->n].len = len; r->n++;
}

static int mock_transport(const char *proxy, const char *host, const char *rel,
                          unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) proxy; (void) host;
    mock_reg_t *r = ud;
    for (int i = 0; i < r->n; i++) {
        if (strcmp(rel, r->obj[i].rel) == 0) {
            if (r->obj[i].len > outcap) return -1;
            memcpy(out, r->obj[i].bytes, r->obj[i].len);
            *outlen = r->obj[i].len;
            return 0;
        }
    }
    return -1;   /* 404 */
}

/* build "data/<2>/<rest><suffix>" for a hash */
static void obj_rel(const cvmfs_hash_t *h, char suffix, char *out, size_t n) {
    char op[160];
    cvmfs_hash_to_object_path(h, suffix, op, sizeof(op));
    snprintf(out, n, "data/%s", op);
}

/* ---- catalog forge ------------------------------------------------------ */
static sqlite3 *cat_create(const char *path) {
    sqlite3 *db = NULL;
    sqlite3_open(path, &db);
    sqlite3_exec(db,
        "CREATE TABLE catalog (md5path_1 INTEGER, md5path_2 INTEGER, parent_1 INTEGER,"
        " parent_2 INTEGER, hardlinks INTEGER, hash BLOB, size INTEGER, mode INTEGER,"
        " mtime INTEGER, flags INTEGER, name TEXT, symlink TEXT, uid INTEGER, gid INTEGER,"
        " xattr BLOB, PRIMARY KEY(md5path_1,md5path_2));"
        "CREATE TABLE nested_catalogs (path TEXT, sha1 TEXT, size INTEGER, PRIMARY KEY(path));"
        "CREATE TABLE properties (key TEXT, value TEXT, PRIMARY KEY(key));"
        "CREATE TABLE chunks (md5path_1 INTEGER, md5path_2 INTEGER, offset INTEGER,"
        " size INTEGER, hash BLOB, PRIMARY KEY(md5path_1,md5path_2,offset));", NULL, NULL, NULL);
    return db;
}

/* Insert one dirent row: rows keyed by md5 of the FULL repo-root-relative path,
 * name = basename, parent = md5 of the parent path. */
static void cat_add(sqlite3 *db, const char *path, const char *parent,
                    const char *name, unsigned flags,
                    const cvmfs_hash_t *hash, uint64_t size, const char *symlink) {
    int64_t m1, m2, p1, p2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    cvmfs_catalog_md5path(parent, &p1, &p2);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db,
        "INSERT INTO catalog VALUES (?,?,?,?,1,?,?,?,1,?,?,?,0,0,NULL)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, m1); sqlite3_bind_int64(st, 2, m2);
    sqlite3_bind_int64(st, 3, p1); sqlite3_bind_int64(st, 4, p2);
    if (hash) sqlite3_bind_blob(st, 5, hash->bytes, 20, SQLITE_STATIC);
    else      sqlite3_bind_null(st, 5);
    sqlite3_bind_int64(st, 6, (int64_t) size);
    sqlite3_bind_int64(st, 7, (flags & CVMFS_FLAG_DIR) ? 040755 : 0100644);
    sqlite3_bind_int64(st, 8, (int64_t) flags);
    sqlite3_bind_text(st, 9, name, -1, SQLITE_STATIC);
    if (symlink) sqlite3_bind_text(st, 10, symlink, -1, SQLITE_STATIC);
    else         sqlite3_bind_null(st, 10);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void cat_add_chunk(sqlite3 *db, const char *path, uint64_t offset,
                          uint64_t size, const cvmfs_hash_t *hash) {
    int64_t m1, m2;
    cvmfs_catalog_md5path(path, &m1, &m2);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "INSERT INTO chunks VALUES (?,?,?,?,?)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, m1); sqlite3_bind_int64(st, 2, m2);
    sqlite3_bind_int64(st, 3, (int64_t) offset);
    sqlite3_bind_int64(st, 4, (int64_t) size);
    sqlite3_bind_blob(st, 5, hash->bytes, 20, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void cat_nested(sqlite3 *db, const char *path, const cvmfs_hash_t *h, uint64_t size) {
    char hex[48];
    cvmfs_hash_to_hex(h, 0, hex, sizeof(hex));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "INSERT INTO nested_catalogs VALUES (?,?,?)", -1, &st, NULL);
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, hex, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (int64_t) size);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Close db, read its bytes, compress, hash the STORED (compressed) form. */
static unsigned char *cat_seal(sqlite3 *db, const char *path,
                               cvmfs_hash_t *out_h, size_t *out_zn) {
    sqlite3_close(db);
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *raw = malloc(sz);
    if (fread(raw, 1, sz, f) != (size_t) sz) {}
    fclose(f);
    unsigned char *z = zlib_of(raw, sz, out_zn);
    free(raw);
    cvmfs_object_hash(CVMFS_HASH_SHA1, z, *out_zn, out_h);
    return z;
}

/* ---- walk-result collector ---------------------------------------------- */
typedef struct { cvmfs_walk_kind_e kind; char hex[48]; char suffix; char path[256]; } seen_t;
typedef struct { seen_t item[32]; int n; int stop_after; } collect_t;

static int collect_cb(const cvmfs_walk_item_t *it, void *ud) {
    collect_t *c = ud;
    if (c->n < 32) {
        seen_t *s = &c->item[c->n];
        s->kind = it->kind;
        cvmfs_hash_to_hex(&it->hash, 0, s->hex, sizeof(s->hex));
        s->suffix = it->suffix;
        snprintf(s->path, sizeof(s->path), "%s", it->path);
    }
    c->n++;
    return (c->stop_after > 0 && c->n >= c->stop_after) ? 1 : 0;
}

static int saw(const collect_t *c, cvmfs_walk_kind_e kind, const cvmfs_hash_t *h,
               char suffix, const char *path) {
    char hex[48];
    cvmfs_hash_to_hex(h, 0, hex, sizeof(hex));
    for (int i = 0; i < c->n && i < 32; i++) {
        const seen_t *s = &c->item[i];
        if (s->kind == kind && s->suffix == suffix
            && strcmp(s->hex, hex) == 0 && strcmp(s->path, path) == 0)
            return 1;
    }
    return 0;
}

int main(void) {
    char tmp_dir[]   = "/tmp/brix_walk_tmp.XXXXXX";
    char cache_dir[] = "/tmp/brix_walk_cache.XXXXXX";
    char cache2[]    = "/tmp/brix_walk_cache2.XXXXXX";
    if (!mkdtemp(tmp_dir) || !mkdtemp(cache_dir) || !mkdtemp(cache2)) {
        perror("mkdtemp"); return 2;
    }

    /* content hashes referenced by catalog rows (the walker never fetches
     * file/chunk bodies, only records them — bodies need not exist) */
    cvmfs_hash_t h_hello, h_inner, h_leaf, h_p1, h_p2;
    cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) "hello", 5, &h_hello);
    cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) "inner", 5, &h_inner);
    cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) "leaf",  4, &h_leaf);
    cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) "p1",    2, &h_p1);
    cvmfs_object_hash(CVMFS_HASH_SHA1, (const unsigned char *) "p2",    2, &h_p2);

    char dbpath[600];

    /* catalog B (deepest): root "/nested/deep" + file "/nested/deep/leaf" */
    snprintf(dbpath, sizeof(dbpath), "%s/b.cat", tmp_dir);
    sqlite3 *db = cat_create(dbpath);
    cat_add(db, "/nested/deep", "/nested", "deep",
            CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_ROOT, NULL, 0, NULL);
    cat_add(db, "/nested/deep/leaf", "/nested/deep", "leaf",
            CVMFS_FLAG_FILE, &h_leaf, 4, NULL);
    cvmfs_hash_t hB; size_t zBn; unsigned char *zB = cat_seal(db, dbpath, &hB, &zBn);

    /* catalog A: root "/nested" + chunked "/nested/big" + mountpoint "/nested/deep" */
    snprintf(dbpath, sizeof(dbpath), "%s/a.cat", tmp_dir);
    db = cat_create(dbpath);
    cat_add(db, "/nested", "", "nested",
            CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_ROOT, NULL, 0, NULL);
    cat_add(db, "/nested/big", "/nested", "big",
            CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK, NULL, 4, NULL);
    cat_add_chunk(db, "/nested/big", 0, 2, &h_p1);
    cat_add_chunk(db, "/nested/big", 2, 2, &h_p2);
    cat_add(db, "/nested/deep", "/nested", "deep",
            CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT, NULL, 0, NULL);
    cat_nested(db, "/nested/deep", &hB, zBn);
    cvmfs_hash_t hA; size_t zAn; unsigned char *zA = cat_seal(db, dbpath, &hA, &zAn);

    /* root catalog: "" + /hello + /dir/inner + /link + mountpoint /nested */
    snprintf(dbpath, sizeof(dbpath), "%s/root.cat", tmp_dir);
    db = cat_create(dbpath);
    cat_add(db, "", "", "", CVMFS_FLAG_DIR, NULL, 0, NULL);
    cat_add(db, "/hello", "", "hello", CVMFS_FLAG_FILE, &h_hello, 5, NULL);
    cat_add(db, "/dir", "", "dir", CVMFS_FLAG_DIR, NULL, 0, NULL);
    cat_add(db, "/dir/inner", "/dir", "inner", CVMFS_FLAG_FILE, &h_inner, 5, NULL);
    cat_add(db, "/link", "", "link", CVMFS_FLAG_LINK, NULL, 0, "hello");
    cat_add(db, "/nested", "", "nested",
            CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT, NULL, 0, NULL);
    cat_nested(db, "/nested", &hA, zAn);
    cvmfs_hash_t hR; size_t zRn; unsigned char *zR = cat_seal(db, dbpath, &hR, &zRn);

    /* serve all three catalogs through the mock transport */
    mock_reg_t reg; memset(&reg, 0, sizeof(reg));
    char rel[256];
    obj_rel(&hR, 'C', rel, sizeof(rel)); reg_add(&reg, rel, zR, zRn);
    obj_rel(&hA, 'C', rel, sizeof(rel)); reg_add(&reg, rel, zA, zAn);
    obj_rel(&hB, 'C', rel, sizeof(rel)); reg_add(&reg, rel, zB, zBn);

    /* fetch orchestrator over the mock */
    cvmfs_failover_t fo;
    cvmfs_failover_init(&fo, 60);
    cvmfs_failover_add_proxy(&fo, "DIRECT", 0);
    cvmfs_failover_add_host(&fo, "http://mock");

    brix_cas_store_t cache;
    brix_cas_init(&cache, cache_dir, 0);

    static unsigned char scratch[1 << 20];
    cvmfs_fetch_ctx_t fx;
    memset(&fx, 0, sizeof(fx));
    fx.fo = &fo; fx.cache = &cache;
    fx.transport = mock_transport; fx.transport_ud = &reg;
    fx.store_form = CVMFS_STORE_COMPRESSED;
    fx.scratch = scratch; fx.scratch_cap = sizeof(scratch);

    /* ---- full walk: exact CAS reference set ----------------------------- */
    collect_t c; memset(&c, 0, sizeof(c));
    int rc = cvmfs_walk_catalog(&fx, &hR, tmp_dir, 8, collect_cb, &c, 1000);
    CHECK(rc == 0, "full walk completes");
    CHECK(c.n == 8, "full walk emits exactly 8 CAS references");
    CHECK(saw(&c, CVMFS_WALK_CATALOG, &hR, 'C', ""), "root catalog emitted");
    CHECK(saw(&c, CVMFS_WALK_CATALOG, &hA, 'C', "/nested"), "nested catalog A emitted");
    CHECK(saw(&c, CVMFS_WALK_CATALOG, &hB, 'C', "/nested/deep"), "nested catalog B emitted");
    CHECK(saw(&c, CVMFS_WALK_FILE, &h_hello, 0, "/hello"), "whole file /hello emitted");
    CHECK(saw(&c, CVMFS_WALK_FILE, &h_inner, 0, "/dir/inner"), "file in plain subdir emitted");
    CHECK(saw(&c, CVMFS_WALK_FILE, &h_leaf, 0, "/nested/deep/leaf"),
          "file two catalogs deep emitted");
    CHECK(saw(&c, CVMFS_WALK_CHUNK, &h_p1, 'P', "/nested/big")
          && saw(&c, CVMFS_WALK_CHUNK, &h_p2, 'P', "/nested/big"),
          "both chunks of /nested/big emitted");

    /* ---- depth 0: root catalog only, nested emitted but not descended --- */
    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_catalog(&fx, &hR, tmp_dir, 0, collect_cb, &c, 1000);
    CHECK(rc == 0 && c.n == 4, "depth-0 walk stays in the root catalog");
    CHECK(saw(&c, CVMFS_WALK_CATALOG, &hA, 'C', "/nested")
          && !saw(&c, CVMFS_WALK_CATALOG, &hB, 'C', "/nested/deep"),
          "depth-0 records the mountpoint without descending");

    /* ---- early stop ------------------------------------------------------ */
    memset(&c, 0, sizeof(c));
    c.stop_after = 1;
    rc = cvmfs_walk_catalog(&fx, &hR, tmp_dir, 8, collect_cb, &c, 1000);
    CHECK(rc == 1 && c.n == 1, "callback stop halts the walk with rc=1");

    /* ---- subtree walks --------------------------------------------------- */
    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_subtree(&fx, &hR, tmp_dir, "/dir", 8, collect_cb, &c, 1000);
    CHECK(rc == 0 && c.n == 1 && saw(&c, CVMFS_WALK_FILE, &h_inner, 0, "/dir/inner"),
          "subtree /dir emits only its own file");

    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_subtree(&fx, &hR, tmp_dir, "/nested", 8, collect_cb, &c, 1000);
    CHECK(rc == 0 && c.n == 4
          && saw(&c, CVMFS_WALK_CHUNK, &h_p1, 'P', "/nested/big")
          && saw(&c, CVMFS_WALK_CHUNK, &h_p2, 'P', "/nested/big")
          && saw(&c, CVMFS_WALK_CATALOG, &hB, 'C', "/nested/deep")
          && saw(&c, CVMFS_WALK_FILE, &h_leaf, 0, "/nested/deep/leaf"),
          "subtree rooted at a mountpoint walks its own catalog");

    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_subtree(&fx, &hR, tmp_dir, "/nested/deep", 8, collect_cb, &c, 1000);
    CHECK(rc == 0 && c.n == 1 && saw(&c, CVMFS_WALK_FILE, &h_leaf, 0, "/nested/deep/leaf"),
          "subtree two mountpoints deep emits only the leaf");

    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_subtree(&fx, &hR, tmp_dir, "/absent", 8, collect_cb, &c, 1000);
    CHECK(rc == 0 && c.n == 0, "subtree of an absent path is an empty walk");

    /* ---- security-neg: tampered nested catalog aborts the walk ----------- */
    /* fresh cache so catalog A is refetched, not served from verified CAS */
    brix_cas_store_t cacheB;
    brix_cas_init(&cacheB, cache2, 0);
    fx.cache = &cacheB;
    zA[zAn / 2] ^= 0x40;
    memset(&c, 0, sizeof(c));
    rc = cvmfs_walk_catalog(&fx, &hR, tmp_dir, 8, collect_cb, &c, 1000);
    CHECK(rc == -1, "tampered nested catalog aborts the walk");   /* security-neg */
    zA[zAn / 2] ^= 0x40;

    /* ---- cvmfs_verify_blob ---------------------------------------------- */
    unsigned char out[256]; size_t outn = 0;
    CHECK(cvmfs_verify_blob(&hR, zR, zRn, scratch, sizeof(scratch), &outn) == 0,
          "verify_blob accepts an authentic compressed catalog");

    const unsigned char body[] = "verify me";
    size_t zbn; unsigned char *zb = zlib_of(body, sizeof(body) - 1, &zbn);
    cvmfs_hash_t hb; cvmfs_object_hash(CVMFS_HASH_SHA1, zb, zbn, &hb);
    rc = cvmfs_verify_blob(&hb, zb, zbn, out, sizeof(out), &outn);
    CHECK(rc == 0 && outn == sizeof(body) - 1 && memcmp(out, body, outn) == 0,
          "verify_blob decodes an authentic blob to its plaintext");

    zb[zbn / 2] ^= 0x01;
    CHECK(cvmfs_verify_blob(&hb, zb, zbn, out, sizeof(out), &outn) == -1,
          "verify_blob rejects a bit-flipped blob");               /* security-neg */
    zb[zbn / 2] ^= 0x01;

    /* plain-stored (not a zlib stream): identity = hash of the raw bytes */
    cvmfs_hash_t hp; cvmfs_object_hash(CVMFS_HASH_SHA1, body, sizeof(body) - 1, &hp);
    rc = cvmfs_verify_blob(&hp, body, sizeof(body) - 1, out, sizeof(out), &outn);
    CHECK(rc == 0 && outn == sizeof(body) - 1 && memcmp(out, body, outn) == 0,
          "verify_blob passes a plain-stored blob through");
    CHECK(cvmfs_verify_blob(&hp, body, sizeof(body) - 1, out, 4, &outn) == -3,
          "verify_blob reports a too-small output buffer");

    free(zR); free(zA); free(zB); free(zb);
    rm_rf(tmp_dir); rm_rf(cache_dir); rm_rf(cache2);

    printf("walk unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
