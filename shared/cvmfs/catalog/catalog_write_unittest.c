/*
 * catalog_write_unittest.c — standalone tests for the CVMFS catalog WRITER,
 * verified with the reader (catalog.c) as the oracle in the same process.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_catw_ut \
 *       shared/cvmfs/catalog/catalog_write_unittest.c \
 *       shared/cvmfs/catalog/catalog_write.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c -lsqlite3 -lcrypto && /tmp/cvmfs_catw_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/catalog/catalog_write.h"

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

static const unsigned char H1[20] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
                                      0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14 };

static cvmfs_hash_t mkhash(unsigned char seed) {
    cvmfs_hash_t h;
    unsigned char b[20];
    memcpy(b, H1, 20);
    b[0] = seed;
    cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, b, 20, &h);
    return h;
}

static int add_row(cvmfs_catwriter_t *w, const char *path, uint32_t flags,
                   uint32_t mode, uint64_t size, const cvmfs_hash_t *hash) {
    cvmfs_catrow_t r;
    memset(&r, 0, sizeof(r));
    r.path = path;
    r.flags = flags;
    r.mode = mode;
    r.size = size;
    r.mtime = 1750000000;
    r.hash = hash;
    return cvmfs_catwriter_insert(w, &r);
}

static void count_cb(const cvmfs_dirent_t *e, void *ud) { (void) e; (*(int *) ud)++; }
static void chunk_cb(uint64_t off, uint64_t size, const cvmfs_hash_t *h, void *ud) {
    (void) size; (void) h;
    int *n = ud;
    if ((uint64_t) (*n) * 100 == off) (*n)++;      /* offsets must arrive in order */
}
static void nested_cb(const char *path, const char *sha1, uint64_t size, void *ud) {
    (void) sha1; (void) size;
    if (strcmp(path, "dir/nested") == 0) (*(int *) ud)++;
}

/* Build the fixture catalog; returns 0 on success. */
static int build(cvmfs_catwriter_t *w) {
    cvmfs_hash_t fh = mkhash(0xf1), ch1 = mkhash(0xc1), ch2 = mkhash(0xc2);
    if (add_row(w, "", CVMFS_FLAG_DIR, 040755, 4096, NULL) != 0) return -1;
    if (add_row(w, "dir", CVMFS_FLAG_DIR, 040755, 4096, NULL) != 0) return -1;
    if (add_row(w, "dir/file.txt", CVMFS_FLAG_FILE, 0100644, 11, &fh) != 0) return -1;
    if (add_row(w, "dir/sub", CVMFS_FLAG_DIR, 040755, 4096, NULL) != 0) return -1;
    if (add_row(w, "dir/sub/deep.txt", CVMFS_FLAG_FILE, 0100644, 5, &fh) != 0) return -1;
    if (add_row(w, "dir/nested", CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT,
                040755, 4096, NULL) != 0) return -1;

    cvmfs_catrow_t link;
    memset(&link, 0, sizeof(link));
    link.path = "link";
    link.flags = CVMFS_FLAG_LINK;
    link.mode = 0120777;
    link.mtime = 1750000000;
    link.symlink = "dir/file.txt";
    if (cvmfs_catwriter_insert(w, &link) != 0) return -1;

    cvmfs_catrow_t hard;
    memset(&hard, 0, sizeof(hard));
    hard.path = "hard.bin";
    hard.flags = CVMFS_FLAG_FILE;
    hard.mode = 0100644;
    hard.size = 3;
    hard.mtime = 1750000000;
    hard.linkcount = 2;
    hard.hardlink_group = 7;
    hard.hash = &fh;
    if (cvmfs_catwriter_insert(w, &hard) != 0) return -1;

    cvmfs_catrow_t big;
    memset(&big, 0, sizeof(big));
    big.path = "big.bin";
    big.flags = CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK;
    big.mode = 0100644;
    big.size = 200;
    big.mtime = 1750000000;
    if (cvmfs_catwriter_insert(w, &big) != 0) return -1;
    if (cvmfs_catwriter_add_chunk(w, "big.bin", 0, 100, &ch1) != 0) return -1;
    if (cvmfs_catwriter_add_chunk(w, "big.bin", 100, 100, &ch2) != 0) return -1;

    unsigned char blob[256];
    const char *keys[] = { "user.brix" };
    const unsigned char *vals[] = { (const unsigned char *) "v1" };
    size_t vlens[] = { 2 };
    int blen = cvmfs_xattr_pack(keys, vals, vlens, 1, blob, sizeof(blob));
    if (blen <= 0) return -1;
    cvmfs_catrow_t xf;
    memset(&xf, 0, sizeof(xf));
    xf.path = "xa.txt";
    xf.flags = CVMFS_FLAG_FILE;
    xf.mode = 0100644;
    xf.size = 1;
    xf.mtime = 1750000000;
    xf.hash = &fh;
    xf.xattr = blob;
    xf.xattr_len = (size_t) blen;
    if (cvmfs_catwriter_insert(w, &xf) != 0) return -1;

    if (cvmfs_catwriter_set_nested(w, "dir/nested",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 512) != 0) return -1;
    if (cvmfs_catwriter_set_property(w, "revision", "3") != 0) return -1;
    return cvmfs_catwriter_update_counters(w);
}

static void check_counter(cvmfs_catalog_t *c, const char *name, int64_t want) {
    int64_t got = -1;
    char label[64];
    snprintf(label, sizeof(label), "counter %s == %lld", name, (long long) want);
    CHECK(cvmfs_catalog_counter(c, name, &got) == 1 && got == want, label);
}

static void read_back(const char *db) {
    cvmfs_catalog_t *c = cvmfs_catalog_open(db);
    CHECK(c != NULL, "reader opens the written catalog");
    if (c == NULL) return;

    cvmfs_dirent_t e;
    CHECK(cvmfs_catalog_lookup(c, "", &e) == 1 && (e.flags & CVMFS_FLAG_DIR),
          "root row present");
    CHECK(cvmfs_catalog_lookup(c, "dir/file.txt", &e) == 1
          && e.size == 11 && e.mode == 0100644 && e.has_hash
          && e.hash.bytes[0] == 0xf1, "file row round-trips");
    CHECK(cvmfs_catalog_lookup(c, "link", &e) == 1
          && strcmp(e.symlink, "dir/file.txt") == 0, "symlink target round-trips");
    CHECK(cvmfs_catalog_lookup(c, "hard.bin", &e) == 1
          && e.linkcount == 2 && e.hardlink_group == 7,
          "hardlink group+linkcount encode/decode");

    int n = 0;
    CHECK(cvmfs_catalog_readdir(c, "dir", count_cb, &n) == 3 && n == 3,
          "readdir(dir) sees 3 children");

    cvmfs_hash_t nh;
    uint64_t nsz = 0;
    CHECK(cvmfs_catalog_nested(c, "dir/nested", &nh, &nsz) == 1
          && nsz == 512 && nh.bytes[0] == 0xaa, "nested row round-trips");

    int order = 0;
    CHECK(cvmfs_catalog_chunks(c, "big.bin", chunk_cb, &order) == 2 && order == 2,
          "chunk rows in offset order");

    char rev[16];
    CHECK(cvmfs_catalog_property(c, "revision", rev, sizeof(rev)) == 1
          && strcmp(rev, "3") == 0, "revision property round-trips");

    check_counter(c, "self_regular", 4);          /* file.txt, deep.txt, hard.bin, xa.txt */
    check_counter(c, "self_chunked", 1);
    check_counter(c, "self_chunks", 2);
    check_counter(c, "self_dir", 3);              /* dir, dir/sub, dir/nested (root excluded) */
    check_counter(c, "self_symlink", 1);
    check_counter(c, "self_nested", 1);
    check_counter(c, "self_xattr", 1);
    check_counter(c, "self_chunked_size", 200);

    unsigned char blob[256];
    long blen = cvmfs_catalog_xattr(c, "xa.txt", blob, sizeof(blob));
    const char *k = NULL;
    const unsigned char *v = NULL;
    size_t kl = 0, vl = 0;
    CHECK(blen > 0 && cvmfs_xattr_count(blob, (size_t) blen) == 1
          && cvmfs_xattr_unpack(blob, (size_t) blen, 0, &k, &kl, &v, &vl) == 0
          && kl == 9 && memcmp(k, "user.brix", 9) == 0
          && vl == 2 && memcmp(v, "v1", 2) == 0, "xattr blob round-trips");
    CHECK(cvmfs_catalog_xattr(c, "dir/file.txt", blob, sizeof(blob)) == 0,
          "xattr of plain file is empty");
    cvmfs_catalog_close(c);
}

static void mutate(const char *db) {
    cvmfs_catwriter_t *w = cvmfs_catwriter_open(db);
    CHECK(w != NULL, "writer reopens an existing catalog");
    if (w == NULL) return;

    cvmfs_dirent_t e;
    CHECK(cvmfs_catwriter_lookup(w, "dir/file.txt", &e) == 1 && e.size == 11,
          "writer lookup sees existing rows");

    int seen = 0;
    CHECK(cvmfs_catwriter_list_nested(w, nested_cb, &seen) == 1 && seen == 1,
          "list_nested enumerates");

    /* upsert replaces; insert refuses a duplicate */
    cvmfs_catrow_t r;
    memset(&r, 0, sizeof(r));
    r.path = "dir/file.txt";
    r.flags = CVMFS_FLAG_FILE;
    r.mode = 0100600;
    r.size = 99;
    r.mtime = 1;
    CHECK(cvmfs_catwriter_insert(w, &r) != 0, "duplicate insert refused");
    CHECK(cvmfs_catwriter_upsert(w, &r) == 0, "upsert replaces");
    CHECK(cvmfs_catwriter_lookup(w, "dir/file.txt", &e) == 1 && e.size == 99,
          "upsert visible");

    /* subtree delete takes dirents + nested rows, count is exact */
    int removed = cvmfs_catwriter_delete_subtree(w, "dir");
    CHECK(removed == 5, "delete_subtree removes 5 rows");
    CHECK(cvmfs_catwriter_lookup(w, "dir/sub/deep.txt", &e) == 0
          && cvmfs_catwriter_lookup(w, "dir", &e) == 0, "subtree rows gone");
    CHECK(cvmfs_catwriter_list_nested(w, NULL, NULL) == 0, "nested row swept");

    /* chunk delete rides row delete */
    CHECK(cvmfs_catwriter_delete(w, "big.bin") == 0, "chunked row deletes");

    cvmfs_catwriter_abort(w);                     /* roll it all back */

    cvmfs_catalog_t *c = cvmfs_catalog_open(db);
    cvmfs_dirent_t back;
    CHECK(c != NULL && cvmfs_catalog_lookup(c, "dir/file.txt", &back) == 1
          && back.size == 11, "abort rolled the mutation back");
    if (c != NULL) cvmfs_catalog_close(c);
}

static void test_errors(const char *db) {
    CHECK(cvmfs_catwriter_create(db) == NULL, "create refuses an existing file");
    CHECK(cvmfs_catwriter_open("/nonexistent/nope.db") == NULL,
          "open on a missing path fails");

    unsigned char out[600];
    const char *keys[] = { "k" };
    const unsigned char *vals[] = { out };
    size_t huge[] = { 70000 };
    CHECK(cvmfs_xattr_pack(keys, vals, huge, 1, out, sizeof(out)) == -1,
          "xattr value > 64KiB refused");
    size_t one[] = { 1 };
    CHECK(cvmfs_xattr_pack(keys, vals, one, 1, out, 4) == -1,
          "xattr pack overflow refused");
    int blen = cvmfs_xattr_pack(keys, vals, one, 1, out, sizeof(out));
    const char *k; const unsigned char *v; size_t kl, vl;
    CHECK(blen > 0 && cvmfs_xattr_unpack(out, (size_t) blen, 1, &k, &kl, &v, &vl) == -1,
          "xattr unpack out-of-range refused");
    /* security-negative: truncated blob must not read out of bounds */
    CHECK(cvmfs_xattr_unpack(out, 3, 0, &k, &kl, &v, &vl) == -1,
          "truncated xattr blob refused");
}

int main(void) {
    char db[128];
    snprintf(db, sizeof(db), "/tmp/cvmfs_catw_ut.%d.db", getpid());
    unlink(db);

    cvmfs_catwriter_t *w = cvmfs_catwriter_create(db);
    CHECK(w != NULL, "create fresh catalog");
    CHECK(w != NULL && build(w) == 0, "fixture rows inserted");
    CHECK(cvmfs_catwriter_commit(w) == 0, "commit");

    read_back(db);
    mutate(db);
    test_errors(db);

    unlink(db);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
