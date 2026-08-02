/* pathidx_unittest.c — phase-87 G6 mmap path-index units.
 *
 * Ritual: success (build/write/open round-trip, point lookups return the full
 * dirent, authoritative absent, sorted readdir runs incl. the root, symlink
 * targets, remount-and-reread), error (truncation, foreign ABI sizes, wrong
 * version, out-of-file geometry all REFUSED at open; corrupt bucket/entry
 * surfaces as a defect, never a wrong answer), security-negative (header-crc
 * bit flip refused at open; a tampered entry hash is served to the CALLER's
 * CAS check — the lookup layer stays memory-safe on hostile offsets).
 *
 * Build: gcc -I shared shared/cvmfs/index/pathidx_unittest.c
 *        shared/cvmfs/index/pathidx.c shared/cvmfs/platform/platform.c -lz
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1        /* mkdtemp under strict -std=c11 */
#endif
#include "cvmfs/index/pathidx.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_fail;

#define CHECK(cond, msg) do {                                                  \
    if (!(cond)) { g_fail++; fprintf(stderr, "FAIL %s:%d %s\n",                \
                                     __FILE__, __LINE__, msg); }               \
} while (0)

#define SIDECAR "pathidx.bxi"

/* ---- corpus: a small tree with every entry species ----------------------- */

typedef struct { const char *path; uint32_t flags; uint64_t size;
                 const char *link; } spec_t;

static const spec_t SPECS[] = {
    { "",              CVMFS_FLAG_DIR,  0,    NULL },
    { "/bin",          CVMFS_FLAG_DIR,  0,    NULL },
    { "/bin/sh",       CVMFS_FLAG_FILE, 812,  NULL },
    { "/bin/tool",     CVMFS_FLAG_FILE, 4096, NULL },
    { "/data",         CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT, 0, NULL },
    { "/data/big",     CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK, 1u << 20, NULL },
    { "/data/blob",    CVMFS_FLAG_FILE, 77,   NULL },
    { "/link",         CVMFS_FLAG_LINK, 0,    "bin/sh" },
    { "/zz",           CVMFS_FLAG_DIR,  0,    NULL },
};
#define NSPEC (sizeof(SPECS) / sizeof(SPECS[0]))

static void spec_dirent(const spec_t *s, cvmfs_dirent_t *e) {
    memset(e, 0, sizeof(*e));
    const char *slash = strrchr(s->path, '/');
    snprintf(e->name, sizeof(e->name), "%s", slash ? slash + 1 : "");
    e->flags = s->flags;
    e->mode = (s->flags & CVMFS_FLAG_DIR) ? 040755 : 0100644;
    e->size = s->size;
    e->mtime = 1700000000 + (int64_t) s->size;
    e->uid = 123; e->gid = 456;
    e->linkcount = 1;
    if (s->link != NULL) snprintf(e->symlink, sizeof(e->symlink), "%s", s->link);
    if ((s->flags & CVMFS_FLAG_FILE) && !(s->flags & CVMFS_FLAG_FILE_CHUNK)) {
        e->has_hash = 1;
        e->hash.algo = CVMFS_HASH_SHA1;
        e->hash.len = 20;
        memset(e->hash.bytes, (int) (s->size & 0xff), 20);
    }
}

static int write_corpus(int dfd, const cvmfs_hash_t *root) {
    cvmfs_pathidx_build_t b;
    cvmfs_pathidx_build_init(&b);
    for (size_t i = 0; i < NSPEC; i++) {
        cvmfs_dirent_t e;
        spec_dirent(&SPECS[i], &e);
        if (cvmfs_pathidx_build_add(&b, SPECS[i].path, &e) != 0) {
            cvmfs_pathidx_build_free(&b);
            return -1;
        }
    }
    int rc = cvmfs_pathidx_write(&b, root, dfd, SIDECAR);
    cvmfs_pathidx_build_free(&b);
    return rc;
}

static cvmfs_hash_t test_root(void) {
    cvmfs_hash_t h;
    memset(&h, 0, sizeof(h));
    h.algo = CVMFS_HASH_SHA1;
    h.len = 20;
    memset(h.bytes, 0xab, 20);
    return h;
}

/* ---- readdir collector --------------------------------------------------- */

typedef struct { char names[16][256]; int n; } dl_t;

static void dl_cb(const cvmfs_dirent_t *e, void *ud) {
    dl_t *d = ud;
    if (d->n < 16) snprintf(d->names[d->n++], 256, "%s", e->name);
}

/* ---- success ------------------------------------------------------------- */

static void test_roundtrip(int dfd) {
    cvmfs_hash_t root = test_root();
    CHECK(write_corpus(dfd, &root) == 0, "write sidecar");

    cvmfs_pathidx_t ix;
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) == 0, "open sidecar");
    CHECK(cvmfs_hash_eq(cvmfs_pathidx_root(&ix), &root), "root recorded");

    for (size_t i = 0; i < NSPEC; i++) {
        cvmfs_dirent_t want, got;
        spec_dirent(&SPECS[i], &want);
        CHECK(cvmfs_pathidx_lookup(&ix, SPECS[i].path, &got) == 1, "lookup hit");
        CHECK(strcmp(got.name, want.name) == 0, "name");
        CHECK(got.flags == want.flags && got.mode == want.mode
              && got.size == want.size && got.mtime == want.mtime
              && got.uid == want.uid && got.gid == want.gid
              && got.linkcount == want.linkcount, "metadata identical");
        CHECK(strcmp(got.symlink, want.symlink) == 0, "symlink target");
        CHECK(got.has_hash == want.has_hash, "has_hash");
        if (want.has_hash)
            CHECK(cvmfs_hash_eq(&got.hash, &want.hash), "content hash");
    }

    cvmfs_dirent_t miss;
    CHECK(cvmfs_pathidx_lookup(&ix, "/absent", &miss) == 0,
          "complete set: absent is authoritative");
    CHECK(cvmfs_pathidx_lookup(&ix, "/bin/shh", &miss) == 0, "near-miss absent");

    dl_t d;
    memset(&d, 0, sizeof(d));
    CHECK(cvmfs_pathidx_readdir(&ix, "", dl_cb, &d) == 4, "root child count");
    CHECK(d.n == 4 && strcmp(d.names[0], "bin") == 0
          && strcmp(d.names[1], "data") == 0 && strcmp(d.names[2], "link") == 0
          && strcmp(d.names[3], "zz") == 0, "root children sorted, no self");
    memset(&d, 0, sizeof(d));
    CHECK(cvmfs_pathidx_readdir(&ix, "/data", dl_cb, &d) == 2, "subdir count");
    CHECK(d.n == 2 && strcmp(d.names[0], "big") == 0
          && strcmp(d.names[1], "blob") == 0, "subdir children sorted");
    memset(&d, 0, sizeof(d));
    CHECK(cvmfs_pathidx_readdir(&ix, "/zz", dl_cb, &d) == 0, "empty dir lists 0");
    CHECK(cvmfs_pathidx_readdir(&ix, "/nosuch", dl_cb, &d) == -1,
          "absent dir cannot be listed");
    CHECK(cvmfs_pathidx_readdir(&ix, "/bin/sh", dl_cb, &d) == -1,
          "a file cannot be listed");

    cvmfs_pathidx_close(&ix);

    /* reopen = the mount-again path; same answers off the same bytes */
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) == 0, "reopen");
    cvmfs_dirent_t got;
    CHECK(cvmfs_pathidx_lookup(&ix, "/bin/tool", &got) == 1
          && got.size == 4096, "reopen serves");
    cvmfs_pathidx_close(&ix);
}

/* ---- error: refusals at open -------------------------------------------- */

static long sidecar_size(int dfd) {
    struct stat st;
    return fstatat(dfd, SIDECAR, &st, 0) == 0 ? (long) st.st_size : -1;
}

/* Flip/patch one byte at `off`, run `fn`, restore. */
static void patch_byte(int dfd, long off, unsigned char xor_mask,
                       const char *msg) {
    int fd = openat(dfd, SIDECAR, O_RDWR);
    CHECK(fd >= 0, "open for patch");
    if (fd < 0) return;
    unsigned char c;
    CHECK(pread(fd, &c, 1, off) == 1, "read patch byte");
    c ^= xor_mask;
    CHECK(pwrite(fd, &c, 1, off) == 1, "write patch byte");
    close(fd);

    cvmfs_pathidx_t ix;
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) != 0, msg);

    fd = openat(dfd, SIDECAR, O_RDWR);
    c ^= xor_mask;
    CHECK(fd >= 0 && pwrite(fd, &c, 1, off) == 1, "restore patch byte");
    if (fd >= 0) close(fd);
}

static void test_open_refusals(int dfd) {
    cvmfs_hash_t root = test_root();
    CHECK(write_corpus(dfd, &root) == 0, "write sidecar");
    long full = sidecar_size(dfd);
    CHECK(full > (long) sizeof(cvmfs_pathidx_hdr_t), "sidecar has payload");

    cvmfs_pathidx_t ix;

    /* truncation: mid-blob and mid-header both refused */
    int fd = openat(dfd, SIDECAR, O_RDWR);
    CHECK(fd >= 0 && ftruncate(fd, full - 7) == 0, "truncate blob tail");
    if (fd >= 0) close(fd);
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) != 0, "truncated file refused");
    fd = openat(dfd, SIDECAR, O_RDWR);
    CHECK(fd >= 0 && ftruncate(fd, (long) sizeof(cvmfs_pathidx_hdr_t) / 2) == 0,
          "truncate header");
    if (fd >= 0) close(fd);
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) != 0, "header stub refused");

    CHECK(write_corpus(dfd, &root) == 0, "rewrite sidecar");
    /* magic / version / ABI-size guards / geometry: each flip trips its
     * semantic check or the header crc — either way the open is refused. */
    patch_byte(dfd, 0, 0xff, "wrong magic refused");
    patch_byte(dfd, 4, 0x02, "wrong version refused");
    patch_byte(dfd, 8, 0x01, "foreign hash_sz refused");
    patch_byte(dfd, 12, 0x01, "foreign ent_sz refused");
    long coff = (long) offsetof(cvmfs_pathidx_hdr_t, count);
    patch_byte(dfd, coff, 0x01, "count drift refused");
    long boff = (long) offsetof(cvmfs_pathidx_hdr_t, blob_off);
    patch_byte(dfd, boff, 0x01, "geometry drift refused");
}

/* ---- security-neg: header crc + hostile entry bytes ---------------------- */

static void test_tamper(int dfd) {
    cvmfs_hash_t root = test_root();
    CHECK(write_corpus(dfd, &root) == 0, "write sidecar");

    /* a pure hdr_crc flip (payload untouched) must refuse the whole file */
    long crcoff = (long) offsetof(cvmfs_pathidx_hdr_t, hdr_crc);
    patch_byte(dfd, crcoff, 0x10, "flipped header crc refused");

    /* hostile ENTRY bytes are outside the crc by design: point path_off past
     * the blob. Open succeeds; the lookup layer must answer -1 (defect),
     * never crash or fabricate. */
    cvmfs_pathidx_t ix;
    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) == 0, "pre-tamper open");
    long e0 = (long) ix.hdr->ents_off;   /* entry 0 = "" root (sorted first) */
    uint64_t huge = ~0ull;
    cvmfs_pathidx_close(&ix);
    int fd = openat(dfd, SIDECAR, O_RDWR);
    CHECK(fd >= 0 && pwrite(fd, &huge, sizeof(huge), e0) == (ssize_t) sizeof(huge),
          "poison entry path_off");
    if (fd >= 0) close(fd);

    CHECK(cvmfs_pathidx_open(&ix, dfd, SIDECAR) == 0,
          "entry payload is outside the header crc (lazy-page design)");
    cvmfs_dirent_t out;
    CHECK(cvmfs_pathidx_lookup(&ix, "", &out) == -1,
          "poisoned entry is a defect, not an answer");
    dl_t d;
    memset(&d, 0, sizeof(d));
    CHECK(cvmfs_pathidx_readdir(&ix, "", dl_cb, &d) == -1,
          "poisoned entry poisons the listing too");
    cvmfs_pathidx_close(&ix);
}

int main(void) {
    char dir[] = "/tmp/pathidx_ut.XXXXXX";
    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 1; }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { perror("open tmpdir"); return 1; }

    test_roundtrip(dfd);
    test_open_refusals(dfd);
    test_tamper(dfd);

    close(dfd);
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "warn: cleanup failed\n");

    if (g_fail == 0) { printf("pathidx unittest: ALL PASS\n"); return 0; }
    fprintf(stderr, "pathidx unittest: %d FAILURES\n", g_fail);
    return 1;
}
