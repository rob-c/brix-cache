/* cas_pack_unittest.c — phase-87 G4/G5 packed CAS store units.
 *
 * Ritual: success (packing, rollover, byte-identity, few inodes, replay),
 * error (torn journal tail, garbage segment tail, orphan-tail adoption,
 * no resurrection of deleted tail records), security-negative (bit-flipped
 * data / header never served; fsck drops them), G5 tiering (cold zstd pack,
 * hot promotion, byte-identity throughout).
 *
 * Build: gcc -I shared shared/cache/cas_pack_unittest.c shared/cache/cas_pack.c
 *        shared/cache/cas_store.c shared/cvmfs/platform/platform.c
 *        -lz -lzstd -pthread
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1        /* mkdtemp/pwrite/truncate under strict -std=c11 */
#endif
#include "cache/cas_pack.h"
#include "cache/cas_store.h"

#include <dirent.h>
#include <errno.h>
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

/* Deterministic object bodies: repeating tagged text — compressible, unique
 * per index, sizes from a few bytes to > the test segment size. */
static size_t make_obj(int i, unsigned char *buf, size_t cap) {
    size_t len = (size_t) (37 + (i * 211) % 9000);
    if (i % 7 == 0) len = 6000 + (size_t) i * 13;      /* forces rollover @4KiB */
    for (size_t o = 0; o < len && o < cap; o++)
        buf[o] = (unsigned char) ("obj-content-"[o % 12] + (i % 29));
    return len < cap ? len : cap;
}

static void obj_key(int i, char *key, size_t cap) {
    snprintf(key, cap, "%08x%032x", (unsigned) i * 2654435761u, (unsigned) i);
}

static long read_all(int fd, unsigned char *buf, size_t cap) {
    size_t got = 0;
    for (;;) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return (long) got;
        got += (size_t) r;
        if (got == cap) return (long) got;
    }
}

/* get via the DISPATCH layer (the store contract callers actually use). */
static int get_matches(brix_cas_store_t *s, const char *key,
                       const unsigned char *want, size_t want_len) {
    int fd = brix_cas_open(s, key);
    if (fd < 0) return 0;
    unsigned char *buf = malloc(want_len + 64);
    long n = buf != NULL ? read_all(fd, buf, want_len + 64) : -1;
    int ok = n == (long) want_len && memcmp(buf, want, want_len) == 0;
    free(buf);
    close(fd);
    return ok;
}

static int count_inodes(const char *root) {
    char pd[600];
    snprintf(pd, sizeof(pd), "%s/pack", root);
    DIR *d = opendir(pd);
    if (d == NULL) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (de->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* Append `len` bytes of `byte` to <root>/<rel>. */
static void append_garbage(const char *root, const char *rel, int byte, size_t len) {
    char path[640];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    int fd = open(path, O_WRONLY | O_APPEND);
    CHECK(fd >= 0, "open for garbage append");
    if (fd < 0) return;
    unsigned char b = (unsigned char) byte;
    for (size_t i = 0; i < len; i++)
        CHECK(write(fd, &b, 1) == 1, "garbage write");
    close(fd);
}

static void truncate_by(const char *root, const char *rel, long delta) {
    char path[640];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    CHECK(stat(path, &st) == 0, "stat for truncate");
    CHECK(truncate(path, st.st_size - delta) == 0, "truncate");
}

/* Flip one byte relative to the LAST occurrence of `pat` in <root>/<rel>
 * (the live record — earlier matches may be dead pre-fsck copies). */
static int flip_in_file(const char *root, const char *rel,
                        const unsigned char *pat, size_t plen, long extra_off) {
    char path[640];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    int fd = open(path, O_RDWR);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 0; }
    unsigned char *buf = malloc((size_t) st.st_size);
    long n = buf != NULL ? read_all(fd, buf, (size_t) st.st_size) : -1;
    long at = -1;
    for (long i = 0; n > 0 && i + (long) plen <= n; i++)
        if (memcmp(buf + i, pat, plen) == 0) at = i;
    int hit = 0;
    if (at >= 0) {
        unsigned char flipped = buf[at + extra_off] ^ 0x40;
        hit = pwrite(fd, &flipped, 1, at + extra_off) == 1;
    }
    free(buf);
    close(fd);
    return hit;
}

/* ---- success ------------------------------------------------------------- */

#define NOBJ 40

static void test_success(const char *root) {
    brix_cas_store_t s;
    unsigned char    body[32768];
    char             key[64];

    CHECK(brix_cas_init_packed(&s, root, 0, 16384, 0) == 0, "init_packed");
    for (int i = 0; i < NOBJ; i++) {
        size_t len = make_obj(i, body, sizeof(body));
        obj_key(i, key, sizeof(key));
        CHECK(brix_cas_put(&s, key, body, len) == 0, "put");
        CHECK(brix_cas_put(&s, key, body, len) == 0, "idempotent re-put");
    }
    long total = 0;
    for (int i = 0; i < NOBJ; i++) {
        size_t len = make_obj(i, body, sizeof(body));
        obj_key(i, key, sizeof(key));
        CHECK(brix_cas_has(&s, key) == 1, "has after put");
        CHECK(get_matches(&s, key, body, len), "byte-identical get");
        total += (long) len;
    }
    CHECK(brix_cas_size(&s) == total, "size == sum of raw puts (no tiering)");
    CHECK(s.pack->seg_hi > s.pack->seg_lo, "16KiB segments must have rolled");
    int inodes = count_inodes(root);
    CHECK(inodes > 0 && inodes < NOBJ / 2, "few inodes for many objects");

    obj_key(1, key, sizeof(key));
    CHECK(brix_cas_del(&s, key) == 0, "del");
    CHECK(brix_cas_has(&s, key) == 0, "has after del");
    CHECK(brix_cas_open(&s, key) < 0, "get after del fails");
    CHECK(brix_cas_del(&s, key) < 0, "double del fails");
    brix_cas_destroy(&s);

    /* replay: everything (minus the deleted one) survives close + reopen */
    CHECK(brix_cas_init_packed(&s, root, 0, 16384, 0) == 0, "reopen");
    for (int i = 0; i < NOBJ; i++) {
        size_t len = make_obj(i, body, sizeof(body));
        obj_key(i, key, sizeof(key));
        if (i == 1) {
            CHECK(brix_cas_has(&s, key) == 0, "deleted stays deleted");
        } else {
            CHECK(get_matches(&s, key, body, len), "get after replay");
        }
    }
    brix_cas_destroy(&s);
}

/* ---- error / crash recovery ---------------------------------------------- */

static void test_recovery(const char *root) {
    brix_cas_store_t s;
    unsigned char    body[32768];
    char             key[64];

    /* orphan tail: drop the journal's last record → reopen adopts it back */
    size_t len = make_obj(100, body, sizeof(body));
    obj_key(100, key, sizeof(key));
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "init");
    CHECK(brix_cas_put(&s, key, body, len) == 0, "orphan put");
    brix_cas_destroy(&s);
    truncate_by(root, "pack/index.log", 40 + (long) strlen(key));
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "reopen orphan");
    CHECK(get_matches(&s, key, body, len), "orphan record adopted");
    brix_cas_destroy(&s);

    /* torn segment tail: garbage after the last record is truncated away */
    append_garbage(root, "pack/seg-00000000.dat", 0x5a, 97);
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "reopen torn seg");
    CHECK(get_matches(&s, key, body, len), "objects intact after torn tail");
    size_t len2 = make_obj(101, body, sizeof(body));
    char key2[64];
    obj_key(101, key2, sizeof(key2));
    CHECK(brix_cas_put(&s, key2, body, len2) == 0, "put after truncation");
    CHECK(get_matches(&s, key2, body, len2), "get after truncation");
    brix_cas_destroy(&s);

    /* torn journal tail: garbage at the end of index.log is truncated away.
     * (`body` is shared — regenerate each object before comparing.) */
    append_garbage(root, "pack/index.log", 0x7f, 23);
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "reopen torn idx");
    len = make_obj(100, body, sizeof(body));
    CHECK(get_matches(&s, key, body, len), "intact after torn journal");
    len2 = make_obj(101, body, sizeof(body));
    CHECK(get_matches(&s, key2, body, len2), "intact after torn journal 2");
    brix_cas_destroy(&s);

    /* deleted tail record must NOT resurrect via adoption */
    size_t len3 = make_obj(102, body, sizeof(body));
    char key3[64];
    obj_key(102, key3, sizeof(key3));
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "init del-tail");
    CHECK(brix_cas_put(&s, key3, body, len3) == 0, "del-tail put");
    CHECK(brix_cas_del(&s, key3) == 0, "del-tail del");
    brix_cas_destroy(&s);
    CHECK(brix_cas_init_packed(&s, root, 0, 4096, 0) == 0, "reopen del-tail");
    CHECK(brix_cas_has(&s, key3) == 0, "deleted tail not resurrected");
    brix_cas_destroy(&s);
}

/* ---- security-negative ---------------------------------------------------- */

static void test_secneg(const char *root) {
    brix_cas_store_t s;
    unsigned char    body[512];
    char             key[64];

    /* non-repeating body: its first 32 bytes occur exactly once in the
     * segment, so the flip lands INSIDE the record's data */
    unsigned seed = 2463534242u;
    for (size_t i = 0; i < sizeof(body); i++) {
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        body[i] = (unsigned char) seed;
    }
    obj_key(200, key, sizeof(key));

    CHECK(brix_cas_init_packed(&s, root, 0, 1 << 20, 0) == 0, "init secneg");
    CHECK(brix_cas_put(&s, key, body, sizeof(body)) == 0, "secneg put");
    char segrel[64];
    snprintf(segrel, sizeof(segrel), "pack/seg-%08u.dat", s.pack->seg_hi);
    brix_cas_destroy(&s);

    /* flip one DATA byte inside the record → crc rejects; never served */
    CHECK(flip_in_file(root, segrel, body, 32, 8) == 1, "locate record data");
    CHECK(brix_cas_init_packed(&s, root, 0, 1 << 20, 0) == 0, "reopen flipped");
    CHECK(brix_cas_has(&s, key) == 1, "index still lists it");
    CHECK(brix_cas_open(&s, key) < 0, "flipped data never served");
    CHECK(brix_cas_pack_fsck(s.pack) == 1, "fsck drops the corrupt record");
    CHECK(brix_cas_has(&s, key) == 0, "gone after fsck");
    CHECK(brix_cas_put(&s, key, body, sizeof(body)) == 0, "re-put after fsck");
    CHECK(get_matches(&s, key, body, sizeof(body)), "healthy again");

    /* flip a KEY byte inside the record header → key-match rejects */
    unsigned char kpat[64];
    memcpy(kpat, key, strlen(key));
    brix_cas_destroy(&s);
    CHECK(flip_in_file(root, segrel, kpat, strlen(key), 4) == 1, "locate key");
    CHECK(brix_cas_init_packed(&s, root, 0, 1 << 20, 0) == 0, "reopen key-flip");
    if (brix_cas_has(&s, key) == 1)
        CHECK(brix_cas_open(&s, key) < 0, "key-flipped record never served");
    brix_cas_destroy(&s);
}

/* ---- G5 tiering ----------------------------------------------------------- */

static void test_tiering(const char *root) {
    brix_cas_store_t s;
    unsigned char    body[16384];
    char             key[64];

    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (unsigned char) ("tier-tier-tier-!"[i % 16]);
    obj_key(300, key, sizeof(key));

    CHECK(brix_cas_init_packed(&s, root, 0, 1 << 20, 1) == 0, "init tiering");
    CHECK(brix_cas_put(&s, key, body, sizeof(body)) == 0, "tier put");
    CHECK(brix_cas_size(&s) < (long) sizeof(body), "cold object stored packed");
    long cold = brix_cas_size(&s);

    for (int i = 0; i < BRIX_PACK_PROMOTE_HITS; i++)
        CHECK(get_matches(&s, key, body, sizeof(body)),
              "byte-identical while cold + across promotion");
    CHECK(brix_cas_size(&s) > cold, "hot object promoted to raw");
    CHECK(get_matches(&s, key, body, sizeof(body)), "byte-identical when hot");
    brix_cas_destroy(&s);

    /* promotion survives replay */
    CHECK(brix_cas_init_packed(&s, root, 0, 1 << 20, 1) == 0, "reopen tiering");
    CHECK(get_matches(&s, key, body, sizeof(body)), "hot object after replay");

    /* incompressible bytes stay raw even with tiering on */
    unsigned char rnd[4096];
    unsigned x = 88172645u;
    for (size_t i = 0; i < sizeof(rnd); i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        rnd[i] = (unsigned char) x;
    }
    char rkey[64];
    obj_key(301, rkey, sizeof(rkey));
    long before = brix_cas_size(&s);
    CHECK(brix_cas_put(&s, rkey, rnd, sizeof(rnd)) == 0, "random put");
    CHECK(brix_cas_size(&s) == before + (long) sizeof(rnd),
          "incompressible stays raw");
    CHECK(get_matches(&s, rkey, rnd, sizeof(rnd)), "random byte-identical");
    brix_cas_destroy(&s);
}

/* ---- quota / whole-segment eviction --------------------------------------- */

static void test_quota(const char *root) {
    brix_cas_store_t s;
    unsigned char    body[4096];
    char             key[64];

    CHECK(brix_cas_init_packed(&s, root, 20000, 8192, 0) == 0, "init quota");
    for (int i = 0; i < 12; i++) {                       /* 12 * 3KiB > quota */
        memset(body, 'q' + i, sizeof(body));
        obj_key(400 + i, key, sizeof(key));
        CHECK(brix_cas_put(&s, key, body, 3072) == 0, "quota put");
    }
    CHECK(brix_cas_size(&s) <= 20000, "quota enforced");
    obj_key(400 + 11, key, sizeof(key));
    CHECK(brix_cas_has(&s, key) == 1, "newest survives eviction");
    obj_key(400, key, sizeof(key));
    CHECK(brix_cas_has(&s, key) == 0, "oldest segment dropped");
    brix_cas_destroy(&s);

    /* eviction rewrote a compact journal: reopen agrees */
    CHECK(brix_cas_init_packed(&s, root, 20000, 8192, 0) == 0, "reopen quota");
    obj_key(400 + 11, key, sizeof(key));
    memset(body, 'q' + 11, sizeof(body));
    CHECK(get_matches(&s, key, body, 3072), "compacted journal replays");
    brix_cas_destroy(&s);
}

int main(void) {
    char tmpl[5][64];
    const char *names[5] = { "success", "recovery", "secneg", "tier", "quota" };
    void (*tests[5])(const char *) = { test_success, test_recovery, test_secneg,
                                       test_tiering, test_quota };
    for (int i = 0; i < 5; i++) {
        snprintf(tmpl[i], sizeof(tmpl[i]), "/tmp/cas_pack_ut.%s.XXXXXX", names[i]);
        if (mkdtemp(tmpl[i]) == NULL) { perror("mkdtemp"); return 2; }
        tests[i](tmpl[i]);
        char rm[128];
        snprintf(rm, sizeof(rm), "rm -rf '%s'", tmpl[i]);
        if (system(rm) != 0) fprintf(stderr, "cleanup failed: %s\n", tmpl[i]);
    }
    if (g_fail) { fprintf(stderr, "%d failure(s)\n", g_fail); return 1; }
    printf("cas_pack unit: all green\n");
    return 0;
}
