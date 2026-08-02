/*
 * xorf_unittest.c — test of the G1 negative-lookup xor filter: builds a filter
 * over a synthetic 50k-path set and proves (success) zero false negatives +
 * a sane false-positive rate + round-trip serialize/deserialize with root-hash
 * binding; (error) geometry/truncation defects are refused; (security-neg) a
 * bit-flipped serialized image fails its checksum and is rejected — a tampered
 * filter can never fabricate an ENOENT.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_xorf_ut \
 *       shared/cvmfs/filter/xorf_unittest.c shared/cvmfs/filter/xorf.c \
 *       shared/cvmfs/grammar/hash.c && /tmp/cvmfs_xorf_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/filter/xorf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

#define NPATHS 50000

static void member_path(char *buf, size_t cap, int i) {
    snprintf(buf, cap, "/sw/pkg%d/lib/libfoo.so.%d", i % 977, i);
}

static void absent_path(char *buf, size_t cap, int i) {
    snprintf(buf, cap, "/sw/pkg%d/include/missing-%d.h", i % 977, i);
}

int main(void) {
    char path[128];
    uint64_t *keys = malloc((NPATHS + 1) * sizeof(*keys));
    if (keys == NULL) { perror("malloc"); return 2; }
    for (int i = 0; i < NPATHS; i++) {
        member_path(path, sizeof(path), i);
        keys[i] = cvmfs_xorf_key(path);
    }
    /* duplicates must be tolerated (dir paths repeat across a walk) */
    keys[NPATHS] = keys[0];

    cvmfs_xorf_t f;
    CHECK(cvmfs_xorf_build(&f, keys, NPATHS + 1) == 0, "build over 50k keys succeeds");
    CHECK(f.nkeys == NPATHS, "duplicate key deduped");

    /* ---- success: no false negatives, sane false-positive rate ---------- */
    int fneg = 0;
    for (int i = 0; i < NPATHS; i++) {
        member_path(path, sizeof(path), i);
        if (!cvmfs_xorf_query(&f, cvmfs_xorf_key(path))) fneg++;
    }
    CHECK(fneg == 0, "zero false negatives over the member set");

    int fpos = 0;
    for (int i = 0; i < NPATHS; i++) {
        absent_path(path, sizeof(path), i);
        if (cvmfs_xorf_query(&f, cvmfs_xorf_key(path))) fpos++;
    }
    /* expectation ~n/256 ≈ 195; 3x headroom keeps the check deterministic-safe */
    CHECK(fpos > 0 && fpos < 3 * NPATHS / 256, "false-positive rate ~1/256");

    /* ---- round-trip with root-hash binding ------------------------------ */
    cvmfs_hash_t root, root2;
    unsigned char digest[20];
    for (int i = 0; i < 20; i++) digest[i] = (unsigned char) (i * 7 + 3);
    cvmfs_hash_from_bytes(CVMFS_HASH_SHA1, digest, 20, &root);

    size_t cap = cvmfs_xorf_size(&f);
    unsigned char *img = malloc(cap);
    size_t ilen = 0;
    CHECK(img != NULL && cvmfs_xorf_serialize(&f, &root, img, cap, &ilen) == 0
          && ilen == cap, "serialize fills exactly the declared size");
    CHECK(cvmfs_xorf_serialize(&f, &root, img, cap - 1, &ilen) == -1,
          "serialize into a short buffer is refused");            /* error */

    cvmfs_xorf_t g;
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen) == 0
          && cvmfs_hash_eq(&root, &root2)
          && g.seed == f.seed && g.block_len == f.block_len && g.nkeys == f.nkeys
          && memcmp(g.fp, f.fp, 3 * f.block_len) == 0,
          "deserialize round-trips the filter + bound root hash");

    member_path(path, sizeof(path), 4242);
    CHECK(cvmfs_xorf_query(&g, cvmfs_xorf_key(path)) == 1,
          "deserialized filter answers like the original");
    cvmfs_xorf_reset(&g);

    /* ---- error: structural defects refused ------------------------------ */
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen - 1) == -1,
          "truncated image refused");
    unsigned char tiny[16] = "BXF1";
    CHECK(cvmfs_xorf_deserialize(&g, &root2, tiny, sizeof(tiny)) == -1,
          "undersized image refused");
    img[0] ^= 0x20;
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen) == -1, "bad magic refused");
    img[0] ^= 0x20;

    /* ---- security-neg: bit-flipped image fails its checksum -------------- */
    img[CVMFS_XORF_HEADER_LEN + f.block_len] ^= 0x01;   /* flip one fingerprint */
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen) == -1,
          "tampered fingerprint array rejected by checksum");     /* security-neg */
    img[CVMFS_XORF_HEADER_LEN + f.block_len] ^= 0x01;
    img[24] ^= 0x80;                                    /* flip the bound root */
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen) == -1,
          "tampered root-hash binding rejected by checksum");     /* security-neg */
    img[24] ^= 0x80;
    CHECK(cvmfs_xorf_deserialize(&g, &root2, img, ilen) == 0,
          "untampered image still accepted after the probes");
    cvmfs_xorf_reset(&g);

    /* ---- edge: empty set builds and stays safe --------------------------- */
    cvmfs_xorf_t e;
    CHECK(cvmfs_xorf_build(&e, keys, 0) == 0, "empty-set build succeeds");
    CHECK(cvmfs_xorf_query(&e, 12345) == 0 || cvmfs_xorf_query(&e, 12345) == 1,
          "empty-set query returns a boolean");
    cvmfs_xorf_reset(&e);

    /* unbuilt filter must fail open (maybe-present), never fabricate ENOENT */
    cvmfs_xorf_t z; memset(&z, 0, sizeof(z));
    CHECK(cvmfs_xorf_query(&z, 1) == 1, "empty struct fails open to maybe-present");

    free(img);
    cvmfs_xorf_reset(&f);
    free(keys);

    printf("xorf unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
