/* bundle_unittest.c — standalone checks for the chunk-bundle frame codec.
 *
 * Build+run (no nginx, no network):
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/bundle_unit \
 *       shared/cvmfs/bundle/bundle.c shared/cvmfs/bundle/bundle_unittest.c \
 *       && /tmp/bundle_unit
 */
#include "cvmfs/bundle/bundle.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, what) do {                                    \
        if (cond) { printf("ok   %s\n", (what)); }                \
        else      { printf("FAIL %s\n", (what)); failures++; }    \
    } while (0)

/* Append one full member (header + data bytes) to buf; returns new length. */
static size_t emit(unsigned char *buf, size_t off, const char *path,
                   const unsigned char *data, uint64_t dlen) {
    int n = cvmfs_bundle_item_encode(buf + off, 4096, path, strlen(path),
                                     data != NULL ? dlen : CVMFS_BUNDLE_MISS);
    off += (size_t) n;
    if (data != NULL) {
        memcpy(buf + off, data, (size_t) dlen);
        off += (size_t) dlen;
    }
    return off;
}

/* WHAT: Check successful decoding of every supported member form.
 * WHY: Keep normal codec semantics distinct from corruption cases.
 * HOW: Walk the prepared four-member stream and validate each view. */
static void test_roundtrip(const unsigned char *stream, size_t len,
                           const unsigned char *payload_a) {
    cvmfs_bundle_iter_t  it;
    cvmfs_bundle_item_t  item;

    CHECK(cvmfs_bundle_iter_init(&it, stream, len) == 0, "iterator binds");
    CHECK(cvmfs_bundle_next(&it, &item) == 1 && !item.miss
          && item.path_len == 12 && memcmp(item.path, "data/ab/cd01", 12) == 0
          && item.data_len == 5 && memcmp(item.data, payload_a, 5) == 0,
          "member 1 decodes with its bytes");
    CHECK(cvmfs_bundle_next(&it, &item) == 1 && item.miss && item.data == NULL,
          "member 2 is the miss marker");
    CHECK(cvmfs_bundle_next(&it, &item) == 1 && !item.miss
          && item.data_len == 1 && item.data[0] == 0xff,
          "member 3 decodes");
    CHECK(cvmfs_bundle_next(&it, &item) == 1 && !item.miss && item.data_len == 0,
          "zero-length member decodes");
    CHECK(cvmfs_bundle_next(&it, &item) == 0, "clean end of stream");
}

/* WHAT: Check every truncated prefix is rejected.
 * WHY: Framing must never accept a partial member as complete.
 * HOW: Bind each prefix and drain it until the parser reports failure. */
static void test_truncations(const unsigned char *stream, size_t len) {
    size_t cut;
    int    sawbad = 0;

    for (cut = CVMFS_BUNDLE_HDR_LEN; cut < len; cut++) {
        cvmfs_bundle_iter_t tit;
        cvmfs_bundle_item_t titem;
        int rc = 1;

        if (cvmfs_bundle_iter_init(&tit, stream, cut) != 0) { sawbad++; continue; }
        while ((rc = cvmfs_bundle_next(&tit, &titem)) == 1) { /* drain */ }
        if (rc == -1) sawbad++;
    }
    CHECK((size_t) sawbad == len - CVMFS_BUNDLE_HDR_LEN,
          "every truncated prefix is rejected");
}

/* WHAT: Check hostile header and member lengths fail closed.
 * WHY: Untrusted lengths must not walk the parser outside its input.
 * HOW: Forge magic/count/path/data fields independently and parse each copy. */
static void test_forged_fields(const unsigned char *stream, size_t len) {
    cvmfs_bundle_iter_t it;
    cvmfs_bundle_item_t item;
    unsigned char       bad[64];

    CHECK(cvmfs_bundle_iter_init(&it, stream, 4) == -1, "short header rejected");
    memcpy(bad, stream, sizeof(bad));
    bad[0] = 'Z';
    CHECK(cvmfs_bundle_iter_init(&it, bad, len) == -1, "bad magic rejected");
    memcpy(bad, stream, sizeof(bad));
    cvmfs_bundle_put_u32(bad + 4, CVMFS_BUNDLE_MAX_ITEMS + 1);
    CHECK(cvmfs_bundle_iter_init(&it, bad, len) == -1,
          "item count over cap rejected");
    memcpy(bad, stream, sizeof(bad));
    cvmfs_bundle_put_u32(bad + CVMFS_BUNDLE_HDR_LEN, 0x7fffffffu);
    CHECK(cvmfs_bundle_iter_init(&it, bad, len) == 0
          && cvmfs_bundle_next(&it, &item) == -1,
          "forged oversize path_len rejected");
    memcpy(bad, stream, sizeof(bad));
    cvmfs_bundle_put_u64(bad + CVMFS_BUNDLE_HDR_LEN + 4 + 12,
                         (uint64_t) CVMFS_BUNDLE_MAX_OBJ + 1);
    CHECK(cvmfs_bundle_iter_init(&it, bad, len) == 0
          && cvmfs_bundle_next(&it, &item) == -1,
          "member over per-object cap rejected");
}

/* WHAT: Check garbage after declared members is rejected.
 * WHY: Trailing bytes otherwise create ambiguous framing.
 * HOW: Append one byte, drain declared members, and require a parser error. */
static void test_trailing(const unsigned char *stream, size_t len) {
    unsigned char       tg[4096];
    cvmfs_bundle_iter_t it;
    cvmfs_bundle_item_t item;

    memcpy(tg, stream, len);
    tg[len] = 0x00;
    CHECK(cvmfs_bundle_iter_init(&it, tg, len + 1) == 0, "tg iter binds");
    while ((cvmfs_bundle_next(&it, &item)) == 1) { /* drain members */ }
    CHECK(it.remaining == 0 && cvmfs_bundle_next(&it, &item) == -1,
          "trailing garbage rejected");
}

/* WHAT: Check encoder bounds mirror parser bounds.
 * WHY: Producers must not emit frames consumers are required to reject.
 * HOW: Attempt oversized path, short buffer, and empty path encodes. */
static void test_encoder_bounds(void) {
    static char   longpath[CVMFS_BUNDLE_MAX_PATH + 2];
    unsigned char out[1024];

    memset(longpath, 'a', sizeof(longpath) - 1);
    CHECK(cvmfs_bundle_item_encode(out, sizeof(out), longpath,
                                   sizeof(longpath) - 1, 0) == -1,
          "encoder refuses oversize path");
    CHECK(cvmfs_bundle_item_encode(out, 4, "data/ab/cd", 10, 0) == -1,
          "encoder refuses short output buffer");
    CHECK(cvmfs_bundle_item_encode(out, sizeof(out), "x", 0, 0) == -1,
          "encoder refuses empty path");
}

int main(void) {
    static unsigned char stream[8192];
    unsigned char        payload_a[5] = { 1, 2, 3, 4, 5 };
    unsigned char        payload_b[1] = { 0xff };
    size_t               len;

    cvmfs_bundle_hdr_encode(stream, 4);
    len = CVMFS_BUNDLE_HDR_LEN;
    len = emit(stream, len, "data/ab/cd01", payload_a, sizeof(payload_a));
    len = emit(stream, len, "data/ab/cd02", NULL, 0);
    len = emit(stream, len, "data/ab/cd03", payload_b, sizeof(payload_b));
    len = emit(stream, len, "data/ab/cd04", payload_a, 0);
    test_roundtrip(stream, len, payload_a);
    test_truncations(stream, len);
    test_forged_fields(stream, len);
    test_trailing(stream, len);
    test_encoder_bounds();

    printf("%s: %d failure(s)\n", failures ? "BUNDLE-UNIT-FAIL" : "BUNDLE-UNIT-OK",
           failures);
    return failures ? 1 : 0;
}
