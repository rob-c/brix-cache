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

int main(void) {
    static unsigned char stream[8192];
    unsigned char        payload_a[5] = { 1, 2, 3, 4, 5 };
    unsigned char        payload_b[1] = { 0xff };
    size_t               len;
    cvmfs_bundle_iter_t  it;
    cvmfs_bundle_item_t  item;

    /* ---- success: 4-member roundtrip (data, miss, data, zero-length) ---- */
    cvmfs_bundle_hdr_encode(stream, 4);
    len = CVMFS_BUNDLE_HDR_LEN;
    len = emit(stream, len, "data/ab/cd01", payload_a, sizeof(payload_a));
    len = emit(stream, len, "data/ab/cd02", NULL, 0);
    len = emit(stream, len, "data/ab/cd03", payload_b, sizeof(payload_b));
    len = emit(stream, len, "data/ab/cd04", payload_a, 0);

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

    /* ---- error: truncations at every seam are fail-closed ---- */
    {
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
    CHECK(cvmfs_bundle_iter_init(&it, stream, 4) == -1, "short header rejected");

    /* ---- security-negative: forged fields cannot walk the parser out ---- */
    {
        unsigned char bad[64];

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
        /* member 1 data_len forged huge (but not the miss marker) */
        cvmfs_bundle_put_u64(bad + CVMFS_BUNDLE_HDR_LEN + 4 + 12,
                             (uint64_t) CVMFS_BUNDLE_MAX_OBJ + 1);
        CHECK(cvmfs_bundle_iter_init(&it, bad, len) == 0
              && cvmfs_bundle_next(&it, &item) == -1,
              "member over per-object cap rejected");
    }

    /* trailing garbage after the declared members is malformed, not ignored */
    {
        unsigned char tg[4096];

        memcpy(tg, stream, len);
        tg[len] = 0x00;
        CHECK(cvmfs_bundle_iter_init(&it, tg, len + 1) == 0, "tg iter binds");
        while ((cvmfs_bundle_next(&it, &item)) == 1) { /* drain members */ }
        CHECK(it.remaining == 0 && cvmfs_bundle_next(&it, &item) == -1,
              "trailing garbage rejected");
    }

    /* encoder refuses what the parser would refuse */
    {
        static char longpath[CVMFS_BUNDLE_MAX_PATH + 2];
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

    printf("%s: %d failure(s)\n", failures ? "BUNDLE-UNIT-FAIL" : "BUNDLE-UNIT-OK",
           failures);
    return failures ? 1 : 0;
}
