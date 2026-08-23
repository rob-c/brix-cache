/* dict_unittest.c — standalone checks for the trained-dictionary codec (G3).
 *
 * Proves the phase-87 G3 success contract at the codec layer: on a corpus of
 * small SIMILAR files a trained dict beats dictless zstd (the live labs store
 * zlib-compressed CAS blobs, where no wire codec can win — the ratio claim
 * belongs here, on raw small-file bytes).
 *
 * Build+run (no nginx, no network):
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/dict_unit \
 *       shared/cvmfs/dict/dict.c shared/cvmfs/object/object.c \
 *       shared/cvmfs/grammar/hash.c shared/cvmfs/dict/dict_unittest.c \
 *       -lzstd -lcrypto -lz && /tmp/dict_unit
 */
#include "cvmfs/dict/dict.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, what) do {                                    \
        if (cond) { printf("ok   %s\n", (what)); }                \
        else      { printf("FAIL %s\n", (what)); failures++; }    \
    } while (0)

/* A deterministic corpus of small similar "config file" samples: a shared
 * boilerplate skeleton with per-sample varying fields — exactly the shape
 * (headers/.py/small .so metadata) G3 targets. */
#define NSAMPLES 96
#define SAMPLE_CAP 2048

static size_t make_sample(unsigned i, char *out) {
    return (size_t) snprintf(out, SAMPLE_CAP,
        "# package manifest v1 — generated, do not edit\n"
        "[package]\nname = experiment-module-%u\nversion = 4.%u.%u\n"
        "arch = x86_64-el9-gcc13-opt\nlicense = Apache-2.0\n"
        "[dependencies]\nlibcore = >= 2.14\nlibio = >= 1.%u\n"
        "libmath = >= 3.7\npython = >= 3.9\n"
        "[environment]\nPATH = ${PKG_ROOT}/bin:${PATH}\n"
        "LD_LIBRARY_PATH = ${PKG_ROOT}/lib64:${LD_LIBRARY_PATH}\n"
        "PYTHONPATH = ${PKG_ROOT}/lib/python3.9/site-packages\n"
        "[checksums]\nbin/tool%u = adler32:%08x\nlib64/libmod%u.so = adler32:%08x\n",
        i, i % 10, i * 7 % 100, i % 5, i, i * 2654435761u, i, i * 40503u);
}

/* WHAT: Round-trip the corpus and accumulate dictionary/no-dictionary sizes.
 * WHY: Isolate the streaming comparison from training and negative tests.
 * HOW: Compress/decompress every packed sample, compare bytes, then compress
 *      without a dictionary and return failure at the first codec defect. */
static int roundtrip_corpus(const char *samples, const size_t *sizes,
                            const unsigned char *dict, size_t dictlen,
                            unsigned char *wire, size_t wire_cap,
                            unsigned char *back, size_t back_cap,
                            size_t *with_dict, size_t *without_dict) {
    size_t off = 0;

    for (unsigned i = 0; i < NSAMPLES; i++) {
        size_t n, m;

        if (cvmfs_dict_compress(dict, dictlen,
                                (const unsigned char *) samples + off, sizes[i],
                                wire, wire_cap, &n) != 0
            || cvmfs_dict_decompress(dict, dictlen, wire, n,
                                     back, back_cap, &m) != 0
            || m != sizes[i] || memcmp(back, samples + off, m) != 0)
        {
            return -1;
        }
        *with_dict += n;
        if (cvmfs_dict_compress(NULL, 0,
                                (const unsigned char *) samples + off, sizes[i],
                                wire, wire_cap, &n) != 0)
        {
            return -1;
        }
        *without_dict += n;
        off += sizes[i];
    }
    return 0;
}

int main(void) {
    static char   samples[NSAMPLES * SAMPLE_CAP];
    static size_t sizes[NSAMPLES];
    static unsigned char dict[CVMFS_DICT_TARGET_BYTES];
    static unsigned char dict2[CVMFS_DICT_TARGET_BYTES];
    static unsigned char wire[SAMPLE_CAP * 2], back[SAMPLE_CAP * 2];
    size_t dictlen = 0, dict2len = 0, n, m;
    char   id[CVMFS_DICT_ID_HEXLEN + 1], id2[CVMFS_DICT_ID_HEXLEN + 1];
    size_t off = 0, with_dict = 0, without_dict = 0;
    unsigned i;

    /* samples packed back-to-back — ZDICT wants one contiguous buffer */
    for (i = 0; i < NSAMPLES; i++) {
        char tmp[SAMPLE_CAP];
        sizes[i] = make_sample(i, tmp);
        memcpy(samples + off, tmp, sizes[i]);
        off += sizes[i];
    }

    /* ---- success: training + self-certifying identity ---- */
    CHECK(cvmfs_dict_train(samples, sizes, NSAMPLES,
                           dict, sizeof(dict), &dictlen) == 0 && dictlen > 0,
          "dict trains on a small-file corpus");
    CHECK(cvmfs_dict_id(dict, dictlen, id) == 0
          && strlen(id) == CVMFS_DICT_ID_HEXLEN
          && strspn(id, "0123456789abcdef") == CVMFS_DICT_ID_HEXLEN,
          "dict id is 40 lowercase hex");
    CHECK(cvmfs_dict_id(dict, dictlen, id2) == 0 && strcmp(id, id2) == 0,
          "dict id is deterministic");

    /* ---- success: exact roundtrip + trained-beats-dictless ratio ---- */
    CHECK(roundtrip_corpus(samples, sizes, dict, dictlen, wire, sizeof(wire),
                           back, sizeof(back), &with_dict, &without_dict) == 0,
          "every sample roundtrips exactly through the dict");
    CHECK(with_dict < without_dict,
          "trained dict beats dictless zstd on the corpus");

    /* ---- security-neg: a frame is bound to ITS dict ---- */
    {
        /* a second dict trained on a disjoint corpus (different template) */
        static char   s2[NSAMPLES * SAMPLE_CAP];
        static size_t z2[NSAMPLES];
        off = 0;
        for (i = 0; i < NSAMPLES; i++) {
            z2[i] = (size_t) snprintf(s2 + off, SAMPLE_CAP,
                "<xml row='%u'><entry key='k%u' val='%u'/>"
                "<blob enc='b64'>QUJDREVGR0hJSktMTU5PUA==</blob></xml>\n",
                i, i * 3, i * 31);
            off += z2[i];
        }
        CHECK(cvmfs_dict_train(s2, z2, NSAMPLES,
                               dict2, sizeof(dict2), &dict2len) == 0,
              "second (foreign) dict trains");
        CHECK(cvmfs_dict_compress(dict, dictlen,
                                  (unsigned char *) samples, sizes[0],
                                  wire, sizeof(wire), &n) == 0
              && cvmfs_dict_decompress(dict2, dict2len, wire, n,
                                       back, sizeof(back), &m) != 0,
              "decode with the wrong dict FAILS (dictID mismatch), never garbage");
    }

    /* ---- error: output overflow + degenerate corpus are clean -1s ---- */
    CHECK(cvmfs_dict_compress(dict, dictlen, (unsigned char *) samples,
                              sizes[0], wire, 4, &n) != 0,
          "undersized compress output is a clean failure");
    {
        size_t one = 3;
        CHECK(cvmfs_dict_train("abc", &one, 1, dict2, sizeof(dict2),
                               &dict2len) != 0,
              "degenerate 1-sample corpus refuses to train");
    }

    printf("DICT-UNIT %s: %d failure(s)\n", failures ? "FAIL" : "OK", failures);
    return failures ? 1 : 0;
}
