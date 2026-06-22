/*
 * codec_nolib_test.c — phase-42 build-matrix: graceful degradation when an
 * optional codec library is ABSENT at compile time.
 *
 * WHAT: Builds the codec kernel (codec_core.c) with the mandatory zlib backend
 *       compiled in (-DXROOTD_HAVE_ZLIB, -lz) but EVERY optional backend
 *       (zstd/xz/brotli/bzip2/lz4) compiled WITHOUT its -DXROOTD_HAVE_* macro —
 *       i.e. as its `available = 0` stub, linking none of those libraries.  This
 *       reproduces a minimal build host where only zlib is present.
 *
 * WHY:  The whole compile-gating contract (codec_core.h) is: an absent library
 *       leaves a descriptor with available=0 so the dispatch table never has a
 *       hole and the server degrades that codec to plaintext / rejects it cleanly
 *       instead of crashing or failing to link.  Five codecs × a build matrix is
 *       exactly the risk the plan calls out ("graceful-degrade must be tested with
 *       libs absent"); this test makes that matrix a single deterministic binary.
 *
 * HOW:  The runner compiles this TU together with codec_core.c + each codec_*.c,
 *       choosing the -D flags per file (see run_compression_tests.sh).  We then
 *       assert: zlib codecs live, optional codecs report unavailable, open()
 *       returns NULL for them, the descriptor table still resolves them by
 *       id/name/token (dense, no holes), and a gzip round-trip still works.
 */

#include "codec_core.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "  FAIL: %s\n", (msg));                             \
            failures++;                                                         \
        }                                                                       \
    } while (0)

/* The optional (compile-gated) codecs — all expected ABSENT in this build. */
static const struct {
    xrootd_codec_id_t  id;
    const char        *name;
    const char        *token;
} optional_codecs[] = {
    { XROOTD_CODEC_ZSTD,   "zstd",  "zstd"  },
    { XROOTD_CODEC_BROTLI, "brotli", "br"   },
    { XROOTD_CODEC_XZ,     "xz",    "xz"    },
    { XROOTD_CODEC_BZIP2,  "bzip2", "bzip2" },
    { XROOTD_CODEC_LZ4,    "lz4",   "lz4"   },
};

/* Drive a full compress->decompress round-trip through one codec id; returns 1
 * iff the output equals the input (used to prove the live zlib path works). */
static int
roundtrip_ok(xrootd_codec_id_t id)
{
    static const char     plain[] =
        "the quick brown fox jumps over the lazy dog 0123456789 "
        "the quick brown fox jumps over the lazy dog 0123456789";
    uint8_t                comp[512];
    uint8_t                back[512];
    xrootd_codec_stream_t *cs, *ds;
    size_t                 in_pos, out_pos;
    xrootd_codec_rc_t      rc;
    size_t                 comp_len, back_len;

    cs = xrootd_codec_open(id, XROOTD_CODEC_DIR_COMPRESS, -1, NULL);
    if (cs == NULL) {
        return 0;
    }
    in_pos = 0; out_pos = 0;
    do {
        rc = xrootd_codec_step(cs, (const uint8_t *) plain, sizeof(plain) - 1,
                               &in_pos, comp, sizeof(comp), &out_pos, 1);
    } while (rc == XROOTD_CODEC_OK);
    xrootd_codec_close(cs);
    if (rc != XROOTD_CODEC_END) {
        return 0;
    }
    comp_len = out_pos;

    ds = xrootd_codec_open(id, XROOTD_CODEC_DIR_DECOMPRESS, -1, NULL);
    if (ds == NULL) {
        return 0;
    }
    in_pos = 0; out_pos = 0;
    do {
        rc = xrootd_codec_step(ds, comp, comp_len, &in_pos,
                               back, sizeof(back), &out_pos, 1);
    } while (rc == XROOTD_CODEC_OK);
    xrootd_codec_close(ds);
    if (rc != XROOTD_CODEC_END) {
        return 0;
    }
    back_len = out_pos;

    return back_len == sizeof(plain) - 1
        && memcmp(back, plain, back_len) == 0;
}

int
main(void)
{
    size_t i;

    /* IDENTITY is always available (passthrough). */
    CHECK(xrootd_codec_available(XROOTD_CODEC_IDENTITY),
          "IDENTITY must always be available");

    /* zlib is mandatory — gzip + deflate must be live and round-trip. */
    CHECK(xrootd_codec_available(XROOTD_CODEC_GZIP), "gzip must be available (zlib)");
    CHECK(xrootd_codec_available(XROOTD_CODEC_DEFLATE), "deflate must be available (zlib)");
    CHECK(roundtrip_ok(XROOTD_CODEC_GZIP), "gzip round-trip must work");
    CHECK(roundtrip_ok(XROOTD_CODEC_DEFLATE), "deflate round-trip must work");

    /* Every optional codec is ABSENT in this build: it must degrade, not crash. */
    for (i = 0; i < sizeof(optional_codecs) / sizeof(optional_codecs[0]); i++) {
        xrootd_codec_id_t          id = optional_codecs[i].id;
        const char                *nm = optional_codecs[i].name;
        const xrootd_codec_desc_t *d  = xrootd_codec_by_id(id);
        char                       buf[96];

        /* 1) descriptor is still present — the table has NO hole. */
        snprintf(buf, sizeof(buf), "%s descriptor must exist (no table hole)", nm);
        CHECK(d != NULL, buf);
        if (d == NULL) {
            continue;
        }

        /* 2) but it reports unavailable, with no backend wired. */
        snprintf(buf, sizeof(buf), "%s must report available=0", nm);
        CHECK(d->available == 0, buf);
        snprintf(buf, sizeof(buf), "%s must have NULL backend", nm);
        CHECK(d->backend == NULL, buf);
        snprintf(buf, sizeof(buf), "%s xrootd_codec_available() must be 0", nm);
        CHECK(xrootd_codec_available(id) == 0, buf);

        /* 3) name / token lookups STILL resolve to the (unavailable) descriptor:
         *    graceful degrade means a known codec is recognised, then declined —
         *    not silently mistaken for a different/unknown one. */
        snprintf(buf, sizeof(buf), "%s must resolve by_name", nm);
        CHECK(xrootd_codec_by_name(nm, strlen(nm)) == d, buf);
        snprintf(buf, sizeof(buf), "%s must resolve by_http_token", nm);
        CHECK(xrootd_codec_by_http_token(optional_codecs[i].token,
                                         strlen(optional_codecs[i].token)) == d, buf);

        /* 4) opening it (either direction) must fail cleanly with NULL — this is
         *    exactly what the server checks before taking the compressed path, so
         *    an absent codec falls back to plaintext / is rejected, never used. */
        snprintf(buf, sizeof(buf), "%s compress open must return NULL", nm);
        CHECK(xrootd_codec_open(id, XROOTD_CODEC_DIR_COMPRESS, -1, NULL) == NULL, buf);
        snprintf(buf, sizeof(buf), "%s decompress open must return NULL", nm);
        CHECK(xrootd_codec_open(id, XROOTD_CODEC_DIR_DECOMPRESS, -1, NULL) == NULL, buf);
    }

    if (failures == 0) {
        printf("== ALL PASSED == (zlib live; 5 optional codecs degrade cleanly)\n");
        return 0;
    }
    fprintf(stderr, "== %d CHECK(s) FAILED ==\n", failures);
    return 1;
}
