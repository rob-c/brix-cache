/*
 * codec_test.c — standalone unit test for the shared codec abstraction
 * (src/core/compat/codec_core.c + codec_<name>.c). Builds ngx-free.
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra -Isrc/core/compat -DBRIX_HAVE_ZLIB -DBRIX_HAVE_ZSTD \
 *      -DBRIX_HAVE_LZMA -DBRIX_HAVE_BROTLI -DBRIX_HAVE_BZIP2 \
 *      tests/c/codec_test.c src/core/compat/codec_core.c src/core/compat/codec_zlib.c \
 *      src/core/compat/codec_zstd.c src/core/compat/codec_lzma.c src/core/compat/codec_brotli.c \
 *      src/core/compat/codec_bzip2.c -lz -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 \
 *      -o /tmp/codec_test && /tmp/codec_test
 *
 * Covers: round-trip every available codec under many sizes + tiny streaming
 * buffers (forces the output-full / more-input loops); the decompression-bomb
 * guard; descriptor lookups; identity passthrough; corrupt-input rejection.
 */

#include "codec_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail = 1; } } while (0)

/* Canonical streaming driver honouring the codec_core contract. Feeds input in
 * `in_chunk` slices and drains into a `out_chunk`-sized buffer, so small values
 * stress the "output full" / "need more input" paths. Returns rc (0 on END). */
static int
run_codec(brix_codec_id_t id, brix_codec_dir_t dir,
          const uint8_t *in, size_t in_len, const brix_codec_guard_t *g,
          uint8_t **outp, size_t *outlenp, size_t in_chunk, size_t out_chunk)
{
    brix_codec_stream_t *s = brix_codec_open(id, dir, -1, g);
    uint8_t *out = NULL, *tmp;
    size_t   outcap = 0, outlen = 0, fed = 0;
    long     budget;
    int      ret = -100, done = 0;

    if (s == NULL) { return -100; }
    tmp = malloc(out_chunk ? out_chunk : 1);
    if (in_chunk == 0)  { in_chunk = 1; }
    if (out_chunk == 0) { out_chunk = 1; }
    budget = (long) (in_len * 4 + 1000000);   /* anti-spin cap */

    while (!done) {
        size_t seg_end = fed + in_chunk;
        int    finish;
        size_t ip;

        if (seg_end > in_len) { seg_end = in_len; }
        finish = (seg_end == in_len);
        ip = fed;
        for (;;) {
            size_t            op = 0;
            brix_codec_rc_t rc;

            if (--budget < 0) { ret = -200; done = 1; break; }
            rc = brix_codec_step(s, in, seg_end, &ip, tmp, out_chunk, &op, finish);
            if (rc < 0) { ret = (int) rc; done = 1; break; }
            if (op) {
                if (outlen + op > outcap) {
                    outcap = (outlen + op) * 2 + 64;
                    out = realloc(out, outcap);
                }
                memcpy(out + outlen, tmp, op);
                outlen += op;
            }
            if (rc == BRIX_CODEC_END) { ret = 0; done = 1; break; }
            if (op == out_chunk) { continue; }   /* output buffer was full: drain more */
            if (ip < seg_end)    { continue; }   /* input remains in this segment   */
            break;                               /* segment consumed; advance        */
        }
        fed = seg_end;
        /* When finish=1 and not yet END, the outer loop re-enters with the same
         * seg_end and keeps flushing until END (budget guards against a stuck backend). */
    }

    if (ret == 0) { *outp = out; *outlenp = outlen; }
    else          { free(out); }
    free(tmp);
    brix_codec_close(s);
    return ret;
}

static void
fill_pattern(uint8_t *b, size_t n, unsigned seed)
{
    size_t i;
    unsigned x = seed * 2654435761u + 1;
    for (i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        /* Mix of structured + pseudo-random so codecs actually have work to do. */
        b[i] = (uint8_t) ((i & 0x3f) ^ (x >> 16));
    }
}

static void
roundtrip_one(brix_codec_id_t id, const char *name, size_t n,
              size_t in_chunk, size_t out_chunk)
{
    uint8_t *orig = malloc(n ? n : 1);
    uint8_t *comp = NULL, *plain = NULL;
    size_t   complen = 0, plainlen = 0;
    int      rc;

    fill_pattern(orig, n, (unsigned) (n + in_chunk));

    rc = run_codec(id, BRIX_CODEC_DIR_COMPRESS, orig, n, NULL,
                   &comp, &complen, in_chunk, out_chunk);
    CHECK(rc == 0, "%s compress n=%zu ic=%zu oc=%zu rc=%d", name, n, in_chunk, out_chunk, rc);
    if (rc != 0) { free(orig); return; }

    rc = run_codec(id, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, NULL,
                   &plain, &plainlen, out_chunk, in_chunk);
    CHECK(rc == 0, "%s decompress n=%zu rc=%d", name, n, rc);
    if (rc == 0) {
        CHECK(plainlen == n, "%s len mismatch n=%zu got=%zu", name, n, plainlen);
        CHECK(plainlen == n && memcmp(orig, plain, n) == 0,
              "%s byte mismatch n=%zu", name, n);
    }
    free(orig); free(comp); free(plain);
}

static void
test_codec(brix_codec_id_t id, const char *name)
{
    static const size_t sizes[]  = { 0, 1, 7, 100, 4095, 4096, 4097, 65536, 250000 };
    static const size_t chunks[] = { 5, 64, 4096, 1 << 20 };
    size_t si, ci;

    if (!brix_codec_available(id)) {
        printf("  SKIP %s (not built in)\n", name);
        return;
    }
    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        for (ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++) {
            roundtrip_one(id, name, sizes[si], chunks[ci], chunks[ci]);
        }
    }
    printf("  ok   %s round-trip (9 sizes x 4 chunk-sizes)\n", name);
}

static void
test_bomb_guard(void)
{
    size_t   n = 8u * 1024u * 1024u;             /* 8 MiB of zeros: ~1000:1 ratio */
    uint8_t *zeros = calloc(n, 1);
    uint8_t *comp = NULL, *plain = NULL;
    size_t   complen = 0, plainlen = 0;
    brix_codec_guard_t g;
    int      rc;

    if (!brix_codec_available(BRIX_CODEC_GZIP)) { free(zeros); return; }
    rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_COMPRESS, zeros, n, NULL,
                   &comp, &complen, 1 << 16, 1 << 16);
    CHECK(rc == 0, "bomb setup compress rc=%d", rc);

    /* out_cap below the true output (8 MiB) must trip the guard. */
    memset(&g, 0, sizeof(g));
    g.out_cap = 1u * 1024u * 1024u;
    rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                   &plain, &plainlen, 1 << 16, 1 << 16);
    CHECK(rc == BRIX_CODEC_ERR_BOMB, "bomb out_cap guard rc=%d (want %d)",
          rc, BRIX_CODEC_ERR_BOMB);
    free(plain); plain = NULL;

    /* ratio guard: cap ratio at 10 — 1000:1 zeros must trip it. */
    memset(&g, 0, sizeof(g));
    g.max_ratio = 10;
    rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                   &plain, &plainlen, 1 << 16, 1 << 16);
    CHECK(rc == BRIX_CODEC_ERR_BOMB, "bomb ratio guard rc=%d", rc);
    free(plain);

    /* a generous cap must NOT trip. */
    memset(&g, 0, sizeof(g));
    g.out_cap = 16u * 1024u * 1024u; g.max_ratio = 100000;
    plain = NULL; plainlen = 0;
    rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                   &plain, &plainlen, 1 << 16, 1 << 16);
    CHECK(rc == 0 && plainlen == n, "bomb generous cap rc=%d len=%zu", rc, plainlen);
    free(plain); free(comp); free(zeros);
    printf("  ok   bomb guard (out_cap + ratio trip; generous passes)\n");
}

static void
test_lookups(void)
{
    CHECK(brix_codec_by_http_token("br", 2) != NULL
          && brix_codec_by_http_token("br", 2)->id == BRIX_CODEC_BROTLI, "token br");
    CHECK(brix_codec_by_http_token("gzip", 4)->id == BRIX_CODEC_GZIP, "token gzip");
    CHECK(brix_codec_by_name("zstd", 4)->id == BRIX_CODEC_ZSTD, "name zstd");
    CHECK(brix_codec_by_name("xz", 2)->id == BRIX_CODEC_XZ, "name xz");
    CHECK(brix_codec_by_http_token("lzip", 4) == NULL, "unknown token -> NULL");
    CHECK(brix_codec_by_name("gz", 2) == NULL, "partial name no match");
    CHECK(brix_codec_by_id(BRIX_CODEC_MAX) == NULL, "id bounds");
    printf("  ok   lookups\n");
}

static void
test_identity(void)
{
    uint8_t  in[1000], *out = NULL;
    size_t   outlen = 0;
    int      rc;

    fill_pattern(in, sizeof(in), 99);
    rc = run_codec(BRIX_CODEC_IDENTITY, BRIX_CODEC_DIR_COMPRESS, in, sizeof(in),
                   NULL, &out, &outlen, 7, 13);
    CHECK(rc == 0 && outlen == sizeof(in) && memcmp(in, out, sizeof(in)) == 0,
          "identity passthrough rc=%d len=%zu", rc, outlen);
    free(out);
    printf("  ok   identity passthrough\n");
}

static void
test_corrupt(void)
{
    uint8_t  in[20000], *comp = NULL, *plain = NULL;
    size_t   complen = 0, plainlen = 0;
    int      rc;

    if (!brix_codec_available(BRIX_CODEC_XZ)) { return; }
    fill_pattern(in, sizeof(in), 7);
    rc = run_codec(BRIX_CODEC_XZ, BRIX_CODEC_DIR_COMPRESS, in, sizeof(in), NULL,
                   &comp, &complen, 1 << 16, 1 << 16);
    CHECK(rc == 0 && complen > 40, "corrupt setup rc=%d", rc);
    if (rc == 0) {
        comp[complen / 2] ^= 0xff;            /* flip a byte mid-stream */
        comp[complen / 2 + 1] ^= 0xa5;
        rc = run_codec(BRIX_CODEC_XZ, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, NULL,
                       &plain, &plainlen, 1 << 16, 1 << 16);
        CHECK(rc == BRIX_CODEC_ERR_DATA, "corrupt xz -> ERR_DATA rc=%d", rc);
        free(plain);
    }
    free(comp);
    printf("  ok   corrupt-input rejection\n");
}

int
main(void)
{
    printf("== codec_core unit test ==\n");
    test_lookups();
    test_identity();
    test_codec(BRIX_CODEC_GZIP,   "gzip");
    test_codec(BRIX_CODEC_DEFLATE,"deflate");
    test_codec(BRIX_CODEC_ZSTD,   "zstd");
    test_codec(BRIX_CODEC_XZ,     "xz");
    test_codec(BRIX_CODEC_BROTLI, "brotli");
    test_codec(BRIX_CODEC_BZIP2,  "bzip2");
    test_codec(BRIX_CODEC_LZ4,    "lz4");
    test_bomb_guard();
    test_corrupt();
    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}
