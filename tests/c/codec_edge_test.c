/*
 * codec_edge_test.c — edge/adversarial unit test for the shared codec kernel
 * (src/core/compat/codec_core.h API). Builds ngx-free, sibling to codec_test.c which
 * covers the happy-path round-trip matrix; this file deliberately attacks the
 * boundaries: lookups (mixed-case tokens / unknown), the dense descriptor table
 * (no holes), unavailable/out-of-range open, empty + 1-byte streams pumped a byte
 * at a time, the decompression-bomb guard (false-positive floor, true ratio trip,
 * absolute out_cap), and per-codec truncated-stream corruption.
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra -I src/core/compat tests/c/codec_edge_test.c \
 *      shared/xrdproto/libxrdproto.a \
 *      -lz -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 -lcrypto \
 *      -o /tmp/codec_edge_test && /tmp/codec_edge_test
 *
 * The harness mirrors codec_test.c: self-contained main(), CHECK() asserts that
 * print "FAIL:" + set a global, "ok ..." per passing case, "== ALL PASSED ==" /
 * "== FAILED ==" at the end, and exit status == failure count (nonzero on any
 * failure).
 */

#include "codec_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail = 1; } } while (0)

/*
 * Canonical streaming driver — identical contract to codec_test.c's run_codec:
 * feeds input in `in_chunk` slices, drains into an `out_chunk`-sized scratch
 * buffer (so in_chunk=out_chunk=1 stresses the "output full" / "need more input"
 * pump), enforces the same anti-spin budget, and returns rc (0 on END, negative
 * brix_codec_rc_t on error, -100 open failure, -200 budget exhausted).
 */
static int
run_codec(brix_codec_id_t id, brix_codec_dir_t dir,
          const uint8_t *in, size_t in_len, const brix_codec_guard_t *g,
          uint8_t **outp, size_t *outlenp, size_t in_chunk, size_t out_chunk)
{
    brix_codec_stream_t *s = brix_codec_open(id, dir, -1, g);
    uint8_t *out = NULL;
    size_t   outcap = 0, outlen = 0, fed = 0;
    long     budget;
    int      ret = -100, done = 0;

    if (s == NULL) { return -100; }
    if (in_chunk == 0)  { in_chunk = 1; }
    if (out_chunk == 0) { out_chunk = 1; }
    uint8_t *tmp = malloc(out_chunk);
    budget = (long) (in_len * 8 + 1000000);   /* anti-spin cap */

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
            if (op == out_chunk) { continue; }   /* output buffer full: drain more */
            if (ip < seg_end)    { continue; }   /* input remains in this segment   */
            break;                               /* segment consumed; advance        */
        }
        fed = seg_end;
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
        b[i] = (uint8_t) ((i & 0x3f) ^ (x >> 16));
    }
}

/* All non-identity codecs we exercise per-codec; identity is tested separately
 * where its passthrough semantics differ (e.g. it cannot "truncate-corrupt"). */
typedef struct { brix_codec_id_t id; const char *name; } codec_row_t;
static const codec_row_t kCodecs[] = {
    { BRIX_CODEC_GZIP,    "gzip"    },
    { BRIX_CODEC_DEFLATE, "deflate" },
    { BRIX_CODEC_ZSTD,    "zstd"    },
    { BRIX_CODEC_BROTLI,  "brotli"  },
    { BRIX_CODEC_XZ,      "xz"      },
    { BRIX_CODEC_BZIP2,   "bzip2"   },
    { BRIX_CODEC_LZ4,     "lz4"     },   /* phase-42 6th codec: in the edge matrix */
};
#define NCODECS (sizeof(kCodecs) / sizeof(kCodecs[0]))

/* ------------------------------------------------------------------ */
/* (1) lookups: by_id / by_name / by_http_token incl. mixed-case + unknown */
/* ------------------------------------------------------------------ */
static void
test_lookups(void)
{
    const brix_codec_desc_t *d;

    /* by_id for the canonical ids returns the matching descriptor. */
    CHECK((d = brix_codec_by_id(BRIX_CODEC_IDENTITY)) && d->id == BRIX_CODEC_IDENTITY,
          "by_id identity");
    CHECK((d = brix_codec_by_id(BRIX_CODEC_GZIP)) && d->id == BRIX_CODEC_GZIP, "by_id gzip");
    CHECK((d = brix_codec_by_id(BRIX_CODEC_BZIP2)) && d->id == BRIX_CODEC_BZIP2, "by_id bzip2");

    /* canonical names are matched EXACTLY (config values); these are lowercase. */
    CHECK((d = brix_codec_by_name("gzip", 4)) && d->id == BRIX_CODEC_GZIP, "name gzip");
    CHECK((d = brix_codec_by_name("deflate", 7)) && d->id == BRIX_CODEC_DEFLATE, "name deflate");
    CHECK((d = brix_codec_by_name("zstd", 4)) && d->id == BRIX_CODEC_ZSTD, "name zstd");
    CHECK((d = brix_codec_by_name("brotli", 6)) && d->id == BRIX_CODEC_BROTLI, "name brotli");
    CHECK((d = brix_codec_by_name("xz", 2)) && d->id == BRIX_CODEC_XZ, "name xz");
    CHECK((d = brix_codec_by_name("bzip2", 5)) && d->id == BRIX_CODEC_BZIP2, "name bzip2");
    CHECK((d = brix_codec_by_name("identity", 8)) && d->id == BRIX_CODEC_IDENTITY, "name identity");

    /* HTTP tokens are case-INSENSITIVE: mixed-case must still resolve. */
    CHECK((d = brix_codec_by_http_token("gzip", 4)) && d->id == BRIX_CODEC_GZIP, "token gzip");
    CHECK((d = brix_codec_by_http_token("GZiP", 4)) && d->id == BRIX_CODEC_GZIP, "token GZiP");
    CHECK((d = brix_codec_by_http_token("GZIP", 4)) && d->id == BRIX_CODEC_GZIP, "token GZIP");
    CHECK((d = brix_codec_by_http_token("br", 2)) && d->id == BRIX_CODEC_BROTLI, "token br");
    CHECK((d = brix_codec_by_http_token("Br", 2)) && d->id == BRIX_CODEC_BROTLI, "token Br");
    CHECK((d = brix_codec_by_http_token("BR", 2)) && d->id == BRIX_CODEC_BROTLI, "token BR");
    CHECK((d = brix_codec_by_http_token("xz", 2)) && d->id == BRIX_CODEC_XZ, "token xz");
    CHECK((d = brix_codec_by_http_token("XZ", 2)) && d->id == BRIX_CODEC_XZ, "token XZ");
    CHECK((d = brix_codec_by_http_token("bzip2", 5)) && d->id == BRIX_CODEC_BZIP2, "token bzip2");
    CHECK((d = brix_codec_by_http_token("BZip2", 5)) && d->id == BRIX_CODEC_BZIP2, "token BZip2");
    CHECK((d = brix_codec_by_http_token("zstd", 4)) && d->id == BRIX_CODEC_ZSTD, "token zstd");
    CHECK((d = brix_codec_by_http_token("ZSTD", 4)) && d->id == BRIX_CODEC_ZSTD, "token ZSTD");

    /* canonical-name lookup is case-SENSITIVE: uppercase must NOT match. */
    CHECK(brix_codec_by_name("GZIP", 4) == NULL, "name GZIP exact -> NULL");
    CHECK(brix_codec_by_name("Br", 2) == NULL, "name Br exact -> NULL");

    /* unknown tokens/names -> NULL. */
    CHECK(brix_codec_by_http_token("lzip", 4) == NULL, "token lzip -> NULL");
    CHECK(brix_codec_by_http_token("snappy", 6) == NULL, "token snappy -> NULL");
    CHECK(brix_codec_by_name("gz", 2) == NULL, "name gz partial -> NULL");
    CHECK(brix_codec_by_name("gzipx", 5) == NULL, "name gzipx (len mismatch) -> NULL");
    CHECK(brix_codec_by_http_token("g", 1) == NULL, "token g (prefix) -> NULL");

    /* degenerate args -> NULL (no crash). */
    CHECK(brix_codec_by_name(NULL, 0) == NULL, "name NULL -> NULL");
    CHECK(brix_codec_by_name("gzip", 0) == NULL, "name len0 -> NULL");
    CHECK(brix_codec_by_http_token(NULL, 4) == NULL, "token NULL -> NULL");
    CHECK(brix_codec_by_http_token("br", 0) == NULL, "token len0 -> NULL");

    printf("  ok   lookups (by_id/name/token, mixed-case, unknown, degenerate)\n");
}

/* ------------------------------------------------------------------ */
/* (2) availability + dense table: by_id non-NULL for EVERY id 0..MAX-1 */
/* ------------------------------------------------------------------ */
static void
test_table_dense(void)
{
    int i;

    for (i = 0; i < BRIX_CODEC_MAX; i++) {
        const brix_codec_desc_t *d = brix_codec_by_id((brix_codec_id_t) i);
        CHECK(d != NULL, "table hole at id=%d (by_id returned NULL)", i);
        if (d != NULL) {
            CHECK(d->id == (brix_codec_id_t) i, "id mismatch slot=%d desc.id=%d", i, d->id);
            CHECK(d->name != NULL, "id=%d has NULL name", i);
            /* available() must agree with the descriptor's own flags. */
            int avail = brix_codec_available((brix_codec_id_t) i);
            int expect = (d->available && d->backend != NULL);
            CHECK(avail == expect, "available(%d)=%d but desc.available=%d backend=%p",
                  i, avail, d->available, (void *) d->backend);
        }
    }
    /* IDENTITY is contractually ALWAYS available. */
    CHECK(brix_codec_available(BRIX_CODEC_IDENTITY), "identity must be available");

    /* out-of-range ids -> NULL / not available (no OOB read). */
    CHECK(brix_codec_by_id(BRIX_CODEC_MAX) == NULL, "by_id(MAX) -> NULL");
    CHECK(brix_codec_by_id((brix_codec_id_t) -1) == NULL, "by_id(-1) -> NULL");
    CHECK(brix_codec_by_id((brix_codec_id_t) 9999) == NULL, "by_id(9999) -> NULL");
    CHECK(!brix_codec_available((brix_codec_id_t) -1), "available(-1) -> 0");
    CHECK(!brix_codec_available(BRIX_CODEC_MAX), "available(MAX) -> 0");
    CHECK(!brix_codec_available((brix_codec_id_t) 9999), "available(9999) -> 0");

    printf("  ok   dense table (no holes 0..MAX-1; available() agrees; OOB->NULL)\n");
}

/* ------------------------------------------------------------------ */
/* (3) open returns NULL for out-of-range / unavailable codec;        */
/*     a NULL guard on decode is fine (covered by all decode calls).  */
/* ------------------------------------------------------------------ */
static void
test_open_guards(void)
{
    /* out-of-range ids: open must reject (NULL) without OOB access. */
    CHECK(brix_codec_open((brix_codec_id_t) -1, BRIX_CODEC_DIR_DECOMPRESS, -1, NULL) == NULL,
          "open(-1) -> NULL");
    CHECK(brix_codec_open(BRIX_CODEC_MAX, BRIX_CODEC_DIR_DECOMPRESS, -1, NULL) == NULL,
          "open(MAX) -> NULL");
    CHECK(brix_codec_open((brix_codec_id_t) 9999, BRIX_CODEC_DIR_COMPRESS, -1, NULL) == NULL,
          "open(9999) -> NULL");

    /* any unavailable (not-built-in) codec id must open to NULL. We don't know
     * statically which are absent in this build, so check the contract for each
     * codec we DON'T deem available. (All present in this build, so this loop is
     * a no-op here but guards future builds where a lib is missing.) */
    size_t k;
    for (k = 0; k < NCODECS; k++) {
        if (!brix_codec_available(kCodecs[k].id)) {
            CHECK(brix_codec_open(kCodecs[k].id, BRIX_CODEC_DIR_DECOMPRESS, -1, NULL) == NULL,
                  "%s unavailable -> open NULL", kCodecs[k].name);
        }
    }

    /* NULL-guard decode is fine: a tiny gzip round-trip with guard==NULL. */
    if (brix_codec_available(BRIX_CODEC_GZIP)) {
        uint8_t  src[256], *comp = NULL, *plain = NULL;
        size_t   complen = 0, plainlen = 0;
        int      rc;
        fill_pattern(src, sizeof(src), 3);
        rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_COMPRESS, src, sizeof(src), NULL,
                       &comp, &complen, 64, 64);
        CHECK(rc == 0, "null-guard setup compress rc=%d", rc);
        if (rc == 0) {
            rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen,
                           NULL /* guard */, &plain, &plainlen, 64, 64);
            CHECK(rc == 0 && plainlen == sizeof(src)
                  && memcmp(src, plain, sizeof(src)) == 0,
                  "null-guard decode rc=%d len=%zu", rc, plainlen);
            free(plain);
        }
        free(comp);
    }

    printf("  ok   open guards (OOB/unavailable -> NULL; NULL-guard decode ok)\n");
}

/* ------------------------------------------------------------------ */
/* (6) double-close: NOT exercised — the API does NOT tolerate it.    */
/* brix_codec_close() does free(s) and does not null the caller's   */
/* pointer; a second close on the same pointer is a double-free       */
/* (use-after-free), which the contract does not promise to survive   */
/* (codec_core.c lines ~230-241). Per the test spec we SKIP this case */
/* rather than invoke undefined behaviour. close(NULL) IS documented  */
/* as safe, so we assert that instead.                                */
/* ------------------------------------------------------------------ */
static void
test_close_null_safe(void)
{
    brix_codec_close(NULL);   /* documented no-op; must not crash */
    printf("  ok   close(NULL) safe (double-close skipped: API frees, no re-close)\n");
}

/* ------------------------------------------------------------------ */
/* (4) empty input round-trips to 0 bytes for each available codec.   */
/* (5) 1-byte input AND 1-byte buffers round-trip byte-exact.         */
/* ------------------------------------------------------------------ */
static void
test_empty_and_tiny(void)
{
    size_t k;

    for (k = 0; k < NCODECS; k++) {
        brix_codec_id_t id = kCodecs[k].id;
        const char       *nm = kCodecs[k].name;
        uint8_t          *comp = NULL, *plain = NULL;
        size_t            complen = 0, plainlen = 0;
        int               rc;

        if (!brix_codec_available(id)) {
            printf("  SKIP %s (not built in)\n", nm);
            continue;
        }

        /* (4) empty: 0 bytes -> compress -> decompress -> 0 bytes. The compress
         * direction still emits a framed empty stream (header/footer), so the
         * compressed length may be >0; the decoded length MUST be 0. Pump with
         * 1-byte buffers to also exercise the empty-input finish path. */
        rc = run_codec(id, BRIX_CODEC_DIR_COMPRESS, (const uint8_t *) "", 0, NULL,
                       &comp, &complen, 1, 1);
        CHECK(rc == 0, "%s empty compress rc=%d", nm, rc);
        if (rc == 0) {
            rc = run_codec(id, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, NULL,
                           &plain, &plainlen, 1, 1);
            CHECK(rc == 0 && plainlen == 0, "%s empty round-trip rc=%d len=%zu",
                  nm, rc, plainlen);
            free(plain); plain = NULL;
        }
        free(comp); comp = NULL;

        /* (5) 1-byte payload, 1-byte input + 1-byte output buffers throughout:
         * loop step() draining a single byte at a time, byte-exact recovery. */
        {
            uint8_t one = (uint8_t) (0xA5 ^ k);
            rc = run_codec(id, BRIX_CODEC_DIR_COMPRESS, &one, 1, NULL,
                           &comp, &complen, 1, 1);
            CHECK(rc == 0, "%s 1-byte compress (1/1 bufs) rc=%d", nm, rc);
            if (rc == 0) {
                rc = run_codec(id, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, NULL,
                               &plain, &plainlen, 1, 1);
                CHECK(rc == 0 && plainlen == 1 && plain != NULL && plain[0] == one,
                      "%s 1-byte round-trip (1/1 bufs) rc=%d len=%zu",
                      nm, rc, plainlen);
                free(plain); plain = NULL;
            }
            free(comp); comp = NULL;
        }
    }
    printf("  ok   empty + 1-byte streams (1-byte in/out buffers) round-trip\n");
}

/* ------------------------------------------------------------------ */
/* (7) bomb guard FALSE-POSITIVE floor: a tiny highly-compressible     */
/* stream that expands BELOW BRIX_CODEC_RATIO_FLOOR must NOT trip.    */
/* and TRUE trip: expanding well past the floor at high ratio MUST trip.*/
/* ------------------------------------------------------------------ */
static void
test_bomb_ratio(void)
{
    if (!brix_codec_available(BRIX_CODEC_GZIP)) {
        printf("  SKIP bomb ratio (gzip not built in)\n");
        return;
    }

    /* (7a) FALSE-POSITIVE floor: 32 KiB of zeros (< 64 KiB floor) at an extreme
     * ratio cap (max_ratio=2) must NOT trip — the ratio guard only engages once
     * total_out >= BRIX_CODEC_RATIO_FLOOR. */
    {
        size_t   n = 32u * 1024u;                  /* below the 64 KiB floor */
        uint8_t *zeros = calloc(n, 1);
        uint8_t *comp = NULL, *plain = NULL;
        size_t   complen = 0, plainlen = 0;
        brix_codec_guard_t g;
        int      rc;

        rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_COMPRESS, zeros, n, NULL,
                       &comp, &complen, 1 << 12, 1 << 12);
        CHECK(rc == 0, "floor setup compress rc=%d", rc);
        if (rc == 0) {
            memset(&g, 0, sizeof(g));
            g.max_ratio = 2;          /* would trip if floor were ignored */
            rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                           &plain, &plainlen, 1 << 12, 1 << 12);
            CHECK(rc == 0 && plainlen == n,
                  "below-floor must NOT trip ratio guard rc=%d len=%zu (want %zu)",
                  rc, plainlen, n);
            free(plain);
        }
        free(comp); free(zeros);
    }

    /* (7b) TRUE trip: 8 MiB of zeros (~1000:1) with a populated ratio guard and
     * output well past the floor MUST return ERR_BOMB. */
    {
        size_t   n = 8u * 1024u * 1024u;
        uint8_t *zeros = calloc(n, 1);
        uint8_t *comp = NULL, *plain = NULL;
        size_t   complen = 0, plainlen = 0;
        brix_codec_guard_t g;
        int      rc;

        rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_COMPRESS, zeros, n, NULL,
                       &comp, &complen, 1 << 16, 1 << 16);
        CHECK(rc == 0, "ratio-trip setup compress rc=%d", rc);
        if (rc == 0) {
            memset(&g, 0, sizeof(g));
            g.max_ratio = 50;         /* 1000:1 >> 50 -> must trip past the floor */
            rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                           &plain, &plainlen, 1 << 16, 1 << 16);
            CHECK(rc == BRIX_CODEC_ERR_BOMB, "ratio guard must trip rc=%d (want %d)",
                  rc, BRIX_CODEC_ERR_BOMB);
            free(plain);
        }
        free(comp); free(zeros);
    }

    printf("  ok   bomb ratio guard (below-floor no false-positive; high-ratio trips)\n");
}

/* ------------------------------------------------------------------ */
/* (8) absolute out_cap: out_cap small, max_ratio 0 -> decode of a     */
/* larger output trips ERR_BOMB.                                       */
/* ------------------------------------------------------------------ */
static void
test_bomb_outcap(void)
{
    if (!brix_codec_available(BRIX_CODEC_GZIP)) {
        printf("  SKIP bomb out_cap (gzip not built in)\n");
        return;
    }
    {
        size_t   n = 4u * 1024u * 1024u;           /* 4 MiB plaintext */
        uint8_t *zeros = calloc(n, 1);
        uint8_t *comp = NULL, *plain = NULL;
        size_t   complen = 0, plainlen = 0;
        brix_codec_guard_t g;
        int      rc;

        rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_COMPRESS, zeros, n, NULL,
                       &comp, &complen, 1 << 16, 1 << 16);
        CHECK(rc == 0, "out_cap setup compress rc=%d", rc);
        if (rc == 0) {
            /* out_cap below the true 4 MiB output, ratio guard OFF -> ERR_BOMB. */
            memset(&g, 0, sizeof(g));
            g.out_cap   = 1u * 1024u * 1024u;      /* 1 MiB hard ceiling */
            g.max_ratio = 0;                        /* ratio guard disabled */
            rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                           &plain, &plainlen, 1 << 16, 1 << 16);
            CHECK(rc == BRIX_CODEC_ERR_BOMB, "out_cap guard must trip rc=%d (want %d)",
                  rc, BRIX_CODEC_ERR_BOMB);
            free(plain); plain = NULL;

            /* a cap at/above the true output, ratio off -> must NOT trip. */
            memset(&g, 0, sizeof(g));
            g.out_cap   = (uint64_t) n;             /* exactly the output size */
            g.max_ratio = 0;
            plainlen = 0;
            rc = run_codec(BRIX_CODEC_GZIP, BRIX_CODEC_DIR_DECOMPRESS, comp, complen, &g,
                           &plain, &plainlen, 1 << 16, 1 << 16);
            CHECK(rc == 0 && plainlen == n,
                  "out_cap == output must NOT trip rc=%d len=%zu", rc, plainlen);
            free(plain);
        }
        free(comp); free(zeros);
    }
    printf("  ok   bomb out_cap guard (small cap trips; exact cap passes)\n");
}

/* ------------------------------------------------------------------ */
/* (9) per-codec truncated-stream corruption: compress, drop the last  */
/* 8 bytes, decode -> negative code, NEVER silent success w/ wrong len.*/
/* ------------------------------------------------------------------ */
static void
test_truncated(void)
{
    size_t k;

    for (k = 0; k < NCODECS; k++) {
        brix_codec_id_t id = kCodecs[k].id;
        const char       *nm = kCodecs[k].name;
        uint8_t           src[40000];
        uint8_t          *comp = NULL, *plain = NULL;
        size_t            complen = 0, plainlen = 0;
        int               rc;

        if (!brix_codec_available(id)) {
            printf("  SKIP %s truncated (not built in)\n", nm);
            continue;
        }

        /* Use mixed structured/random data so the compressed stream is well
         * over 8 bytes and the codec actually had work to do (a real end
         * marker / checksum exists to be lost when we truncate). */
        fill_pattern(src, sizeof(src), 0x1234u + (unsigned) k);
        rc = run_codec(id, BRIX_CODEC_DIR_COMPRESS, src, sizeof(src), NULL,
                       &comp, &complen, 1 << 16, 1 << 16);
        CHECK(rc == 0 && complen > 8, "%s truncated setup rc=%d complen=%zu",
              nm, rc, complen);
        if (rc != 0 || complen <= 8) { free(comp); continue; }

        /* Drop the last 8 bytes -> the stream is now incomplete/corrupt. A
         * conforming decoder must NOT report END with the full plaintext; it
         * must return a negative code (ERR_DATA for malformed/checksum, or
         * ERR_BOMB if our anti-spin guard fires first), OR run out of input
         * without ever reaching END (our driver surfaces that as the -200
         * budget guard, also negative). The one outcome we forbid is rc==0
         * with plainlen == original length (silent acceptance of a truncated
         * stream). */
        size_t truncated = complen - 8;
        rc = run_codec(id, BRIX_CODEC_DIR_DECOMPRESS, comp, truncated, NULL,
                       &plain, &plainlen, 1 << 16, 1 << 16);
        CHECK(rc != 0, "%s truncated decode must NOT return END rc=%d len=%zu",
              nm, rc, plainlen);
        CHECK(rc < 0, "%s truncated decode must be a negative code rc=%d", nm, rc);
        CHECK(!(rc == 0 && plainlen == sizeof(src)),
              "%s truncated decode silently accepted full length (rc=%d)", nm, rc);
        free(plain);
        free(comp);
    }
    printf("  ok   per-codec truncated-stream rejection (drop last 8 bytes)\n");
}

/* ------------------------------------------------------------------ */
/* (10) post-frame TRAILING bytes: a complete frame followed by garbage */
/* must decode to EXACTLY the first frame's plaintext and stop at the   */
/* frame boundary — never silently merge a concatenated second frame    */
/* (zstd/lz4 support concatenation) nor consume the trailing junk.      */
/* ------------------------------------------------------------------ */
static void
test_trailing_bytes(void)
{
    size_t k;

    for (k = 0; k < NCODECS; k++) {
        brix_codec_id_t id = kCodecs[k].id;
        const char       *nm = kCodecs[k].name;
        uint8_t           src[20000];
        uint8_t          *comp = NULL, *buf = NULL;
        size_t            complen = 0, total, i;

        if (!brix_codec_available(id)) {
            printf("  SKIP %s trailing (not built in)\n", nm);
            continue;
        }

        fill_pattern(src, sizeof(src), 0x9e37u + (unsigned) k);
        if (run_codec(id, BRIX_CODEC_DIR_COMPRESS, src, sizeof(src), NULL,
                      &comp, &complen, 1 << 16, 1 << 16) != 0 || complen == 0) {
            CHECK(0, "%s trailing setup failed", nm);
            free(comp);
            continue;
        }

        /* one complete frame + 16 trailing garbage bytes */
        total = complen + 16;
        buf = malloc(total);
        memcpy(buf, comp, complen);
        for (i = 0; i < 16; i++) { buf[complen + i] = (uint8_t) (0xC3u ^ (i + k)); }

        {
            brix_codec_stream_t *s =
                brix_codec_open(id, BRIX_CODEC_DIR_DECOMPRESS, -1, NULL);
            uint8_t           out[40000];
            size_t            in_pos = 0, out_pos = 0;
            brix_codec_rc_t r = BRIX_CODEC_OK;

            CHECK(s != NULL, "%s trailing open", nm);
            if (s != NULL) {
                /* feed the whole buffer once; loop step() until END (or error). */
                while (r == BRIX_CODEC_OK && out_pos < sizeof(out)) {
                    r = brix_codec_step(s, buf, total, &in_pos,
                                          out, sizeof(out), &out_pos, 1);
                    if (r == BRIX_CODEC_END) { break; }
                    if (r != BRIX_CODEC_OK) { break; }
                    if (in_pos >= total) { break; }   /* ran out without END */
                }
                /* MUST finish the first frame cleanly... */
                CHECK(r == BRIX_CODEC_END,
                      "%s trailing must reach END at the frame boundary rc=%d",
                      nm, (int) r);
                /* ...recovering EXACTLY the original (no extra/merged frame)... */
                CHECK(out_pos == sizeof(src)
                      && memcmp(out, src, sizeof(src)) == 0,
                      "%s trailing: decoded must equal original exactly (got %zu)",
                      nm, out_pos);
                /* ...and stop at the frame end without consuming the 16 junk bytes. */
                CHECK(in_pos == complen,
                      "%s trailing: in_pos=%zu must equal complen=%zu (junk not consumed)",
                      nm, in_pos, complen);
                brix_codec_close(s);
            }
        }
        free(buf);
        free(comp);
    }
    printf("  ok   post-frame trailing bytes stop at frame boundary (no silent merge)\n");
}

/* ------------------------------------------------------------------ */
/* (11) compression-level clamping: an out-of-range level must be      */
/* clamped (open succeeds, never rejected) and still round-trip.       */
/* ------------------------------------------------------------------ */
static void
test_level_clamp(void)
{
    size_t k;

    for (k = 0; k < NCODECS; k++) {
        brix_codec_id_t          id = kCodecs[k].id;
        const char                *nm = kCodecs[k].name;
        const brix_codec_desc_t *d  = brix_codec_by_id(id);
        int                        levels[4];
        size_t                     li;

        if (!brix_codec_available(id) || d == NULL) {
            printf("  SKIP %s level-clamp (not built in)\n", nm);
            continue;
        }

        levels[0] = -999;                 /* far below min (but != -1 default) */
        levels[1] = d->level_min - 5;     /* just below min                    */
        levels[2] = d->level_max + 999;   /* far above max                     */
        levels[3] = d->level_max;         /* exact max                         */

        for (li = 0; li < 4; li++) {
            brix_codec_stream_t *s =
                brix_codec_open(id, BRIX_CODEC_DIR_COMPRESS, levels[li], NULL);
            CHECK(s != NULL,
                  "%s open at out-of-range level %d must succeed (clamped)",
                  nm, levels[li]);
            if (s != NULL) { brix_codec_close(s); }
        }

        /* a full round-trip with an extreme (clamped) compress level is byte-exact:
         * compress manually at level_max+999, decode via the standard driver. */
        {
            uint8_t                src[8000];
            uint8_t               *plain = NULL;
            uint8_t                comp[16000];
            size_t                 in_pos = 0, out_pos = 0, plen = 0;
            brix_codec_stream_t *s;
            brix_codec_rc_t      r = BRIX_CODEC_OK;
            int                    rc;

            fill_pattern(src, sizeof(src), 0x55aau + (unsigned) k);
            s = brix_codec_open(id, BRIX_CODEC_DIR_COMPRESS,
                                  d->level_max + 999, NULL);
            CHECK(s != NULL, "%s clamp round-trip open", nm);
            if (s != NULL) {
                while (r == BRIX_CODEC_OK && out_pos < sizeof(comp)) {
                    r = brix_codec_step(s, src, sizeof(src), &in_pos,
                                          comp, sizeof(comp), &out_pos, 1);
                    if (r != BRIX_CODEC_OK) { break; }
                }
                CHECK(r == BRIX_CODEC_END, "%s clamp compress rc=%d", nm, (int) r);
                brix_codec_close(s);
                if (r == BRIX_CODEC_END) {
                    rc = run_codec(id, BRIX_CODEC_DIR_DECOMPRESS, comp, out_pos,
                                   NULL, &plain, &plen, 1 << 16, 1 << 16);
                    CHECK(rc == 0 && plen == sizeof(src)
                          && memcmp(plain, src, sizeof(src)) == 0,
                          "%s clamp round-trip byte-exact rc=%d len=%zu", nm, rc, plen);
                    free(plain);
                }
            }
        }
    }
    printf("  ok   compression-level clamping (out-of-range clamps + round-trips)\n");
}

int
main(void)
{
    printf("== codec_core EDGE/adversarial unit test ==\n");
    test_lookups();
    test_table_dense();
    test_open_guards();
    test_close_null_safe();
    test_empty_and_tiny();
    test_bomb_ratio();
    test_bomb_outcap();
    test_truncated();
    test_trailing_bytes();
    test_level_clamp();
    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}
