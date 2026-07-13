/*
 * xmeta_unittest.c — standalone unit test for the xmeta record codec (P1).
 *
 * Compiles without nginx:
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/xmeta_ut \
 *       src/fs/meta/xmeta_unittest.c src/fs/meta/xmeta.c \
 *       src/core/compat/crc32c.c && /tmp/xmeta_ut
 *
 * With an argument, additionally writes a populated record to that path so
 * the caller can cross-check the stock prefix with xrdpfc_print (see
 * tests/run_xmeta.sh). Exit 0 = all checks pass.
 *
 * STRUCTURE: each self-contained assertion group is one static test_*()
 * function; a descriptor table (g_tests) drives main() so the file stays under
 * the complexity gate without any change to the assertions or their order.
 * Every test rebuilds the record state it needs from build_sample(), so the
 * cases share no live state and run in table order.
 */

#include "xmeta.h"
#include "core/compat/crc32c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_failed;

#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/*
 * build_sample — WHAT: populate a fully-featured xmeta record (STATE, ORIGIN,
 * BLOCKCRC and two digests over 2.5 blocks). WHY: every test starts from the
 * same known record so the cases are self-contained. HOW: field-by-field, then
 * two block-set / digest-add calls.
 */
static void
build_sample(brix_xmeta_t *m)
{
    /* 2.5 blocks of 1MiB */
    brix_xmeta_init(m, 2621440, 1048576);
    m->origin_mtime = 1751400000;
    m->mode         = 0644;
    m->dirty_lo     = 100;
    m->dirty_hi     = 200;
    m->flush_gen    = 7;
    m->access_cnt   = 3;
    m->astat_count  = 1;
    m->astat.attach_time = 1751400001;
    m->astat.detach_time = 1751400002;
    m->astat.bytes_hit   = 12345;
    brix_xmeta_block_set(m, 0);
    brix_xmeta_block_set(m, 2);
    m->blockcrc[0] = 0xAABBCCDD;
    m->blockcrc[2] = 0x11223344;
    m->last_flush    = 1751400500;
    m->bytes_flushed = 4096;
    m->filled_at     = 1751400600;
    m->expires_at    = 1751401500;
    m->state_flags   = BRIX_XMETA_F_VERIFIED | BRIX_XMETA_F_EXPIRES;
    m->etag_len = 8;      memcpy(m->etag, "\"abc123\"", 8);
    m->cks_alg_len = 7;   memcpy(m->cks_alg, "adler32", 7);
    m->cks_len = 8;       memcpy(m->cks_hex, "0badcafe", 8);
    brix_xmeta_digest_add(m, BRIX_XMETA_ALG_CRC32C,
                            "\xde\xad\xbe\xef", 4);
    brix_xmeta_digest_add(m, BRIX_XMETA_ALG_MD5,
                            "0123456789abcdef", 16);
}

/*
 * encode_sample — WHAT: build the sample record and encode it into a freshly
 * allocated buffer. WHY: the round-trip, corruption and unknown-section tests
 * all need an on-wire buffer to poke at. HOW: build_sample() then encode; the
 * source record is freed here, the caller owns *buf and frees it. Assertion-
 * free on purpose so it can be called by every case without perturbing the
 * check count/order; the init/encode CHECKs live once in test_round_trip.
 */
static void
encode_sample(uint8_t **buf, size_t *blen)
{
    brix_xmeta_t m;

    build_sample(&m);
    brix_xmeta_encode(&m, buf, blen);
    brix_xmeta_free(&m);
}

/*
 * check_state_section — WHAT: assert the decoded STATE section fields match the
 * sample. WHY: keeps the wide predicate readable and out of test_round_trip.
 * HOW: one CHECK over every STATE field including the cvmfs manifest TTL.
 */
static void
check_state_section(const brix_xmeta_t *d)
{
    CHECK(d->have_state && d->origin_mtime == 1751400000 && d->mode == 0644
          && d->dirty_lo == 100 && d->dirty_hi == 200 && d->flush_gen == 7
          && d->last_flush == 1751400500 && d->bytes_flushed == 4096
          && d->filled_at == 1751400600 && d->expires_at == 1751401500
          && d->state_flags == (BRIX_XMETA_F_VERIFIED
                               | BRIX_XMETA_F_EXPIRES),
          "STATE section round-trips (incl. cvmfs manifest TTL)");
}

/*
 * check_digests — WHAT: assert the two added digests round-trip and index 2 is
 * past the end. WHY: isolates the nested out-param dance from test_round_trip.
 * HOW: three brix_xmeta_digest_get() calls with a shared alg/val/dl scratch.
 */
static void
check_digests(const brix_xmeta_t *d)
{
    uint16_t alg = 0, dl = 0;
    const uint8_t *val = NULL;

    CHECK(brix_xmeta_digest_get(d, 0, &alg, &val, &dl)
              == BRIX_XMETA_OK
          && alg == BRIX_XMETA_ALG_CRC32C && dl == 4
          && memcmp(val, "\xde\xad\xbe\xef", 4) == 0,
          "digest[0] round-trips");
    CHECK(brix_xmeta_digest_get(d, 1, &alg, &val, &dl)
              == BRIX_XMETA_OK
          && alg == BRIX_XMETA_ALG_MD5 && dl == 16,
          "digest[1] round-trips");
    CHECK(brix_xmeta_digest_get(d, 2, &alg, &val, &dl)
              == BRIX_XMETA_FOREIGN, "digest[2] is past the end");
}

/*
 * test_round_trip — WHAT: encode the sample, decode it, and assert every
 * section survives the round trip. WHY: the primary happy path of the codec.
 * HOW: encode_sample() then decode + per-section CHECK helpers.
 */
static void
test_round_trip(void)
{
    brix_xmeta_t m, d;
    uint8_t     *buf = NULL;
    size_t       blen = 0;

    build_sample(&m);
    CHECK(m.nblocks == 3, "init: 2.5 blocks rounds up to 3");
    CHECK(brix_xmeta_encode(&m, &buf, &blen) == BRIX_XMETA_OK,
          "encode ok");
    brix_xmeta_free(&m);
    CHECK(brix_xmeta_decode(buf, blen, &d) == BRIX_XMETA_OK,
          "decode ok");
    CHECK(d.file_size == 2621440 && d.buffer_size == 1048576,
          "stock store fields round-trip");
    CHECK(d.astat_count == 1 && d.astat.bytes_hit == 12345,
          "astat record round-trips");
    CHECK(brix_xmeta_block_test(&d, 0) && !brix_xmeta_block_test(&d, 1)
          && brix_xmeta_block_test(&d, 2), "bitmap bits round-trip");
    CHECK(!brix_xmeta_complete(&d), "incomplete bitmap detected");
    check_state_section(&d);
    CHECK(d.etag_len == 8 && memcmp(d.etag, "\"abc123\"", 8) == 0
          && d.cks_alg_len == 7 && memcmp(d.cks_alg, "adler32", 7) == 0
          && d.cks_len == 8 && memcmp(d.cks_hex, "0badcafe", 8) == 0,
          "ORIGIN section round-trips");
    CHECK(d.have_blockcrc && d.blockcrc[0] == 0xAABBCCDD
          && d.blockcrc[1] == BRIX_XMETA_CRC_UNSET
          && d.blockcrc[2] == 0x11223344, "BLOCKCRC table round-trips");
    check_digests(&d);
    brix_xmeta_free(&d);
    free(buf);
}

/*
 * test_corruption — WHAT: flip a byte in each guarded region and assert decode
 * fails, then restore and assert it decodes again. WHY: proves every CRC guard
 * covers its region. HOW: XOR a store/bitmap/section byte in turn, decode,
 * XOR back.
 */
static void
test_corruption(void)
{
    brix_xmeta_t d;
    uint8_t     *buf = NULL;
    size_t       blen = 0;

    encode_sample(&buf, &blen);
    buf[6] ^= 0xFF;                                    /* store POD byte */
    CHECK(brix_xmeta_decode(buf, blen, &d) == BRIX_XMETA_ERR,
          "store corruption detected");
    buf[6] ^= 0xFF;
    buf[57] ^= 0xFF;                                   /* bitmap byte */
    CHECK(brix_xmeta_decode(buf, blen, &d) == BRIX_XMETA_ERR,
          "bitmap corruption detected");
    buf[57] ^= 0xFF;
    buf[blen - 6] ^= 0xFF;                             /* last section payload */
    CHECK(brix_xmeta_decode(buf, blen, &d) == BRIX_XMETA_ERR,
          "section corruption detected");
    buf[blen - 6] ^= 0xFF;
    CHECK(brix_xmeta_decode(buf, blen, &d) == BRIX_XMETA_OK,
          "restored record decodes again");
    brix_xmeta_free(&d);
    free(buf);
}

/*
 * test_foreign_inputs — WHAT: assert a wrong-version blob and a too-short buffer
 * both decode as FOREIGN. WHY: foreign inputs must be recognised, not errored.
 * HOW: decode a bogus int32 and a truncated real buffer.
 */
static void
test_foreign_inputs(void)
{
    brix_xmeta_t d;
    uint8_t     *buf = NULL;
    size_t       blen = 0;
    int32_t      v = 3;

    encode_sample(&buf, &blen);
    CHECK(brix_xmeta_decode((uint8_t *) &v, 4, &d)
              == BRIX_XMETA_FOREIGN, "wrong version is FOREIGN");
    CHECK(brix_xmeta_decode(buf, 10, &d) == BRIX_XMETA_FOREIGN,
          "short buffer is FOREIGN");
    free(buf);
}

/*
 * test_unknown_section — WHAT: retag the DIGEST section as an unknown type,
 * fix its crc, and assert the decoder skips it while still delivering
 * STATE+BLOCKCRC. WHY: forward compatibility with unknown section types.
 * HOW: walk the ext sections to DIGEST, rewrite its type, recompute its crc,
 * then decode a copy.
 */
static void
test_unknown_section(void)
{
    brix_xmeta_t d;
    uint8_t     *buf = NULL;
    size_t       blen = 0;
    uint8_t     *tmp;
    size_t       sec;
    uint32_t     plen, crc;

    encode_sample(&buf, &blen);
    tmp = malloc(blen);
    memcpy(tmp, buf, blen);
    /* walk the sections (ext header sits right after the stock trailer:
     * 4+48+4 + bitmap(1) + astat(56) + 4 + 8) and find DIGEST by type */
    sec = 4 + 48 + 4 + 1 + 56 + 4 + 8;
    for ( ;; ) {
        uint16_t t;

        memcpy(&t, tmp + sec, 2);
        if (t == BRIX_XMETA_SEC_DIGEST) {
            break;
        }
        memcpy(&plen, tmp + sec + 4, 4);
        sec += 8 + plen + 4;
    }
    tmp[sec] = 0x77; tmp[sec + 1] = 0x77;
    memcpy(&plen, tmp + sec + 4, 4);
    crc = brix_crc32c_value(tmp + sec, 8 + plen);
    memcpy(tmp + sec + 8 + plen, &crc, 4);
    CHECK(brix_xmeta_decode(tmp, blen, &d) == BRIX_XMETA_OK,
          "unknown section type skipped");
    CHECK(d.have_state && d.have_blockcrc && d.digests == NULL,
          "known sections still delivered, unknown dropped");
    brix_xmeta_free(&d);
    free(tmp);
    free(buf);
}

/*
 * test_stock_only — WHAT: encode a bare stock-only record (no extension) and
 * assert it decodes with no STATE/BLOCKCRC but the bitmap intact. WHY: the
 * extension must be optional so stock cinfo files still parse. HOW: init,
 * clear the ext flags, set one block, encode, decode.
 */
static void
test_stock_only(void)
{
    brix_xmeta_t s, d;
    uint8_t     *sbuf = NULL;
    size_t       sblen = 0;

    brix_xmeta_init(&s, 1048576, 1048576);
    s.have_state = 0;
    s.have_blockcrc = 0;
    brix_xmeta_block_set(&s, 0);
    CHECK(brix_xmeta_encode(&s, &sbuf, &sblen) == BRIX_XMETA_OK,
          "stock-only encode ok");
    brix_xmeta_free(&s);
    CHECK(brix_xmeta_decode(sbuf, sblen, &d) == BRIX_XMETA_OK
          && !d.have_state && d.blockcrc == NULL
          && brix_xmeta_block_test(&d, 0),
          "stock-only record decodes (extension optional)");
    brix_xmeta_free(&d);
    free(sbuf);
}

/*
 * g_tests — descriptor table driving main(): each row is one self-contained
 * assertion group, run in order. Adding a case is one row, not a new branch.
 */
static void (*const g_tests[])(void) = {
    test_round_trip,
    test_corruption,
    test_foreign_inputs,
    test_unknown_section,
    test_stock_only,
};

/*
 * emit_sample — WHAT: optionally write a populated sample record to a path for
 * the xrdpfc_print stock cross-check. WHY: keeps the file-I/O side effect out
 * of the assertion-only main() and behind the "all passed" guard. HOW: encode
 * the sample, write it, free the buffer; bumps g_failed on write error.
 */
static void
emit_sample(const char *path)
{
    uint8_t *buf = NULL;
    size_t   blen = 0;
    FILE    *f;

    encode_sample(&buf, &blen);
    f = fopen(path, "wb");
    if (f == NULL || fwrite(buf, 1, blen, f) != blen) {
        fprintf(stderr, "cannot write %s\n", path);
        g_failed++;
    }
    if (f != NULL) {
        fclose(f);
    }
    free(buf);
}

int
main(int argc, char **argv)
{
    size_t i;

    for (i = 0; i < sizeof(g_tests) / sizeof(g_tests[0]); i++) {
        g_tests[i]();
    }

    /* ---- optional: emit the sample for the xrdpfc_print cross-check ---- */
    if (argc > 1 && g_failed == 0) {
        emit_sample(argv[1]);
    }

    printf("xmeta_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
