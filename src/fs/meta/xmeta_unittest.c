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

static void
build_sample(xrootd_xmeta_t *m)
{
    /* 2.5 blocks of 1MiB */
    xrootd_xmeta_init(m, 2621440, 1048576);
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
    xrootd_xmeta_block_set(m, 0);
    xrootd_xmeta_block_set(m, 2);
    m->blockcrc[0] = 0xAABBCCDD;
    m->blockcrc[2] = 0x11223344;
    m->last_flush    = 1751400500;
    m->bytes_flushed = 4096;
    m->filled_at     = 1751400600;
    m->state_flags   = XROOTD_XMETA_F_VERIFIED;
    m->etag_len = 8;      memcpy(m->etag, "\"abc123\"", 8);
    m->cks_alg_len = 7;   memcpy(m->cks_alg, "adler32", 7);
    m->cks_len = 8;       memcpy(m->cks_hex, "0badcafe", 8);
    xrootd_xmeta_digest_add(m, XROOTD_XMETA_ALG_CRC32C,
                            "\xde\xad\xbe\xef", 4);
    xrootd_xmeta_digest_add(m, XROOTD_XMETA_ALG_MD5,
                            "0123456789abcdef", 16);
}

int
main(int argc, char **argv)
{
    xrootd_xmeta_t m, d;
    uint8_t       *buf = NULL;
    size_t         blen = 0;

    /* ---- round trip ---- */
    build_sample(&m);
    CHECK(m.nblocks == 3, "init: 2.5 blocks rounds up to 3");
    CHECK(xrootd_xmeta_encode(&m, &buf, &blen) == XROOTD_XMETA_OK,
          "encode ok");
    CHECK(xrootd_xmeta_decode(buf, blen, &d) == XROOTD_XMETA_OK,
          "decode ok");
    CHECK(d.file_size == 2621440 && d.buffer_size == 1048576,
          "stock store fields round-trip");
    CHECK(d.astat_count == 1 && d.astat.bytes_hit == 12345,
          "astat record round-trips");
    CHECK(xrootd_xmeta_block_test(&d, 0) && !xrootd_xmeta_block_test(&d, 1)
          && xrootd_xmeta_block_test(&d, 2), "bitmap bits round-trip");
    CHECK(!xrootd_xmeta_complete(&d), "incomplete bitmap detected");
    CHECK(d.have_state && d.origin_mtime == 1751400000 && d.mode == 0644
          && d.dirty_lo == 100 && d.dirty_hi == 200 && d.flush_gen == 7
          && d.last_flush == 1751400500 && d.bytes_flushed == 4096
          && d.filled_at == 1751400600
          && d.state_flags == XROOTD_XMETA_F_VERIFIED,
          "STATE section round-trips");
    CHECK(d.etag_len == 8 && memcmp(d.etag, "\"abc123\"", 8) == 0
          && d.cks_alg_len == 7 && memcmp(d.cks_alg, "adler32", 7) == 0
          && d.cks_len == 8 && memcmp(d.cks_hex, "0badcafe", 8) == 0,
          "ORIGIN section round-trips");
    CHECK(d.have_blockcrc && d.blockcrc[0] == 0xAABBCCDD
          && d.blockcrc[1] == XROOTD_XMETA_CRC_UNSET
          && d.blockcrc[2] == 0x11223344, "BLOCKCRC table round-trips");
    {
        uint16_t alg = 0, dl = 0;
        const uint8_t *val = NULL;

        CHECK(xrootd_xmeta_digest_get(&d, 0, &alg, &val, &dl)
                  == XROOTD_XMETA_OK
              && alg == XROOTD_XMETA_ALG_CRC32C && dl == 4
              && memcmp(val, "\xde\xad\xbe\xef", 4) == 0,
              "digest[0] round-trips");
        CHECK(xrootd_xmeta_digest_get(&d, 1, &alg, &val, &dl)
                  == XROOTD_XMETA_OK
              && alg == XROOTD_XMETA_ALG_MD5 && dl == 16,
              "digest[1] round-trips");
        CHECK(xrootd_xmeta_digest_get(&d, 2, &alg, &val, &dl)
                  == XROOTD_XMETA_FOREIGN, "digest[2] is past the end");
    }
    xrootd_xmeta_free(&d);

    /* ---- corruption: each guarded region fails decode ---- */
    buf[6] ^= 0xFF;                                    /* store POD byte */
    CHECK(xrootd_xmeta_decode(buf, blen, &d) == XROOTD_XMETA_ERR,
          "store corruption detected");
    buf[6] ^= 0xFF;
    buf[57] ^= 0xFF;                                   /* bitmap byte */
    CHECK(xrootd_xmeta_decode(buf, blen, &d) == XROOTD_XMETA_ERR,
          "bitmap corruption detected");
    buf[57] ^= 0xFF;
    buf[blen - 6] ^= 0xFF;                             /* last section payload */
    CHECK(xrootd_xmeta_decode(buf, blen, &d) == XROOTD_XMETA_ERR,
          "section corruption detected");
    buf[blen - 6] ^= 0xFF;
    CHECK(xrootd_xmeta_decode(buf, blen, &d) == XROOTD_XMETA_OK,
          "restored record decodes again");
    xrootd_xmeta_free(&d);

    /* ---- foreign inputs ---- */
    {
        int32_t v = 3;

        CHECK(xrootd_xmeta_decode((uint8_t *) &v, 4, &d)
                  == XROOTD_XMETA_FOREIGN, "wrong version is FOREIGN");
        CHECK(xrootd_xmeta_decode(buf, 10, &d) == XROOTD_XMETA_FOREIGN,
              "short buffer is FOREIGN");
    }

    /* ---- unknown section type is skipped (fwd compat) ---- */
    {
        /* retag the DIGEST section (2nd ext section) as type 0x7777 and fix
         * its crc: decoder must skip it and still deliver STATE+BLOCKCRC */
        uint8_t *tmp = malloc(blen);
        size_t   sec;
        uint32_t plen, crc;

        memcpy(tmp, buf, blen);
        /* walk the sections (ext header sits right after the stock trailer:
         * 4+48+4 + bitmap(1) + astat(56) + 4 + 8) and find DIGEST by type */
        sec = 4 + 48 + 4 + 1 + 56 + 4 + 8;
        for ( ;; ) {
            uint16_t t;

            memcpy(&t, tmp + sec, 2);
            if (t == XROOTD_XMETA_SEC_DIGEST) {
                break;
            }
            memcpy(&plen, tmp + sec + 4, 4);
            sec += 8 + plen + 4;
        }
        tmp[sec] = 0x77; tmp[sec + 1] = 0x77;
        memcpy(&plen, tmp + sec + 4, 4);
        crc = xrootd_crc32c_value(tmp + sec, 8 + plen);
        memcpy(tmp + sec + 8 + plen, &crc, 4);
        CHECK(xrootd_xmeta_decode(tmp, blen, &d) == XROOTD_XMETA_OK,
              "unknown section type skipped");
        CHECK(d.have_state && d.have_blockcrc && d.digests == NULL,
              "known sections still delivered, unknown dropped");
        xrootd_xmeta_free(&d);
        free(tmp);
    }

    /* ---- stock-only record (no extension) decodes ---- */
    {
        xrootd_xmeta_t s;
        uint8_t       *sbuf = NULL;
        size_t         sblen = 0;

        xrootd_xmeta_init(&s, 1048576, 1048576);
        s.have_state = 0;
        s.have_blockcrc = 0;
        xrootd_xmeta_block_set(&s, 0);
        CHECK(xrootd_xmeta_encode(&s, &sbuf, &sblen) == XROOTD_XMETA_OK,
              "stock-only encode ok");
        xrootd_xmeta_free(&s);
        CHECK(xrootd_xmeta_decode(sbuf, sblen, &d) == XROOTD_XMETA_OK
              && !d.have_state && d.blockcrc == NULL
              && xrootd_xmeta_block_test(&d, 0),
              "stock-only record decodes (extension optional)");
        xrootd_xmeta_free(&d);
        free(sbuf);
    }

    /* ---- optional: emit the sample for the xrdpfc_print cross-check ---- */
    if (argc > 1 && g_failed == 0) {
        FILE *f = fopen(argv[1], "wb");

        if (f == NULL || fwrite(buf, 1, blen, f) != blen) {
            fprintf(stderr, "cannot write %s\n", argv[1]);
            g_failed++;
        }
        if (f != NULL) {
            fclose(f);
        }
    }

    free(buf);
    xrootd_xmeta_free(&m);
    printf("xmeta_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
