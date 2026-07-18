/*
 * test_wverify.c — standalone unit test for the write-integrity accumulator
 * (src/core/compat/wverify.c). Verifies the offset-addressed CRC folding that
 * backs brix_gridftp_verify_write:
 *
 *   success  — in-order extents coalesce to the whole-buffer zlib CRC-32;
 *   edge     — out-of-order / reverse arrival yields the SAME whole-buffer CRC
 *              (GridFTP MODE E writes blocks by offset, not in order);
 *   error    — a gap makes expected() fail closed; an overlap is rejected by
 *              update(); the extent cap degrades the accumulator.
 *
 * ngx-free: links against libc + zlib only, mirroring the kernel it exercises.
 */
#include "core/compat/wverify.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static uint32_t
whole_crc(const unsigned char *buf, size_t len)
{
    return (uint32_t) crc32(crc32(0L, Z_NULL, 0), buf, (uInt) len);
}

/* success: three in-order extents covering [0,N) → one run, whole-buffer CRC. */
static void
test_in_order(void)
{
    unsigned char buf[3000];
    brix_wverify_t *w = brix_wverify_begin();
    uint32_t crc = 0;
    off_t total = 0;
    size_t i;

    assert(w != NULL);
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char) (i * 31u + 7u);
    }
    assert(brix_wverify_update(w, buf,           0, 1000) == 0);
    assert(brix_wverify_update(w, buf + 1000, 1000, 1000) == 0);
    assert(brix_wverify_update(w, buf + 2000, 2000, 1000) == 0);

    assert(brix_wverify_expected(w, &crc, &total) == 0);
    assert(total == (off_t) sizeof(buf));
    assert(crc == whole_crc(buf, sizeof(buf)));
    brix_wverify_free(w);
    printf("ok in_order\n");
}

/* edge: reverse / interleaved arrival must converge to the same CRC + total. */
static void
test_out_of_order(void)
{
    unsigned char buf[3000];
    brix_wverify_t *w = brix_wverify_begin();
    uint32_t crc = 0;
    off_t total = 0;
    size_t i;

    assert(w != NULL);
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char) (i ^ 0xA5u);
    }
    /* feed last, first, middle */
    assert(brix_wverify_update(w, buf + 2000, 2000, 1000) == 0);
    assert(brix_wverify_update(w, buf,           0, 1000) == 0);
    assert(brix_wverify_update(w, buf + 1000, 1000, 1000) == 0);

    assert(brix_wverify_expected(w, &crc, &total) == 0);
    assert(total == (off_t) sizeof(buf));
    assert(crc == whole_crc(buf, sizeof(buf)));
    brix_wverify_free(w);
    printf("ok out_of_order\n");
}

/* error: a hole in coverage → expected() declines (fail closed). */
static void
test_gap_fails_closed(void)
{
    unsigned char buf[3000];
    brix_wverify_t *w = brix_wverify_begin();
    uint32_t crc = 0;
    off_t total = 0;

    assert(w != NULL);
    memset(buf, 0x5A, sizeof(buf));
    assert(brix_wverify_update(w, buf,           0, 1000) == 0);
    /* skip [1000,2000) */
    assert(brix_wverify_update(w, buf + 2000, 2000, 1000) == 0);
    assert(brix_wverify_expected(w, &crc, &total) == -1);
    brix_wverify_free(w);
    printf("ok gap_fails_closed\n");
}

/* error: an extent overlapping a committed one is rejected and degrades. */
static void
test_overlap_rejected(void)
{
    unsigned char buf[3000];
    brix_wverify_t *w = brix_wverify_begin();
    uint32_t crc = 0;
    off_t total = 0;

    assert(w != NULL);
    memset(buf, 0x11, sizeof(buf));
    assert(brix_wverify_update(w, buf,          0, 1000) == 0);
    assert(brix_wverify_update(w, buf + 500,  500, 1000) == -1);  /* [500,1500) */
    /* even the earlier good extent no longer yields a whole-object answer */
    assert(brix_wverify_expected(w, &crc, &total) == -1);
    brix_wverify_free(w);
    printf("ok overlap_rejected\n");
}

/* error: zero-length is a no-op; nothing written → expected() declines. */
static void
test_empty_and_zero(void)
{
    unsigned char buf[16];
    brix_wverify_t *w = brix_wverify_begin();
    uint32_t crc = 0;
    off_t total = 0;

    assert(w != NULL);
    memset(buf, 0, sizeof(buf));
    assert(brix_wverify_update(w, buf, 0, 0) == 0);         /* no-op */
    assert(brix_wverify_expected(w, &crc, &total) == -1);   /* nothing written */
    brix_wverify_free(w);
    printf("ok empty_and_zero\n");
}

int
main(void)
{
    test_in_order();
    test_out_of_order();
    test_gap_fails_closed();
    test_overlap_rejected();
    test_empty_and_zero();
    printf("PASS test_wverify\n");
    return 0;
}
