#include "../../src/core/compat/crc32c.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int
expect_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("%s failed: got %08x want %08x\n", name, got, want);
        return 1;
    }

    return 0;
}

/*
 * Independent reference CRC-32c (Castagnoli, reflected poly 0x82F63B78),
 * computed bit-by-bit straight from the definition.  This is the oracle the
 * hardware (serial + 3-way parallel) paths are validated against, so a bug in
 * the SSE4.2 / GF(2)-combine code cannot silently corrupt a wire checksum
 * (Invariant #1) without this test going red.
 */
static uint32_t
ref_crc32c(uint32_t crc, const unsigned char *p, size_t len)
{
    size_t i;

    crc ^= 0xFFFFFFFFu;
    for (i = 0; i < len; i++) {
        int k;

        crc ^= p[i];
        for (k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0x82F63B78u & (uint32_t) -(int32_t) (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

#define BUFSZ 70000

/*
 * Sweep many lengths, alignments and split points so every regime of the 3-way
 * path is exercised: the byte-alignment prologue, the SHORT (256-byte) triple
 * blocks, the LONG (8192-byte) triple blocks (need >= 24576 bytes), the 8-byte
 * tail, and the single-byte tail.  Equivalence must hold for the one-shot value,
 * the incremental extend, and the copy-while-checksum variant.
 */
static int
sweep_equivalence(void)
{
    static unsigned char buf[BUFSZ];
    static unsigned char dst[BUFSZ];
    const size_t lens[] = {
        0, 1, 7, 8, 9, 15, 16, 255, 256, 257, 767, 768, 769, 1000, 1024,
        2047, 2048, 8191, 8192, 8193, 24575, 24576, 24577, 30000,
        49151, 49152, 49153, 60000, 69992
    };
    uint32_t lcg = 0x12345678u;
    size_t   i, off;
    int      failed = 0;

    for (i = 0; i < BUFSZ; i++) {
        lcg = lcg * 1103515245u + 12345u;
        buf[i] = (unsigned char) (lcg >> 16);
    }

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        size_t len = lens[i];

        for (off = 0; off < 8; off++) {
            uint32_t want, got, split;
            size_t   s;

            if (off + len > BUFSZ) {
                continue;
            }

            want = ref_crc32c(0, buf + off, len);

            got = xrootd_crc32c_value(buf + off, len);
            if (got != want) {
                printf("value mismatch len=%zu off=%zu got=%08x want=%08x\n",
                       len, off, got, want);
                failed = 1;
            }

            /* Incremental extend across an interior split point. */
            s = len / 3;
            split = xrootd_crc32c_extend(0, buf + off, s);
            split = xrootd_crc32c_extend(split, buf + off + s, len - s);
            if (split != want) {
                printf("extend mismatch len=%zu off=%zu got=%08x want=%08x\n",
                       len, off, split, want);
                failed = 1;
            }

            /* Copy-while-checksum must match and produce an identical copy. */
            memset(dst, 0, len);
            got = xrootd_crc32c_copy_value(buf + off, dst, len);
            if (got != want) {
                printf("copy crc mismatch len=%zu off=%zu got=%08x want=%08x\n",
                       len, off, got, want);
                failed = 1;
            }
            if (len != 0 && memcmp(dst, buf + off, len) != 0) {
                printf("copy bytes mismatch len=%zu off=%zu\n", len, off);
                failed = 1;
            }
        }
    }

    return failed;
}

/*
 * Negative / contract cases for the copy path (now routed through the 3-way
 * xrootd_crc32c_copy_hw3 for len >= 768):
 *   - NULL guard: a NULL src/dst with len != 0 must copy nothing and return 0
 *     (the documented "not a valid checksum" sentinel), never deref or scribble.
 *   - Corruption detection: flipping a single byte anywhere in a large buffer
 *     must change the checksum, proving every byte feeds the parallel streams
 *     (a recombine bug that dropped a stream could otherwise pass the value
 *     sweep yet silently miss corruption — Invariant #1).
 */
static int
copy_negative_cases(void)
{
    static unsigned char src[4096];
    static unsigned char dst[4096];
    uint32_t             base, flipped;
    size_t               i;
    int                  failed = 0;
    int                  guard = 0xAB;

    for (i = 0; i < sizeof(src); i++) {
        src[i] = (unsigned char) (i * 31u + 7u);
    }

    /* NULL guard: must return 0 and touch nothing. */
    memset(dst, guard, sizeof(dst));
    if (xrootd_crc32c_copy_value(NULL, dst, sizeof(dst)) != 0) {
        printf("null-src copy did not return 0\n");
        failed = 1;
    }
    for (i = 0; i < sizeof(dst); i++) {
        if (dst[i] != (unsigned char) guard) {
            printf("null-src copy scribbled dst at %zu\n", i);
            failed = 1;
            break;
        }
    }
    if (xrootd_crc32c_copy_value(src, NULL, sizeof(src)) != 0) {
        printf("null-dst copy did not return 0\n");
        failed = 1;
    }

    /* Corruption detection across the 3-way path (len 4096 >= 768). */
    base = xrootd_crc32c_copy_value(src, dst, sizeof(src));
    for (i = 0; i < sizeof(src); i += 257) {
        unsigned char saved = src[i];

        src[i] ^= 0x01;
        flipped = xrootd_crc32c_copy_value(src, dst, sizeof(src));
        src[i] = saved;
        if (flipped == base) {
            printf("flipping byte %zu did not change copy crc\n", i);
            failed = 1;
        }
    }

    return failed;
}

int
main(void)
{
    const unsigned char known[] = "123456789";
    const unsigned char payload[] = "split crc32c payload";
    unsigned char       copy[sizeof(payload)];
    uint32_t            split;
    int                 failed = 0;

    failed |= expect_u32("known vector",
                         xrootd_crc32c_value(known, strlen((const char *) known)),
                         0xe3069283u);

    memset(copy, 0, sizeof(copy));
    failed |= expect_u32("copy vector",
                         xrootd_crc32c_copy_value(payload, copy, sizeof(payload) - 1),
                         xrootd_crc32c_value(payload, sizeof(payload) - 1));
    if (memcmp(copy, payload, sizeof(payload) - 1) != 0) {
        printf("copy payload failed\n");
        failed = 1;
    }

    split = 0;
    split = xrootd_crc32c_extend(split, payload, 5);
    split = xrootd_crc32c_extend(split, payload + 5, sizeof(payload) - 6);
    failed |= expect_u32("split extend", split,
                         xrootd_crc32c_value(payload, sizeof(payload) - 1));

    failed |= sweep_equivalence();
    failed |= copy_negative_cases();

    if (failed) {
        return 1;
    }

    printf("crc32c compat helpers passed\n");
    return 0;
}
