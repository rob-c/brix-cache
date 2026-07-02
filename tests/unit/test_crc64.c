#include "../../src/core/compat/crc64.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Independent reference CRC64 (reflected, init/xorout all-FF), computed bit-by-
 * bit straight from the definition for a given reflected polynomial. This is the
 * oracle the table-driven kernel + the GF(2) combine are validated against, so a
 * wrong polynomial, table, or combine cannot silently corrupt a wire/S3 checksum
 * without this test going red.
 *   XZ   reflected poly 0xC96C5795D7870F42, check("123456789")=0x995DC9BBDF1939FA
 *   NVME reflected poly 0x9A6C9329AC4BC9B5, check("123456789")=0xAE8B14860A799888
 */
#define XZ_POLY_REFL   0xC96C5795D7870F42ULL
#define NVME_POLY_REFL 0x9A6C9329AC4BC9B5ULL

static uint64_t
ref_crc64(uint64_t poly_refl, uint64_t crc, const unsigned char *p, size_t len)
{
    size_t i;

    crc = ~crc;
    for (i = 0; i < len; i++) {
        int k;

        crc ^= p[i];
        for (k = 0; k < 8; k++) {
            crc = (crc & 1) ? (crc >> 1) ^ poly_refl : (crc >> 1);
        }
    }

    return ~crc;
}

static int
expect_u64(const char *name, uint64_t got, uint64_t want)
{
    if (got != want) {
        printf("%s failed: got %016llx want %016llx\n", name,
               (unsigned long long) got, (unsigned long long) want);
        return 1;
    }

    return 0;
}

#define BUFSZ 70000

/*
 * Sweep many lengths, alignments and split points for one variant: validate the
 * one-shot value and the incremental extend against the oracle, and validate the
 * GF(2) combine (whole == combine(crc(A), crc(B), |B|)) used for S3 multipart
 * FULL_OBJECT checksums.
 */
static int
sweep_variant(const char *tag, xrootd_crc64_variant_t var, uint64_t poly_refl)
{
    static unsigned char buf[BUFSZ];
    const size_t lens[] = {
        0, 1, 7, 8, 9, 15, 16, 255, 256, 257, 1000, 1024, 8191, 8192, 8193,
        24576, 30000, 69992
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
            uint64_t want, got, split, ca, cb, comb;
            size_t   s;

            if (off + len > BUFSZ) {
                continue;
            }

            want = ref_crc64(poly_refl, 0, buf + off, len);

            got = xrootd_crc64_value(var, buf + off, len);
            if (got != want) {
                printf("%s value mismatch len=%zu off=%zu got=%016llx want=%016llx\n",
                       tag, len, off, (unsigned long long) got,
                       (unsigned long long) want);
                failed = 1;
            }

            /* Incremental extend across an interior split point. */
            s = len / 3;
            split = xrootd_crc64_extend(var, 0, buf + off, s);
            split = xrootd_crc64_extend(var, split, buf + off + s, len - s);
            if (split != want) {
                printf("%s extend mismatch len=%zu off=%zu\n", tag, len, off);
                failed = 1;
            }

            /* GF(2) combine: crc(A||B) == combine(crc(A), crc(B), |B|). */
            ca = xrootd_crc64_value(var, buf + off, s);
            cb = xrootd_crc64_value(var, buf + off + s, len - s);
            comb = xrootd_crc64_combine(var, ca, cb, (uint64_t) (len - s));
            if (comb != want) {
                printf("%s combine mismatch len=%zu off=%zu got=%016llx want=%016llx\n",
                       tag, len, off, (unsigned long long) comb,
                       (unsigned long long) want);
                failed = 1;
            }
        }
    }

    return failed;
}

int
main(void)
{
    const unsigned char known[] = "123456789";
    int                 failed = 0;

    /* Published check constants — guard against a swapped/wrong polynomial. */
    failed |= expect_u64("xz known vector",
                         xrootd_crc64_value(XROOTD_CRC64_XZ, known,
                                            strlen((const char *) known)),
                         0x995DC9BBDF1939FAULL);
    failed |= expect_u64("nvme known vector",
                         xrootd_crc64_value(XROOTD_CRC64_NVME, known,
                                            strlen((const char *) known)),
                         0xAE8B14860A799888ULL);

    failed |= sweep_variant("xz",   XROOTD_CRC64_XZ,   XZ_POLY_REFL);
    failed |= sweep_variant("nvme", XROOTD_CRC64_NVME, NVME_POLY_REFL);

    if (failed) {
        return 1;
    }

    printf("crc64 compat helpers passed\n");
    return 0;
}
