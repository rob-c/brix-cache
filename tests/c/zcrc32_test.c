/*
 * zcrc32_test.c — standalone unit test for the zcrc32 checksum kernel
 * (src/core/compat/checksum_core.h BRIX_CK_ZCRC32 via brix_cksum_u32_fd).
 * Builds ngx-free; links against libxrdproto + zlib.
 *
 * WHAT: For several payloads (empty, 1 byte, ~1 MiB pseudo-random, all-zeros)
 *       written to a temp fd, assert that
 *         brix_cksum_u32_fd(BRIX_CK_ZCRC32, fd, &out)
 *       equals (a) the value zlib's crc32() produces over the same bytes in
 *       process (the oracle) and (b) the kernel's own BRIX_CK_CRC32 result —
 *       i.e. zcrc32 IS the zlib CRC-32 (XRootD's registered name for it).
 * WHY:  Pins the contract documented in checksum_core.h that the "zcrc32" name
 *       folds onto the CRC32/ISO-HDLC kernel path, so the server's `z=` READ
 *       marker checksum and clients agree byte-for-byte with stock zlib.
 * HOW:  Same harness style as codec_test.c — self-contained main(), CHECK()
 *       asserts, "ok ..." lines, prints "== ALL PASSED ==" or exits nonzero.
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra \
 *      -I /home/rcurrie/HEP-x/nginx-xrootd/src/core/compat \
 *      tests/c/zcrc32_test.c \
 *      /home/rcurrie/HEP-x/nginx-xrootd/shared/xrdproto/libxrdproto.a \
 *      -lz -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 -lcrypto \
 *      -o /tmp/zcrc32_test && /tmp/zcrc32_test
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* mkstemp(3) prototype under -std=c11 */
#endif

#include "checksum_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail = 1; } } while (0)

/* Deterministic pseudo-random-ish payload (same mixer style as codec_test.c)
 * so the checksum has non-trivial structure to chew on. */
static void
fill_pattern(uint8_t *b, size_t n, unsigned seed)
{
    size_t   i;
    unsigned x = seed * 2654435761u + 1;
    for (i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        b[i] = (uint8_t) ((i & 0x3f) ^ (x >> 16));
    }
}

/* Write `len` bytes of `data` to a fresh anonymous temp fd, positioned anywhere
 * (the kernel pread()s from offset 0). Returns an open fd or -1. */
static int
write_temp_fd(const uint8_t *data, size_t len)
{
    char  path[] = "/tmp/zcrc32_test.XXXXXX";
    int   fd = mkstemp(path);
    size_t off = 0;

    if (fd < 0) {
        return -1;
    }
    /* Unlink immediately: the open fd keeps the inode alive, no litter left. */
    unlink(path);

    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            close(fd);
            return -1;
        }
        off += (size_t) w;
    }
    return fd;
}

/* The in-process oracle: stock zlib crc32() over the whole buffer. */
static uint32_t
zlib_crc32_oracle(const uint8_t *data, size_t len)
{
    uLong c = crc32(0L, Z_NULL, 0);
    if (len > 0) {
        c = crc32(c, data, (uInt) len);
    }
    return (uint32_t) c;
}

/* One payload: kernel zcrc32 must equal the zlib oracle AND the kernel crc32. */
static void
test_payload(const char *name, const uint8_t *data, size_t len)
{
    uint32_t oracle = zlib_crc32_oracle(data, len);
    uint32_t z_out  = 0;
    uint32_t c_out  = 0;
    int      fd;
    int      rc;

    fd = write_temp_fd(data, len);
    CHECK(fd >= 0, "%s: temp fd create failed", name);
    if (fd < 0) {
        return;
    }

    rc = brix_cksum_u32_fd(BRIX_CK_ZCRC32, fd, &z_out);
    CHECK(rc == 0, "%s: zcrc32 rc=%d (want 0)", name, rc);

    rc = brix_cksum_u32_fd(BRIX_CK_CRC32, fd, &c_out);
    CHECK(rc == 0, "%s: crc32 rc=%d (want 0)", name, rc);

    /* zcrc32 == zlib crc32 oracle */
    CHECK(z_out == oracle,
          "%s: zcrc32=0x%08x != zlib oracle=0x%08x (len=%zu)",
          name, z_out, oracle, len);

    /* zcrc32 IS crc32: the kernel must produce the identical value for both. */
    CHECK(z_out == c_out,
          "%s: zcrc32=0x%08x != crc32=0x%08x (len=%zu)",
          name, z_out, c_out, len);

    if (z_out == oracle && z_out == c_out && rc == 0) {
        printf("  ok   %-16s len=%-8zu zcrc32=crc32=oracle=0x%08x\n",
               name, len, z_out);
    }
    close(fd);
}

int
main(void)
{
    static const size_t big_len = 1024u * 1024u;   /* ~1 MiB */
    uint8_t  one = 0x5a;
    uint8_t *big;
    uint8_t *zeros;

    printf("== zcrc32 checksum-kernel unit test ==\n");

    /* Sanity: the well-known crc32 of the 9-byte ASCII string "123456789"
     * is 0xCBF43926 (the standard CRC-32/ISO-HDLC check value). This pins the
     * oracle itself before we trust it against the kernel. */
    {
        static const uint8_t check_vec[] = "123456789";   /* 9 bytes, no NUL */
        uint32_t got = zlib_crc32_oracle(check_vec, 9);
        CHECK(got == 0xCBF43926u, "check-vector crc32=0x%08x (want 0xCBF43926)", got);
        if (got == 0xCBF43926u) {
            printf("  ok   check-vector \"123456789\" crc32=0xCBF43926\n");
        }
    }

    /* empty */
    test_payload("empty", (const uint8_t *) "", 0);

    /* 1 byte */
    test_payload("one-byte", &one, 1);

    /* ~1 MiB pseudo-random-ish */
    big = malloc(big_len);
    if (big == NULL) {
        printf("  FAIL: OOM allocating big payload\n");
        g_fail = 1;
    } else {
        fill_pattern(big, big_len, 0xC0FFEEu);
        test_payload("1MiB-randomish", big, big_len);
        free(big);
    }

    /* all-zeros (1 MiB) */
    zeros = calloc(big_len, 1);
    if (zeros == NULL) {
        printf("  FAIL: OOM allocating zeros payload\n");
        g_fail = 1;
    } else {
        test_payload("1MiB-zeros", zeros, big_len);
        free(zeros);
    }

    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}
