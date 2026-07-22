/*
 * crc32c.c - CRC-32c (Castagnoli polynomial) checksum: dispatch + software path.
 *
 * WHAT: Public CRC-32c API (extend, value-compute, copy-with-checksum) plus the
 *       portable software fallback (bit-by-bit Castagnoli polynomial 0x82F63B78).
 *       On x86_64 it dispatches to the SSE4.2 hardware and 3-way-parallel paths in
 *       crc32c_hw.c (declared in crc32c_internal.h); everywhere else it uses the
 *       software path here.
 *
 * WHY: XRootD pgread/pgwrite per-page CRC32c validation (Invariant #1) requires fast
 *      checksum computation. TPC data transfer needs copy + checksum in a single pass.
 *      This file is the shared entry point for all 32-bit checksum paths.
 *
 * HOW: Software path uses bit-by-bit polynomial division with a precomputed constant.
 *      brix_crc32c_extend / _copy_value pick the 3-way-parallel hardware path for
 *      buffers >= 3*SHORT, the serial hardware path for smaller x86_64 buffers, and
 *      the software path when SSE4.2 is unavailable (via brix_crc32c_sse42_available).
 */
#include "crc32c.h"
#include "crc32c_internal.h"

/*
 * brix_crc32c_sw_extend - software CRC-32c (Castagnoli polynomial) increment.
 *
 * WHAT: Computes CRC-32c over p[0..len] using bit-by-bit polynomial division with
 *       the Castagnoli polynomial 0x82F63B78. Takes initial crc value and returns
 *       extended checksum.
 *
 * WHY: Fallback path when SSE4.2 is unavailable (ARM, older x86). Used by
 *      brix_crc32c_extend() when __builtin_cpu_supports("sse4.2") returns false.
 *      Also used in tests to verify hardware correctness.
 *
 * HOW: XOR crc with 0xFFFFFFFF, then for each byte: XOR into crc, shift right 1 bit,
 *      XOR with polynomial if LSB was set. Final XOR with 0xFFFFFFFF (standard CRC
 *      complement). O(len*8) bit operations.
 */

static uint32_t
brix_crc32c_sw_extend(uint32_t crc, const unsigned char *p, size_t len)
{
    crc ^= 0xFFFFFFFFu;

    while (len--) {
        int bit;

        crc ^= *p++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (BRIX_CRC32C_POLY & (uint32_t) -(int) (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

/*
 * brix_crc32c_copy_sw - software copy + CRC-32c in single pass.
 *
 * WHAT: Copies src[0..len] into dst while simultaneously computing CRC-32c checksum,
 *       returning the 32-bit result. Same algorithm as sw_extend but interleaves copy.
 *
 * WHY: TPC (transfer between clients) needs to copy data and compute checksum in one
 *      pass — avoids reading the source twice. Used by brix_crc32c_copy_value().
 *
 * HOW: For each byte: read from src, write to dst, XOR into running CRC state,
 *      shift+polynomial per bit (same as sw_extend). Returns complemented result.
 */

static uint32_t
brix_crc32c_copy_sw(const unsigned char *src, unsigned char *dst, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;

    while (len--) {
        int           bit;
        unsigned char b;

        b = *src++;
        *dst++ = b;

        crc ^= b;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (BRIX_CRC32C_POLY & (uint32_t) -(int) (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

uint32_t
brix_crc32c_extend(uint32_t crc, const void *buf, size_t len)
{
    const unsigned char *p;

    if (buf == NULL && len != 0) {
        return crc;
    }

    p = (const unsigned char *) buf;

#ifdef __x86_64__
    if (brix_crc32c_sse42_available()) {
        /*
         * The 3-way parallel path only pays off once a SHORT block triple fits
         * (>= 768 bytes); below that its prologue is pure overhead, so small
         * buffers (the common per-page pgread/pgwrite case is one 4 KiB page,
         * which still benefits) use the straight serial loop.
         */
        if (len >= BRIX_CRC32C_SHORT * 3) {
            return brix_crc32c_hw3_extend(crc, p, len);
        }
        return brix_crc32c_hw_extend(crc, p, len);
    }
#endif

    return brix_crc32c_sw_extend(crc, p, len);
}

uint32_t
brix_crc32c_value(const void *buf, size_t len)
{
    return brix_crc32c_extend(0, buf, len);
}

uint32_t
brix_crc32c_copy_value(const unsigned char *src, unsigned char *dst,
    size_t len)
{
    if ((src == NULL || dst == NULL) && len != 0) {
        return 0;
    }

#ifdef __x86_64__
    if (brix_crc32c_sse42_available()) {
        /*
         * Mirror brix_crc32c_extend's dispatch: the 3-way parallel copy only
         * pays off once a SHORT-block triple fits (>= 768 bytes); below that its
         * recombine prologue is pure overhead. The 4 KiB pgread/pgwrite page is
         * well above the threshold, so the data plane takes the fast path.
         */
        if (len >= BRIX_CRC32C_SHORT * 3) {
            return brix_crc32c_copy_hw3(src, dst, len);
        }
        return brix_crc32c_copy_hw(src, dst, len);
    }
#endif

    return brix_crc32c_copy_sw(src, dst, len);
}
