/*
 * crc32c.c - CRC-32c (Castagnoli polynomial) checksum implementation.
 *
 * WHAT: Implements CRC-32c with both SSE4.2 hardware acceleration (_mm_crc32_u64/u32/u8)
 *       and software fallback (bit-by-bit Castagnoli polynomial 0x82F63B78). Provides
 *       extend, value-compute, and copy-with-checksum operations.
 *
 * WHY: XRootD pgread/pgwrite per-page CRC32c validation (Invariant #1) requires fast
 *      checksum computation. TPC data transfer needs copy + checksum in a single pass.
 *      This file is the shared CRC-32c engine for all 32-bit checksum paths.
 *
 * HOW: Software path uses bit-by-bit polynomial division with precomputed constant.
 *      SSE4.2 path processes 8-byte chunks via _mm_crc32_u64, then 4-byte and byte
 *      tail. CPU feature detection via __builtin_cpu_supports("sse4.2") cached in
 *      xrootd_crc32c_has_sse42.
 */
#include "crc32c.h"

#include <string.h>

#ifdef __x86_64__
#include <nmmintrin.h>
#endif

#define XROOTD_CRC32C_POLY 0x82F63B78u

/*
 * xrootd_crc32c_sw_extend - software CRC-32c (Castagnoli polynomial) increment.
 *
 * WHAT: Computes CRC-32c over p[0..len] using bit-by-bit polynomial division with
 *       the Castagnoli polynomial 0x82F63B78. Takes initial crc value and returns
 *       extended checksum.
 *
 * WHY: Fallback path when SSE4.2 is unavailable (ARM, older x86). Used by
 *      xrootd_crc32c_extend() when __builtin_cpu_supports("sse4.2") returns false.
 *      Also used in tests to verify hardware correctness.
 *
 * HOW: XOR crc with 0xFFFFFFFF, then for each byte: XOR into crc, shift right 1 bit,
 *      XOR with polynomial if LSB was set. Final XOR with 0xFFFFFFFF (standard CRC
 *      complement). O(len*8) bit operations.
 */

static uint32_t
xrootd_crc32c_sw_extend(uint32_t crc, const unsigned char *p, size_t len)
{
    crc ^= 0xFFFFFFFFu;

    while (len--) {
        int bit;

        crc ^= *p++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (XROOTD_CRC32C_POLY & (uint32_t) -(int) (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

/*
 * xrootd_crc32c_copy_sw - software copy + CRC-32c in single pass.
 *
 * WHAT: Copies src[0..len] into dst while simultaneously computing CRC-32c checksum,
 *       returning the 32-bit result. Same algorithm as sw_extend but interleaves copy.
 *
 * WHY: TPC (transfer between clients) needs to copy data and compute checksum in one
 *      pass — avoids reading the source twice. Used by xrootd_crc32c_copy_value().
 *
 * HOW: For each byte: read from src, write to dst, XOR into running CRC state,
 *      shift+polynomial per bit (same as sw_extend). Returns complemented result.
 */

static uint32_t
xrootd_crc32c_copy_sw(const unsigned char *src, unsigned char *dst, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;

    while (len--) {
        int           bit;
        unsigned char b;

        b = *src++;
        *dst++ = b;

        crc ^= b;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (XROOTD_CRC32C_POLY & (uint32_t) -(int) (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

#ifdef __x86_64__

static int xrootd_crc32c_has_sse42 = -1;

/*
 * xrootd_crc32c_sse42_available - detect SSE4.2 CPU feature with lazy caching.
 *
 * WHAT: Returns 1 if the CPU supports SSE4.2 (needed for _mm_crc32_u64 intrinsics),
 *       0 if not. Caches result in xrootd_crc32c_has_sse42 to avoid repeated detection.
 *
 * WHY: CRC-32c hardware path uses Intel SSE4.2 intrinsics (_mm_crc32_u64/u32/u8).
 *      This function determines whether to use the fast hw_extend() or sw_extend().
 *
 * HOW: First call uses __builtin_cpu_supports("sse4.2") (GCC/Clang builtin). Result
 *      cached in xrootd_crc32c_has_sse42 (initialized to -1 = unknown). Subsequent
 *      calls return cached value.
 */

static int
xrootd_crc32c_sse42_available(void)
{
    if (xrootd_crc32c_has_sse42 < 0) {
        xrootd_crc32c_has_sse42 =
            __builtin_cpu_supports("sse4.2") ? 1 : 0;
    }

    return xrootd_crc32c_has_sse42;
}

__attribute__((target("sse4.2")))
/*
 * xrootd_crc32c_hw_extend - SSE4.2 hardware CRC-32c increment.
 *
 * WHAT: Computes CRC-32c over p[0..len] using Intel _mm_crc32_u64/u32/u8 intrinsics.
 *       Processes 8-byte chunks at a time, then 4-byte and byte tail. Returns
 *       extended checksum from initial crc value.
 *
 * WHY: Fast path for CRC-32c on x86_64 CPUs with SSE4.2 (most modern servers).
 *      Used by xrootd_crc32c_extend() when SSE4.2 is available. ~100x faster than
 *      software path for large buffers.
 *
 * HOW: XOR crc with 0xFFFFFFFF → uint64_t state. Loop: memcpy 8 bytes, _mm_crc32_u64;
 *      then 4-byte chunk if remaining >= 4; then byte-by-byte tail via _mm_crc32_u8.
 *      Final XOR complement. __attribute__((target("sse4.2")) ensures correct codegen.
 */

static uint32_t
xrootd_crc32c_hw_extend(uint32_t crc, const unsigned char *p, size_t len)
{
    uint64_t state;

    state = (uint64_t) (crc ^ 0xFFFFFFFFu);

    while (len >= 8) {
        uint64_t v;

        memcpy(&v, p, 8);
        state = _mm_crc32_u64(state, v);
        p += 8;
        len -= 8;
    }

    if (len >= 4) {
        uint32_t v;

        memcpy(&v, p, 4);
        state = _mm_crc32_u32((uint32_t) state, v);
        p += 4;
        len -= 4;
    }

    while (len--) {
        state = _mm_crc32_u8((uint32_t) state, *p++);
    }

    return (uint32_t) state ^ 0xFFFFFFFFu;
}

__attribute__((target("sse4.2")))
/*
 * xrootd_crc32c_copy_hw - SSE4.2 hardware copy + CRC-32c in single pass.
 *
 * WHAT: Copies src[0..len] into dst while computing CRC-32c using _mm_crc32_u64/u32/u8
 *       intrinsics. Processes 8-byte chunks at a time, then 4-byte and byte tail.
 *
 * WHY: TPC data transfer on SSE4.2 CPUs — copy + checksum in one pass with hardware
 *      acceleration. Used by xrootd_crc32c_copy_value() when SSE4.2 available.
 *
 * HOW: Same loop structure as hw_extend but interleaves memcpy(dst, &v, N) after each
 *      _mm_crc32_uXX operation. Final XOR complement returns checksum result.
 */

static uint32_t
xrootd_crc32c_copy_hw(const unsigned char *src, unsigned char *dst, size_t len)
{
    uint64_t state = 0xFFFFFFFFu;

    while (len >= 8) {
        uint64_t v;

        memcpy(&v, src, 8);
        state = _mm_crc32_u64(state, v);
        memcpy(dst, &v, 8);
        src += 8;
        dst += 8;
        len -= 8;
    }

    if (len >= 4) {
        uint32_t v;

        memcpy(&v, src, 4);
        state = _mm_crc32_u32((uint32_t) state, v);
        memcpy(dst, &v, 4);
        src += 4;
        dst += 4;
        len -= 4;
    }

    while (len--) {
        unsigned char b;

        b = *src++;
        state = _mm_crc32_u8((uint32_t) state, b);
        *dst++ = b;
    }

    return (uint32_t) state ^ 0xFFFFFFFFu;
}

#endif

uint32_t
xrootd_crc32c_extend(uint32_t crc, const void *buf, size_t len)
{
    const unsigned char *p;

    if (buf == NULL && len != 0) {
        return crc;
    }

    p = (const unsigned char *) buf;

#ifdef __x86_64__
    if (xrootd_crc32c_sse42_available()) {
        return xrootd_crc32c_hw_extend(crc, p, len);
    }
#endif

    return xrootd_crc32c_sw_extend(crc, p, len);
}

uint32_t
xrootd_crc32c_value(const void *buf, size_t len)
{
    return xrootd_crc32c_extend(0, buf, len);
}

uint32_t
xrootd_crc32c_copy_value(const unsigned char *src, unsigned char *dst,
    size_t len)
{
    if ((src == NULL || dst == NULL) && len != 0) {
        return 0;
    }

#ifdef __x86_64__
    if (xrootd_crc32c_sse42_available()) {
        return xrootd_crc32c_copy_hw(src, dst, len);
    }
#endif

    return xrootd_crc32c_copy_sw(src, dst, len);
}
