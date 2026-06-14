#ifndef XROOTD_COMPAT_CRC32C_H
#define XROOTD_COMPAT_CRC32C_H

#include <stddef.h>
#include <stdint.h>

/*
 * xrootd_crc32c_value - compute CRC-32c checksum of a buffer.
 *
 * WHAT: Computes the CRC-32c (Castagnoli) polynomial hash over buf[0..len] and
 *       returns the 32-bit result. Uses SSE4.2 hardware on x86_64, software fallback
 *       otherwise.
 *
 * WHY: XRootD pgread/pgwrite per-page CRC32c validation (Invariant #1). Used to verify
 *      data integrity during reads and writes without needing an fd.
 *
 * HOW: Delegates to xrootd_crc32c_extend(0, buf, len).
 */
uint32_t xrootd_crc32c_value(const void *buf, size_t len);

/* Contract: CRC-32c (Castagnoli, refin/refout, init 0) of buf[0..len), returned
 * as the seed-0 case of xrootd_crc32c_extend. buf is read-only and unowned.
 * buf==NULL with len!=0 is a no-op that returns 0 (the seed); len==0 returns 0. */
uint32_t xrootd_crc32c_value(const void *buf, size_t len);
/*
 * xrootd_crc32c_copy_value - compute CRC-32c while copying buffer contents.
 *
 * WHAT: Copies src[0..len] into dst and simultaneously computes the CRC-32c checksum,
 *       returning the 32-bit result. Uses SSE4.2 hardware on x86_64, software fallback
 *       otherwise.
 *
 * WHY: TPC (transfer between clients) needs to copy data while computing checksums
 *      for integrity verification — avoids a second pass over the data.
 *
 * HOW: Delegates to xrootd_crc32c_copy_hw() or xrootd_crc32c_copy_sw() depending on
 *      SSE4.2 availability.
 */
uint32_t xrootd_crc32c_copy_value(const unsigned char *src,
    unsigned char *dst, size_t len);

/* Contract: single-pass copy src[0..len) -> dst[0..len) returning the CRC-32c of
 * the bytes copied. dst is caller-owned and must hold >= len bytes; buffers must
 * not overlap. If src or dst is NULL while len!=0 it copies nothing and returns 0
 * (NOT a valid checksum). len==0 returns 0. */
uint32_t xrootd_crc32c_copy_value(const unsigned char *src,
    unsigned char *dst, size_t len);
/*
 * xrootd_crc32c_extend - incrementally extend a CRC-32c checksum with new data.
 *
 * WHAT: Takes an existing CRC-32c value (crc) and updates it by absorbing buf[0..len].
 *       Returns the extended 32-bit checksum. Uses SSE4.2 hardware on x86_64, software
 *       fallback otherwise.
 *
 * WHY: pgread/pgwrite per-page CRC32c validation requires incrementally updating the
 *      checksum for each page (Invariant #1). This is the core extend function used by
 *      xrootd_checksum_u32_fd() and the pgread/pgwrite CRC paths.
 *
 * HOW: Delegates to xrootd_crc32c_hw_extend() on SSE4.2 (_mm_crc32_u64/u32/u8 intrinsics)
 *      or xrootd_crc32c_sw_extend() (bit-by-bit Castagnoli polynomial) otherwise.
 */
uint32_t xrootd_crc32c_extend(uint32_t crc, const void *buf, size_t len);

/* Contract: rolling CRC-32c update — absorbs buf[0..len) into the running value
 * crc and returns the new value (seed with 0 for a fresh checksum). buf is
 * read-only and unowned. buf==NULL with len!=0 returns crc unchanged (no-op);
 * len==0 returns crc. Picks a 3-way-parallel HW path for buffers >= 3*SHORT. */
uint32_t xrootd_crc32c_extend(uint32_t crc, const void *buf, size_t len);

#endif /* XROOTD_COMPAT_CRC32C_H */
