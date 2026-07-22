#ifndef BRIX_COMPAT_CRC32C_INTERNAL_H
#define BRIX_COMPAT_CRC32C_INTERNAL_H

/*
 * crc32c_internal.h - shared internals for the CRC-32c engine split across
 * crc32c.c (public dispatch + software path) and crc32c_hw.c (SSE4.2 hardware
 * and 3-way-parallel paths). Not a public API — do not include outside the
 * crc32c*.c translation units in this directory.
 */

#include <stddef.h>
#include <stdint.h>

/* Castagnoli reflected polynomial — shared by the software bit-by-bit path and
 * the GF(2) zeros-operator construction in the hardware combine tables. */
#define BRIX_CRC32C_POLY 0x82F63B78u

/* SHORT parallel-block length; also the dispatch threshold (3*SHORT bytes)
 * below which the 3-way-parallel hardware paths do not pay off. */
#define BRIX_CRC32C_SHORT 256     /* must be a power of two */

#ifdef __x86_64__

/* Cross-split hardware entry points defined in crc32c_hw.c and called by the
 * dispatch functions in crc32c.c. Single-file helpers stay static in crc32c_hw.c. */

int brix_crc32c_sse42_available(void);

uint32_t brix_crc32c_hw_extend(uint32_t crc, const unsigned char *p, size_t len);

uint32_t brix_crc32c_hw3_extend(uint32_t crc, const unsigned char *p, size_t len);

uint32_t brix_crc32c_copy_hw(const unsigned char *src, unsigned char *dst,
    size_t len);

uint32_t brix_crc32c_copy_hw3(const unsigned char *src, unsigned char *dst,
    size_t len);

#endif /* __x86_64__ */

#endif /* BRIX_COMPAT_CRC32C_INTERNAL_H */
