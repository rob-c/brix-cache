/* Inline byte order conversions.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * BYTE ORDER OPERATIONS (inline for performance)
 *
 * Host <-> Big-Endian conversion for 16/32/64-bit integers.
 * These are inline functions for zero overhead.
 * ========================================================================== */

/* The host names its native operations as BRIX_PLAT_NATIVE_*. */
#include BRIX_PLAT_HOST_HEADER(host_endian.h)

/* One wrapper body per public API; the mapping above selects its native operation. */
static inline uint64_t brix_plat_htobe64(uint64_t x) { return BRIX_PLAT_NATIVE_HTOBE64(x); }
static inline uint64_t brix_plat_be64toh(uint64_t x) { return BRIX_PLAT_NATIVE_BE64TOH(x); }
static inline uint32_t brix_plat_htobe32(uint32_t x) { return BRIX_PLAT_NATIVE_HTOBE32(x); }
static inline uint32_t brix_plat_be32toh(uint32_t x) { return BRIX_PLAT_NATIVE_BE32TOH(x); }
static inline uint16_t brix_plat_htobe16(uint16_t x) { return BRIX_PLAT_NATIVE_HTOBE16(x); }
static inline uint16_t brix_plat_be16toh(uint16_t x) { return BRIX_PLAT_NATIVE_BE16TOH(x); }

#undef BRIX_PLAT_NATIVE_HTOBE64
#undef BRIX_PLAT_NATIVE_BE64TOH
#undef BRIX_PLAT_NATIVE_HTOBE32
#undef BRIX_PLAT_NATIVE_BE32TOH
#undef BRIX_PLAT_NATIVE_HTOBE16
#undef BRIX_PLAT_NATIVE_BE16TOH
