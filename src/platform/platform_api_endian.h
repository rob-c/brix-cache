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

#if BRIX_PLATFORM_LINUX
#define BRIX_PLAT_NATIVE_HTOBE64 htobe64
#define BRIX_PLAT_NATIVE_BE64TOH be64toh
#define BRIX_PLAT_NATIVE_HTOBE32 htobe32
#define BRIX_PLAT_NATIVE_BE32TOH be32toh
#define BRIX_PLAT_NATIVE_HTOBE16 htobe16
#define BRIX_PLAT_NATIVE_BE16TOH be16toh
#elif BRIX_PLATFORM_DARWIN
#define BRIX_PLAT_NATIVE_HTOBE64 OSSwapHostToBigInt64
#define BRIX_PLAT_NATIVE_BE64TOH OSSwapBigToHostInt64
#define BRIX_PLAT_NATIVE_HTOBE32 OSSwapHostToBigInt32
#define BRIX_PLAT_NATIVE_BE32TOH OSSwapBigToHostInt32
#define BRIX_PLAT_NATIVE_HTOBE16 OSSwapHostToBigInt16
#define BRIX_PLAT_NATIVE_BE16TOH OSSwapBigToHostInt16
#elif BRIX_PLATFORM_WINDOWS
#define BRIX_PLAT_NATIVE_HTOBE64 _byteswap_uint64
#define BRIX_PLAT_NATIVE_BE64TOH _byteswap_uint64
#define BRIX_PLAT_NATIVE_HTOBE32 _byteswap_ulong
#define BRIX_PLAT_NATIVE_BE32TOH _byteswap_ulong
#define BRIX_PLAT_NATIVE_HTOBE16 _byteswap_ushort
#define BRIX_PLAT_NATIVE_BE16TOH _byteswap_ushort
#else
/* Preserve the existing fallback through network-order conversions. */
static inline uint64_t brix_plat_fallback_htobe64(uint64_t x) {
    return ((uint64_t)htonl((uint32_t)(x >> 32)) |
            ((uint64_t)htonl((uint32_t)x) << 32));
}
static inline uint64_t brix_plat_fallback_be64toh(uint64_t x) {
    return ((uint64_t)ntohl((uint32_t)(x >> 32)) |
            ((uint64_t)ntohl((uint32_t)x) << 32));
}
#define BRIX_PLAT_NATIVE_HTOBE64 brix_plat_fallback_htobe64
#define BRIX_PLAT_NATIVE_BE64TOH brix_plat_fallback_be64toh
#define BRIX_PLAT_NATIVE_HTOBE32 htonl
#define BRIX_PLAT_NATIVE_BE32TOH ntohl
#define BRIX_PLAT_NATIVE_HTOBE16 htons
#define BRIX_PLAT_NATIVE_BE16TOH ntohs
#endif

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
