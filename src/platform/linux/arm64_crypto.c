/*
 * src/platform/linux/arm64_crypto.c - ARM64 cryptographic acceleration
 * 
 * Hardware-accelerated CRC32 and checksum operations for ARM64 Linux.
 * Uses ARMv8-A CRC extensions when available.
 * 
 * CPU feature detection:
 * - HWCAP_CRC32: CRC32 instructions available
 * - HWCAP_PMULL: Polynomial multiply for carry-less multiplication
 * - HWCAP_SHA2: SHA2 instructions
 * 
 * Fallback: Generic C implementation if hardware features unavailable
 */

#include "../platform.h"

#if BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64

#include "../platform_api.h"
#include "core/compat/crc32c.h"
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ==========================================================================
 * CPU FEATURE DETECTION
 * ========================================================================== */

/* ARM64 hardware capability bits */
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1 << 7)
#endif

#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 8)
#endif

#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 11)
#endif

static int g_arm64_has_crc32 = -1;
static int g_arm64_has_pmull = -1;
static int g_arm64_has_sha2 = -1;

void
brix_arm64_detect_features(void)
{
    unsigned long hwcap = getauxval(AT_HWCAP);
    
    g_arm64_has_crc32 = (hwcap & HWCAP_CRC32) ? 1 : 0;
    g_arm64_has_pmull = (hwcap & HWCAP_PMULL) ? 1 : 0;
    g_arm64_has_sha2 = (hwcap & HWCAP_SHA2) ? 1 : 0;
}

int
brix_arm64_has_crc32_instructions(void)
{
    if (g_arm64_has_crc32 < 0) {
        brix_arm64_detect_features();
    }
    return g_arm64_has_crc32;
}

/* ==========================================================================
 * CRC32C HARDWARE ACCELERATION
 * ========================================================================== */

#if defined(__ARM_FEATURE_CRC32)

#include <arm_acle.h>

/*
 * Hardware CRC32C using ARMv8-A CRC extensions
 * 
 * Performance: ~1 cycle per byte (vs ~10 cycles/byte for software)
 * Instructions used:
 *   - __crc32cb: CRC32 of byte
 *   - __crc32ch: CRC32 of halfword
 *   - __crc32cw: CRC32 of word
 *   - __crc32cd: CRC32 of doubleword
 */

uint32_t
brix_crc32c_arm64_hw(const uint8_t *buf, size_t len, uint32_t crc)
{
    /* Process 8 bytes at a time using 64-bit CRC */
    while (len >= 8) {
        uint64_t val;
        memcpy(&val, buf, sizeof(val));
        crc = __crc32cd(crc, val);
        buf += 8;
        len -= 8;
    }
    
    /* Process 4 bytes */
    if (len >= 4) {
        uint32_t val;
        memcpy(&val, buf, sizeof(val));
        crc = __crc32cw(crc, val);
        buf += 4;
        len -= 4;
    }
    
    /* Process 2 bytes */
    if (len >= 2) {
        uint16_t val;
        memcpy(&val, buf, sizeof(val));
        crc = __crc32ch(crc, val);
        buf += 2;
        len -= 2;
    }
    
    /* Process 1 byte */
    if (len >= 1) {
        crc = __crc32cb(crc, *buf);
    }
    
    return crc;
}

#endif /* __ARM_FEATURE_CRC32 */

/* ---- Raw CRC32C compatibility fallback ----
 * WHAT: Extends a raw, uncomplemented CRC32C register over the input bytes.
 * WHY: The hardware helper exposes raw register state; the canonical helper
 * exposes a complemented checksum. Both dispatch arms must preserve the ABI.
 * HOW: 1. Complement the incoming state. 2. Extend through the shared engine.
 * 3. Complement its result back to the raw register convention.
 */
uint32_t
brix_crc32c_generic(const uint8_t *buf, size_t len, uint32_t crc)
{
    return ~brix_crc32c_extend(~crc, buf, len);
}

/*
 * Dispatch function: hardware or software CRC32C
 */
uint32_t
brix_crc32c_dispatch(const uint8_t *buf, size_t len, uint32_t crc)
{
#if defined(__ARM_FEATURE_CRC32)
    if (brix_arm64_has_crc32_instructions()) {
        return brix_crc32c_arm64_hw(buf, len, crc);
    }
#endif
    return brix_crc32c_generic(buf, len, crc);
}

/* ==========================================================================
 * NEON SIMD CHECKSUM
 * ========================================================================== */

#if defined(__ARM_NEON)

#include <arm_neon.h>

/* ---- Sum a partial vector as zero-padded 64-bit words ----
 * WHAT: Returns the modulo-2^64 sum of all remaining whole and partial words.
 * WHY: Adding tail bytes individually changes the checksum at vector boundaries.
 * HOW: 1. Copy at most eight bytes into a zeroed word. 2. Add and advance.
 */
static uint64_t
brix_arm64_word_tail(const uint8_t *data, size_t length)
{
    uint64_t sum = 0;
    while (length != 0) {
        uint64_t word = 0;
        size_t count = length < sizeof(word) ? length : sizeof(word);
        memcpy(&word, data, count);
        sum += word;
        data += count;
        length -= count;
    }
    return sum;
}

/*
 * NEON-accelerated checksum using SIMD
 *
 * WHAT: Returns the modulo-2^64 sum of native words, zero-padding the last word.
 * WHY: Vector and scalar paths must give the same result for unaligned tails.
 * HOW: 1. Sum groups of four words. 2. Reduce lanes. 3. Add bounded tail words.
 * 
 * Processes 16 bytes per iteration using 128-bit NEON registers
 * Can be extended to 32 bytes with SVE (Scalable Vector Extension)
 * 
 * Algorithm: Sum all 64-bit words modulo 2^64
 * 
 * Performance: ~4x faster than scalar implementation
 */

uint64_t
brix_checksum_neon(const void *buf, size_t len)
{
    const uint8_t *data = (const uint8_t *)buf;
    uint64x2_t sum0 = vdupq_n_u64(0);
    uint64x2_t sum1 = vdupq_n_u64(0);
    size_t i;
    
    /* Process 32 bytes (4 x 64-bit words) per iteration */
    for (i = 0; i < len / 32; i++) {
        uint64x2_t v0 = vreinterpretq_u64_u8(vld1q_u8(data + i * 32));
        uint64x2_t v1 = vreinterpretq_u64_u8(vld1q_u8(data + i * 32 + 16));
        
        sum0 = vaddq_u64(sum0, v0);
        sum1 = vaddq_u64(sum1, v1);
    }
    
    /* Accumulate sums */
    sum0 = vaddq_u64(sum0, sum1);
    
    /* Horizontal add */
    uint64_t result = vgetq_lane_u64(sum0, 0) + vgetq_lane_u64(sum0, 1);
    
    /* Handle remaining bytes */
    size_t remaining = len % 32;
    return result + brix_arm64_word_tail(data + i * 32, remaining);
}

#endif /* __ARM_NEON */

/* ==========================================================================
 * SVE ACCELERATION (Future)
 * ========================================================================== */

#if defined(__ARM_FEATURE_SVE)

#include <arm_sve.h>

/*
 * SVE (Scalable Vector Extension) checksum
 * 
 * SVE provides variable-length vector registers (128-2048 bits)
 * This implementation adapts to the hardware's vector length
 * 
 * Performance: Scales with vector length (2x NEON on 256-bit SVE)
 * 
 * Note: Requires ARMv8.2-A or later with SVE extension
 */

uint64_t
brix_checksum_sve(const void *buf, size_t len)
{
    const uint64_t *data = (const uint64_t *)buf;
    size_t vl;  /* Vector length in elements */
    uint64_t sum = 0;
    size_t i = 0;
    
    /* Get vector length */
    vl = svcntd();  /* Count of 64-bit elements in vector */
    
    /* Process vectors */
    while (i + vl <= len / 8) {
        svuint64_t v = svld1_u64(svptrue_b64(), data + i);
        sum += svaddv_u64(svptrue_b64(), v);
        i += vl;
    }
    
    /* Handle scalar tail */
    for (size_t j = i * 8; j < len; j++) {
        sum += ((const uint8_t *)buf)[j];
    }
    
    return sum;
}

#endif /* __ARM_FEATURE_SVE */

/* ==========================================================================
 * INITIALIZATION
 * ========================================================================== */

void
brix_arm64_init(void)
{
    brix_arm64_detect_features();
}

/*
 * Get ARM64 optimization info
 */
const char *
brix_arm64_get_optimization_info(void)
{
    static char info[256];
    
    if (g_arm64_has_crc32 < 0) {
        brix_arm64_detect_features();
    }
    
    snprintf(info, sizeof(info),
             "ARM64: CRC32=%s, PMULL=%s, SHA2=%s",
             g_arm64_has_crc32 ? "yes" : "no",
             g_arm64_has_pmull ? "yes" : "no",
             g_arm64_has_sha2 ? "yes" : "no");
    
    return info;
}

#endif /* BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64 */
