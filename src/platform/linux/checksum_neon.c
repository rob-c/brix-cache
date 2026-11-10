/*
 * src/platform/linux/checksum_neon.c - ARM64 NEON SIMD checksum optimizations
 * 
 * Uses ARM NEON SIMD instructions for vectorized checksum and hash operations.
 * Computes Adler-32, Fletcher, CRC32C and simple checksums over bounded blocks.
 * 
 * 
 * References:
 * - ARM NEON Programming Guide
 * - ARM C Language Extensions (ACLE)
 * - arm_neon.h intrinsic reference
 */

#include "../platform.h"

#if BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64

#include "core/compat/crc32c.h"
#include "core/types/tunables_core.h"

#include <arm_neon.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__ARM_FEATURE_CRC32)
#include <arm_acle.h>
#endif

/* ---- Weighted contribution of one 16-byte block ----
 * WHAT: Returns sum((16 - i) * byte[i]) for a loaded vector.
 * WHY: Adler and Fletcher's second sum includes every prefix of the block.
 * HOW: 1. Multiply each half by descending weights. 2. Widen and add both sums.
 */
static uint32_t
brix_neon_weighted_sum(uint8x16_t bytes)
{
    const uint8_t low_weights[8] = {16, 15, 14, 13, 12, 11, 10, 9};
    const uint8_t high_weights[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    uint16x8_t low = vmull_u8(vget_low_u8(bytes), vld1_u8(low_weights));
    uint16x8_t high = vmull_u8(vget_high_u8(bytes), vld1_u8(high_weights));
    return vaddlvq_u16(low) + vaddlvq_u16(high);
}

/*
 * NEON-accelerated Adler-32 checksum
 *
 * WHAT: Extends Adler-32 with every input byte, retaining the supplied seed.
 * WHY: The vector second sum must include all sixteen byte prefixes.
 * HOW: 1. Add weighted blocks modulo 65521. 2. Add scalar tail bytes.
 * 
 * Processes 16 bytes per iteration using NEON vector operations.
 * Maintains two 32-bit accumulators (s1, s2) in parallel.
 * 
 * 
 * @param buf  Input buffer
 * @param len  Buffer length in bytes
 * @param adler Initial Adler-32 value (use 1 for fresh computation)
 * @return     Updated Adler-32 checksum
 */
uint32_t brix_adler32_neon(const uint8_t *buf, size_t len, uint32_t adler)
{
    const uint32_t MOD_ADLER = BRIX_ADLER_MOD;
    uint32_t s1 = adler & 0xFFFF;
    uint32_t s2 = (adler >> 16) & 0xFFFF;
    
    /* Process 16 bytes at a time using NEON */
    size_t nblocks = len / 16;
    const uint8_t *ptr = buf;
    
    while (nblocks > 0) {
        /* Load 16 bytes into NEON register */
        uint8x16_t v = vld1q_u8(ptr);
        
        /* Each prefix contributes the incoming s1 plus its weighted bytes. */
        s2 += 16 * s1 + brix_neon_weighted_sum(v);
        s1 += vaddlvq_u8(v);
        
        /* Reduce modulo ADLER_MOD periodically */
        s1 %= MOD_ADLER;
        s2 %= MOD_ADLER;
        
        ptr += 16;
        nblocks--;
    }
    
    /* Handle remaining bytes with scalar code */
    size_t remaining = len % 16;
    for (size_t i = 0; i < remaining; i++) {
        s1 += ptr[i];
        s2 += s1;
    }
    
    s1 %= MOD_ADLER;
    s2 %= MOD_ADLER;
    
    return (s2 << 16) | s1;
}

/*
 * NEON-accelerated Fletcher-16 checksum
 *
 * WHAT: Returns the two modulo-255 sums of the entire input.
 * WHY: Weighted prefix sums and bounded reduction preserve the scalar result.
 * HOW: 1. Add weighted blocks modulo 255. 2. Add and reduce the scalar tail.
 * 
 * Similar to Adler-32 but uses modulo 255 instead of 65521.
 * Processes 16 bytes per iteration.
 * 
 * 
 * @param buf  Input buffer
 * @param len  Buffer length
 * @return     Fletcher-16 checksum
 */
uint16_t brix_fletcher16_neon(const uint8_t *buf, size_t len)
{
    uint32_t s1 = 0, s2 = 0;
    
    size_t nblocks = len / 16;
    const uint8_t *ptr = buf;
    
    while (nblocks > 0) {
        uint8x16_t v = vld1q_u8(ptr);
        
        s2 = (s2 + 16 * s1 + brix_neon_weighted_sum(v)) % 255;
        s1 = (s1 + vaddlvq_u8(v)) % 255;
        
        ptr += 16;
        nblocks--;
    }
    
    size_t remaining = len % 16;
    for (size_t i = 0; i < remaining; i++) {
        s1 += ptr[i];
        s2 += s1;
    }
    
    s1 %= 255;
    s2 %= 255;
    
    return (uint16_t)((s2 << 8) | s1);
}

/*
 * NEON-accelerated XOR-based checksum (64-bit)
 *
 * WHAT: XORs each little-endian word and a zero-padded tail into the seed.
 * WHY: The seed must contribute once, including for an empty buffer.
 * HOW: 1. XOR zero-initialized vector lanes. 2. Fold into seed. 3. Add tail.
 * 
 * Computes 64-bit XOR checksum by processing 16 bytes at a time.
 * Useful for quick integrity checks where cryptographic strength
 * is not required.
 * 
 * 
 * @param buf  Input buffer
 * @param len  Buffer length
 * @param seed Initial seed value
 * @return     64-bit XOR checksum
 */
uint64_t brix_xor_checksum_neon(const uint8_t *buf, size_t len, uint64_t seed)
{
    uint64x2_t vseed = vdupq_n_u64(0);
    const uint8_t *ptr = buf;
    size_t qwords = len / 16;
    
    while (qwords > 0) {
        uint64x2_t v = vreinterpretq_u64_u8(vld1q_u8(ptr));
        vseed = veorq_u64(vseed, v);
        ptr += 16;
        qwords--;
    }
    
    /* Combine lanes */
    uint64_t result = seed ^ vgetq_lane_u64(vseed, 0) ^ vgetq_lane_u64(vseed, 1);
    
    /* Handle remaining bytes */
    size_t remaining = len % 16;
    
    for (size_t i = 0; i < remaining; i++) {
        result ^= ((uint64_t)ptr[i]) << ((i % 8) * 8);
    }
    
    return result;
}

/*
 * NEON-accelerated memcpy with checksum
 *
 * WHAT: Copies len bytes and extends the public, complemented CRC32C value.
 * WHY: Hardware and software paths must checksum identical bytes and seeds.
 * HOW: 1. Complement seed. 2. Copy/checksum blocks and tail. 3. Complement back.
 * 
 * Combines memory copy and checksum computation in a single pass,
 * improving cache efficiency and reducing memory bandwidth.
 * 
 * 
 * @param dest Destination buffer
 * @param src  Source buffer
 * @param len  Number of bytes to copy
 * @param crc  Initial CRC value (updated with checksum)
 * @return     Updated CRC value
 */
uint32_t brix_memcpy_crc32_neon(void *dest, const void *src, size_t len, uint32_t crc)
{
#if defined(__ARM_FEATURE_CRC32)
    uint8_t *dst = (uint8_t *)dest;
    const uint8_t *source = (const uint8_t *)src;
    /* Match brix_crc32c_extend's complemented public checksum convention. */
    crc = ~crc;
    
    size_t qwords = len / 16;
    
    while (qwords > 0) {
        /* Load from source */
        uint8x16_t v = vld1q_u8(source);
        
        /* Store to destination */
        vst1q_u8(dst, v);
        
        /* Compute CRC on the data */
        uint64x2_t words = vreinterpretq_u64_u8(v);
        crc = __crc32cd(crc, vgetq_lane_u64(words, 0));
        crc = __crc32cd(crc, vgetq_lane_u64(words, 1));
        
        source += 16;
        dst += 16;
        qwords--;
    }
    
    /* Handle remaining bytes */
    size_t remaining = len % 16;
    for (size_t i = 0; i < remaining; i++) {
        dst[i] = source[i];
        crc = __crc32cb(crc, source[i]);
    }
    
    return ~crc;
#else
    /* Fallback: separate memcpy and CRC */
    memcpy(dest, src, len);
    return brix_crc32c_extend(crc, src, len);
#endif
}

/*
 * NEON vectorized sum for error detection
 * 
 * Computes sum of all bytes in buffer using NEON parallelism.
 * Returns 32-bit sum (can be used for simple error detection).
 * 
 * 
 * @param buf  Input buffer
 * @param len  Buffer length
 * @return     Sum of all bytes (mod 2^32)
 */
uint32_t brix_byte_sum_neon(const uint8_t *buf, size_t len)
{
    uint32x4_t vsum = vdupq_n_u32(0);
    const uint8_t *ptr = buf;
    
    size_t nblocks = len / 64;
    
    while (nblocks > 0) {
        /* Load 64 bytes */
        uint8x16_t v0 = vld1q_u8(ptr);
        uint8x16_t v1 = vld1q_u8(ptr + 16);
        uint8x16_t v2 = vld1q_u8(ptr + 32);
        uint8x16_t v3 = vld1q_u8(ptr + 48);
        
        /* Widen to 16-bit */
        uint16x8_t v0_low = vmovl_u8(vget_low_u8(v0));
        uint16x8_t v0_high = vmovl_u8(vget_high_u8(v0));
        uint16x8_t v1_low = vmovl_u8(vget_low_u8(v1));
        uint16x8_t v1_high = vmovl_u8(vget_high_u8(v1));
        uint16x8_t v2_low = vmovl_u8(vget_low_u8(v2));
        uint16x8_t v2_high = vmovl_u8(vget_high_u8(v2));
        uint16x8_t v3_low = vmovl_u8(vget_low_u8(v3));
        uint16x8_t v3_high = vmovl_u8(vget_high_u8(v3));
        
        /* Sum pairs */
        uint16x8_t sum0 = vpaddq_u16(v0_low, v0_high);
        uint16x8_t sum1 = vpaddq_u16(v1_low, v1_high);
        uint16x8_t sum2 = vpaddq_u16(v2_low, v2_high);
        uint16x8_t sum3 = vpaddq_u16(v3_low, v3_high);
        
        /* Widen to 32-bit and accumulate */
        uint32x4_t s0 = vpaddlq_u16(sum0);
        uint32x4_t s1 = vpaddlq_u16(sum1);
        uint32x4_t s2 = vpaddlq_u16(sum2);
        uint32x4_t s3 = vpaddlq_u16(sum3);
        
        vsum = vaddq_u32(vsum, s0);
        vsum = vaddq_u32(vsum, s1);
        vsum = vaddq_u32(vsum, s2);
        vsum = vaddq_u32(vsum, s3);
        
        ptr += 64;
        nblocks--;
    }
    
    /* Reduce vector to scalar */
    uint32x2_t vlow = vget_low_u32(vsum);
    uint32x2_t vhigh = vget_high_u32(vsum);
    uint32x2_t vtotal = vpadd_u32(vlow, vhigh);
    uint32_t sum = vget_lane_u32(vtotal, 0) + vget_lane_u32(vtotal, 1);
    
    /* Handle remaining bytes */
    size_t remaining = len % 64;
    for (size_t i = 0; i < remaining; i++) {
        sum += ptr[i];
    }
    
    return sum;
}



#endif /* BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64 */
