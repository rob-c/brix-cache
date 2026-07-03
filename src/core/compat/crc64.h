#ifndef BRIX_COMPAT_CRC64_H
#define BRIX_COMPAT_CRC64_H

/*
 * crc64.h - parameterized 64-bit CRC kernel (pure, ngx-free).
 *
 * WHAT: Whole-buffer and rolling CRC64 for the two variants this gateway
 *       exposes as checksum types:
 *         BRIX_CRC64_XZ   = CRC-64/XZ   (a.k.a. GO-ECMA; the common library
 *                             "crc64"). reflected, init/xorout all-FF,
 *                             normal poly 0x42F0E1EBA9EA3693
 *                             (reflected 0xC96C5795D7870F42),
 *                             check("123456789") = 0x995DC9BBDF1939FA.
 *         BRIX_CRC64_NVME = CRC-64/NVME (a.k.a. Rocksoft; AWS S3
 *                             x-amz-checksum-crc64nvme; Linux crc64_rocksoft).
 *                             reflected, init/xorout all-FF, normal poly
 *                             0xAD93D23594C93659 (reflected 0x9A6C9329AC4BC9B5),
 *                             check("123456789") = 0xAE8B14860A799888.
 * WHY:  Stock XRootD ships no crc64 calculator, so this is the single shared
 *       engine behind every protocol surface (root:// kXR_Qcksum, WebDAV Digest,
 *       S3 x-amz-checksum-crc64nvme) and the native client, mirroring how
 *       crc32c.c backs all 32-bit checksum paths. Pure C with no nginx/OpenSSL
 *       deps so it builds into libxrdproto (build-in-place) for the client too.
 * HOW:  256-entry reflected lookup table per variant (built once at load by a
 *       constructor, single-threaded before any worker runs); byte-at-a-time
 *       table-driven extend. crc64_combine implements the zlib crc32_combine
 *       GF(2) construction at 64-bit width for S3 multipart FULL_OBJECT values.
 *       No hardware path: x86 baseline has no CRC64 instruction.
 *
 * IMPORTANT: per-protocol ENCODING (16 lowercase hex for root://+WebDAV-legacy,
 * base64 of the 8 big-endian bytes for S3 + RFC 9530) is handled by callers, not
 * here. This kernel only returns the raw uint64_t register value.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    BRIX_CRC64_XZ   = 0,   /* CRC-64/XZ   — generic "crc64"/"crc64xz" */
    BRIX_CRC64_NVME = 1    /* CRC-64/NVME — S3 "crc64nvme" */
} brix_crc64_variant_t;

/*
 * brix_crc64_extend - rolling CRC64 update for the given variant.
 *
 * Contract: absorbs buf[0..len) into the running value crc and returns the new
 * value; seed with 0 for a fresh checksum (init=all-FF is applied internally, as
 * for crc32c). buf is read-only and unowned. buf==NULL with len!=0 returns crc
 * unchanged (no-op); len==0 returns crc. An unknown variant returns crc.
 */
uint64_t brix_crc64_extend(brix_crc64_variant_t variant, uint64_t crc,
    const void *buf, size_t len);

/*
 * brix_crc64_value - one-shot CRC64 of buf[0..len) for the given variant.
 * Equivalent to brix_crc64_extend(variant, 0, buf, len).
 */
uint64_t brix_crc64_value(brix_crc64_variant_t variant, const void *buf,
    size_t len);

/*
 * brix_crc64_combine - combine two CRC64 values without re-reading data.
 *
 * Contract: given crc1 = crc64(A) and crc2 = crc64(B) with |B| = len2 bytes,
 * returns crc64(A concatenated with B). Used for S3 multipart FULL_OBJECT, where
 * the whole-object checksum is derived from the per-part checksums. Mirrors
 * zlib's crc32_combine over GF(2) at 64-bit width. len2==0 returns crc1.
 */
uint64_t brix_crc64_combine(brix_crc64_variant_t variant, uint64_t crc1,
    uint64_t crc2, uint64_t len2);

#endif /* BRIX_COMPAT_CRC64_H */
