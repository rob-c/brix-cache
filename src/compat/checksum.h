#ifndef XROOTD_COMPAT_CHECKSUM_H
#define XROOTD_COMPAT_CHECKSUM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "../fs/backend/sd.h"   /* xrootd_sd_obj_t — driver-routed checksum read */

typedef enum {
    XROOTD_CHECKSUM_ADLER32 = 0,
    XROOTD_CHECKSUM_CRC32,
    XROOTD_CHECKSUM_CRC32C,
    XROOTD_CHECKSUM_MD5,
    XROOTD_CHECKSUM_SHA1,
    XROOTD_CHECKSUM_SHA256,
    XROOTD_CHECKSUM_CRC64,      /* CRC-64/XZ   — canonical "crc64" (alias "crc64xz") */
    XROOTD_CHECKSUM_CRC64NVME,  /* CRC-64/NVME — "crc64nvme" (AWS S3 x-amz-checksum) */
    XROOTD_CHECKSUM_ZCRC32      /* zlib CRC-32 — XRootD "zcrc32" (== crc32 algorithm,
                                 * distinct registered name; ordinal matches the
                                 * kernel's XROOTD_CK_ZCRC32) */
} xrootd_checksum_alg_t;

/*
 * xrootd_checksum_parse - resolve a checksum algorithm name string to an enum value.
 *
 * WHAT: Accepts a case-insensitive algorithm name and returns the corresponding
 *       XROOTD_CHECKSUM_* enum constant. Also writes canonical lowercase into normalized.
 *
 * WHY: XRootD wire messages carry algorithm names as strings; callers need a uniform
 *      parser handling case variations, rejecting non-alphanumeric input,
 *      distinguishing unknown (NGX_DECLINED) from parse error (NGX_ERROR).
 *
 * HOW: Lowercases input into buf[32], validates alphanumeric chars, matches via strcmp.
 */

ngx_int_t xrootd_checksum_parse(const char *name, size_t len,
    xrootd_checksum_alg_t *alg, char *normalized, size_t normalized_sz);
/*
 * xrootd_checksum_name - return canonical string name for a checksum algorithm enum.
 *
 * WHAT: Maps XROOTD_CHECKSUM_* enum to its human-readable label (e.g. CRC32C → "crc32c")
 *       Returns NULL for unknown values.
 *
 * WHY: Used in logging, error messages, and protocol framing where algorithms must
 *      be expressed as strings rather than enum integers.
 *
 * HOW: Direct switch-case lookup returning lowercase canonical names.
 */

const char *xrootd_checksum_name(xrootd_checksum_alg_t alg);
/*
 * xrootd_checksum_is_u32 - check whether an algorithm produces a 32-bit result.
 *
 * WHAT: Returns NGX_TRUE for Adler-32, CRC-32, CRC-32c (uint32_t); NGX_FALSE for
 *       MD5/SHA1/SHA256 (variable-length digests).
 *
 * WHY: Callers decide between fast u32_fd path vs EVP digest path, and hex output
 *      length (8 chars vs EVP_MAX_MD_SIZE*2 chars).
 *
 * HOW: Simple equality check against three u32 algorithm constants.
 */

ngx_flag_t xrootd_checksum_is_u32(xrootd_checksum_alg_t alg);
/*
 * xrootd_checksum_is_u64 - check whether an algorithm produces a 64-bit result.
 *
 * WHAT: Returns NGX_TRUE for the CRC64 family (CRC-64/XZ, CRC-64/NVME), which
 *       yield a uint64_t rendered as 16 hex chars; NGX_FALSE for everything else.
 *
 * WHY:  The hex/compute paths have three width classes — 32-bit (8 hex), 64-bit
 *       (16 hex), and variable-length EVP digests. Callers branch on is_u32 then
 *       is_u64 then fall through to the digest path.
 *
 * HOW:  Equality check against the two CRC64 enum constants.
 */
ngx_flag_t xrootd_checksum_is_u64(xrootd_checksum_alg_t alg);

/*
 * xrootd_checksum_u32_fd - compute 32-bit checksum (Adler-32/CRC-32/CRC-32c) from fd.
 *
 * WHAT: Reads entire file at fd in 64KB chunks, accumulates checksum into *out.
 *       Supports Adler-32, CRC-32 (zlib), and CRC-32c (table lookup).
 *
 * WHY: XRootD kXR_fattr responses include checksums; WebDAV PROPFIND returns checksum
 *      properties. Common read-and-compute path for all 32-bit algorithms.
 *
 * HOW: Loop pread with EINTR retry. Adler-32 uses adler32(), CRC-32 uses crc32(),
 *      CRC-32c uses xrootd_crc32c_extend(). Final value written to *out.
 */

ngx_int_t xrootd_checksum_u32_fd(xrootd_checksum_alg_t alg, int fd,
    const char *path, ngx_log_t *log, uint32_t *out);
/*
 * xrootd_checksum_u64_fd - compute 64-bit checksum (CRC-64/XZ or /NVME) from fd.
 *
 * WHAT: Streams the whole file at fd and accumulates the selected CRC64 variant
 *       into *out. Rejects non-CRC64 algorithms (NGX_ERROR).
 *
 * WHY:  S3 x-amz-checksum-crc64nvme, root:// kXR_Qcksum crc64, and WebDAV Digest
 *       crc64 all need a whole-file 64-bit checksum; this is the ngx wrapper over
 *       the shared kernel, mirroring xrootd_checksum_u32_fd.
 *
 * HOW:  Validates is_u64(alg), delegates to xrootd_cksum_u64_fd((int)alg, fd, out)
 *       (alg ordinals match the kind codes); logs a read error via the shared
 *       read-error helper on failure.
 */
ngx_int_t xrootd_checksum_u64_fd(xrootd_checksum_alg_t alg, int fd,
    const char *path, ngx_log_t *log, uint64_t *out);
/*
 * xrootd_checksum_digest_fd - compute variable-length digest (MD5/SHA1/SHA256) from fd.
 *
 * WHAT: Reads entire file at fd in 64KB chunks, computes OpenSSL EVP digest into
 *       out[outlen]. Supports MD5, SHA1, and SHA256.
 *
 * WHY: XRootD fattr reports SHA1/SHA256 checksums; WebDAV may need MD5 for legacy
 *      compatibility. Common digest path using OpenSSL EVP API.
 *
 * HOW: EVP_MD_CTX_new → EVP_DigestInit_ex → loop pread + EVP_DigestUpdate →
 *      EVP_DigestFinal_ex. The digest loop runs in a worker that uses flat early
 *      returns; this wrapper owns the ctx and frees it on every exit.
 */

ngx_int_t xrootd_checksum_digest_fd(xrootd_checksum_alg_t alg, int fd,
    const char *path, ngx_log_t *log, unsigned char *out,
    unsigned int *outlen);
/*
 * xrootd_checksum_hex_fd - compute checksum and write hex-encoded representation.
 *
 * WHAT: Combines u32 or digest computation with hex encoding. For u32 algorithms
 *       outputs 8-char hex; for digest algorithms outputs EVP_MAX_MD_SIZE*2 chars.
 *
 * WHY: XRootD wire protocol and WebDAV PROPFIND return checksums as hex strings.
 *      Single function handling both algorithm families without caller knowing path upfront.
 *
 * HOW: Branches on xrootd_checksum_is_u32(). u32 calls xrootd_checksum_u32_fd + snprintf;
 *      digest calls xrootd_checksum_digest_fd + xrootd_checksum_hex_encode().
 */

ngx_int_t xrootd_checksum_hex_fd(xrootd_checksum_alg_t alg, int fd,
    const char *path, ngx_log_t *log, char *hex, size_t hexsz);

/* Layer 3: hex checksum of a driver-bound object — reads every byte through
 * obj->driver so a multi-block backend file is summed in full. Same output
 * format as xrootd_checksum_hex_fd. */
ngx_int_t xrootd_checksum_hex_obj(xrootd_checksum_alg_t alg,
    xrootd_sd_obj_t *obj, const char *path, ngx_log_t *log,
    char *hex, size_t hexsz);
/*
 * xrootd_checksum_hex_name_fd - parse checksum name string, compute digest, return hex.
 *
 * WHAT: Takes raw algorithm name (e.g. "crc32c"), parses via xrootd_checksum_parse(),
 *       then computes hex-encoded checksum via xrootd_checksum_hex_fd(). Optionally
 *       writes canonical lowercase to normalized.
 *
 * WHY: High-level convenience for callers receiving a name string from wire or HTTP
 *      needing the hex result directly without intermediate steps.
 *
 * HOW: Calls xrootd_checksum_parse(); if NGX_OK, delegates to xrootd_checksum_hex_fd().
 */

ngx_int_t xrootd_checksum_hex_name_fd(const char *name, int fd,
    const char *path, ngx_log_t *log, char *hex, size_t hexsz,
    char *normalized, size_t normalized_sz);
/*
 * xrootd_checksum_hex_encode - convert raw binary digest to lowercase hex string.
 *
 * WHAT: Takes binary digest (e.g. from EVP_DigestFinal_ex) and writes lowercase hex
 *       into hex. Each byte becomes two hex chars.
 *
 * WHY: OpenSSL digests are binary; wire protocols and HTTP headers need ASCII hex.
 *      Shared encoding step used by xrootd_checksum_hex_fd().
 *
 * HOW: Iterates digest bytes, writes snprintf("%02x") into hex[i*2] for each byte.
 */

void xrootd_checksum_hex_encode(const unsigned char *digest,
    unsigned int digest_len, char *hex);

#endif /* XROOTD_COMPAT_CHECKSUM_H */
