/*
 * checksum.c - shared file checksum and digest algorithms.
 *
 * WHAT: Implements 32-bit checksums (Adler-32, CRC-32, CRC-32c) and variable-length
 *       digests (MD5, SHA1, SHA256) for XRootD wire protocol and WebDAV/S3 responses.
 *
 * WHY: XRootD fattr/PROPFIND return checksums as hex strings. pgread/pgwrite require
 *      per-page CRC32c validation. All callers share this single implementation to
 *      avoid duplication between native XRootD, WebDAV, and S3 modules.
 *
 * HOW: 32-bit paths use zlib (adler32/crc32) or crc32c table lookup; digest paths
 *      use OpenSSL EVP API. All fd-based functions loop pread in 64KB chunks with
 *      EINTR retry. Hex encoding converts binary digests to lowercase ASCII.
*/

#include "checksum.h"
#include "checksum_core.h"   /* shared (ngx-free) fd→checksum compute kernels */
#include "crc32c.h"
#include "hex.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);

#define XROOTD_CHECKSUM_BUFSZ  65536

/*
 * xrootd_checksum_name — algorithm enum to human-readable string.
 *
 * WHAT: Maps checksum algorithm enum values to their canonical lowercase names for
 *      logging and diagnostic messages. WHY: Access logs, error messages, and Prometheus
 *      labels need readable algorithm identifiers; callers don't want to switch-case the
 *      enum themselves. HOW: Direct switch-case returning "adler32", "crc32", "crc32c",
 *      "md5", "sha1", or "sha256"; returns NULL for unknown values. */

const char *
xrootd_checksum_name(xrootd_checksum_alg_t alg)
{
    switch (alg) {
    case XROOTD_CHECKSUM_ADLER32:
        return "adler32";
    case XROOTD_CHECKSUM_CRC32:
        return "crc32";
    case XROOTD_CHECKSUM_CRC32C:
        return "crc32c";
    case XROOTD_CHECKSUM_MD5:
        return "md5";
    case XROOTD_CHECKSUM_SHA1:
        return "sha1";
    case XROOTD_CHECKSUM_SHA256:
        return "sha256";
    case XROOTD_CHECKSUM_CRC64:
        return "crc64";
    case XROOTD_CHECKSUM_CRC64NVME:
        return "crc64nvme";
    case XROOTD_CHECKSUM_ZCRC32:
        return "zcrc32";
    default:
        return NULL;
    }
}

/*
 * xrootd_checksum_is_u64 — classify algorithm as a 64-bit CRC.
 *
 * WHAT: Returns true for CRC-64/XZ and CRC-64/NVME (uint64_t → 16 hex chars),
 *      false for everything else. WHY: the hex/compute path has three width
 *      classes (32-bit, 64-bit, variable digest); callers check is_u32 then
 *      is_u64 then fall through to the digest path. HOW: equality against the two
 *      CRC64 enum constants. */

ngx_flag_t
xrootd_checksum_is_u64(xrootd_checksum_alg_t alg)
{
    return alg == XROOTD_CHECKSUM_CRC64
           || alg == XROOTD_CHECKSUM_CRC64NVME;
}

/*
 * xrootd_checksum_is_u32 — classify algorithm as 32-bit vs digest.
 *
 * WHAT: Returns true if the algorithm produces a fixed 32-bit checksum (Adler-32, CRC-32,
 *      CRC-32c), false for variable-length digests (MD5, SHA1, SHA256). WHY: The hex output
 *      path diverges — u32 algorithms use snprintf("%08x") while digest algorithms need
 *      EVP_DigestFinal_ex + hex encoding. Callers branch on this to pick the right code path.
 * HOW: Simple boolean check against the three u32 algorithm enum values. */

ngx_flag_t
xrootd_checksum_is_u32(xrootd_checksum_alg_t alg)
{
    return alg == XROOTD_CHECKSUM_ADLER32
           || alg == XROOTD_CHECKSUM_CRC32
           || alg == XROOTD_CHECKSUM_CRC32C
           || alg == XROOTD_CHECKSUM_ZCRC32;
}

/*
 * xrootd_checksum_parse — parse algorithm name string into enum value.
 *
 * WHAT: Converts a checksum algorithm name (e.g. "crc32c", "sha256") from config or wire
 *      protocol into the corresponding enum value, with optional normalized lowercase output.
 * WHY: Config directives and fattr responses carry algorithm names as strings; callers need
 *      the enum to dispatch to the right code path (u32 vs digest). HOW: 1) Validate name
 *      length < 32 bytes → 2) Reject non-alphanumeric chars → 3) Lowercase into buf → 4)
 *      strcmp against canonical names → 5) Set *alg if not NULL → 6) Copy normalized buf
 *      to output buffer → 7) Return NGX_OK/NGX_ERROR/NGX_DECLINED. */

ngx_int_t
xrootd_checksum_parse(const char *name, size_t len, xrootd_checksum_alg_t *alg,
    char *normalized, size_t normalized_sz)
{
    char   buf[32];
    size_t i;
    xrootd_checksum_alg_t parsed;

    if (name == NULL || len == 0 || len >= sizeof(buf)) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char) name[i])) {
            return NGX_ERROR;
        }
        buf[i] = (char) tolower((unsigned char) name[i]);
    }
    buf[len] = '\0';

    if (strcmp(buf, "adler32") == 0) {
        parsed = XROOTD_CHECKSUM_ADLER32;
    } else if (strcmp(buf, "crc32") == 0) {
        parsed = XROOTD_CHECKSUM_CRC32;
    } else if (strcmp(buf, "crc32c") == 0) {
        parsed = XROOTD_CHECKSUM_CRC32C;
    } else if (strcmp(buf, "md5") == 0) {
        parsed = XROOTD_CHECKSUM_MD5;
    } else if (strcmp(buf, "sha1") == 0) {
        parsed = XROOTD_CHECKSUM_SHA1;
    } else if (strcmp(buf, "sha256") == 0) {
        parsed = XROOTD_CHECKSUM_SHA256;
    } else if (strcmp(buf, "crc64") == 0 || strcmp(buf, "crc64xz") == 0) {
        parsed = XROOTD_CHECKSUM_CRC64;
    } else if (strcmp(buf, "crc64nvme") == 0) {
        parsed = XROOTD_CHECKSUM_CRC64NVME;
    } else if (strcmp(buf, "zcrc32") == 0) {
        parsed = XROOTD_CHECKSUM_ZCRC32;   /* XRootD zlib-CRC32 name */
    } else {
        return NGX_DECLINED;
    }

    if (alg != NULL) {
        *alg = parsed;
    }

    /* Emit the CANONICAL name (not the raw input) so aliases normalize — e.g.
     * "crc64xz" → "crc64" — keeping xattr cache keys and wire names consistent.
     * For every non-aliased algorithm the canonical name equals buf, so this is
     * a no-op there. parsed is always valid here, so name() is never NULL. */
    if (normalized != NULL && normalized_sz > 0) {
        ngx_cpystrn((u_char *) normalized,
                    (u_char *) xrootd_checksum_name(parsed), normalized_sz);
    }

    return NGX_OK;
}

/*
 * xrootd_checksum_log_read_error - format and log a pread/read failure for checksum path.
 *
 * WHAT: Sanitizes the file path (escapes control chars, quotes), then logs an error
 *       message of the form "xrootd: <algo> read("<path>") failed" with errno.
 *
 * WHY: All checksum fd functions share this logger to avoid repeated sanitization +
 *      formatting code. Ensures consistent error messages across Adler-32, CRC-32,
 *      CRC-32c, and digest paths.
 *
 * HOW: Calls xrootd_sanitize_log_string(path) → ngx_log_error(NGX_LOG_ERR, log, err,
 *      "xrootd: %s read("%s") failed", algo, safe).
 */

static void
xrootd_checksum_log_read_error(ngx_log_t *log, ngx_err_t err,
    const char *algo, const char *path)
{
    char safe[512];

    xrootd_sanitize_log_string(path ? path : "-", safe, sizeof(safe));
    ngx_log_error(NGX_LOG_ERR, log, err,
                  "xrootd: %s read(\"%s\") failed", algo, safe);
}

/*
 * xrootd_checksum_u32_fd — compute Adler-32 / CRC-32 / CRC-32c on file descriptor.
 *
 * WHAT: Reads an entire file via pread in 64KB chunks, accumulating a 32-bit checksum
 *      (Adler-32 via zlib adler32(), CRC-32 via crc32(), or CRC-32c via xrootd_crc32c_extend()).
 * WHY: pgread/pgwrite require per-page CRC32c validation; fattr/PROPFIND return checksums.
 *      This shared function serves both XRootD and WebDAV/S3 callers without duplication.
 * HOW: 1) Validate alg is u32 type → 2) Initialise accumulator (adler32/crc32 or zero for crc32c)
 *      → 3) Loop pread(buf, 64KB, offset) with EINTR retry → 4) Update accumulator per chunk
 *      → 5) Return result via *out. Returns NGX_ERROR on read failure or invalid alg. */

ngx_int_t
xrootd_checksum_u32_fd(xrootd_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, uint32_t *out)
{
    if (out == NULL || !xrootd_checksum_is_u32(alg)) {
        return NGX_ERROR;
    }
    /* Compute via the shared (ngx-free) kernel; errno carries any read error so
     * we keep the module's specific read-error log line. (alg ordinals match.) */
    if (xrootd_cksum_u32_fd((int) alg, fd, out) != 0) {
        xrootd_checksum_log_read_error(log, errno, xrootd_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * xrootd_checksum_u64_fd — compute CRC-64/XZ or /NVME on a file descriptor.
 *
 * WHAT: Streams the whole file at fd and accumulates the 64-bit CRC into *out.
 * WHY:  S3 crc64nvme, root:// crc64 and WebDAV crc64 Digest all need a whole-file
 *      64-bit checksum; this is the ngx wrapper over the shared kernel.
 * HOW:  Validates is_u64(alg), delegates to xrootd_cksum_u64_fd((int)alg, fd, out)
 *      (alg ordinals match the kind codes), logs a read error on failure. */

ngx_int_t
xrootd_checksum_u64_fd(xrootd_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, uint64_t *out)
{
    if (out == NULL || !xrootd_checksum_is_u64(alg)) {
        return NGX_ERROR;
    }
    if (xrootd_cksum_u64_fd((int) alg, fd, out) != 0) {
        xrootd_checksum_log_read_error(log, errno, xrootd_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_checksum_digest_fd(xrootd_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, unsigned char *out, unsigned int *outlen)
{
    /* digest algs = the non-u32, non-u64 ones (md5/sha1/sha256). Compute via the
     * shared (ngx-free) kernel; errno carries any read error for the module's log. */
    if (xrootd_checksum_is_u32(alg) || xrootd_checksum_is_u64(alg)
        || out == NULL || outlen == NULL)
    {
        return NGX_ERROR;
    }
    if (xrootd_cksum_digest_fd((int) alg, fd, out, outlen) != 0) {
        xrootd_checksum_log_read_error(log, errno, xrootd_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * xrootd_checksum_hex_encode — binary digest to lowercase hex string.
 *
 * WHAT: Converts a raw cryptographic digest (MD5/SHA1/SHA256 bytes) into a lowercase ASCII
 *      hex string suitable for fattr responses and PROPFIND output. WHY: XRootD wire protocol
 *      and WebDAV/S3 require checksums as hex-encoded strings; callers delegate encoding to
 *      this shared helper rather than implementing their own conversion. HOW: Single delegation
 *      to xrootd_hex_encode() which handles the byte-to-hex conversion. */

void
xrootd_checksum_hex_encode(const unsigned char *digest, unsigned int digest_len,
    char *hex)
{
    xrootd_hex_encode(digest, (size_t) digest_len, hex);
}

/*
 * xrootd_checksum_hex_fd — compute checksum and return as hex string.
 *
 * WHAT: Computes a checksum on file descriptor and writes the result as a hex-encoded string,
 *      branching between 32-bit (snprintf "%08x") and digest (EVP_DigestFinal_ex + hex_encode)
 *      paths based on algorithm type. WHY: This is the unified entry point for all callers that
 *      need a hex checksum — XRootD fattr, WebDAV PROPFIND, S3 metadata — without requiring
 *      callers to know whether their algorithm is u32 or digest. HOW: 1) Branch on is_u32() →
 *      2) For u32: validate hexsz >= 9 bytes, call u32_fd(), snprintf("%08x") → 3) For digest:
 *      validate hexsz >= EVP_MAX_MD_SIZE*2+1, call digest_fd(), hex_encode(). Returns NGX_ERROR
 *      on buffer overflow or computation failure. */

ngx_int_t
xrootd_checksum_hex_fd(xrootd_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, char *hex, size_t hexsz)
{
    if (xrootd_checksum_is_u32(alg)) {
        uint32_t value;

        if (hexsz < 9) {
            return NGX_ERROR;
        }

        if (xrootd_checksum_u32_fd(alg, fd, path, log, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        snprintf(hex, hexsz, "%08x", (unsigned int) value);
        return NGX_OK;
    }

    if (xrootd_checksum_is_u64(alg)) {
        uint64_t value;

        if (hexsz < 17) {                       /* 16 hex digits + NUL */
            return NGX_ERROR;
        }

        if (xrootd_checksum_u64_fd(alg, fd, path, log, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        snprintf(hex, hexsz, "%016llx", (unsigned long long) value);
        return NGX_OK;
    }

    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  digest_len;

        if (hexsz < (EVP_MAX_MD_SIZE * 2 + 1)) {
            return NGX_ERROR;
        }

        if (xrootd_checksum_digest_fd(alg, fd, path, log, digest, &digest_len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        xrootd_checksum_hex_encode(digest, digest_len, hex);
        return NGX_OK;
    }
}

/*
 * xrootd_checksum_hex_obj — hex checksum of a driver-bound OBJECT.
 *
 * WHAT: Same contract as xrootd_checksum_hex_fd, but reads every byte through
 *      obj->driver (block-striped / object store) so a multi-block file is
 *      summed in full rather than just its first backing block. WHY: a Layer-3
 *      backend's open handle exposes only block 0 as a bare fd; checksum-at-rest
 *      must traverse the whole logical object. HOW: branch on alg type and call
 *      the obj-aware kernel (xrootd_cksum_u32_obj / _u64_obj / _digest_obj),
 *      formatting identically to hex_fd. */
ngx_int_t
xrootd_checksum_hex_obj(xrootd_checksum_alg_t alg, xrootd_sd_obj_t *obj,
    const char *path, ngx_log_t *log, char *hex, size_t hexsz)
{
    if (obj == NULL || obj->driver == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_checksum_is_u32(alg)) {
        uint32_t value;

        if (hexsz < 9 || xrootd_cksum_u32_obj((int) alg, obj, &value) != 0) {
            xrootd_checksum_log_read_error(log, errno,
                                           xrootd_checksum_name(alg), path);
            return NGX_ERROR;
        }
        snprintf(hex, hexsz, "%08x", (unsigned int) value);
        return NGX_OK;
    }

    if (xrootd_checksum_is_u64(alg)) {
        uint64_t value;

        if (hexsz < 17 || xrootd_cksum_u64_obj((int) alg, obj, &value) != 0) {
            xrootd_checksum_log_read_error(log, errno,
                                           xrootd_checksum_name(alg), path);
            return NGX_ERROR;
        }
        snprintf(hex, hexsz, "%016llx", (unsigned long long) value);
        return NGX_OK;
    }

    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  digest_len;

        if (hexsz < (EVP_MAX_MD_SIZE * 2 + 1)
            || xrootd_cksum_digest_obj((int) alg, obj, digest, &digest_len) != 0)
        {
            xrootd_checksum_log_read_error(log, errno,
                                           xrootd_checksum_name(alg), path);
            return NGX_ERROR;
        }
        xrootd_checksum_hex_encode(digest, digest_len, hex);
        return NGX_OK;
    }
}

/*
 * xrootd_checksum_hex_name_fd — parse algorithm name and compute hex checksum.
 *
 * WHAT: Convenience entry point that accepts an algorithm name string (e.g. "crc32c") instead
 *      of the enum value, parses it via xrootd_checksum_parse(), then delegates to
 *      xrootd_checksum_hex_fd() for computation. WHY: Config directives and wire protocol
 *      carry algorithm names as strings; this wrapper saves callers from calling parse() +
 *      hex_fd() separately. HOW: 1) Parse name string into alg enum → 2) On NGX_OK, call
 *      hex_fd(alg, fd, path, log, hex, hexsz). Returns NGX_ERROR/NGX_DECLINED if parsing fails. */

ngx_int_t
xrootd_checksum_hex_name_fd(const char *name, int fd, const char *path,
    ngx_log_t *log, char *hex, size_t hexsz, char *normalized,
    size_t normalized_sz)
{
    xrootd_checksum_alg_t alg;
    ngx_int_t             rc;

    rc = xrootd_checksum_parse(name, strlen(name), &alg, normalized,
                               normalized_sz);
    if (rc != NGX_OK) {
        return rc;
    }

    return xrootd_checksum_hex_fd(alg, fd, path, log, hex, hexsz);
}
