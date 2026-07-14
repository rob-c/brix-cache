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

size_t brix_sanitize_log_string(const char *in, char *out, size_t outsz);

#define BRIX_CHECKSUM_BUFSZ  65536

/*
 * brix_checksum_name — algorithm enum to human-readable string.
 *
 * WHAT: Maps checksum algorithm enum values to their canonical lowercase names for
 *      logging and diagnostic messages. WHY: Access logs, error messages, and Prometheus
 *      labels need readable algorithm identifiers; callers don't want to switch-case the
 *      enum themselves. HOW: Direct switch-case returning "adler32", "crc32", "crc32c",
 *      "md5", "sha1", or "sha256"; returns NULL for unknown values. */

const char *
brix_checksum_name(brix_checksum_alg_t alg)
{
    switch (alg) {
    case BRIX_CHECKSUM_ADLER32:
        return "adler32";
    case BRIX_CHECKSUM_CRC32:
        return "crc32";
    case BRIX_CHECKSUM_CRC32C:
        return "crc32c";
    case BRIX_CHECKSUM_MD5:
        return "md5";
    case BRIX_CHECKSUM_SHA1:
        return "sha1";
    case BRIX_CHECKSUM_SHA256:
        return "sha256";
    case BRIX_CHECKSUM_CRC64:
        return "crc64";
    case BRIX_CHECKSUM_CRC64NVME:
        return "crc64nvme";
    case BRIX_CHECKSUM_ZCRC32:
        return "zcrc32";
    default:
        return NULL;
    }
}

/*
 * brix_checksum_is_u64 — classify algorithm as a 64-bit CRC.
 *
 * WHAT: Returns true for CRC-64/XZ and CRC-64/NVME (uint64_t → 16 hex chars),
 *      false for everything else. WHY: the hex/compute path has three width
 *      classes (32-bit, 64-bit, variable digest); callers check is_u32 then
 *      is_u64 then fall through to the digest path. HOW: equality against the two
 *      CRC64 enum constants. */

ngx_flag_t
brix_checksum_is_u64(brix_checksum_alg_t alg)
{
    return alg == BRIX_CHECKSUM_CRC64
           || alg == BRIX_CHECKSUM_CRC64NVME;
}

/*
 * brix_checksum_is_u32 — classify algorithm as 32-bit vs digest.
 *
 * WHAT: Returns true if the algorithm produces a fixed 32-bit checksum (Adler-32, CRC-32,
 *      CRC-32c), false for variable-length digests (MD5, SHA1, SHA256). WHY: The hex output
 *      path diverges — u32 algorithms use snprintf("%08x") while digest algorithms need
 *      EVP_DigestFinal_ex + hex encoding. Callers branch on this to pick the right code path.
 * HOW: Simple boolean check against the three u32 algorithm enum values. */

ngx_flag_t
brix_checksum_is_u32(brix_checksum_alg_t alg)
{
    return alg == BRIX_CHECKSUM_ADLER32
           || alg == BRIX_CHECKSUM_CRC32
           || alg == BRIX_CHECKSUM_CRC32C
           || alg == BRIX_CHECKSUM_ZCRC32;
}

/*
 * brix_checksum_normalize_name — validate and lowercase an algorithm name.
 *
 * WHAT: Copies name[0..len) into buf as a NUL-terminated lowercase string,
 *      rejecting an empty name, one that overflows buf, or one containing a
 *      non-alphanumeric byte. Returns NGX_OK on success, NGX_ERROR on any
 *      rejection. WHY: brix_checksum_parse must sanitize wire/config input to
 *      the exact same rules regardless of which algorithm it later matches;
 *      isolating the byte handling keeps the parser flat and testable. HOW:
 *      1) Reject NULL/empty/oversized → 2) Loop each byte, reject non-alnum,
 *      tolower into buf → 3) NUL-terminate at len. */

static ngx_int_t
brix_checksum_normalize_name(const char *name, size_t len,
    char *buf, size_t bufsz)
{
    size_t i;

    if (name == NULL || len == 0 || len >= bufsz) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char) name[i])) {
            return NGX_ERROR;
        }
        buf[i] = (char) tolower((unsigned char) name[i]);
    }
    buf[len] = '\0';

    return NGX_OK;
}

/*
 * brix_checksum_lookup_alg — map a normalized name to its algorithm enum.
 *
 * WHAT: Matches an already-lowercased name against the canonical algorithm
 *      names (plus the "crc64xz" alias for CRC-64/XZ), writing the enum to
 *      *out and returning NGX_OK; returns NGX_DECLINED for an unknown name.
 * WHY: expressing the name→enum mapping as a table instead of a strcmp ladder
 *      keeps brix_checksum_parse's complexity low and makes the accepted set
 *      obvious in one place. HOW: linear strcmp scan over the name/enum table;
 *      first match wins, matching the prior if-else ordering exactly. */

static ngx_int_t
brix_checksum_lookup_alg(const char *lname, brix_checksum_alg_t *out)
{
    static const struct {
        const char          *name;
        brix_checksum_alg_t  alg;
    } table[] = {
        { "adler32",   BRIX_CHECKSUM_ADLER32 },
        { "crc32",     BRIX_CHECKSUM_CRC32 },
        { "crc32c",    BRIX_CHECKSUM_CRC32C },
        { "md5",       BRIX_CHECKSUM_MD5 },
        { "sha1",      BRIX_CHECKSUM_SHA1 },
        { "sha256",    BRIX_CHECKSUM_SHA256 },
        { "crc64",     BRIX_CHECKSUM_CRC64 },
        { "crc64xz",   BRIX_CHECKSUM_CRC64 },      /* alias of crc64 (CRC-64/XZ) */
        { "crc64nvme", BRIX_CHECKSUM_CRC64NVME },
        { "zcrc32",    BRIX_CHECKSUM_ZCRC32 },     /* XRootD zlib-CRC32 name */
    };
    size_t i;

    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(lname, table[i].name) == 0) {
            *out = table[i].alg;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

/*
 * brix_checksum_parse — parse algorithm name string into enum value.
 *
 * WHAT: Converts a checksum algorithm name (e.g. "crc32c", "sha256") from config or wire
 *      protocol into the corresponding enum value, with optional normalized lowercase output.
 * WHY: Config directives and fattr responses carry algorithm names as strings; callers need
 *      the enum to dispatch to the right code path (u32 vs digest). HOW: 1) Normalize name
 *      (validate + lowercase) into buf → 2) Table-lookup buf → enum → 3) Set *alg if not NULL
 *      → 4) Copy normalized buf to output buffer → 5) Return NGX_OK/NGX_ERROR/NGX_DECLINED. */

ngx_int_t
brix_checksum_parse(const char *name, size_t len, brix_checksum_alg_t *alg,
    char *normalized, size_t normalized_sz)
{
    char   buf[32];
    brix_checksum_alg_t parsed;

    if (brix_checksum_normalize_name(name, len, buf, sizeof(buf)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_checksum_lookup_alg(buf, &parsed) != NGX_OK) {
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
                    (u_char *) brix_checksum_name(parsed), normalized_sz);
    }

    return NGX_OK;
}

/*
 * brix_checksum_log_read_error - format and log a pread/read failure for checksum path.
 *
 * WHAT: Sanitizes the file path (escapes control chars, quotes), then logs an error
 *       message of the form "brix: <algo> read("<path>") failed" with errno.
 *
 * WHY: All checksum fd functions share this logger to avoid repeated sanitization +
 *      formatting code. Ensures consistent error messages across Adler-32, CRC-32,
 *      CRC-32c, and digest paths.
 *
 * HOW: Calls brix_sanitize_log_string(path) → ngx_log_error(NGX_LOG_ERR, log, err,
 *      "brix: %s read("%s") failed", algo, safe).
 */

static void
brix_checksum_log_read_error(ngx_log_t *log, ngx_err_t err,
    const char *algo, const char *path)
{
    char safe[512];

    brix_sanitize_log_string(path ? path : "-", safe, sizeof(safe));
    ngx_log_error(NGX_LOG_ERR, log, err,
                  "brix: %s read(\"%s\") failed", algo, safe);
}

/*
 * brix_checksum_u32_fd — compute Adler-32 / CRC-32 / CRC-32c on file descriptor.
 *
 * WHAT: Reads an entire file via pread in 64KB chunks, accumulating a 32-bit checksum
 *      (Adler-32 via zlib adler32(), CRC-32 via crc32(), or CRC-32c via brix_crc32c_extend()).
 * WHY: pgread/pgwrite require per-page CRC32c validation; fattr/PROPFIND return checksums.
 *      This shared function serves both XRootD and WebDAV/S3 callers without duplication.
 * HOW: 1) Validate alg is u32 type → 2) Initialise accumulator (adler32/crc32 or zero for crc32c)
 *      → 3) Loop pread(buf, 64KB, offset) with EINTR retry → 4) Update accumulator per chunk
 *      → 5) Return result via *out. Returns NGX_ERROR on read failure or invalid alg. */

ngx_int_t
brix_checksum_u32_fd(brix_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, uint32_t *out)
{
    if (out == NULL || !brix_checksum_is_u32(alg)) {
        return NGX_ERROR;
    }
    /* Compute via the shared (ngx-free) kernel; errno carries any read error so
     * we keep the module's specific read-error log line. (alg ordinals match.) */
    if (brix_cksum_u32_fd((int) alg, fd, out) != 0) {
        brix_checksum_log_read_error(log, errno, brix_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_checksum_u64_fd — compute CRC-64/XZ or /NVME on a file descriptor.
 *
 * WHAT: Streams the whole file at fd and accumulates the 64-bit CRC into *out.
 * WHY:  S3 crc64nvme, root:// crc64 and WebDAV crc64 Digest all need a whole-file
 *      64-bit checksum; this is the ngx wrapper over the shared kernel.
 * HOW:  Validates is_u64(alg), delegates to brix_cksum_u64_fd((int)alg, fd, out)
 *      (alg ordinals match the kind codes), logs a read error on failure. */

ngx_int_t
brix_checksum_u64_fd(brix_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, uint64_t *out)
{
    if (out == NULL || !brix_checksum_is_u64(alg)) {
        return NGX_ERROR;
    }
    if (brix_cksum_u64_fd((int) alg, fd, out) != 0) {
        brix_checksum_log_read_error(log, errno, brix_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_checksum_digest_fd(brix_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, unsigned char *out, unsigned int *outlen)
{
    /* digest algs = the non-u32, non-u64 ones (md5/sha1/sha256). Compute via the
     * shared (ngx-free) kernel; errno carries any read error for the module's log. */
    if (brix_checksum_is_u32(alg) || brix_checksum_is_u64(alg)
        || out == NULL || outlen == NULL)
    {
        return NGX_ERROR;
    }
    if (brix_cksum_digest_fd((int) alg, fd, out, outlen) != 0) {
        brix_checksum_log_read_error(log, errno, brix_checksum_name(alg), path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_checksum_hex_encode — binary digest to lowercase hex string.
 *
 * WHAT: Converts a raw cryptographic digest (MD5/SHA1/SHA256 bytes) into a lowercase ASCII
 *      hex string suitable for fattr responses and PROPFIND output. WHY: XRootD wire protocol
 *      and WebDAV/S3 require checksums as hex-encoded strings; callers delegate encoding to
 *      this shared helper rather than implementing their own conversion. HOW: Single delegation
 *      to brix_hex_encode() which handles the byte-to-hex conversion. */

void
brix_checksum_hex_encode(const unsigned char *digest, unsigned int digest_len,
    char *hex)
{
    brix_hex_encode(digest, (size_t) digest_len, hex);
}

/*
 * brix_checksum_hex_fd — compute checksum and return as hex string.
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
brix_checksum_hex_fd(brix_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, char *hex, size_t hexsz)
{
    if (brix_checksum_is_u32(alg)) {
        uint32_t value;

        if (hexsz < 9) {
            return NGX_ERROR;
        }

        if (brix_checksum_u32_fd(alg, fd, path, log, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        snprintf(hex, hexsz, "%08x", (unsigned int) value);
        return NGX_OK;
    }

    if (brix_checksum_is_u64(alg)) {
        uint64_t value;

        if (hexsz < 17) {                       /* 16 hex digits + NUL */
            return NGX_ERROR;
        }

        if (brix_checksum_u64_fd(alg, fd, path, log, &value) != NGX_OK) {
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

        if (brix_checksum_digest_fd(alg, fd, path, log, digest, &digest_len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        brix_checksum_hex_encode(digest, digest_len, hex);
        return NGX_OK;
    }
}

/*
 * brix_checksum_hex_obj — hex checksum of a driver-bound OBJECT.
 *
 * WHAT: Same contract as brix_checksum_hex_fd, but reads every byte through
 *      obj->driver (block-striped / object store) so a multi-block file is
 *      summed in full rather than just its first backing block. WHY: a Layer-3
 *      backend's open handle exposes only block 0 as a bare fd; checksum-at-rest
 *      must traverse the whole logical object. HOW: branch on alg type and call
 *      the obj-aware kernel (brix_cksum_u32_obj / _u64_obj / _digest_obj),
 *      formatting identically to hex_fd. */
ngx_int_t
brix_checksum_hex_obj(brix_checksum_alg_t alg, brix_sd_obj_t *obj,
    const char *path, ngx_log_t *log, char *hex, size_t hexsz)
{
    if (obj == NULL || obj->driver == NULL) {
        return NGX_ERROR;
    }

    if (brix_checksum_is_u32(alg)) {
        uint32_t value;

        if (hexsz < 9 || brix_cksum_u32_obj((int) alg, obj, &value) != 0) {
            brix_checksum_log_read_error(log, errno,
                                           brix_checksum_name(alg), path);
            return NGX_ERROR;
        }
        snprintf(hex, hexsz, "%08x", (unsigned int) value);
        return NGX_OK;
    }

    if (brix_checksum_is_u64(alg)) {
        uint64_t value;

        if (hexsz < 17 || brix_cksum_u64_obj((int) alg, obj, &value) != 0) {
            brix_checksum_log_read_error(log, errno,
                                           brix_checksum_name(alg), path);
            return NGX_ERROR;
        }
        snprintf(hex, hexsz, "%016llx", (unsigned long long) value);
        return NGX_OK;
    }

    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  digest_len;

        if (hexsz < (EVP_MAX_MD_SIZE * 2 + 1)
            || brix_cksum_digest_obj((int) alg, obj, digest, &digest_len) != 0)
        {
            brix_checksum_log_read_error(log, errno,
                                           brix_checksum_name(alg), path);
            return NGX_ERROR;
        }
        brix_checksum_hex_encode(digest, digest_len, hex);
        return NGX_OK;
    }
}

/*
 * brix_checksum_hex_name_fd — parse algorithm name and compute hex checksum.
 *
 * WHAT: Convenience entry point that accepts an algorithm name string (e.g. "crc32c") instead
 *      of the enum value, parses it via brix_checksum_parse(), then delegates to
 *      brix_checksum_hex_fd() for computation. WHY: Config directives and wire protocol
 *      carry algorithm names as strings; this wrapper saves callers from calling parse() +
 *      hex_fd() separately. HOW: 1) Parse name string into alg enum → 2) On NGX_OK, call
 *      hex_fd(alg, fd, path, log, hex, hexsz). Returns NGX_ERROR/NGX_DECLINED if parsing fails. */

ngx_int_t
brix_checksum_hex_name_fd(const char *name, int fd, const char *path,
    ngx_log_t *log, char *hex, size_t hexsz, char *normalized,
    size_t normalized_sz)
{
    brix_checksum_alg_t alg;
    ngx_int_t             rc;

    rc = brix_checksum_parse(name, strlen(name), &alg, normalized,
                               normalized_sz);
    if (rc != NGX_OK) {
        return rc;
    }

    return brix_checksum_hex_fd(alg, fd, path, log, hex, hexsz);
}
