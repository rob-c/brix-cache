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
    default:
        return NULL;
    }
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
           || alg == XROOTD_CHECKSUM_CRC32C;
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
    } else {
        return NGX_DECLINED;
    }

    if (alg != NULL) {
        *alg = parsed;
    }

    if (normalized != NULL && normalized_sz > 0) {
        ngx_cpystrn((u_char *) normalized, (u_char *) buf, normalized_sz);
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
    u_char   buf[XROOTD_CHECKSUM_BUFSZ];
    off_t    offset;
    ssize_t  n;
    uint32_t crc32c;
    uLong    zcrc;
    const char *name;

    if (out == NULL || !xrootd_checksum_is_u32(alg)) {
        return NGX_ERROR;
    }

    name = xrootd_checksum_name(alg);
    offset = 0;
    crc32c = 0;

    if (alg == XROOTD_CHECKSUM_ADLER32) {
        zcrc = adler32(0L, Z_NULL, 0);
    } else if (alg == XROOTD_CHECKSUM_CRC32) {
        zcrc = crc32(0L, Z_NULL, 0);
    } else {
        zcrc = 0;
    }

    for (;;) {
        n = pread(fd, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            xrootd_checksum_log_read_error(log, errno, name, path);
            return NGX_ERROR;
        }

        if (n == 0) {
            break;
        }

        offset += (off_t) n;

        if (alg == XROOTD_CHECKSUM_ADLER32) {
            zcrc = adler32(zcrc, buf, (uInt) n);
        } else if (alg == XROOTD_CHECKSUM_CRC32) {
            zcrc = crc32(zcrc, buf, (uInt) n);
        } else {
            crc32c = xrootd_crc32c_extend(crc32c, buf, (size_t) n);
        }
    }

    *out = (alg == XROOTD_CHECKSUM_CRC32C) ? crc32c : (uint32_t) zcrc;
    return NGX_OK;
}

/*
 * xrootd_checksum_evp_md - map checksum algorithm enum to OpenSSL EVP_MD pointer.
 *
 * WHAT: Returns the OpenSSL digest type for MD5, SHA1, or SHA256. Returns NULL for
 *       non-digest algorithms (Adler-32, CRC-32, CRC-32c).
 *
 * WHY: xrootd_checksum_digest_fd() needs an EVP_MD pointer to initialise the digest
 *      context. This switch-case provides the lookup without caller needing OpenSSL
 *      knowledge.
 *
 * HOW: Direct switch-case returning EVP_md5(), EVP_sha1(), EVP_sha256().
 */

static const EVP_MD *
xrootd_checksum_evp_md(xrootd_checksum_alg_t alg)
{
    switch (alg) {
    case XROOTD_CHECKSUM_MD5:
        return EVP_md5();
    case XROOTD_CHECKSUM_SHA1:
        return EVP_sha1();
    case XROOTD_CHECKSUM_SHA256:
        return EVP_sha256();
    default:
        return NULL;
    }
}

/*
 * xrootd_checksum_digest_fd — compute MD5 / SHA1 / SHA256 on file descriptor.
 *
 * WHAT: Reads an entire file via pread in 64KB chunks, accumulating a cryptographic digest
 *      (MD5, SHA1, or SHA256) using OpenSSL EVP API. WHY: fattr/PROPFIND return hex-encoded
 *      digests for integrity verification; WebDAV/S3 use SHA-256 for object checksums. This
 *      shared function serves all three protocol callers without duplication. HOW: 1) Map alg
 *      to EVP_MD via xrootd_checksum_evp_md() → 2) Create EVP_MD_CTX, init with EVP_DigestInit_ex
 *      → 3) Loop pread(buf, 64KB, offset) with EINTR retry → 4) Update digest per chunk via
 *      EVP_DigestUpdate → 5) Finalise via EVP_DigestFinal_ex → 6) Return binary digest + length.
 *      Returns NGX_ERROR on init/final failure or read error (logged via log_read_error). */

/*
 * Drive an already-initialised EVP_MD_CTX over the whole file: init the digest,
 * pread it in chunks (EINTR-retried), update per chunk, and finalise into
 * out/outlen. Returns NGX_OK on success, NGX_ERROR on any OpenSSL or read
 * failure (read errors are logged). The caller owns ctx and frees it; keeping
 * ownership at the edge lets this worker use flat early returns.
 */
static ngx_int_t
xrootd_checksum_digest_ctx(EVP_MD_CTX *ctx, const EVP_MD *md, int fd,
    const char *path, xrootd_checksum_alg_t alg, ngx_log_t *log,
    unsigned char *out, unsigned int *outlen)
{
    u_char   buf[XROOTD_CHECKSUM_BUFSZ];
    off_t    offset;
    ssize_t  n;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        return NGX_ERROR;
    }

    offset = 0;
    for (;;) {
        n = pread(fd, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            xrootd_checksum_log_read_error(log, errno,
                                           xrootd_checksum_name(alg), path);
            return NGX_ERROR;
        }

        if (n == 0) {
            break;
        }

        offset += (off_t) n;
        if (EVP_DigestUpdate(ctx, buf, (size_t) n) != 1) {
            return NGX_ERROR;
        }
    }

    if (EVP_DigestFinal_ex(ctx, out, outlen) != 1) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_checksum_digest_fd(xrootd_checksum_alg_t alg, int fd, const char *path,
    ngx_log_t *log, unsigned char *out, unsigned int *outlen)
{
    const EVP_MD *md;
    EVP_MD_CTX   *ctx;
    ngx_int_t     rc;

    md = xrootd_checksum_evp_md(alg);
    if (md == NULL || out == NULL || outlen == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    rc = xrootd_checksum_digest_ctx(ctx, md, fd, path, alg, log, out, outlen);

    EVP_MD_CTX_free(ctx);
    return rc;
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
