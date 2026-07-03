#include "query_internal.h"
#include "core/compat/checksum.h"

#include <errno.h>

/*
 * WHAT: File checksum and digest helpers shared by kXR_Qcksum (checksum query) opcodes.
 * WHY: Clients need to verify file integrity before or after transfer operations. Adler-32 is the default for xrdcp compatibility;
 *      EVP-based digests support md5, sha1, and sha256 via the brix_checksum_alg directive. Two variants exist per algorithm — fd-based
 *      (for open handles during query) and file-based (path lookup + open + compute). INVARIANT: all path strings sanitized with
 *      brix_sanitize_log_string() before logging to prevent binary data corruption in access logs.
 * HOW: Adler-32 uses 65536-byte read buffer with pread() loop; A/B accumulator modulo 65521 returns (B << 16) | A. EVP digests create
 *      MD_CTX via EVP_MD_CTX_new(), chain Init_ex → Update loop → Final_ex, free context on all exit paths. File variants wrap fd variants
 *      with brix_open_confined() and close(). All error paths return 0xFFFFFFFF (adler32) or 0 (digest).
 */

/*
 * brix_query_adler32_fd — Adler-32 checksum from open file descriptor.

 * WHAT: Compute Adler-32 (RFC 3309) checksum of file contents using pread()
 *      on an already-open FD. Returns the checksum value or 0xFFFFFFFF sentinel
 *      on I/O error.

 * WHY: Handles kXR_Qcksum variant where client provides a file handle rather than
 *      a path string — avoids reopening the same file during read operations for
 *      inline integrity verification. Adler-32 is the default algorithm for xrdcp
 *      compatibility.

 * HOW: Delegates to brix_checksum_u32_fd() with BRIX_CHECKSUM_ADLER32 → on
 *      NGX_OK success returns computed value, on failure returns 0xFFFFFFFF sentinel.

 * Parameters:
 *   fd   — already-open file descriptor (O_RDONLY)
 *   path — filesystem path string for error logging context
 *   log  — nginx log pointer for I/O error reporting
 */

/*
 * brix_query_adler32_file — Adler-32 checksum from filesystem path.

 * WHAT: Open file via confined canonical resolution, compute Adler-32 checksum,
 *      close FD on completion. Returns checksum value or 0xFFFFFFFF sentinel on error.

 * WHY: Path variant of kXR_Qcksum where client requests checksum by filesystem
 *      path string instead of a handle. Uses brix_open_confined for security
 *      confinement (prevents traversal outside configured root).

 * HOW: Sanitize path for logging → open via brix_open_confined(log, root, path,
 *      O_RDONLY) → call brix_query_adler32_fd(fd, path, log) → close(fd) → return.
 *      Error sentinel 0xFFFFFFFF returned on open failure or checksum computation error.

 * Parameters:
 *   root — configured root filesystem path (ngx_str_t)
 *   path — target file path string for checksum
 *   log  — nginx log pointer for error reporting
 */

/*
 * brix_query_digest_fd — EVP digest from open file descriptor.

 * WHAT: Compute any OpenSSL EVP-compatible digest (md5, sha1, sha256) from an
 *      already-open FD. Returns 1 on success with digest bytes written to out[],
 *      or 0 on error (context freed on all exit paths).

 * WHY: Handles kXR_Qcksum variant where client requests a non-Adler-32 checksum
 *      via an existing file handle during read operations. Supports configurable
 *      algorithms set via brix_checksum_alg directive.

 * HOW: Create EVP_MD_CTX → EVP_DigestInit_ex(md, NULL) → pread loop (65536-byte
 *      buffer): EVP_DigestUpdate on each chunk → handle EINTR retries → break on EOF
 *      → EVP_DigestFinal_ex(out, outlen) → free context. Error paths: free context,
 *      log at ERR level with sanitized path, return 0.

 * Parameters:
 *   fd     — already-open file descriptor (O_RDONLY)
 *   path   — filesystem path string for error logging
 *   md     — EVP_MD pointer selecting algorithm (md5/sha1/sha256)
 *   out    — output buffer for digest bytes (must be EVP_MAX_MD_SIZE or larger)
 *   outlen — output pointer for actual digest length in bytes
 *   log    — nginx log pointer for I/O error reporting
 */

/*
 * brix_query_digest_file — EVP digest from filesystem path.

 * WHAT: Open file via confined canonical resolution, compute EVP digest, close FD
 *      on completion. Returns 1 on success with digest written to out[], or 0 on error.

 * WHY: Path variant of kXR_Qcksum where client requests a non-Adler-32 checksum by
 *      filesystem path string. Uses brix_open_confined for security confinement.

 * HOW: Open via brix_open_confined(log, root, path, O_RDONLY) → call
 *      brix_query_digest_fd(fd, path, md, out, outlen, log) → close(fd) → return.
 *      Error sentinel 0 returned on open failure or digest computation error.

 * Parameters:
 *   root   — configured root filesystem path (ngx_str_t)
 *   path   — target file path string for digest
 *   md     — EVP_MD pointer selecting algorithm (md5/sha1/sha256)
 *   out    — output buffer for digest bytes (must be EVP_MAX_MD_SIZE or larger)
 *   outlen — output pointer for actual digest length in bytes
 *   log    — nginx log pointer for error reporting
 */

uint32_t
brix_query_adler32_fd(int fd, const char *path, ngx_log_t *log)
{
    uint32_t out;

    if (brix_checksum_u32_fd(BRIX_CHECKSUM_ADLER32, fd, path, log, &out)
        != NGX_OK)
    {
        return 0xFFFFFFFF;
    }

    return out;
}

uint32_t
brix_query_adler32_file(const ngx_str_t *root, const char *path,
    ngx_log_t *log)
{
    int      fd;
    uint32_t cksum;
    char     safe_path[512];

    brix_sanitize_log_string(path, safe_path, sizeof(safe_path));

    fd = brix_open_confined(log, root, path, O_RDONLY, 0);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix: adler32 open(\"%s\") failed", safe_path);
        return 0xFFFFFFFF;
    }

    cksum = brix_query_adler32_fd(fd, path, log);
    close(fd);
    return cksum;
}

ngx_flag_t
brix_query_digest_fd(int fd, const char *path,
    brix_checksum_alg_t alg,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log)
{
    return brix_checksum_digest_fd(alg, fd, path, log, out, outlen)
           == NGX_OK ? 1 : 0;
}

ngx_flag_t
brix_query_digest_file(const ngx_str_t *root, const char *path,
    brix_checksum_alg_t alg, unsigned char *out, unsigned int *outlen,
    ngx_log_t *log)
{
    int        fd;
    char       safe[512];
    ngx_flag_t ok;

    fd = brix_open_confined(log, root, path, O_RDONLY, 0);
    if (fd < 0) {
        brix_sanitize_log_string(path, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix: digest open(\"%s\") failed", safe);
        return 0;
    }

    ok = brix_query_digest_fd(fd, path, alg, out, outlen, log);
    close(fd);
    return ok;
}

/*
 * brix_query_crc32_fd — ISO-3309 CRC-32 from open file descriptor.

 * WHAT: Compute CRC-32 (IEEE 802.3 / ISO-3309) checksum via zlib's crc32() on an
 *      already-open FD. Returns the checksum value or 0xFFFFFFFF sentinel on error.

 * WHY: Historically used by ATLAS experiments; distinct from CRC32c (Castagnoli)
 *      which is the default for xrootd internal operations. Handles kXR_Qcksum variant
 *      where client requests legacy CRC-32 via a file handle.

 * HOW: Delegates to brix_checksum_u32_fd() with BRIX_CHECKSUM_CRC32 → on NGX_OK
 *      success returns computed value, on failure returns 0xFFFFFFFF sentinel.

 * Parameters:
 *   fd   — already-open file descriptor (O_RDONLY)
 *   path — filesystem path string for error logging context
 *   log  — nginx log pointer for I/O error reporting
 */

uint32_t
brix_query_crc32_fd(int fd, const char *path, ngx_log_t *log)
{
    uint32_t out;

    if (brix_checksum_u32_fd(BRIX_CHECKSUM_CRC32, fd, path, log, &out)
        != NGX_OK)
    {
        return 0xFFFFFFFF;
    }

    return out;
}

uint32_t
brix_query_crc32_file(const ngx_str_t *root, const char *path,
    ngx_log_t *log)
{
    int      fd;
    uint32_t cksum;
    char     safe_path[512];

    brix_sanitize_log_string(path, safe_path, sizeof(safe_path));

    fd = brix_open_confined(log, root, path, O_RDONLY, 0);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix: crc32 open(\"%s\") failed", safe_path);
        return 0xFFFFFFFF;
    }

    cksum = brix_query_crc32_fd(fd, path, log);
    close(fd);
    return cksum;
}
/*
 * brix_query_crc32_fd — ISO-3309 CRC-32 from open file descriptor.

 * WHAT: Compute CRC-32 (IEEE 802.3 / ISO-3309) checksum via zlib's crc32() on an
 *      already-open FD. Returns the checksum value or 0xFFFFFFFF sentinel on error.

 * WHY: Historically used by ATLAS experiments; distinct from CRC32c (Castagnoli)
 *      which is the default for xrootd internal operations. Handles kXR_Qcksum variant
 *      where client requests legacy CRC-32 via a file handle.

 * HOW: Delegates to brix_checksum_u32_fd() with BRIX_CHECKSUM_CRC32 → on NGX_OK
 *      success returns computed value, on failure returns 0xFFFFFFFF sentinel.

 * Parameters:
 *   fd   — already-open file descriptor (O_RDONLY)
 *   path — filesystem path string for error logging context
 *   log  — nginx log pointer for I/O error reporting
 */
/*
 * brix_query_crc32_file — ISO-3309 CRC-32 from filesystem path.

 * WHAT: Open file via confined canonical resolution, compute CRC-32 checksum,
 *      close FD on completion. Returns checksum value or 0xFFFFFFFF sentinel on error.

 * WHY: Path variant of kXR_Qcksum where client requests legacy CRC-32 (IEEE 802.3 /
 *      ISO-3309) by filesystem path string. Historically used by ATLAS experiments;
 *      distinct from CRC32c (Castagnoli). Uses brix_open_confined for security confinement.

 * HOW: Sanitize path for logging → open via brix_open_confined(log, root, path,
 *      O_RDONLY) → call brix_query_crc32_fd(fd, path, log) → close(fd) → return.
 *      Error sentinel 0xFFFFFFFF returned on open failure or checksum computation error.

 * Parameters:
 *   root — configured root filesystem path (ngx_str_t)
 *   path — target file path string for CRC-32
 *   log  — nginx log pointer for error reporting
 */

