#include "core/ngx_brix_module.h"
#include "core/compat/crc32c.h"
#include "core/compat/checksum.h"

/* CRC32C checksum helpers for XRootD wire protocol and file integrity verification.
 *
 * WHAT: Thin wrappers around the compat layer's CRC32C implementation providing three access patterns:
 * raw buffer checksum, copy-while-compute (checksum + memcpy in one call), and sequential-file-read
 * checksum using pread with 64KB chunks.
 *
 * WHY: CRC32C is used per-page on pgread/pgwrite wire frames to detect corruption during data transfer.
 * The file variant supports integrity verification of stored files without loading them entirely into memory.
 */

uint32_t
brix_crc32c(const void *buf, size_t len)
/* WHAT: Compute CRC32C checksum over a raw memory buffer.
 * WHY: Used by pgread/pgwrite handlers to compute per-page frame checksums before sending wire data.
 * HOW: Delegate to brix_crc32c_value() from the compat layer — pure wrapper, no local computation. */
{
    return brix_crc32c_value(buf, len);
}

uint32_t
brix_crc32c_copy(const u_char *src, u_char *dst, size_t len)
/* WHAT: Compute CRC32C checksum while copying src→dst in a single pass.
 * WHY: Used by pgwrite handlers to compute the frame checksum and write page data simultaneously, avoiding
 * two separate memory passes (one for checksum, one for copy).
 * HOW: Delegate to brix_crc32c_copy_value() from the compat layer — pure wrapper, no local computation. */
{
    return brix_crc32c_copy_value(src, dst, len);
}

/* WHAT: Compute CRC32C checksum of an open file.
 * WHY: Supports post-write integrity verification without loading the entire file into memory.
 * HOW: Delegates to brix_checksum_u32_fd(CRC32C) — the shared pread+accumulate loop in
 *      compat/checksum.c; returns (uint32_t)-1 sentinel on I/O error, matching prior API. */
uint32_t
brix_crc32c_file(int fd, const char *path, ngx_log_t *log)
{
    uint32_t out;

    if (brix_checksum_u32_fd(BRIX_CHECKSUM_CRC32C, fd, path, log, &out)
        != NGX_OK)
    {
        return (uint32_t) -1;
    }

    return out;
}
