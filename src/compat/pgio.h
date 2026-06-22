/*
 * pgio.h — kXR page-mode (kXR_pgread / kXR_pgwrite) per-page CRC32c framing.
 *
 * WHAT: encode/decode the wire layout [CRC32c-BE(4)][data ≤ kXR_pgPageSZ] repeated,
 *       with each page aligned to the FILE offset (the first/last fragment may be
 *       short on an unaligned offset).
 * WHY:  the module (pgread encode / pgwrite decode) and the native client (pgwrite
 *       encode / pgread decode) implement the IDENTICAL framing + per-page CRC; one
 *       shared kernel makes producer and consumer agree by construction.
 * HOW:  pure ptr+len over caller buffers, using the shared CRC32c kernels
 *       (libxrdproto). No ngx, no allocation, no I/O. (libxrdproto)
 */
#ifndef XROOTD_COMPAT_PGIO_H
#define XROOTD_COMPAT_PGIO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

/*
 * Encode src[0..len) into page units at dst. Pages align to file_off, so the
 * first fragment is shortened to land later pages on a kXR_pgPageSZ boundary.
 * dst must hold at least len + 4*(number-of-pages) bytes. Returns encoded length.
 */
size_t xrdp_pg_encode(const uint8_t *src, size_t len, int64_t file_off,
                      uint8_t *dst);

/*
 * Decode page units in pg[0..pglen) (aligned at file_off) into dst[0..dstcap),
 * verifying each page's CRC32c. Returns:
 *   >= 0  decoded data byte count
 *   -1    a page's CRC did not match (sets *bad_off to that page's file offset)
 *   -2    malformed framing, dst overflow, or offset overflow
 * bad_off may be NULL.
 */
ssize_t xrdp_pg_decode(const uint8_t *pg, size_t pglen, int64_t file_off,
                       uint8_t *dst, size_t dstcap, int64_t *bad_off);

#endif /* XROOTD_COMPAT_PGIO_H */
