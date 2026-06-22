/*
 * pgio.c — kXR page-mode CRC32c framing (see pgio.h).
 *
 * Shared by the module's pgread-encode / pgwrite-decode and the client's
 * pgwrite-encode / pgread-decode. ngx-free; uses the shared CRC32c kernels.
 */
#include "pgio.h"
#include "crc32c.h"
#include "../protocol/flags.h"   /* kXR_pgPageSZ */

#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>   /* htonl / ntohl */

#define XRDP_PG_CKSZ 4   /* one CRC32c per page (big-endian) */

size_t
xrdp_pg_encode(const uint8_t *src, size_t len, int64_t file_off, uint8_t *dst)
{
    const uint8_t *p   = src;
    uint8_t       *out = dst;
    size_t   remaining = len;
    int64_t  cur       = file_off;

    while (remaining > 0) {
        /* kXR_pgPageSZ is a power of two, so (cur & (sz-1)) is the in-page offset;
         * shorten the first fragment so every later page starts on a boundary. */
        size_t   to_boundary = (size_t) kXR_pgPageSZ
                               - (size_t) (cur & (int64_t) (kXR_pgPageSZ - 1));
        size_t   page_data   = (remaining < to_boundary) ? remaining : to_boundary;
        uint32_t crc_be;

        /* Wire per page: [CRC32c(4)][data] — copy + CRC in one pass. */
        crc_be = htonl(xrootd_crc32c_copy_value(p, out + XRDP_PG_CKSZ, page_data));
        memcpy(out, &crc_be, XRDP_PG_CKSZ);
        out       += XRDP_PG_CKSZ + page_data;
        p         += page_data;
        cur       += page_data;
        remaining -= page_data;
    }
    return (size_t) (out - dst);
}

ssize_t
xrdp_pg_decode(const uint8_t *pg, size_t pglen, int64_t file_off,
               uint8_t *dst, size_t dstcap, int64_t *bad_off)
{
    size_t  i   = 0;
    size_t  out = 0;
    int64_t cur = file_off;

    if (bad_off != NULL) {
        *bad_off = file_off;
    }
    if (file_off < 0) {
        return -2;
    }
    while (i < pglen) {
        uint32_t want, actual;
        size_t   to_boundary, data_n;

        /* A lone/short trailing CRC (≤ 4 bytes with no full page) is malformed. */
        if (pglen - i <= XRDP_PG_CKSZ) {
            if (bad_off != NULL) { *bad_off = cur; }
            return -2;
        }
        memcpy(&want, pg + i, XRDP_PG_CKSZ);   /* unaligned-safe BE read */
        want = ntohl(want);
        i   += XRDP_PG_CKSZ;

        to_boundary = (size_t) kXR_pgPageSZ
                      - (size_t) (cur & (int64_t) (kXR_pgPageSZ - 1));
        data_n = (pglen - i < to_boundary) ? (pglen - i) : to_boundary;

        if (out + data_n > dstcap) {
            if (bad_off != NULL) { *bad_off = cur; }
            return -2;
        }
        if (cur > INT64_MAX - (int64_t) data_n) {
            if (bad_off != NULL) { *bad_off = cur; }
            return -2;
        }
        actual = xrootd_crc32c_copy_value(pg + i, dst + out, data_n);
        if (actual != want) {
            if (bad_off != NULL) { *bad_off = cur; }
            return -1;
        }
        out += data_n;
        i   += data_n;
        cur += data_n;
    }
    return (ssize_t) out;
}
