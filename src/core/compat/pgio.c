/*
 * pgio.c — kXR page-mode CRC32c framing (see pgio.h).
 *
 * Shared by the module's pgread-encode / pgwrite-decode and the client's
 * pgwrite-encode / pgread-decode. ngx-free; uses the shared CRC32c kernels.
 */
#include "pgio.h"
#include "crc32c.h"
#include "protocols/root/protocol/flags.h"   /* kXR_pgPageSZ */

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
        crc_be = htonl(brix_crc32c_copy_value(p, out + XRDP_PG_CKSZ, page_data));
        memcpy(out, &crc_be, XRDP_PG_CKSZ);
        out       += XRDP_PG_CKSZ + page_data;
        p         += page_data;
        cur       += page_data;
        remaining -= page_data;
    }
    return (size_t) (out - dst);
}

/*
 * pg_walk_t — cursor state plus last-frame report for the shared decode walk:
 * the wire (i), destination (out) and absolute file (cur) cursors, and the CRC
 * pair + payload length of the most recently consumed frame.
 */
typedef struct {
    size_t   i;       /* wire cursor into pg                        */
    size_t   out;     /* dst cursor                                 */
    int64_t  cur;     /* absolute file offset of the NEXT frame     */
    uint32_t want;    /* last frame: CRC32c carried on the wire     */
    uint32_t actual;  /* last frame: CRC32c computed over the copy  */
    uint32_t dlen;    /* last frame: payload bytes                  */
} pg_walk_t;

/*
 * pg_consume_frame — consume one [CRC32c(4)][data] frame at the walk cursor:
 * validate the framing (short trailing CRC, dst capacity, offset overflow),
 * copy the payload into dst while computing its CRC32c, and advance the walk
 * past the frame.  Returns 0 with w->want/actual/dlen describing the frame
 * (CRC match is the CALLER's judgement — strict aborts, collect records), or
 * -2 on a malformed frame (the caller must stop; w is not meaningful past it).
 */
static int
pg_consume_frame(const uint8_t *pg, size_t pglen, pg_walk_t *w, uint8_t *dst,
                 size_t dstcap)
{
    uint32_t want;
    size_t   to_boundary, data_n;

    /* A lone/short trailing CRC (≤ 4 bytes with no full page) is malformed. */
    if (pglen - w->i <= XRDP_PG_CKSZ) {
        return -2;
    }
    memcpy(&want, pg + w->i, XRDP_PG_CKSZ);   /* unaligned-safe BE read */
    w->want = ntohl(want);
    w->i   += XRDP_PG_CKSZ;

    to_boundary = (size_t) kXR_pgPageSZ
                  - (size_t) (w->cur & (int64_t) (kXR_pgPageSZ - 1));
    data_n = (pglen - w->i < to_boundary) ? (pglen - w->i) : to_boundary;

    if (w->out + data_n > dstcap) {
        return -2;
    }
    if (w->cur > INT64_MAX - (int64_t) data_n) {
        return -2;
    }
    w->actual = brix_crc32c_copy_value(pg + w->i, dst + w->out, data_n);
    w->dlen   = (uint32_t) data_n;
    w->out += data_n;
    w->i   += data_n;
    w->cur += data_n;
    return 0;
}

ssize_t
xrdp_pg_decode(const uint8_t *pg, size_t pglen, int64_t file_off,
               uint8_t *dst, size_t dstcap, int64_t *bad_off)
{
    pg_walk_t w = { 0, 0, file_off, 0, 0, 0 };

    if (bad_off != NULL) {
        *bad_off = file_off;
    }
    if (file_off < 0) {
        return -2;
    }
    while (w.i < pglen) {
        int64_t frame_off = w.cur;

        if (pg_consume_frame(pg, pglen, &w, dst, dstcap) != 0) {
            if (bad_off != NULL) { *bad_off = frame_off; }
            return -2;
        }
        if (w.actual != w.want) {
            if (bad_off != NULL) { *bad_off = frame_off; }
            return -1;
        }
    }
    return (ssize_t) w.out;
}

ssize_t
xrdp_pg_decode_collect(const uint8_t *pg, size_t pglen, int64_t file_off,
                       uint8_t *dst, size_t dstcap,
                       xrdp_pg_bad_t *bad_out, size_t max_bad,
                       size_t *bad_count)
{
    pg_walk_t w = { 0, 0, file_off, 0, 0, 0 };

    *bad_count = 0;
    if (file_off < 0) {
        return -2;
    }
    while (w.i < pglen) {
        int64_t frame_off = w.cur;

        if (pg_consume_frame(pg, pglen, &w, dst, dstcap) != 0) {
            return -2;
        }

        /* The frame is already copied (good or bad) so the caller writes every
         * byte — stock "accept-then-correct". A mismatch is recorded, not fatal. */
        if (w.actual != w.want) {
            if (*bad_count >= max_bad) {
                *bad_count = max_bad;
                return -3;
            }
            bad_out[*bad_count].off  = frame_off;
            bad_out[*bad_count].dlen = w.dlen;
            (*bad_count)++;
        }
    }
    return (ssize_t) w.out;
}
