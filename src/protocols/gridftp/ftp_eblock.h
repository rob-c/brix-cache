#ifndef BRIX_GRIDFTP_EBLOCK_H
#define BRIX_GRIDFTP_EBLOCK_H

/*
 * ftp_eblock.h — GridFTP MODE E extended-block framing (GFD.020 §3.4).
 *
 * WHAT: the 17-byte extended-block header codec (descriptor + count + offset),
 * the descriptor flag constants, and the committed-range overlap guard shared by
 * both gateway engines' MODE E paths.
 *
 * WHY: MODE E frames a transfer as offset-addressed records that arrive out of
 * order across up to `Parallelism` data connections — there is no shared stream
 * cursor, so every block carries its own absolute file offset and a receiver must
 * reject a block that overlaps an already-committed range (corruption or a
 * deliberate overwrite, §2.6 R4).  The wire codec and the overlap test are pure,
 * self-contained functions; keeping one definition here means the event engine's
 * RETR framer and STOR receiver (ev/ftp_ev_mode_e.c) frame identically and cannot
 * drift.  Marker formatting and the reassembly state machine stay in the engine
 * (they touch its reply path and I/O model).
 *
 * HOW: header-only `static ngx_inline` — each translation unit inlines its own
 * copy from this single source; GCC does not warn on an unused static inline, so
 * a TU that needs only the codec (RETR framing) and not the range guard compiles
 * clean under -Werror.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>    /* uint64_t for the 8-byte count/offset fields */

/* 17-byte header, network byte order: 1-byte descriptor + 8-byte count + 8-byte
 * offset, then `count` payload bytes.  An EOF-flagged block carries no payload
 * and puts the total EOD count in its OFFSET field (globus convention); each data
 * connection ends with exactly one EOD. */
#define FTP_EB_HDR   17
#define FTP_EB_EOF   0x40    /* no payload; offset field = total EOD count      */
#define FTP_EB_EOD   0x08    /* last block on this data connection              */


static ngx_inline void
ftp_eb_pack(u_char *h, u_char desc, uint64_t count, uint64_t offset)
{
    int i;
    h[0] = desc;
    for (i = 0; i < 8; i++) { h[1 + i] = (u_char) (count  >> (56 - 8 * i)); }
    for (i = 0; i < 8; i++) { h[9 + i] = (u_char) (offset >> (56 - 8 * i)); }
}


static ngx_inline void
ftp_eb_unpack(const u_char *h, u_char *desc, uint64_t *count, uint64_t *offset)
{
    uint64_t c = 0, o = 0;
    int      i;
    *desc = h[0];
    for (i = 0; i < 8; i++) { c = (c << 8) | h[1 + i]; }
    for (i = 0; i < 8; i++) { o = (o << 8) | h[9 + i]; }
    *count  = c;
    *offset = o;
}


/* A byte range already committed this transfer.  MODE E blocks are addressed by
 * absolute offset, so a block overlapping a committed range is corruption or a
 * deliberate overwrite attack and must fail the transfer. */
typedef struct { off_t lo, hi; } ftp_eb_range_t;

static ngx_inline int
ftp_eb_range_overlaps(const ftp_eb_range_t *r, size_t n, off_t lo, off_t hi)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (lo < r[i].hi && r[i].lo < hi) {
            return 1;
        }
    }
    return 0;
}

#endif /* BRIX_GRIDFTP_EBLOCK_H */
