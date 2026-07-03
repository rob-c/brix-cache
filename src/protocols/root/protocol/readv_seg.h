/*
 * readv_seg.h — kXR_readv segment-header codec (single source of truth).
 *
 * WHAT: each kXR_readv request and response carries an array of fixed 16-byte
 *       segment headers, one per requested range:
 *         [ fhandle[4] ][ rlen[4 BE] ][ offset[8 BE] ]   (BRIX_READV_SEGSIZE)
 *       This header owns that layout for everyone who assembles or reads it:
 *         - brix_readv_seg_pack: fields -> 16-byte header
 *         - brix_readv_seg_rlen: 16-byte header -> rlen (the field a reader needs)
 * WHY:  the layout — and the magic +4 / +8 / 16 offsets — were hand-spelled in
 *       BOTH directions across BOTH trees: the native client builds the request
 *       segments and reads the response segments (client/lib/ops_file.c), and the
 *       module builds the response segments (src/read/readv.c). pgio already
 *       single-sources the paged-I/O wire layout; readv was the remaining gap.
 * HOW:  header-only static inlines over the shared, unaligned-safe big-endian
 *       accessors in frame_hdr.h — no ngx, no allocation — so the same code
 *       compiles into the nginx module and the ngx-free client. The module's
 *       request *parse* uses the typed `readahead_list` struct directly (clean,
 *       not raw bytes) and is left as-is; this codec covers the raw-byte sites.
 *
 * Clean-room: layout from src/protocol readahead_list (vs XProtocol read_args).
 */
#ifndef BRIX_PROTOCOL_READV_SEG_H
#define BRIX_PROTOCOL_READV_SEG_H

#include <stdint.h>
#include <string.h>

#include "frame_hdr.h"   /* xrd_put_u32_be / xrd_put_u64_be / xrd_get_u32_be */
#include "flags.h"       /* BRIX_READV_SEGSIZE */

/*
 * Pack one readv segment header into `out` (BRIX_READV_SEGSIZE bytes): the
 * 4-byte file handle verbatim, then rlen and offset in big-endian. `offset` and
 * `rlen` are host-order; the encode is the exact inverse of brix_readv_seg_rlen
 * (and of the typed readahead_list the module parses on the request side).
 */
static inline void
brix_readv_seg_pack(uint8_t out[BRIX_READV_SEGSIZE], const uint8_t fhandle[4],
                      uint32_t rlen, uint64_t offset)
{
    memcpy(out, fhandle, 4);
    xrd_put_u32_be(out + 4, rlen);
    xrd_put_u64_be(out + 8, offset);
}

/* Read the rlen field (host order) from a 16-byte segment header. */
static inline uint32_t
brix_readv_seg_rlen(const uint8_t in[BRIX_READV_SEGSIZE])
{
    return xrd_get_u32_be(in + 4);
}

#endif /* BRIX_PROTOCOL_READV_SEG_H */
