/*
 * fs/meta/xmeta_internal.h — declarations shared across the xmeta codec files
 * after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the block-geometry helpers (defined in xmeta.c) and the
 *       two persisted wire descriptors (the STATE section struct and the ORIGIN
 *       fixed-header size) that the encode and decode halves both need.
 * WHY:  xmeta.c (942 lines) split into three focused files under the 500-line
 *       cap: xmeta.c (record lifecycle, bitmap ops, DIGEST-list ops),
 *       xmeta_encode.c (record → wire buffer) and xmeta_decode.c (wire buffer →
 *       record). The bitmap byte-length / block-count math is used by all three;
 *       xmeta_state_wire_t and XMETA_ORIGIN_FIXED describe on-disk layout and
 *       must be identical on the encode and decode sides — so exactly those
 *       symbols become non-static / shared here, nothing else crosses.
 * HOW:  xmeta.c, xmeta_encode.c and xmeta_decode.c all include this header; none
 *       of the symbols is exported beyond the xmeta codec unit.
 *
 * Requires: xmeta.h (brix_xmeta_t) — included below.
 */
#ifndef BRIX_FS_META_XMETA_INTERNAL_H
#define BRIX_FS_META_XMETA_INTERNAL_H

#include "xmeta.h"

/* ---- STATE section wire layout (80 bytes) --------------------------------
 * Persisted little-endian; the encode side (xmeta_encode_state_section) and
 * the decode side (xmeta_decode_state) must copy these fields in the same
 * order. Size is pinned by a static assert in xmeta_encode.c. */
typedef struct {
    uint64_t origin_mtime;
    uint64_t dirty_lo;
    uint64_t dirty_hi;
    uint64_t flush_gen;
    uint64_t dirty_since;
    uint64_t last_flush;
    uint64_t bytes_flushed;
    uint64_t expires_at;
    uint64_t filled_at;
    uint32_t mode;
    uint32_t state_flags;
} xmeta_state_wire_t;

/* ORIGIN section fixed header: {u8 etag_len, u8 alg_len, u8 cks_len, u8 pad}
 * followed by the three length-prefixed strings. */
#define XMETA_ORIGIN_FIXED 4

/* ---- shared block-geometry helpers (defined in xmeta.c) ------------------ */

/* Number of buffer_size-granule blocks covering file_size (0 for empty). */
uint64_t xmeta_nblocks(int64_t file_size, int64_t buffer_size);

/* Present-bitmap length in bytes for nblocks blocks (ceil(nblocks/8)). */
size_t xmeta_bitmap_len(uint64_t nblocks);

#endif /* BRIX_FS_META_XMETA_INTERNAL_H */
