/*
 * cas_pack_format.h — THE packed-segment record format (phase-88 W2).
 *
 * WHAT: The on-disk layout of one "BXS1" segment record — the single format
 *       shared by BOTH packed stores: the client CAS cache runtime
 *       (shared/cache/cas_pack.c, journal-indexed, single-process) and the
 *       server pblock small-blob arena (src/fs/backend/pblock/pblock_pack.c,
 *       catalog-indexed, cross-process). One segment record:
 *
 *         u32 magic "BXS1" · u16 klen · u8 fmt · u8 rsvd · u32 crc32(data)
 *         · u64 stored_len · u64 raw_len · key[klen] · data[stored_len]
 *
 * WHY:  Phase-87 G4 shipped the packed heap client-side only; phase-88 W2
 *       gives pblock the same arena. Sharing the record layout (not the
 *       runtime — the client's in-memory-hash/journal engine is single-process
 *       by design and cannot serve nginx's multi-worker stores) keeps the two
 *       from drifting and lets one fsck/scavenger vocabulary read both.
 *
 * HOW:  Constants + the fixed-offset codec (host-endian, store-local, never
 *       interchanged between hosts) + one encode and one decode helper. This
 *       header is PRIVATE to the pack TUs: the short helper names (put32,
 *       crc_of, SEG_HDR) are part of cas_pack.c's original vocabulary — do not
 *       include it from anything but a pack engine. Requires <zlib.h> linkage.
 */
#ifndef BRIX_CAS_PACK_FORMAT_H
#define BRIX_CAS_PACK_FORMAT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#define SEG_MAGIC   0x31535842u                /* "BXS1" */
#define SEG_HDR     28u
#define PACK_KMAX   128u                       /* longest record key (== BRIX_PACK_KMAX) */

/* ---- little fixed-offset codec (avoids struct padding) ------------------ */

static inline void put32(unsigned char *b, uint32_t v) { memcpy(b, &v, 4); }
static inline void put64(unsigned char *b, uint64_t v) { memcpy(b, &v, 8); }
static inline uint32_t get32(const unsigned char *b) { uint32_t v; memcpy(&v, b, 4); return v; }
static inline uint64_t get64(const unsigned char *b) { uint64_t v; memcpy(&v, b, 8); return v; }

static inline uint32_t crc_of(const void *buf, size_t len) {
    return (uint32_t) crc32(crc32(0L, Z_NULL, 0), buf, (uInt) len);
}

/* One decoded segment-record header. */
typedef struct {
    size_t   klen;
    uint8_t  fmt;          /* 0 = raw, 1 = zstd (client tiering only) */
    uint32_t crc;          /* crc32 of the STORED data bytes */
    uint64_t stored;       /* bytes on disk */
    uint64_t raw;          /* plaintext length */
} brix_pack_rec_t;

/* Encode a record header (+ trailing key) into hdr[SEG_HDR + r->klen]. */
static inline void
brix_pack_seg_encode(unsigned char *hdr, const char *key,
    const brix_pack_rec_t *r)
{
    put32(hdr, SEG_MAGIC);
    hdr[4] = (unsigned char) (r->klen & 0xff);
    hdr[5] = (unsigned char) (r->klen >> 8);
    hdr[6] = r->fmt;
    hdr[7] = 0;
    put32(hdr + 8, r->crc);
    put64(hdr + 12, r->stored);
    put64(hdr + 20, r->raw);
    memcpy(hdr + SEG_HDR, key, r->klen);
}

/* Decode + shape-check a record header from hdr[SEG_HDR]. Returns 0 (out
 * filled) or -1 on a bad magic / key length / format byte — the caller still
 * bounds-checks stored/raw against its own limits and verifies the data crc. */
static inline int
brix_pack_seg_decode(const unsigned char *hdr, brix_pack_rec_t *out)
{
    out->klen   = (size_t) hdr[4] | ((size_t) hdr[5] << 8);
    out->fmt    = hdr[6];
    out->crc    = get32(hdr + 8);
    out->stored = get64(hdr + 12);
    out->raw    = get64(hdr + 20);
    if (get32(hdr) != SEG_MAGIC || out->klen == 0 || out->klen > PACK_KMAX
        || out->fmt > 1)
    {
        return -1;
    }
    return 0;
}

#endif /* BRIX_CAS_PACK_FORMAT_H */
