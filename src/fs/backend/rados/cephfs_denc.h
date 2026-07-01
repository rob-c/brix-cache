/*
 * cephfs_denc.h — read-only cursor over a Ceph-encoded buffer.
 *
 * WHAT: The low-level decode primitives for Ceph's wire/disk encoding —
 *       fixed-width little-endian integers, length-prefixed strings/byte runs,
 *       and the ENCODE_START/DECODE_FINISH struct framing (struct_v / compat_v /
 *       byte-length) used by every versioned Ceph type. Bytes in, scalars out.
 *
 * WHY:  Reading a CephFS directly from RADOS means decoding the MDS's on-disk
 *       structures (dentries, inodes, file layouts, fragtrees). Those are all
 *       built from this same handful of primitives. Isolating them here — with
 *       no RADOS and no nginx dependency — lets the typed decoders in
 *       cephfs_layout.* be written and unit-tested against byte fixtures with a
 *       plain compiler, and keeps every bounds check in one audited place.
 *
 * HOW:  A cephfs_denc_t holds (cursor, end, sticky-error). Every accessor checks
 *       remaining space before reading; on overrun it sets the sticky error and
 *       returns a zero/NULL value, so a caller can decode a whole struct and test
 *       cephfs_denc_ok() once at the end rather than after every field. The frame
 *       helpers record where a struct's payload ends so callers can forward-skip
 *       fields they don't understand (forward compatibility across versions).
 *
 * This header is pure C with no nginx/RADOS dependency by design.
 */
#ifndef XROOTD_CEPHFS_DENC_H
#define XROOTD_CEPHFS_DENC_H

#include <stddef.h>
#include <stdint.h>

/* A read-only cursor. `err` is sticky: once set, every further accessor is a
 * no-op that returns zero/NULL, so partial decodes never read out of bounds. */
typedef struct {
    const uint8_t *p;     /* next byte to read                                  */
    const uint8_t *end;   /* one past the last valid byte                       */
    int            err;   /* 0 = ok; non-zero once an overrun/decode error hits */
} cephfs_denc_t;

/* A decoded ENCODE_START frame header (struct version, compat version, and the
 * absolute end of this struct's payload — used by cephfs_denc_finish). */
typedef struct {
    uint8_t        struct_v;
    uint8_t        struct_compat;
    const uint8_t *payload_end;
} cephfs_denc_frame_t;

/* Bind a cursor to [buf, buf+len). */
void   cephfs_denc_init(cephfs_denc_t *d, const void *buf, size_t len);

/* 1 when no error has been recorded, else 0. */
int    cephfs_denc_ok(const cephfs_denc_t *d);

/* Bytes left between the cursor and end (0 once errored or exhausted). */
size_t cephfs_denc_remaining(const cephfs_denc_t *d);

/* Fixed-width little-endian integers. On overrun: set err, return 0. */
uint8_t  cephfs_denc_u8 (cephfs_denc_t *d);
uint16_t cephfs_denc_u16(cephfs_denc_t *d);
uint32_t cephfs_denc_u32(cephfs_denc_t *d);
uint64_t cephfs_denc_u64(cephfs_denc_t *d);
int64_t  cephfs_denc_s64(cephfs_denc_t *d);

/* A run of n raw bytes: returns a pointer into the buffer (no copy) and advances
 * the cursor; returns NULL (and sets err) on overrun. */
const uint8_t *cephfs_denc_bytes(cephfs_denc_t *d, size_t n);

/* Advance the cursor by n bytes (clamped; sets err on overrun). */
void   cephfs_denc_skip(cephfs_denc_t *d, size_t n);

/* A Ceph string/bufferlist: u32 length prefix + that many bytes. On success sets
 * *s to a pointer into the buffer (NOT null-terminated) and *len to the length,
 * and returns 0; on overrun sets err and returns -1. Either out-param may be
 * NULL to decode-and-discard. */
int    cephfs_denc_str(cephfs_denc_t *d, const char **s, uint32_t *len);

/* Read an ENCODE_START header: struct_v(u8), struct_compat(u8), struct_len(u32).
 * Records the payload bounds in *f and returns struct_v. On overrun, or if the
 * declared length runs past the buffer, sets err and returns 0. */
uint8_t cephfs_denc_start(cephfs_denc_t *d, cephfs_denc_frame_t *f);

/* Jump the cursor to the end of a frame's payload (skipping any trailing fields a
 * newer encoder added that this decoder did not read). No-op if errored or if the
 * cursor is already at/past payload_end. */
void   cephfs_denc_finish(cephfs_denc_t *d, const cephfs_denc_frame_t *f);

#endif /* XROOTD_CEPHFS_DENC_H */
