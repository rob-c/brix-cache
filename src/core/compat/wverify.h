/*
 * wverify.h — self-computed write-integrity accumulator (backend-agnostic).
 *
 * WHAT: Accumulate a CRC-32 over the bytes a protocol WRITES to a storage
 *       handle, so that after close the object can be re-read through the
 *       storage driver and compared: proof the driver actually persisted every
 *       byte, rather than trusting the write path (the class of failure where a
 *       fd-keyed helper bypassed an object backend's block routing and the
 *       object read back short/empty).
 * WHY:  An object backend (pblock, rados) has no single kernel fd whose bytes
 *       are the file; the only trustworthy end-to-end check is "read it back
 *       through the same driver and confirm the content". This kernel supplies
 *       the write-side expectation for that compare, with no client cooperation.
 * HOW:  Each written extent [off, off+len) is CRC-32'd (zlib) and folded into an
 *       offset-sorted list; adjacent extents are coalesced via crc32_combine, so
 *       an in-order stream collapses to a single whole-file CRC and an
 *       out-of-order writer (GridFTP MODE E) still converges to the same value
 *       regardless of arrival order. brix_wverify_expected() yields the whole-
 *       object CRC only when the extents cover exactly [0, total) with no gap or
 *       overlap — a gap/overlap is itself a write-integrity failure.
 *
 * ngx-free (libc + zlib, malloc-owned) so it links into the shared compat kernel
 * and is unit-testable standalone; the VFS seam (brix_vfs_wverify_check) drives
 * the read-back compare through brix_cksum_u32_obj.
 */
#ifndef BRIX_WVERIFY_H
#define BRIX_WVERIFY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* off_t */

typedef struct brix_wverify_s brix_wverify_t;

/* Begin an accumulator. NULL on OOM. Free with brix_wverify_free. */
brix_wverify_t *brix_wverify_begin(void);
void            brix_wverify_free(brix_wverify_t *w);

/* Fold a just-written extent [off, off+len). Extents may arrive in any order.
 * Returns 0, or -1 on a zero/negative argument, an overlap with an already-fed
 * extent, arithmetic overflow, or exceeding the extent cap (a degraded state
 * that makes brix_wverify_expected fail closed). len == 0 is a no-op (0). */
int brix_wverify_update(brix_wverify_t *w, const void *buf, off_t off,
                        size_t len);

/* The whole-object CRC-32, valid ONLY when the fed extents coalesce to exactly
 * one run starting at offset 0 (a complete, gapless, overlap-free write): fills
 * *crc and *total (= object length) and returns 0. Returns -1 otherwise (a gap,
 * an overlap, a degraded accumulator, or nothing written). */
int brix_wverify_expected(const brix_wverify_t *w, uint32_t *crc, off_t *total);

#endif /* BRIX_WVERIFY_H */
