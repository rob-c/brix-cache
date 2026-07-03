#ifndef BRIX_FS_BACKEND_CSI_TAGSTORE_H
#define BRIX_FS_BACKEND_CSI_TAGSTORE_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * fs/backend/csi_tagstore.h — block-granule checksum integrity on the unified
 * metadata record (xmeta P3; replaces the phase-59 per-page ".xrdt" sidecar).
 *
 * WHAT: One CRC32C per cinfo block (the record's buffer_size granule, default
 *       brix_csi_block = 1MiB), stored in the file's own xmeta record
 *       (BLOCKCRC section) — user.xrd.cinfo xattr or "<path>.cinfo" sidecar,
 *       via the shared fs/meta/xmeta_path.c carrier. No more tag tree.
 *
 * WHY:  One form of metadata per file (spec 2026-07-02-xmeta-unified-
 *       metadata-design.md §CSI): integrity tags live beside the cache /
 *       write-back state in a single record readable by stock cinfo tools.
 *
 * HOW:  Reads verify only the blocks they FULLY span against the recorded
 *       CRCs (a slot of 0 = "not computed" and is skipped; partial-edge
 *       blocks are covered by verify-on-fill and scrub, not the hot path).
 *       Writes never touch the record: the engine folds CRCs of fully
 *       covered blocks into a handle-local table as the bytes stream through
 *       and merges them into the record ONCE at close (brix_csi_flush),
 *       recomputing up to BRIX_CSI_FLUSH_READ blocks of unaligned edges
 *       from disk. Fail-closed: a crash before flush leaves stale CRCs, so
 *       reads of a torn upload fail kXR_ChkSumErr until rewritten.
 */

#define BRIX_CSI_OK         0
#define BRIX_CSI_MISMATCH  (-1)
#define BRIX_CSI_NOTAGS    (-2)
#define BRIX_CSI_ERR       (-3)

/* Max blocks recomputed from disk at flush (unaligned write edges); dirty
 * blocks beyond this stay unset (unverified, never falsely failing). */
#define BRIX_CSI_FLUSH_READ 32

/* Handle-local tag table cap: 2^20 blocks = a 1 TiB file at 1MiB granule. */
#define BRIX_CSI_LOCAL_MAX  (1u << 20)

typedef struct {
    char      path[PATH_MAX];    /* absolute data-file path (record carrier) */
    uint32_t  granule;           /* block size for NEW records               */
    unsigned  trust_fs:1;        /* self-checksumming fs: skip read-verify   */
    unsigned  writable:1;        /* write handle: fold tags, flush at close  */
    unsigned  dirty:1;           /* bytes were written through this handle   */
    unsigned  overflow:1;        /* local table cap hit: flush leaves unset  */
    int64_t   dirty_lo;          /* written byte extent (flush recompute)    */
    int64_t   dirty_hi;
    uint32_t *local;             /* handle-local folded CRCs (0 = none)      */
    uint64_t  local_n;           /* entries allocated in local[]             */
} brix_csi_t;

/*
 * Bind a CSI handle to the data file at abs_path. granule sizes new records
 * (existing records keep their own). writable != 0 for write opens.
 * Returns BRIX_CSI_OK; for a read handle, BRIX_CSI_NOTAGS when the file
 * has no record with a checksum table (csi_require gates on this) or
 * BRIX_CSI_ERR on a hard carrier error.
 */
int  brix_csi_open(brix_csi_t *c, const char *abs_path,
    uint32_t granule, int writable);

/* Flush (write handles) then release the handle-local state. */
void brix_csi_close(brix_csi_t *c);

/* ---- verify / update (csi_verify.c) ------------------------------------- */

/* Verify the blocks of [off,off+len) that the buffer FULLY covers against
 * the recorded CRCs. OK (also when trusting / nothing verifiable) /
 * MISMATCH / NOTAGS (no record or no table) / ERR. */
int  brix_csi_verify_read(brix_csi_t *c, const unsigned char *buf,
    off_t off, size_t len);

/* Fold the CRCs of the blocks [off,off+len) fully covers into the
 * handle-local table (no record I/O; the record is written at flush). */
int  brix_csi_write_update(brix_csi_t *c, const unsigned char *buf,
    off_t off, size_t len);

/* Merge the handle-local tags into the file's record under the per-file
 * lock: resize/create the record from the file's current size, store folded
 * CRCs, recompute up to BRIX_CSI_FLUSH_READ edge blocks from disk. */
int  brix_csi_flush(brix_csi_t *c);

#endif /* BRIX_FS_BACKEND_CSI_TAGSTORE_H */
