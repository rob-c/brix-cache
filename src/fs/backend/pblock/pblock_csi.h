#ifndef BRIX_SD_PBLOCK_CSI_H
#define BRIX_SD_PBLOCK_CSI_H

/*
 * pblock_csi.h — F3 per-block CRC32c integrity (CSI) for the pblock driver.
 *
 * WHAT: One CRC-32c (Castagnoli, INVARIANT 1/9) per pblock block, at rest in a
 *       `csi(blob_id, block_no, crc)` catalog table. Keyed by blob_id — NOT
 *       logical path — so a rename (which keeps the blob) never re-tags. The
 *       driver verifies fully-spanned blocks on read (mismatch ⇒ EIO, never
 *       serve garbage) and flushes recomputed CRCs on close.
 *
 * WHY:  pblock is the only full-parity driver missing filesystem page checksums
 *       (BRIX_SD_CAP_FSCS). The posix CSI tagstore (csi_tagstore.h) carries tags
 *       in an xmeta record at a real POSIX path — meaningless for pblock, whose
 *       data is sharded blobs with nothing at the logical path. So pblock owns
 *       its integrity in its own store (the catalog), advertised as CAP_FSCS
 *       only when csi=1 (honest per-instance capability).
 *
 * HOW:  Opt-in `csi=1` (rides the `?tail` static-opts channel like audit/lab).
 *       The at-rest CRC row set for the open object is snapshotted into a
 *       handle-local array ONCE at open — the hot read path verifies against
 *       memory with zero DB I/O and zero locks, matching the pblock prime
 *       directive. Writes only widen an integer [dlo,dhi) block extent on the
 *       hot path; close reads those blocks back and UPSERTs their CRCs in one
 *       transaction. ngx-free (libc + sqlite3 + the crc32c helper), gated by
 *       BRIX_HAVE_SQLITE like the rest of the backend.
 *
 * Requires: sd_pblock_catalog.h (pblock_catalog), pblock_store.h
 *           (pblock_state_t), <stdint.h>, <sys/types.h> before inclusion.
 */

/* Create the csi table if absent. 0 / -1 (hard error). */
int pblock_csi_init(pblock_catalog *cat);

/* Snapshot the at-rest CRCs for blob_id into a fresh calloc'd array sized to
 * hold `nblocks` slots (0 = unset/absent). *out is owned by the caller; freed
 * at close. Returns 0 (even with no rows) or -1 on OOM / hard error. */
int pblock_csi_load(pblock_catalog *cat, const char *blob_id, int64_t nblocks,
    uint32_t **out, uint64_t *out_n);

/* Verify the blocks of [off, off+len) that `buf` FULLY covers against the
 * snapshot CRCs (block granule `bs`, file size `size` clamps the short last
 * block). Slots that are unset (0), beyond the snapshot, or inside the
 * this-handle written extent [dlo, dhi) are skipped. Returns 0 (ok / nothing
 * verifiable) or -1 with errno=EIO on the first mismatch. */
int pblock_csi_verify(const uint32_t *crc, uint64_t n, int64_t bs, int64_t size,
    const unsigned char *buf, off_t off, size_t len, int64_t dlo, int64_t dhi);

/* Recompute the CRCs of blocks [dlo, dhi) (clamped to `size`) by reading them
 * back through the block engine and UPSERT them into the csi table in one
 * transaction. Best-effort at the call site (close logs, never fails the op).
 * Returns 0 / -1. */
int pblock_csi_flush(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs, int64_t dlo, int64_t dhi);

/* Drop every CRC row for blob_id (blob removed: unlink / replace). */
void pblock_csi_drop(pblock_catalog *cat, const char *blob_id);

#endif /* BRIX_SD_PBLOCK_CSI_H */
