/*
 * pblock_refs.h — Phase-83 F10: content-addressed dedup + refcounted blobs.
 *
 * WHAT: The foundation of wave D: a driver-owned `blobs(blob_id, refcount,
 *       size, block_size, content_hash)` table that lets several `objects` rows
 *       share one physical blob. server_copy becomes a refcount bump
 *       (O(metadata) copy-on-write), publish-time dedup folds identical content
 *       onto an existing blob, and any write to a shared blob first breaks the
 *       share by copying the blocks to a fresh blob (block granularity makes
 *       that cheap).
 *
 * WHY:  Exercises every CAP_SERVER_COPY caller (kXR clone, WebDAV COPY) against
 *       real copy-on-write semantics, and gives F6 snapshots / F11 versioning
 *       their O(metadata) foundation.
 *
 * HOW:  Armed by the `dedup=1` static opt (its own gate, like csi/locks — this
 *       is a capability, not a lab toy); an init failure leaves the
 *       byte-for-byte production path. A row's absence means "refcount 1"
 *       (legacy blobs from before the gate was set), so enabling dedup on a
 *       populated export is safe. The content hash is the whole-object CRC-32
 *       from the wverify accumulator fed on the write path; a hash match is
 *       only a CANDIDATE — dedup always byte-verifies both blobs before
 *       linking, so a CRC collision (or a forged row) can never alias content.
 *       Share-break happens at OPEN for write-intent opens (a metadata
 *       boundary), keeping the byte hot path free of refcount reads.
 *       ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h (pblock_state_t), sd_pblock_catalog.h (pblock_meta)
 *           before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_REFS_H
#define BRIX_FS_BACKEND_PBLOCK_REFS_H

#include <stdint.h>

/* Ensure the blobs table (+ hash index) exists. 0 or -1/errno. */
int pblock_refs_init(pblock_state_t *st);

/* Upsert the tracking row for a blob, preserving any existing refcount
 * (INSERT refcount=1, ON CONFLICT update only size/block_size/hash). crc is
 * recorded only when crc_ok; otherwise the hash is cleared (''), taking the
 * blob out of the dedup candidate pool. 0 or -1/errno. */
int pblock_refs_track(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs, uint32_t crc, int crc_ok);

/* Add one reference to `blob_id` (server_copy / dedup link). A missing row is
 * created with refcount 2 — the implicit legacy reference plus the new one.
 * 0 or -1/errno. */
int pblock_refs_bump(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs);

/* This blob's refcount: >= 1 (absent row = the implicit single reference),
 * or -1/errno on a DB error. */
int pblock_refs_count(const pblock_state_t *st, const char *blob_id);

/* Release one reference to a blob — the single unlink/overwrite entry for BOTH
 * gate states: with refs off (or on the last reference) it removes the block
 * files and the blob's csi rows exactly like the pre-F10 code; with a live
 * shared reference it only decrements. A DB error keeps the blocks (an orphan
 * for `pblock-fsck --gc`, never a shared-block removal). */
void pblock_refs_release(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs);

/* Publish-time dedup: with the object's row already pointing at meta->blob_id,
 * look for a byte-identical existing blob (hash+size+block_size candidates,
 * then a full byte compare) and fold onto it — bump the survivor, repoint the
 * row, release our now-redundant blob. Skips (tracking the blob as-is) when
 * crc_ok is 0, when our blob is already shared, or when no candidate survives
 * verification. Returns 1 (folded), 0 (kept), -1/errno. */
int pblock_refs_dedup_publish(pblock_state_t *st, const char *path,
    pblock_meta *meta, uint32_t crc, int crc_ok);

/* Copy-on-write share-break for a write-intent open: when meta->blob_id is
 * shared, copy its blocks to a fresh private blob (or start empty when `trunc`
 * — the content is being replaced anyway), repoint the object's row, carry the
 * csi rows over, and release the old reference. Updates meta->blob_id in
 * place. 0 (private — possibly a no-op) or -1/errno. */
int pblock_refs_break_share(pblock_state_t *st, const char *path,
    pblock_meta *meta, int trunc);

#endif /* BRIX_FS_BACKEND_PBLOCK_REFS_H */
