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
 *       populated export is safe. The content hash (phase-88 W3) is a
 *       PREFIXED STRING: "sha256:<hex>" from the write path's in-order SHA
 *       accumulator (or computed on demand at the dedup_publish slot) — a
 *       cryptographic identity a fold TRUSTS outright, making pblock a real
 *       CAS; "crc32:<hex>" for legacy rows and out-of-order writers — only a
 *       CANDIDATE, always byte-verified before linking so a CRC collision can
 *       never alias content. (A forged sha256 row is out of the threat model:
 *       writing catalog.db at all means owning the whole store. csi=1 remains
 *       the at-rest bit-rot detector either way.) Share-break happens at OPEN
 *       for write-intent opens (a metadata boundary), keeping the byte hot
 *       path free of refcount reads. ngx-free (libc + sqlite3 + libcrypto);
 *       BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h (pblock_state_t), sd_pblock_catalog.h (pblock_meta)
 *           before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_REFS_H
#define BRIX_FS_BACKEND_PBLOCK_REFS_H

#include <stdint.h>

#include "core/compat/wverify.h"   /* brix_wverify_t (the write accumulator) */

/* Longest content-hash string the refs schema records ("sha256:" + 64 hex). */
#define PBLOCK_REFS_HASH_CAP 80

/* Ensure the blobs table (+ hash index) exists. 0 or -1/errno. */
int pblock_refs_init(pblock_state_t *st);

/* Build the preferred content-hash string for a completely-written object out
 * of its write accumulator: "sha256:<hex>" when the in-order SHA covered
 * exactly `size` bytes, else "crc32:<hex>" when the (order-independent) CRC
 * did, else "" — no trustworthy hash. out[cap] with cap >=
 * PBLOCK_REFS_HASH_CAP. NULL-safe on wv. */
void pblock_refs_wv_hash(const brix_wverify_t *wv, int64_t size,
    char *out, size_t cap);

/* Upsert the tracking row for a blob, preserving any existing refcount
 * (INSERT refcount=1, ON CONFLICT update only size/block_size/hash). `hash`
 * is the prefixed content-hash string, or ""/NULL to clear it — taking the
 * blob out of the dedup candidate pool. 0 or -1/errno. */
int pblock_refs_track(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs, const char *hash);

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
 * look for an identical existing blob (hash+size+block_size candidates; a
 * "sha256:" identity folds outright, a "crc32:" candidate is byte-verified
 * first) and fold onto it — bump the survivor, repoint the row, release our
 * now-redundant blob. Skips (tracking the blob as-is) when `hash` is empty,
 * when our blob is already shared, or when no candidate survives. Returns 1
 * (folded), 0 (kept), -1/errno. */
int pblock_refs_dedup_publish(pblock_state_t *st, const char *path,
    pblock_meta *meta, const char *hash);

/* Explicit dedup of an ALREADY-COMMITTED object (phase-88 W1: the
 * driver->dedup_publish slot): re-nominate `path`'s blob for a fold using the
 * content hash recorded in its blobs row at commit time — computing (and
 * recording) a fresh "sha256:" identity from the stored bytes when none was
 * (a legacy blob, or an out-of-order write history forfeited it). Skips (0)
 * when the object is a dir/empty or its blob is already shared. Returns 1
 * (folded), 0 (kept), -1/errno. */
int pblock_refs_dedup_existing(pblock_state_t *st, const char *path);

/* Copy-on-write share-break for a write-intent open: when meta->blob_id is
 * shared, copy its blocks to a fresh private blob (or start empty when `trunc`
 * — the content is being replaced anyway), repoint the object's row, carry the
 * csi rows over, and release the old reference. Updates meta->blob_id in
 * place. 0 (private — possibly a no-op) or -1/errno. */
int pblock_refs_break_share(pblock_state_t *st, const char *path,
    pblock_meta *meta, int trunc);

#endif /* BRIX_FS_BACKEND_PBLOCK_REFS_H */
