/*
 * pblock_pack.h — phase-88 W2: the packed small-blob arena.
 *
 * WHAT: A log-structured resting state for small immutable blobs: instead of a
 *       per-object dir + block file, a blob at/below pack_max whose staged
 *       commit kept it (not dedup-folded) is appended as ONE record into a
 *       shared segment file (<root>/pack/seg-<n>.dat) and its location kept in
 *       the catalog's `pack` table. One inode per ~64 MiB of small objects
 *       instead of two per object — the phase-87 G4 win, server-side.
 *
 * WHY:  pblock's striped layout is a large-file design; a CVMFS-style cache
 *       store is dominated by small chunks where the per-object dir + block
 *       file COST inodes over the flat store. The client's packed store
 *       (shared/cache/cas_pack.c) proved the segment format but its runtime is
 *       single-process (in-memory hash + private journal) — nginx workers are
 *       many processes, so the arena reuses the RECORD FORMAT verbatim
 *       (shared/cache/cas_pack_format.h, records keyed by blob_id) while the
 *       cross-process index is the SQLite catalog and appends serialize under
 *       a pack/.lock flock.
 *
 * HOW:  Packed is a metadata-boundary concept only — the hot byte path never
 *       sees it: a read open MATERIALISES the record into a sealed memfd (a
 *       real fd, so CAP_FD/SENDFILE hold and every byte op runs unchanged); a
 *       write-intent open materialises back to real block files first (packed
 *       blobs are single-block by admission, so the layouts are equivalent).
 *       Record crc32 is verified whenever a whole record is decoded (memfd
 *       open, materialise) — a damaged record is EIO, never wrong bytes.
 *       Deletion drops the row; a segment whose rows are all gone is unlinked
 *       (checked under the same flock appends hold, so an in-flight append —
 *       which inserts its row before unlocking — can never lose its segment).
 *       ngx-free (libc + sqlite3 + zlib crc32); BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h (pblock_state_t), sd_pblock_catalog.h (pblock_meta)
 *           before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_PACK_H
#define BRIX_FS_BACKEND_PBLOCK_PACK_H

#include <stdint.h>
#include <sys/types.h>

/* Default admission ceiling (opts pack_max=) and the segment roll size. */
#define PBLOCK_PACK_MAX_DEFAULT   (1LL * 1024 * 1024)
#define PBLOCK_PACK_SEG_BYTES     (64LL * 1024 * 1024)

/* A record's location, resolved from the catalog pack table. */
typedef struct {
    int64_t seg;
    int64_t off;          /* record start (header) inside the segment */
    int64_t len;          /* data length (== blob size; fmt is always raw) */
} pblock_pack_loc_t;

/* Ensure the pack table + pack/ dir exist. 0 or -1/errno. */
int pblock_pack_arm(pblock_state_t *st);

/* Locate `blob_id` in the arena. 0 = found (*out filled), 1 = not packed,
 * -1/errno on a catalog error. */
int pblock_pack_find(const pblock_state_t *st, const char *blob_id,
    pblock_pack_loc_t *out);

/* Admit a committed single-block blob (its recorded stripe size is `bs`):
 * read its block-0 file, append the record (fdatasync'd), insert the pack
 * row, then drop the block file + dir. Best-effort for the caller: -1/errno
 * leaves the striped layout untouched. */
int pblock_pack_admit(pblock_state_t *st, const char *blob_id, int64_t size,
    int64_t bs);

/* Read-serve a packed blob: decode + crc-verify its record into a sealed
 * memfd. Returns the fd, or -1 with errno — ENOENT = not packed (caller falls
 * through to the striped layout), anything else = a damaged record/segment
 * (fail the open; never serve unverified bytes). */
int pblock_pack_open_memfd(const pblock_state_t *st, const pblock_meta *meta);

/* Materialise a packed blob back to its striped block files (write-intent
 * open, physical copy, CoW share-break) and drop the pack row. 0 when done OR
 * the blob was not packed; -1/errno on a hard failure. */
int pblock_pack_materialize(pblock_state_t *st, const pblock_meta *meta);

/* Drop `blob_id`'s pack row (unlink/release path; no-op when absent) and
 * reap its segment once no rows reference it. */
void pblock_pack_del(const pblock_state_t *st, const char *blob_id);

/* Read [off, off+len) of a blob that may live in EITHER layout — the arena
 * record or the striped block files. For metadata-boundary readers (dedup
 * byte-verify, on-demand CRC); never on the hot path. Returns bytes read
 * (short at EOF) or -1/errno. */
ssize_t pblock_pack_or_block_read(const pblock_state_t *st,
    const char *blob_id, int64_t bs, void *buf, size_t len, off_t off);

#endif /* BRIX_FS_BACKEND_PBLOCK_PACK_H */
