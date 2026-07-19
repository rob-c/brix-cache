/*
 * src/write/pgw_fob.h — kXR_pgwrite CSE uncorrected-page registry (the "Fob").
 *
 * WHAT: A fixed-size set (BRIX_PGW_FOB_SLOTS entries) embedded in
 *       brix_file_t recording the pages that failed CRC32c on a kXR_pgwrite
 *       and have not yet been corrected by a kXR_pgRetry resend.  Mirrors stock
 *       XrdXrootdPgwFob: an entry is keyed by (offset << kXR_pgPageBL) |
 *       (dlen < kXR_pgPageSZ ? dlen : 0) so partial (unaligned) last pages are
 *       distinct from full pages at the same offset.
 *
 * WHY:  Under the accept-then-correct (CSE) protocol the server writes corrupt
 *       bytes to disk and reports them to the client, which must resend each
 *       page.  kXR_close fails with kXR_ChkSumErr while any page remains in the
 *       Fob — that close gate is what guarantees a committed file never holds
 *       known-corrupt data.
 *
 * HOW:  Linear O(N) scan over at most BRIX_PGW_FOB_SLOTS (256) entries; no
 *       heap.  All callers run on the single connection event-loop thread, so
 *       no locking is needed (unlike stock's mutex-guarded std::set).
 */

#ifndef BRIX_WRITE_PGW_FOB_H
#define BRIX_WRITE_PGW_FOB_H

#include "core/types/file.h"

/* Initialise the Fob for a writable handle.  Idempotent; called lazily on the
 * first kXR_pgwrite so read-only / plain-write handles pay nothing. */
void brix_pgw_fob_open(brix_file_t *f);

/* Record a page (off,dlen) as uncorrected.  Idempotent on the same key (a page
 * re-failing keeps a single entry).  Returns 1 on success, 0 if the registry is
 * full (caller must reply kXR_TooManyErrs). */
int brix_pgw_fob_add(brix_file_t *f, int64_t off, uint32_t dlen);

/* Remove a corrected page (off,dlen).  Returns 1 if it was present. */
int brix_pgw_fob_del(brix_file_t *f, int64_t off, uint32_t dlen);

/* Return 1 if (off,dlen) is currently registered as uncorrected. */
int brix_pgw_fob_has(const brix_file_t *f, int64_t off, uint32_t dlen);

/* Number of pages currently uncorrected (0 == clean → close may proceed). */
uint32_t brix_pgw_fob_count(const brix_file_t *f);

/* Commit gate (INVARIANT 1): the number of uncorrected pgwrite checksum errors
 * that must block a publish/commit of this handle, or 0 when the handle is clean
 * (or the Fob was never armed).  Consulted by BOTH the kXR_close gate and the
 * kXR_sync staged-commit path so a staged/POSC object is never published while
 * known-corrupt pages remain — the two commit points must never drift apart. */
uint32_t brix_pgw_fob_commit_blocked(const brix_file_t *f);

/* Clear the registry (handle teardown). */
void brix_pgw_fob_reset(brix_file_t *f);

#endif /* BRIX_WRITE_PGW_FOB_H */
