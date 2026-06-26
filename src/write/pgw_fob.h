/*
 * src/write/pgw_fob.h — kXR_pgwrite CSE uncorrected-page registry (the "Fob").
 *
 * WHAT: A fixed-size set (XROOTD_PGW_FOB_SLOTS entries) embedded in
 *       xrootd_file_t recording the pages that failed CRC32c on a kXR_pgwrite
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
 * HOW:  Linear O(N) scan over at most XROOTD_PGW_FOB_SLOTS (256) entries; no
 *       heap.  All callers run on the single connection event-loop thread, so
 *       no locking is needed (unlike stock's mutex-guarded std::set).
 */

#ifndef XROOTD_WRITE_PGW_FOB_H
#define XROOTD_WRITE_PGW_FOB_H

#include "../types/file.h"

/* Initialise the Fob for a writable handle.  Idempotent; called lazily on the
 * first kXR_pgwrite so read-only / plain-write handles pay nothing. */
void xrootd_pgw_fob_open(xrootd_file_t *f);

/* Record a page (off,dlen) as uncorrected.  Idempotent on the same key (a page
 * re-failing keeps a single entry).  Returns 1 on success, 0 if the registry is
 * full (caller must reply kXR_TooManyErrs). */
int xrootd_pgw_fob_add(xrootd_file_t *f, int64_t off, uint32_t dlen);

/* Remove a corrected page (off,dlen).  Returns 1 if it was present. */
int xrootd_pgw_fob_del(xrootd_file_t *f, int64_t off, uint32_t dlen);

/* Return 1 if (off,dlen) is currently registered as uncorrected. */
int xrootd_pgw_fob_has(const xrootd_file_t *f, int64_t off, uint32_t dlen);

/* Number of pages currently uncorrected (0 == clean → close may proceed). */
uint32_t xrootd_pgw_fob_count(const xrootd_file_t *f);

/* Clear the registry (handle teardown). */
void xrootd_pgw_fob_reset(xrootd_file_t *f);

#endif /* XROOTD_WRITE_PGW_FOB_H */
