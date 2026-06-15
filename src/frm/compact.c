/*
 * compact.c — durable file compaction (Category-2, deferred to Phase 4).
 *
 * WHAT: Hooks to dense-rewrite the queue file (active records packed at the
 *   front, trailing FREE slots truncated). The real engine lands in Phase 4.
 *
 * WHY: Phase 0 reuses FREE slots in place (queue.c scans for the first FREE
 *   slot before growing the file), so the file naturally bounds to the
 *   high-water-mark of concurrent requests (≈ max_inflight). Compaction only
 *   matters for a queue that has churned through a very large number of requests
 *   and wants to give space back — not a correctness concern. We therefore ship
 *   honest no-op stubs here and wire the real dense-rewrite + atomic rename in
 *   Phase 4 (the design's F-tier work).
 *
 * The Phase-4 implementation will: hold the excl lock, stream active records to
 * <path>.new, fsync, rename over <path>, bump generation, and request a SHM
 * index rebuild — a crash mid-compact leaves the *old* file intact (the rename
 * is the commit point).
 */

#include "frm_internal.h"


int
frm_compact_needed(const frm_file_hdr_t *hdr, int64_t file_size)
{
    (void) hdr;
    (void) file_size;
    return 0;   /* Phase 0: slot reuse keeps the file bounded; never compact */
}

ngx_int_t
frm_compact(frm_queue_t *q, ngx_log_t *log)
{
    (void) q;
    (void) log;
    return NGX_OK;
}
