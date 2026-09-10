#ifndef BRIX_CMS_COALESCE_WAKE_H
#define BRIX_CMS_COALESCE_WAKE_H

#include <ngx_core.h>

/*
 * cms/coalesce_wake.h — settle every client parked on one kYR_state wave.
 *
 * WHAT: Wakes the pending entry whose streamid the answering node echoed AND
 *       — §2.15 — every other entry on this worker parked on the same probed
 *       path, all with the same redirect target.  Returns how many woke.
 * WHY:  The node echoes exactly one streamid, the leader's.  Coalescing is
 *       only sound if the followers are answered too; left to time out they
 *       would retry after the full window, which is strictly worse than the
 *       duplicate probes coalescing removed.  Keeping both wakes behind one
 *       call means the ingest site cannot answer the leader and forget the
 *       followers.
 * HOW:  brix_cms_wake_pending_session() for the leader, then
 *       brix_pending_find_probe() to collect the followers and the same wake
 *       for each — so every recycle guard, proxy pin and state check applies
 *       unchanged.  With coalescing off there are no followers and the scan
 *       finds nothing, so the call costs one locked scan of a 32-slot array.
 *
 * Lives in its own translation unit because both plausible homes —
 * server_recv_frame_handlers.c and recv_frame.c — are within a few lines of
 * the 600-line ceiling.
 */
ngx_uint_t brix_cms_wake_locate_answer(ngx_log_t *log, const char *path,
    uint32_t leader_sid, const char *host, uint16_t port);

#endif /* BRIX_CMS_COALESCE_WAKE_H */
