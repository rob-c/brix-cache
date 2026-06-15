/*
 * waiter.h — async stage-completion waiter table (Phase 35 / Phase 3).
 *
 * WHAT: A small SHM table of clients parked on an in-flight recall. When a
 *   kXR_open hits a nearline file and xrootd_frm_async_recall is on, the request
 *   is acknowledged with kXR_waitresp and a waiter row is recorded
 *   {reqid, streamid, conn_fd, conn_number, worker_pid}. When the recall
 *   completes, the worker that staged it marks every matching waiter ready; each
 *   owning worker then delivers the real open response via kXR_attn(asynresp) on
 *   the parked streamid — no poll/retry, full disconnect tolerance.
 *
 * WHY: Phase 1 stalls clients with kXR_wait (disconnect-and-retry), which adds
 *   latency and reconnection load. Phase 3 satisfies the open in place. It is
 *   strictly opt-in (the directive defaults off) so the Phase 1 model is the
 *   default and this never destabilises it.
 *
 * Cross-worker design (no IPC): the staging worker is usually NOT the worker that
 *   parked the waiter. frm_waiter_deliver() marks all matching rows ready under
 *   the SHM lock; each worker only ever touches its OWN connections, delivering
 *   its ready rows from frm_waiter_poll_local() (called on the stage scheduler
 *   timer). This keeps every wire write on the owning connection's worker.
 */

#ifndef NGX_XROOTD_FRM_WAITER_H
#define NGX_XROOTD_FRM_WAITER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "frm.h"

/* Configure the waiter SHM zone (postconfiguration; slab-safe). */
ngx_int_t frm_waiter_configure(ngx_conf_t *cf, ngx_uint_t slots);

/*
 * Park a stalled open. `reqid` is the durable request id frm_request_add
 * returned; `options` are the original kXR_open options (replayed at delivery).
 * Returns NGX_OK (parked), NGX_AGAIN (table full → caller should fall back to
 * kXR_wait), or NGX_ERROR.
 */
ngx_int_t frm_waiter_add(const char *reqid, uint16_t options,
                         const u_char client_streamid[2],
                         int conn_fd, ngx_atomic_uint_t conn_number,
                         ngx_pid_t worker_pid, ngx_msec_t timeout_ms);

/*
 * A recall finished (code 0 = ok, else the errno-ish fail code). Mark every
 * waiter on `reqid` ready, then deliver this worker's matching ones inline.
 */
void frm_waiter_deliver(const char *reqid, int code);

/* Per-worker tick: deliver this worker's ready rows and reap expired ones. */
void frm_waiter_poll_local(void);

/* Best-effort drop of any waiter for (conn_fd, conn_number) on disconnect. */
void frm_waiter_drop_conn(int conn_fd, ngx_atomic_uint_t conn_number);

#endif /* NGX_XROOTD_FRM_WAITER_H */
