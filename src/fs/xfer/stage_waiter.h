/*
 * stage_waiter.h — async stage/recall completion waiter table.
 *
 * WHAT: A small SHM table of clients parked on an in-flight recall. When a
 *   kXR_open hits a nearline file and async recall is on, the request is
 *   acknowledged with kXR_waitresp and a waiter row is recorded
 *   {reqid, streamid, conn_fd, conn_number, worker_pid}. When the recall
 *   completes, the worker that staged it marks every matching waiter ready; each
 *   owning worker then delivers the real open response via kXR_attn(asynresp) on
 *   the parked streamid — no poll/retry, full disconnect tolerance.
 *
 * WHY: The FRM-dissolution (§13b, phase-64 P6) re-home of the FRM waiter
 *   (former src/frm/waiter.c). The park/wake substrate is protocol-layer (only the
 *   owning worker may write to a parked connection), so it lives beside the stage
 *   engine + request registry rather than in a backend driver. The recall itself
 *   is driven by the sd_frm backend / stage engine; this table only tracks who is
 *   parked and delivers the in-place open response on completion.
 *
 * Cross-worker design (no IPC): the staging worker is usually NOT the worker that
 *   parked the waiter. brix_stage_waiter_deliver() marks all matching rows ready
 *   under the SHM lock; each worker only ever touches its OWN connections,
 *   delivering its ready rows from brix_stage_waiter_poll_local() (called on the
 *   stage scheduler tick). This keeps every wire write on the owning worker.
 *
 * See docs/superpowers/plans/2026-07-01-frm-dissolution.md (Task 2).
 */
#ifndef BRIX_STAGE_WAITER_H
#define BRIX_STAGE_WAITER_H

#include <ngx_config.h>
#include <ngx_core.h>

/* Configure the waiter SHM zone (postconfiguration; slab-safe). */
ngx_int_t brix_stage_waiter_configure(ngx_conf_t *cf, ngx_uint_t slots);

/*
 * Park a stalled open. `reqid` is the durable request id the registry add returned;
 * `options` are the original kXR_open options (replayed at delivery). Returns
 * NGX_OK (parked), NGX_AGAIN (table full → caller falls back to kXR_wait), or
 * NGX_ERROR.
 */
ngx_int_t brix_stage_waiter_add(const char *reqid, uint16_t options,
                                  const u_char client_streamid[2],
                                  int conn_fd, ngx_atomic_uint_t conn_number,
                                  ngx_pid_t worker_pid, ngx_msec_t timeout_ms);

/*
 * A recall finished (code 0 = ok, else the errno-ish fail code). Mark every waiter
 * on `reqid` ready, then deliver this worker's matching ones inline.
 */
void brix_stage_waiter_deliver(const char *reqid, int code);

/* Per-worker tick: deliver this worker's ready rows and reap expired ones. */
void brix_stage_waiter_poll_local(void);

/* Best-effort drop of any waiter for (conn_fd, conn_number) on disconnect. */
void brix_stage_waiter_drop_conn(int conn_fd, ngx_atomic_uint_t conn_number);

#endif /* BRIX_STAGE_WAITER_H */
