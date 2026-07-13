#ifndef BRIX_RECV_FRAME_H
#define BRIX_RECV_FRAME_H

/*
 * recv_frame.h — the per-PDU framing phases of the root:// recv loop, split out
 * of recv.c so that translation unit holds only the slim event-loop skeleton
 * (the connection/ dir already splits helpers this way: chain_helpers,
 * write_helpers, event_sched).
 *
 * Every phase helper runs INSIDE ngx_stream_brix_recv's `for (;;)` loop but
 * cannot itself break/continue/return the caller's loop, so each returns a
 * brix_recv_step_t telling the loop what to do — exactly the control-code idiom
 * already used by brix_recv_pre_loop / brix_recv_handoff_state.  The logic moved
 * here is byte-for-byte the original; only the loop-exit statements were
 * translated to step codes.
 */

#include "core/ngx_brix_module.h"

typedef enum {
    BRIX_RECV_STEP_NEXT = 0,   /* PDU phase complete — proceed to the next phase */
    BRIX_RECV_STEP_CONTINUE,   /* `continue` the recv for-loop                   */
    BRIX_RECV_STEP_RETURN,     /* `return` from the recv handler                 */
    BRIX_RECV_STEP_BREAK       /* `break` the recv for-loop (→ teardown)         */
} brix_recv_step_t;

/*
 * Phase 29 drain barrier: a non-pipelinable request was fully read while
 * pipelined reads/writes were still in flight; run it once out_count and
 * wr_inflight have drained, then dispatch.  RETURN/BREAK/CONTINUE.
 */
brix_recv_step_t brix_recv_run_deferred(ngx_stream_session_t *s,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx,
    ngx_event_t *rev, size_t *rx_pending);

/*
 * Read the next chunk of the current PDU unit (handshake / header / payload):
 * compute dest/need for the current state, c->recv() into it, and accumulate.
 * NEXT when the unit is complete (caller disarms the deadline and processes it);
 * CONTINUE/RETURN/BREAK otherwise.
 */
brix_recv_step_t brix_recv_read_frame(ngx_stream_session_t *s,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx,
    ngx_event_t *rev, size_t *rx_pending);

/*
 * Process a fully-received PDU unit: validate/dispatch the handshake, request
 * header, or payload body (incl. kXR_writev / kXR_chkpoint body extension).
 * CONTINUE to read the next unit, or RETURN/BREAK.
 */
brix_recv_step_t brix_recv_process_frame(ngx_stream_session_t *s,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx,
    ngx_event_t *rev, size_t *rx_pending);

#endif /* BRIX_RECV_FRAME_H */
