#include "disconnect.h"
#include "disconnect_internal.h"   /* reporting helpers moved to disconnect_report.c */
#include "fd_table.h"   /* brix_close_all_files (deferred teardown) */
#include "budget.h"
#include "protocols/root/session/session.h"   /* Phase 51 (E4): brix_gsi_inflight_release */
#include "protocols/root/session/registry.h"
#include "net/upstream/upstream.h"
#include "net/proxy/proxy.h"
#include "net/ratelimit/ratelimit.h"
#include "net/ratelimit/throttle_compat.h"   /* phase-59 W3a: open-files release */
#include "net/mirror/stream_wmirror.h"
#include "observability/sesslog/sesslog_ngx.h"
#include "core/aio/uring.h"   /* brix_uring_orphan_owner (late-CQE UAF guard) */

#include <ngx_event.h>
#include <ngx_stream.h>
#include <stdio.h>
#include <string.h>

/* §F6 GSI proxy-delegation teardown (src/gsi/delegation.c). Declared here to
 * avoid pulling the GSI internal header into the connection layer. */
void brix_gsi_delegation_cleanup(brix_ctx_t *ctx);

/* Free the payload buffer (detached from ctx->recv.payload_buf by the AIO write/read
 * paths) and any kXR_prepare staging paths, on every disconnect/close path. */

static void
brix_release_disconnect_owned_buffers(brix_ctx_t *ctx)
{
    if (ctx->recv.payload_buf != NULL) {
        ngx_free(ctx->recv.payload_buf);
        ctx->recv.payload_buf = NULL;
        ctx->recv.payload_buf_size = 0;
        ctx->recv.payload = NULL;
    }

    if (ctx->prepare.paths != NULL) {
        ngx_free(ctx->prepare.paths);
        ctx->prepare.paths = NULL;
        ctx->prepare.paths_len = 0;
    }

    /*
     * Phase 31: the reusable transfer scratch buffers are raw heap allocations
     * (ngx_alloc, see src/aio/buffers.c brix_get_pool_scratch) — not pool
     * anchored — so they must be freed explicitly here, like payload_buf above.
     */
    if (ctx->rd.read_scratch != NULL) {
        ngx_free(ctx->rd.read_scratch);
        ctx->rd.read_scratch = NULL;
        ctx->rd.read_scratch_size = 0;
    }
    if (ctx->rd.read_hdr_scratch != NULL) {
        ngx_free(ctx->rd.read_hdr_scratch);
        ctx->rd.read_hdr_scratch = NULL;
        ctx->rd.read_hdr_scratch_size = 0;
    }
    if (ctx->rd.write_scratch != NULL) {
        ngx_free(ctx->rd.write_scratch);
        ctx->rd.write_scratch = NULL;
        ctx->rd.write_scratch_size = 0;
    }
    if (ctx->rd.cmp_scratch != NULL) {           /* phase-42 W4 codec output */
        ngx_free(ctx->rd.cmp_scratch);
        ctx->rd.cmp_scratch = NULL;
        ctx->rd.cmp_scratch_size = 0;
    }

    /*
     * Phase 32 WS3: free the concurrent-AIO read-pool buffers (raw ngx_alloc'd,
     * see src/aio/buffers.c).  An in-flight task's done callback no-ops via the
     * destroyed guard, so the buffers are safe to release here.
     */
    {
        ngx_uint_t i;
        for (i = 0; i < ctx->out.pipeline_depth; i++) {
            if (ctx->rd.pool[i].buf != NULL) {
                ngx_free(ctx->rd.pool[i].buf);
                ctx->rd.pool[i].buf = NULL;
                ctx->rd.pool[i].size = 0;
                ctx->rd.pool[i].in_use = 0;
            }
        }
        ctx->rd.inflight = 0;
    }

    /* Phase 24 W3: free per-file data-write-mirror accumulation buffers for any
     * write-opens that never reached kXR_close (e.g. client dropped mid-write).
     * Detached replays already in flight own their own copies and are unaffected. */
    brix_stream_wmirror_cleanup(ctx);
}

/* Free OpenSSL crypto objects from authentication: the GSI DH key (EVP_PKEY) and
 * the sigver MAC context (EVP_MAC_CTX/EVP_MAC). These persist through a normal
 * session and are released only on disconnect. */

static void
brix_release_disconnect_crypto_state(brix_ctx_t *ctx)
{
    if (ctx->gsi.dh_key != NULL) {
        EVP_PKEY_free(ctx->gsi.dh_key);
        ctx->gsi.dh_key = NULL;
    }

    /* §F6: release any captured X.509 delegation state + cleanse the session key. */
    brix_gsi_delegation_cleanup(ctx);

    if (ctx->sigver.mac_ctx != NULL) {
        EVP_MAC_CTX_free(ctx->sigver.mac_ctx);
        ctx->sigver.mac_ctx = NULL;
    }

    if (ctx->sigver.mac != NULL) {
        EVP_MAC_free(ctx->sigver.mac);
        ctx->sigver.mac = NULL;
    }
}

/*
 * WHAT: Release any throttle open-files slots still held by this connection at
 * disconnect, then clear the held count. No-op when the connection holds none.
 * WHY: Handles closed implicitly by a dropped connection (phase-59 W3a) — rather
 * than an explicit kXR_close — would otherwise leak their per-user open-files
 * reservations in the throttle zone; this is the single release point on that path.
 * HOW: (1) return early when no slots are held; (2) look up the stream srv conf;
 * (3) with a configured throttle zone, decrement per user until the held count
 * reaches 0; (4) without a zone, just clear the held count.
 */
static void
brix_disconnect_release_throttle_slots(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->throttle.open_held == 0) {
        return;
    }

    ngx_stream_brix_srv_conf_t *tconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
    if (tconf->throttle.zone == NULL) {
        ctx->throttle.open_held = 0;
        return;
    }

    const char *tuser = ctx->login.dn[0] ? ctx->login.dn : "anonymous";
    while (ctx->throttle.open_held > 0) {
        brix_throttle_open_dec(tconf->throttle.zone, tuser);
        ctx->throttle.open_held--;
    }
}

/*
 * WHAT: Disarm this connection's steady-state read/write deadline timers and
 * clear the armed bits. No-op for any timer that is not currently armed+set.
 * WHY: nginx connection finalize also tears c->read/c->write timers down, but
 * clearing them here keeps the armed-bit bookkeeping consistent and is defensive
 * against an AIO completion racing teardown (phase 39). The armed-bit guard keeps
 * this from touching the CMS/FRM WAITING timers that share c->read.
 * HOW: (1) delete the read timer only when our read deadline is armed and set,
 * then clear the armed bit; (2) do the same for the write/send deadline timer.
 */
static void
brix_disconnect_disarm_deadline_timers(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->deadline.read_armed && c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    ctx->deadline.read_armed = 0;

    if (ctx->deadline.send_armed && c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ctx->deadline.send_armed = 0;
}

/*
 * WHAT: End SciTags packet marking for this connection: cancel the echo timer and
 * emit the firefly "end" report, clearing ctx->pmark.flow. No-op if never marked.
 * WHY: The echo timer's ngx_event_t lives in this ctx (freed with the pool during
 * teardown), so it must be cancelled first; the "end" report must be emitted while
 * the socket fd is still open because it reads TCP_INFO byte/rtt counters here.
 * HOW: (1) delete the echo timer when it is set; (2) when a flow exists, emit its
 * end report and null the pointer so later teardown does not touch it again.
 */
static void
brix_disconnect_end_pmark(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->pmark.echo_ev.timer_set) {
        ngx_del_timer(&ctx->pmark.echo_ev);
    }
    if (ctx->pmark.flow != NULL) {
        brix_pmark_flow_end(ctx->pmark.flow, c->log);
        ctx->pmark.flow = NULL;
    }
}

/* brix_on_disconnect — entry point for an unexpected TCP close (not a normal
 * kXR_close): three-phase cleanup — buffer/crypto release, metrics finalization,
 * and cancelled access-log entries — releasing every resource (buffers, crypto
 * objects, open handles, registry slots). */

void
brix_on_disconnect(brix_ctx_t *ctx, ngx_connection_t *c)
{
    char       session_detail[128];
    size_t     session_total_bytes;
    ngx_msec_t now;

    now = ngx_current_msec;
    ctx->destroyed = 1;

#if (BRIX_HAVE_LIBURING)
    /* Sever any in-flight io_uring ops owned by this connection BEFORE its
     * pool (which holds their task structs and the completion ngx_event_t
     * inside each task) can be destroyed: a late CQE for a freed task must be
     * dropped by the reaper, never posted — a freed event linked into
     * ngx_posted_events corrupts the queue and crashes the worker. */
    brix_uring_orphan_owner(c);
#endif

    /* phase-59 W3a: release any throttle open-files slots still held by this
     * connection (handles closed implicitly by disconnect, not kXR_close). */
    brix_disconnect_release_throttle_slots(ctx, c);

    /* Phase 39: disarm any steady-state read/write deadline this connection armed
     * (SciTags echo timer is handled next). */
    brix_disconnect_disarm_deadline_timers(ctx, c);

    /* SciTags packet marking (phase-34): end the flow while the socket is open. */
    brix_disconnect_end_pmark(ctx, c);

    /* Phase 31 W4: return this connection's charged transfer-heap bytes to the
     * SHM-global budget before its scratch buffers are freed below. */
    brix_budget_release(ctx);

    /* Phase 25 W7 (stream): release the per-connection concurrency slot reserved
     * by the dispatch gate.  The stream plane has no per-request LOG phase, so the
     * in-flight slot is held for the connection's lifetime and freed exactly once
     * here.  No-op if no concurrency rule matched. */
    brix_rl_release_ctx(ctx);

    /* Phase 51 (E4): release this connection's in-flight GSI-handshake slot if it
     * still holds one (handshake aborted before completion).  Leak-proof: this
     * funnel always runs on close, and the release is gated by ctx->login.gsi_counted
     * so a completed handshake (already released) is a no-op. */
    brix_gsi_inflight_release(ctx);

    if (ctx->upstream != NULL) {
        brix_upstream_cleanup(ctx->upstream);
    }

    if (ctx->proxy != NULL) {
        brix_proxy_cleanup(ctx->proxy);
        ctx->proxy = NULL;
    }

    brix_release_disconnect_owned_buffers(ctx);
    brix_release_disconnect_crypto_state(ctx);
    brix_disconnect_update_metrics(ctx);
    brix_disconnect_log_open_files(ctx, c, now);
    brix_sess_end(ctx->sess, brix_disconnect_sess_reason(ctx, c));
    ctx->sess = NULL;

    /* Free any transfer monitor slots for this session (handles kXR_close was never sent). */
    if (ngx_brix_dashboard_shm_zone != NULL) {
        brix_transfer_slot_free_all_for_session(
            ngx_brix_dashboard_shm_zone->data, ctx->login.sessid);
    }

    if (!ctx->login.logged_in) {
        /* Phase 33 C1: make this connection's buffered access-log lines durable
         * (it may have logged errors before login). */
        brix_access_log_flush();
        return;
    }

    /*
     * Bound sessions are represented in the shared registry by their parent
     * session.  Only unregister the session that owns the registry slot.
     */
    if (ctx->login.auth_done && !ctx->is_bound) {
        brix_session_unregister(ctx->login.sessid);
    }

    brix_disconnect_format_session_detail(ctx, now, session_detail,
                                            sizeof(session_detail),
                                            &session_total_bytes);

    ctx->req_start = ctx->totals.start;
    brix_log_access(ctx, c, "DISCONNECT", "-", session_detail, 1, 0, NULL,
                      session_total_bytes);

    /* Phase 33 C1: the connection is gone — flush its batched access-log lines
     * (including the DISCONNECT record above) so they are durable now rather
     * than waiting for the next buffer-full / timer tick. */
    brix_access_log_flush();
}

/* brix_defer_teardown_if_writing — hold off teardown while pwrites run.
 *
 * Called at every data-plane finalize site (recv EOF/timeout/error, send
 *   error/timeout).  If a pipelined kXR_write is still in flight (wr_inflight > 0)
 *   the connection MUST NOT be finalized yet — ctx and the open fds are still
 *   referenced by pwrites running in worker threads.  Records the pending finalize
 *   (status), marks the connection destroyed so the recv loop stops and write
 *   completion callbacks skip their ack, disarms our deadline timers so no stale
 *   timer re-fires, and returns 1 (caller must return without tearing down).  The
 *   last write completion (brix_write_aio_done) then runs the real teardown via
 *   brix_run_deferred_teardown().  Returns 0 when there are no in-flight writes,
 *   i.e. teardown may proceed normally.
 *
 * WHY: Pipelined writes break the old "exactly one AIO in flight, recv suspended"
 *   invariant that made teardown trivially safe.  This is the single chokepoint
 *   that restores the guarantee: no finalize while any pwrite references ctx/fds. */
ngx_flag_t
brix_defer_teardown_if_writing(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_int_t status)
{
    if (ctx->out.wr_inflight == 0) {
        return 0;
    }

    if (!ctx->out.finalize_pending) {
        ctx->out.finalize_pending = 1;
        ctx->out.finalize_status  = status;
        ctx->destroyed        = 1;

        brix_disconnect_disarm_deadline_timers(ctx, c);
    }

    return 1;
}

/* brix_run_deferred_teardown — finalize once the last pwrite has landed.
 *
 * Invoked from brix_write_aio_done when wr_inflight reaches 0 and a
 *   teardown was deferred.  Runs the full teardown that was held off — on_disconnect
 *   (metrics/log/registry, idempotent re: the already-set destroyed flag), then
 *   close_all_files (now safe: no pwrite references any fd), then finalize the
 *   stream session with the recorded status.  After this returns the ctx/pool are
 *   gone, so the caller must touch nothing further. */
void
brix_run_deferred_teardown(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_session_t *s = c->data;
    ngx_int_t             status = ctx->out.finalize_status;

    ctx->out.finalize_pending = 0;
    brix_on_disconnect(ctx, c);
    brix_close_all_files(ctx);
    ngx_stream_finalize_session(s, status);
}
