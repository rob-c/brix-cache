#include "disconnect.h"
#include "fd_table.h"   /* brix_close_all_files (deferred teardown) */
#include "budget.h"
#include "protocols/root/session/session.h"   /* Phase 51 (E4): brix_gsi_inflight_release */
#include "protocols/root/session/registry.h"
#include "net/upstream/upstream.h"
#include "net/proxy/proxy.h"
#include "net/ratelimit/ratelimit.h"
#include "net/ratelimit/throttle_compat.h"   /* phase-59 W3a: open-files release */
#include "net/mirror/stream_wmirror.h"

#include <ngx_event.h>
#include <ngx_stream.h>
#include <stdio.h>
#include <string.h>

/* §F6 GSI proxy-delegation teardown (src/gsi/delegation.c). Declared here to
 * avoid pulling the GSI internal header into the connection layer. */
void brix_gsi_delegation_cleanup(brix_ctx_t *ctx);

/* Free the payload buffer (detached from ctx->payload_buf by the AIO write/read
 * paths) and any kXR_prepare staging paths, on every disconnect/close path. */

static void
brix_release_disconnect_owned_buffers(brix_ctx_t *ctx)
{
    if (ctx->payload_buf != NULL) {
        ngx_free(ctx->payload_buf);
        ctx->payload_buf = NULL;
        ctx->payload_buf_size = 0;
        ctx->payload = NULL;
    }

    if (ctx->prepare_paths != NULL) {
        ngx_free(ctx->prepare_paths);
        ctx->prepare_paths = NULL;
        ctx->prepare_paths_len = 0;
    }

    /*
     * Phase 31: the reusable transfer scratch buffers are raw heap allocations
     * (ngx_alloc, see src/aio/buffers.c brix_get_pool_scratch) — not pool
     * anchored — so they must be freed explicitly here, like payload_buf above.
     */
    if (ctx->read_scratch != NULL) {
        ngx_free(ctx->read_scratch);
        ctx->read_scratch = NULL;
        ctx->read_scratch_size = 0;
    }
    if (ctx->read_hdr_scratch != NULL) {
        ngx_free(ctx->read_hdr_scratch);
        ctx->read_hdr_scratch = NULL;
        ctx->read_hdr_scratch_size = 0;
    }
    if (ctx->write_scratch != NULL) {
        ngx_free(ctx->write_scratch);
        ctx->write_scratch = NULL;
        ctx->write_scratch_size = 0;
    }
    if (ctx->cmp_scratch != NULL) {           /* phase-42 W4 codec output */
        ngx_free(ctx->cmp_scratch);
        ctx->cmp_scratch = NULL;
        ctx->cmp_scratch_size = 0;
    }

    /*
     * Phase 32 WS3: free the concurrent-AIO read-pool buffers (raw ngx_alloc'd,
     * see src/aio/buffers.c).  An in-flight task's done callback no-ops via the
     * destroyed guard, so the buffers are safe to release here.
     */
    {
        ngx_uint_t i;
        for (i = 0; i < ctx->pipeline_depth; i++) {
            if (ctx->rd_pool[i].buf != NULL) {
                ngx_free(ctx->rd_pool[i].buf);
                ctx->rd_pool[i].buf = NULL;
                ctx->rd_pool[i].size = 0;
                ctx->rd_pool[i].in_use = 0;
            }
        }
        ctx->rd_inflight = 0;
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
    if (ctx->gsi_dh_key != NULL) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    /* §F6: release any captured X.509 delegation state + cleanse the session key. */
    brix_gsi_delegation_cleanup(ctx);

    if (ctx->sigver_mac_ctx != NULL) {
        EVP_MAC_CTX_free(ctx->sigver_mac_ctx);
        ctx->sigver_mac_ctx = NULL;
    }

    if (ctx->sigver_mac != NULL) {
        EVP_MAC_free(ctx->sigver_mac);
        ctx->sigver_mac = NULL;
    }
}

/* Finalize session metrics: decrement connections_active and accumulate the
 * lifecycle rx/tx byte totals (with per-IP-version and per-protocol breakdowns),
 * which must be committed here before ctx is destroyed. */

static void
brix_disconnect_update_metrics(brix_ctx_t *ctx)
{
    if (ctx->metrics == NULL) {
        return;
    }

    ngx_atomic_fetch_add(&ctx->metrics->connections_active,
                         (ngx_atomic_int_t) -1);
    ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_total,
                         (ngx_atomic_int_t) ctx->session_bytes_written);
    ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_total,
                         (ngx_atomic_int_t) ctx->session_bytes);

    /* Per-IP-version byte accounting — mirrors the aggregate totals above. */
    if (ctx->ip_version == AF_INET6) {
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_ipv6_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_ipv6_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    } else if (ctx->ip_version == AF_INET) {
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_ipv4_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_ipv4_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    }

    /* Per-protocol byte accounting for native stream-layer traffic. */
    if (ngx_strcmp(ctx->protocol_label, "root") == 0) {
        ngx_atomic_fetch_add(&ctx->metrics->proto_root_bytes_rx_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->proto_root_bytes_tx_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    }
}

/* Dominant byte count for an open handle in disconnect logging: bytes_written when
 * any write occurred (upload), else bytes_read — so an interrupted upload is not
 * logged as a zero-byte read. */

static size_t
brix_disconnect_file_bytes(const brix_file_t *file)
{
    /*
     * A handle is either read-heavy or write-heavy in the access log.  Prefer
     * written bytes when present so interrupted uploads are not reported as
     * zero-byte reads.
     */
    if (file->bytes_written > 0) {
        return file->bytes_written;
    }

    return file->bytes_read;
}

/* Emit a kXR_Cancelled access-log entry for every still-open handle when the
 * connection drops (detail "interrupted X.XXMB/s" or "interrupted"), with duration
 * measured from the original open_time via req_start reuse. */

static void
brix_disconnect_log_open_files(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_msec_t now)
{
    int handle_index;

    for (handle_index = 0; handle_index < BRIX_MAX_FILES; handle_index++) {
        brix_file_t *file;
        char           detail[64];
        size_t         byte_total;
        ngx_msec_t     duration_ms;

        file = &ctx->files[handle_index];
        if (file->fd < 0) {
            continue;
        }

        byte_total = brix_disconnect_file_bytes(file);
        duration_ms = now - file->open_time;

        if (byte_total > 0 && duration_ms > 0) {
            double mb_per_second;

            mb_per_second = (double) byte_total / (double) duration_ms
                            / 1000.0;
            snprintf(detail, sizeof(detail), "interrupted %.2fMB/s",
                     mb_per_second);
        } else {
            snprintf(detail, sizeof(detail), "interrupted");
        }

        /*
         * Reuse req_start so the common access logger reports per-handle
         * duration from the original open time, not from disconnect time.
         */
        ctx->req_start = file->open_time;
        brix_log_access(ctx, c, "CLOSE", file->path, detail, 0,
                          kXR_Cancelled, "connection lost", byte_total);
    }
}

/* Format session-level throughput for the final access-log entry: separate rx/tx
 * MB/s when both occurred, otherwise a single aggregate. */

static void
brix_disconnect_format_session_detail(brix_ctx_t *ctx, ngx_msec_t now,
    char *detail, size_t detail_size, size_t *total_bytes)
{
    ngx_msec_t session_duration_ms;

    *total_bytes = ctx->session_bytes + ctx->session_bytes_written;
    session_duration_ms = now - ctx->session_start;

    if (*total_bytes == 0 || session_duration_ms == 0) {
        snprintf(detail, detail_size, "-");
        return;
    }

    if (ctx->session_bytes_written > 0) {
        double read_mbps;
        double write_mbps;

        read_mbps = (double) ctx->session_bytes
                    / (double) session_duration_ms / 1000.0;
        write_mbps = (double) ctx->session_bytes_written
                      / (double) session_duration_ms / 1000.0;
        snprintf(detail, detail_size, "rx=%.2fMB/s tx=%.2fMB/s",
                 read_mbps, write_mbps);
        return;
    }

    snprintf(detail, detail_size, "%.2fMB/s",
             (double) *total_bytes / (double) session_duration_ms / 1000.0);
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

    /* phase-59 W3a: release any throttle open-files slots still held by this
     * connection (handles closed implicitly by disconnect, not kXR_close). */
    if (ctx->throttle_open_held > 0) {
        ngx_stream_brix_srv_conf_t *tconf = ngx_stream_get_module_srv_conf(
            (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
        if (tconf->throttle_zone != NULL) {
            const char *tuser = ctx->dn[0] ? ctx->dn : "anonymous";
            while (ctx->throttle_open_held > 0) {
                brix_throttle_open_dec(tconf->throttle_zone, tuser);
                ctx->throttle_open_held--;
            }
        } else {
            ctx->throttle_open_held = 0;
        }
    }

    /*
     * Phase 39: disarm any steady-state read/write deadline this connection armed.
     * nginx's connection finalize also tears c->read/c->write timers down, but
     * clearing them here keeps the armed-bit bookkeeping consistent and is
     * defensive against an AIO completion racing teardown.  Guarded on our armed
     * bit so it never touches the CMS/FRM WAITING timers that share c->read.
     */
    if (ctx->read_deadline_armed && c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    ctx->read_deadline_armed = 0;
    if (ctx->send_deadline_armed && c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ctx->send_deadline_armed = 0;

    /* SciTags packet marking (phase-34): cancel the echo timer (its ngx_event_t
     * lives in this ctx, freed with the pool below), then emit the firefly "end"
     * report while the socket fd is still open (TCP_INFO byte/rtt read here).
     * No-op if the connection was never marked. */
    if (ctx->pmark_echo_ev.timer_set) {
        ngx_del_timer(&ctx->pmark_echo_ev);
    }
    if (ctx->pmark_flow != NULL) {
        brix_pmark_flow_end(ctx->pmark_flow, c->log);
        ctx->pmark_flow = NULL;
    }

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
     * funnel always runs on close, and the release is gated by ctx->gsi_counted
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

    /* Free any transfer monitor slots for this session (handles kXR_close was never sent). */
    if (ngx_brix_dashboard_shm_zone != NULL) {
        brix_transfer_slot_free_all_for_session(
            ngx_brix_dashboard_shm_zone->data, ctx->sessid);
    }

    if (!ctx->logged_in) {
        /* Phase 33 C1: make this connection's buffered access-log lines durable
         * (it may have logged errors before login). */
        brix_access_log_flush();
        return;
    }

    /*
     * Bound sessions are represented in the shared registry by their parent
     * session.  Only unregister the session that owns the registry slot.
     */
    if (ctx->auth_done && !ctx->is_bound) {
        brix_session_unregister(ctx->sessid);
    }

    brix_disconnect_format_session_detail(ctx, now, session_detail,
                                            sizeof(session_detail),
                                            &session_total_bytes);

    ctx->req_start = ctx->session_start;
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
    if (ctx->wr_inflight == 0) {
        return 0;
    }

    if (!ctx->finalize_pending) {
        ctx->finalize_pending = 1;
        ctx->finalize_status  = status;
        ctx->destroyed        = 1;

        if (ctx->read_deadline_armed && c->read->timer_set) {
            ngx_del_timer(c->read);
        }
        ctx->read_deadline_armed = 0;
        if (ctx->send_deadline_armed && c->write->timer_set) {
            ngx_del_timer(c->write);
        }
        ctx->send_deadline_armed = 0;
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
    ngx_int_t             status = ctx->finalize_status;

    ctx->finalize_pending = 0;
    brix_on_disconnect(ctx, c);
    brix_close_all_files(ctx);
    ngx_stream_finalize_session(s, status);
}
