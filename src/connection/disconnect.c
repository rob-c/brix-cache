#include "disconnect.h"
#include "budget.h"
#include "../session/registry.h"
#include "../upstream/upstream.h"
#include "../proxy/proxy.h"
#include "../ratelimit/ratelimit.h"
#include "../mirror/stream_wmirror.h"

#include <ngx_event.h>
#include <ngx_stream.h>
#include <stdio.h>
#include <string.h>

/* ---- Buffer release helper — disconnect-owned payload cleanup ----
 *
 * WHAT: Free payload buffer and prepare_paths allocated during connection lifecycle.
 *       Called on any disconnect/close path to prevent memory leaks.
 *
 * WHY: Payload buffers are detached from ctx->payload_buf in AIO write/read paths (src/write/write.c, src/aio/).
 *      Prepare paths allocated for kXR_prepare staging requests (src/prepare/). Must be freed on disconnect. */

static void
xrootd_release_disconnect_owned_buffers(xrootd_ctx_t *ctx)
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
     * (ngx_alloc, see src/aio/buffers.c xrootd_get_pool_scratch) — not pool
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
        for (i = 0; i < XROOTD_PIPELINE_MAX; i++) {
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
    xrootd_stream_wmirror_cleanup(ctx);
}

/* ---- Crypto state release — GSI/sigver cleanup on disconnect ----
 *
 * WHAT: Free OpenSSL crypto objects allocated during authentication.
 *       GSI DH key (EVP_PKEY) and sigver MAC context (EVP_MAC_CTX/EVP_MAC).
 *
 * WHY: Gsi authentication allocates DH key pair in src/gsi/; request signing allocates MAC ctx
 *      in src/sigver/. These are NOT freed during normal session — only on unexpected disconnect. */

static void
xrootd_release_disconnect_crypto_state(xrootd_ctx_t *ctx)
{
    if (ctx->gsi_dh_key != NULL) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    if (ctx->sigver_mac_ctx != NULL) {
        EVP_MAC_CTX_free(ctx->sigver_mac_ctx);
        ctx->sigver_mac_ctx = NULL;
    }

    if (ctx->sigver_mac != NULL) {
        EVP_MAC_free(ctx->sigver_mac);
        ctx->sigver_mac = NULL;
    }
}

/* ---- Metrics update — session byte totals accumulation on disconnect ----
 *
 * WHAT: Finalize session metrics by decrementing connections_active and accumulating
 *       total bytes (rx/tx) for the connection lifecycle. Includes per-IP-version and per-protocol breakdowns.
 *
 * WHY: Prometheus metrics need accurate session totals at close time — not just individual request counts.
 *      Bytes accumulated during AIO operations must be finalized here before ctx is destroyed. */

static void
xrootd_disconnect_update_metrics(xrootd_ctx_t *ctx)
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

/* ---- File bytes helper — prefer written over read for interrupted uploads ----
 *
 * WHAT: Return the dominant byte count for an open handle during disconnect logging.
 *       If writes occurred (upload), return bytes_written; otherwise bytes_read.
 *
 * WHY: Interrupted uploads should NOT be reported as zero-byte reads in access logs.
 *      This ensures metrics accuracy when a connection drops mid-upload. */

static size_t
xrootd_disconnect_file_bytes(const xrootd_file_t *file)
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

/* ---- Log open files — access-log entries for all handles at disconnect ----
 *
 * WHAT: Log access entries for every still-open handle when connection drops.
 *       Detail = "interrupted X.XXMB/s" or "interrupted". Status = kXR_Cancelled.
 *
 * WHY: When a connection drops unexpectedly, all open handles must be logged as cancelled.
 *      Duration measured from original open_time (not disconnect time) via req_start reuse. */

static void
xrootd_disconnect_log_open_files(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_msec_t now)
{
    int handle_index;

    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        xrootd_file_t *file;
        char           detail[64];
        size_t         byte_total;
        ngx_msec_t     duration_ms;

        file = &ctx->files[handle_index];
        if (file->fd < 0) {
            continue;
        }

        byte_total = xrootd_disconnect_file_bytes(file);
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
        xrootd_log_access(ctx, c, "CLOSE", file->path, detail, 0,
                          kXR_Cancelled, "connection lost", byte_total);
    }
}

/* ---- Session detail formatter — throughput calculation for disconnect logging ----
 *
 * WHAT: Format session-level throughput details (rx/tx MB/s breakdown or single aggregate).
 *       Called before final access-log entry for the connection lifecycle.
 *
 * WHY: Provides accurate session-level metrics for Prometheus dashboards and access logs.
 *      Shows separate read/write throughput when both occurred; aggregate otherwise. */

static void
xrootd_disconnect_format_session_detail(xrootd_ctx_t *ctx, ngx_msec_t now,
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

/* ---- xrootd_on_disconnect — main entry point for unexpected connection close ----
 *
 * WHAT: Called when a TCP connection is closed unexpectedly (not via normal kXR_close).
 *       Performs three-phase cleanup: buffer/crypto release, metrics finalization, access-log entries.
 *
 * WHY: Handles graceful degradation when clients disconnect without proper session termination.
 *      Must clean up ALL resources — buffers, crypto objects, open handles, registry slots. */

void
xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    char       session_detail[128];
    size_t     session_total_bytes;
    ngx_msec_t now;

    now = ngx_current_msec;
    ctx->destroyed = 1;

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
        xrootd_pmark_flow_end(ctx->pmark_flow, c->log);
        ctx->pmark_flow = NULL;
    }

    /* Phase 31 W4: return this connection's charged transfer-heap bytes to the
     * SHM-global budget before its scratch buffers are freed below. */
    xrootd_budget_release(ctx);

    /* Phase 25 W7 (stream): release the per-connection concurrency slot reserved
     * by the dispatch gate.  The stream plane has no per-request LOG phase, so the
     * in-flight slot is held for the connection's lifetime and freed exactly once
     * here.  No-op if no concurrency rule matched. */
    xrootd_rl_release_ctx(ctx);

    if (ctx->upstream != NULL) {
        xrootd_upstream_cleanup(ctx->upstream);
    }

    if (ctx->proxy != NULL) {
        xrootd_proxy_cleanup(ctx->proxy);
        ctx->proxy = NULL;
    }

    xrootd_release_disconnect_owned_buffers(ctx);
    xrootd_release_disconnect_crypto_state(ctx);
    xrootd_disconnect_update_metrics(ctx);
    xrootd_disconnect_log_open_files(ctx, c, now);

    /* Free any transfer monitor slots for this session (handles kXR_close was never sent). */
    if (ngx_xrootd_dashboard_shm_zone != NULL) {
        xrootd_transfer_slot_free_all_for_session(
            ngx_xrootd_dashboard_shm_zone->data, ctx->sessid);
    }

    if (!ctx->logged_in) {
        /* Phase 33 C1: make this connection's buffered access-log lines durable
         * (it may have logged errors before login). */
        xrootd_access_log_flush();
        return;
    }

    /*
     * Bound sessions are represented in the shared registry by their parent
     * session.  Only unregister the session that owns the registry slot.
     */
    if (ctx->auth_done && !ctx->is_bound) {
        xrootd_session_unregister(ctx->sessid);
    }

    xrootd_disconnect_format_session_detail(ctx, now, session_detail,
                                            sizeof(session_detail),
                                            &session_total_bytes);

    ctx->req_start = ctx->session_start;
    xrootd_log_access(ctx, c, "DISCONNECT", "-", session_detail, 1, 0, NULL,
                      session_total_bytes);

    /* Phase 33 C1: the connection is gone — flush its batched access-log lines
     * (including the DISCONNECT record above) so they are durable now rather
     * than waiting for the next buffer-full / timer tick. */
    xrootd_access_log_flush();
}
