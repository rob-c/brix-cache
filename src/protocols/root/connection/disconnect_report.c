/*
 * disconnect_report.c — metrics finalization + access-log reporting for
 * root:// connection teardown (split from disconnect.c, phase-79).
 *
 * WHAT: The reporting half of connection teardown — finalizes the session
 *       metrics (connections_active, rx/tx byte totals) and emits the
 *       access-log records (a kXR_Cancelled line per still-open handle and the
 *       session-level throughput detail). The four public entry points
 *       (brix_disconnect_update_metrics, _sess_reason, _log_open_files,
 *       _format_session_detail) are invoked by brix_on_disconnect()
 *       (disconnect.c); brix_disconnect_file_bytes stays private here.
 * WHY:  disconnect.c owns the teardown ORDER and resource release; this file
 *       owns what the teardown REPORTS. Separating the two keeps each half
 *       focused and under the 500-line file-size cap. These helpers are pure
 *       reporting — they read ctx counters and emit log/metric side effects,
 *       with no bearing on cleanup ordering.
 * HOW:  Each helper takes ctx (and c/now where needed) explicitly and returns
 *       void, mirroring the resource-release helpers in disconnect.c. The
 *       cross-file entry points are declared in disconnect_internal.h.
 */

#include "disconnect.h"
#include "disconnect_internal.h"   /* cross-file: reporting entry points */
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

/* Finalize session metrics: decrement connections_active and accumulate the
 * lifecycle rx/tx byte totals (with per-IP-version and per-protocol breakdowns),
 * which must be committed here before ctx is destroyed. */

void
brix_disconnect_update_metrics(brix_ctx_t *ctx)
{
    if (ctx->metrics == NULL) {
        return;
    }

    ngx_atomic_fetch_add(&ctx->metrics->connections_active,
                         (ngx_atomic_int_t) -1);
    ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_total,
                         (ngx_atomic_int_t) ctx->totals.bytes_written);
    ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_total,
                         (ngx_atomic_int_t) ctx->totals.bytes);

    /* Per-IP-version byte accounting — mirrors the aggregate totals above. */
    if (ctx->ip_version == AF_INET6) {
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_ipv6_total,
                             (ngx_atomic_int_t) ctx->totals.bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_ipv6_total,
                             (ngx_atomic_int_t) ctx->totals.bytes);
    } else if (ctx->ip_version == AF_INET) {
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_ipv4_total,
                             (ngx_atomic_int_t) ctx->totals.bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_ipv4_total,
                             (ngx_atomic_int_t) ctx->totals.bytes);
    }

    /* Per-protocol byte accounting for native stream-layer traffic. */
    if (ngx_strcmp(ctx->protocol_label, "root") == 0) {
        ngx_atomic_fetch_add(&ctx->metrics->proto_root_bytes_rx_total,
                             (ngx_atomic_int_t) ctx->totals.bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->proto_root_bytes_tx_total,
                             (ngx_atomic_int_t) ctx->totals.bytes);
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

/*
 * WHAT: Derive the sesslog END reason for root connection teardown.
 * WHY: END lines need a stable low-cardinality reason even though many nginx
 * callbacks funnel through brix_on_disconnect().
 * HOW: Prefer an explicit hint, then shutdown, timeout, socket error, and
 * finally the normal client-disconnect case.
 */
brix_sess_end_t
brix_disconnect_sess_reason(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->sess_end_hint_set) {
        return ctx->sess_end_hint;
    }
    if (ngx_exiting || ngx_terminate) {
        return BRIX_SESS_END_SHUTDOWN;
    }
    if (c != NULL && c->timedout) {
        return BRIX_SESS_END_TIMEOUT;
    }
    if (c != NULL && c->error) {
        return BRIX_SESS_END_ERROR;
    }

    return BRIX_SESS_END_CLIENT;
}

/* Emit a kXR_Cancelled access-log entry for every still-open handle when the
 * connection drops (detail "interrupted X.XXMB/s" or "interrupted"), with duration
 * measured from the original open_time via req_start reuse. */

void
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
        if (file->sess_xfer.active && byte_total > file->sess_xfer.bytes) {
            brix_sess_xfer_add(&file->sess_xfer,
                               (uint64_t) (byte_total - file->sess_xfer.bytes));
        }
        brix_sess_xfer_end(ctx->sess, &file->sess_xfer,
                           (ngx_exiting || ngx_terminate)
                               ? BRIX_SESS_XFER_SHUTDOWN
                               : BRIX_SESS_XFER_ABORTED);
    }
}

/* Format session-level throughput for the final access-log entry: separate rx/tx
 * MB/s when both occurred, otherwise a single aggregate. */

void
brix_disconnect_format_session_detail(brix_ctx_t *ctx, ngx_msec_t now,
    char *detail, size_t detail_size, size_t *total_bytes)
{
    ngx_msec_t session_duration_ms;

    *total_bytes = ctx->totals.bytes + ctx->totals.bytes_written;
    session_duration_ms = now - ctx->totals.start;

    if (*total_bytes == 0 || session_duration_ms == 0) {
        snprintf(detail, detail_size, "-");
        return;
    }

    if (ctx->totals.bytes_written > 0) {
        double read_mbps;
        double write_mbps;

        read_mbps = (double) ctx->totals.bytes
                    / (double) session_duration_ms / 1000.0;
        write_mbps = (double) ctx->totals.bytes_written
                      / (double) session_duration_ms / 1000.0;
        snprintf(detail, detail_size, "rx=%.2fMB/s tx=%.2fMB/s",
                 read_mbps, write_mbps);
        return;
    }

    snprintf(detail, detail_size, "%.2fMB/s",
             (double) *total_bytes / (double) session_duration_ms / 1000.0);
}
