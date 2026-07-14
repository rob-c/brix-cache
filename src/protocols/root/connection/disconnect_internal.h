#ifndef BRIX_CONN_DISCONNECT_INTERNAL_H
#define BRIX_CONN_DISCONNECT_INTERNAL_H
/*
 * disconnect_internal.h — declarations shared between the two halves of the
 * root:// connection-teardown module after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the reporting helpers that brix_on_disconnect()
 *       (disconnect.c) calls but which now live in disconnect_report.c.
 * WHY:  disconnect.c (the teardown orchestrator + resource/timer release +
 *       write-pipelining deferral guards) and disconnect_report.c (the
 *       metrics-finalization and access-log reporting helpers) were one
 *       521-line file, over the 500-line cap. Splitting keeps each focused and
 *       under the cap. The orchestrator in disconnect.c calls four reporting
 *       helpers that move to disconnect_report.c, so exactly those four become
 *       non-static; brix_disconnect_file_bytes stays private to the reporting
 *       file (only its own log helper uses it).
 * HOW:  Both translation units include this header; none of these symbols is
 *       exported beyond the root:// connection layer.
 */
#include "core/ngx_brix_module.h"                 /* brix_ctx_t, ngx types */
#include "observability/sesslog/sesslog_ngx.h"    /* brix_sess_end_t */
#include <stddef.h>                                /* size_t */

/* All defined in disconnect_report.c; all called by brix_on_disconnect()
 * (disconnect.c). */

/* Decrement connections_active and accumulate the lifecycle rx/tx byte totals
 * (per IP-version and per-protocol) before ctx is destroyed. */
void brix_disconnect_update_metrics(brix_ctx_t *ctx);

/* Derive the sesslog END reason (explicit hint / shutdown / timeout / socket
 * error / normal client disconnect) for this connection teardown. */
brix_sess_end_t brix_disconnect_sess_reason(brix_ctx_t *ctx,
    ngx_connection_t *c);

/* Emit a kXR_Cancelled access-log entry for every still-open handle when the
 * connection drops, with per-handle duration measured from its open time. */
void brix_disconnect_log_open_files(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_msec_t now);

/* Format the session-level throughput detail (separate rx/tx MB/s, or a single
 * aggregate) for the final DISCONNECT access-log entry, and report the total. */
void brix_disconnect_format_session_detail(brix_ctx_t *ctx, ngx_msec_t now,
    char *detail, size_t detail_size, size_t *total_bytes);

#endif /* BRIX_CONN_DISCONNECT_INTERNAL_H */
