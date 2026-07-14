/*
 * tpc_marker.c — 202 Accepted response with WLCG Performance-Marker streaming.
 *
 * When brix_webdav_tpc_marker_interval is non-zero, HTTP-TPC COPY requests
 * receive a "202 Accepted" response immediately and stream Performance-Marker
 * blocks in the chunked body while the curl transfer runs in a thread pool
 * worker.  The body ends with "success\r\n" or "failure\r\n" when the transfer
 * completes.  This matches the XrdHttp wire behaviour expected by FTS and RUCIO.
 *
 * For multi-stream pull (X-Number-Of-Streams: N), N parallel Range-based GET
 * streams run concurrently via curl_multi.  Each stream's write callback
 * increments an atomic per-stream byte counter; the poll timer reads these and
 * emits one Performance-Marker block per stripe per interval:
 *
 *   Perf Marker\r\n
 *   Timestamp: <unix-epoch-seconds>\r\n
 *   Stripe Index: <0..N-1>\r\n
 *   Stripe Bytes Transferred: <bytes>\r\n
 *   Total Stripe Count: <N>\r\n
 *   End\r\n
 *
 * For single-stream pull, byte counts are read from stat(2) on the in-progress
 * temp file.  For push, interim markers report 0 bytes; the final marker carries
 * the full file size.
 *
 * The poll timer fires every TPC_MARKER_POLL_MSEC and is re-armed until the
 * thread marks progress->completed = 1.  A pool cleanup callback aborts the
 * transfer if the request is destroyed before completion.
 */

#include "webdav.h"
#include "core/compat/net_target.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "core/aio/aio.h"          /* brix_task_bind */
#include "tpc/common/metrics.h"
#include "tpc/common/registry.h"

#include "tpc_marker_internal.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


static void
tpc_marker_send_one(ngx_http_request_t *r, time_t ts,
    ngx_uint_t stripe_index, off_t bytes, ngx_uint_t total_stripes)
{
    char        block[512];
    int         n;
    ngx_buf_t  *b;
    ngx_chain_t out;

    n = snprintf(block, sizeof(block),
                 "Perf Marker\r\n"
                 "Timestamp: %ld\r\n"
                 "Stripe Index: %u\r\n"
                 "Stripe Bytes Transferred: %lld\r\n"
                 "Total Stripe Count: %u\r\n"
                 "End\r\n",
                 (long) ts, (unsigned) stripe_index,
                 (long long) bytes, (unsigned) total_stripes);

    if (n <= 0 || n >= (int) sizeof(block)) {
        return;
    }

    b = ngx_create_temp_buf(r->pool, (size_t) n);
    if (b == NULL) {
        return;
    }

    ngx_memcpy(b->pos, block, (size_t) n);
    b->last = b->pos + n;
    out.buf  = b;
    out.next = NULL;
    (void) ngx_http_output_filter(r, &out);
}

void
tpc_marker_send_all(ngx_http_request_t *r, time_t ts,
    tpc_marker_ctx_t *ctx)
{
    tpc_ms_progress_t *progress = ctx->progress;
    ngx_uint_t         n        = progress->n_streams;
    ngx_uint_t         i;

    if (n > 1) {
        /* Emit one block per stripe with atomically-read per-stream counts. */
        for (i = 0; i < n; i++) {
            off_t stream_bytes = (off_t) progress->bytes_per_stream[i];
            tpc_marker_send_one(r, ts, i, stream_bytes, n);
        }
    } else {
        /* Single-stream: approximate via stat on the in-progress temp file. */
        off_t bytes = 0;
        if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
            struct stat sb;
            if (stat(ctx->tmp_path, &sb) == 0) {  /* vfs-seam-allow: TPC in-progress transfer temp (committed via rename) */
                bytes = sb.st_size;
            }
        }
        tpc_marker_send_one(r, ts, 0, bytes, 1);
    }
}


/*
 * tpc_marker_final_bytes — WHAT: compute the byte count for the final marker.
 * WHY: the last Performance-Marker and the success metric both report the total
 * transferred size, sourced differently for pull (stat the temp file) vs push
 * (the pre-recorded local file size).  HOW: pull with a live temp path stats it
 * (0 on failure); otherwise pull is 0 and push is the recorded size.  Pure query
 * apart from the stat(2) probe — no state mutation.
 */
static off_t
tpc_marker_final_bytes(tpc_marker_ctx_t *ctx)
{
    if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
        struct stat sb;
        return (stat(ctx->tmp_path, &sb) == 0) ? sb.st_size : 0;  /* vfs-seam-allow: TPC in-progress transfer temp */
    }
    return ctx->is_pull ? 0 : ctx->push_file_size;
}

/*
 * tpc_marker_commit_pull — WHAT: atomically publish the pull temp file to its
 * final path (link+unlink for no-overwrite, rename for overwrite).  WHY: a
 * successful pull stages into a temp file that must be committed under the
 * caller-selected overwrite semantics; a commit failure downgrades the whole
 * transfer to failed.  HOW: pick link vs rename by ctx->overwrite; on error log,
 * unlink the temp, bump the commit-error metric and return 1 (now failed); clear
 * tmp_path in every branch so cleanup does not double-act.  Returns the possibly
 * updated failed flag.
 */
static int
tpc_marker_commit_pull(ngx_http_request_t *r, tpc_marker_ctx_t *ctx)
{
    if (!ctx->overwrite) {
        if (brix_link_confined_canon(r->connection->log, ctx->root_canon,
                                       ctx->tmp_path, ctx->final_path) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "brix_webdav: TPC marker link() failed");
            brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                         ctx->tmp_path, 0);
            ctx->tmp_path[0] = '\0';
            BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
            return 1;
        }
        brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                     ctx->tmp_path, 0);
        ctx->tmp_path[0] = '\0';
        return 0;
    }

    if (brix_rename_confined_canon(r->connection->log, ctx->root_canon,
                                     ctx->tmp_path, ctx->final_path) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "brix_webdav: TPC marker rename() failed");
        brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                     ctx->tmp_path, 0);
        ctx->tmp_path[0] = '\0';
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
        return 1;
    }
    ctx->tmp_path[0] = '\0';
    return 0;
}

/*
 * tpc_marker_settle_temp — WHAT: resolve the pull temp file's fate before the
 * result is reported.  WHY: a success must commit the staged temp to its final
 * name; a failure must discard it — either way the outcome may flip failed.
 * HOW: on success commit via tpc_marker_commit_pull; on failure unlink and clear
 * the path.  Non-pull or already-consumed temp is a no-op.  Returns the possibly
 * updated failed flag.
 */
static int
tpc_marker_settle_temp(ngx_http_request_t *r, tpc_marker_ctx_t *ctx, int failed)
{
    if (!ctx->is_pull || ctx->tmp_path[0] == '\0') {
        return failed;
    }

    if (!failed) {
        return tpc_marker_commit_pull(r, ctx);
    }

    brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                 ctx->tmp_path, 0);
    ctx->tmp_path[0] = '\0';
    return failed;
}

/*
 * tpc_marker_trailer_t — WHAT: the chunked-body trailer word and its length.
 * WHY: lets tpc_marker_record_result return the "success\r\n"/"failure\r\n"
 * selection by value instead of through a pair of out-params.  HOW: filled by
 * record_result, consumed by send_trailer.
 */
typedef struct {
    const char *line;
    size_t      len;
} tpc_marker_trailer_t;

/*
 * tpc_marker_record_result — WHAT: emit the terminal registry/metric/dashboard
 * bookkeeping and return the trailer status word.  WHY: after the temp is
 * settled the transfer must deregister and record success/error counters plus
 * the dashboard byte total, then the chunked body is closed with success/failure.
 * HOW: always remove the registry entry; on failure bump error metrics and log a
 * dashboard error; on success bump the direction-specific success metrics and add
 * bytes; finish the dashboard.  Returns the trailer word by value.  Side effects
 * live here (edge); no return-value control flow.
 */
static tpc_marker_trailer_t
tpc_marker_record_result(ngx_http_request_t *r, tpc_marker_ctx_t *ctx,
    int failed, off_t final_bytes)
{
    tpc_marker_trailer_t trailer = { NULL, 0 };

    (void) brix_tpc_registry_remove(ctx->transfer_id, r->connection->log);

    if (failed) {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_ERROR]);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV,
                                   ctx->is_pull ? BRIX_TPC_DIR_PULL
                                                : BRIX_TPC_DIR_PUSH,
                                   BRIX_TPC_METRIC_ERROR, 0,
                                   r->connection->log);
        brix_dashboard_http_error(r, "webdav TPC failed");
        trailer.line = "failure\r\n";
        trailer.len  = sizeof("failure\r\n") - 1;
        brix_dashboard_http_finish(r);
        return trailer;
    }

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_SUCCESS]);
    if (ctx->is_pull) {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_SUCCESS]);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                                   BRIX_TPC_METRIC_SUCCESS,
                                   (size_t) final_bytes, r->connection->log);
    } else {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PUSH_SUCCESS]);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PUSH,
                                   BRIX_TPC_METRIC_SUCCESS,
                                   (size_t) final_bytes, r->connection->log);
    }
    if (final_bytes > 0) {
        brix_dashboard_http_add(r, (ngx_atomic_int_t) final_bytes);
    }
    trailer.line = "success\r\n";
    trailer.len  = sizeof("success\r\n") - 1;
    brix_dashboard_http_finish(r);
    return trailer;
}

/*
 * tpc_marker_send_trailer — WHAT: write the trailer status word and close the
 * chunked response.  WHY: the 202-streaming body ends with "success\r\n" or
 * "failure\r\n" followed by the terminating chunk, then the request is finalized.
 * HOW: build a temp buf with the status text (best-effort; skip on alloc
 * failure), flush it, send the final chunk and finalize with NGX_DONE.
 */
static void
tpc_marker_send_trailer(ngx_http_request_t *r, tpc_marker_trailer_t trailer)
{
    ngx_buf_t  *b;
    ngx_chain_t out;

    b = ngx_create_temp_buf(r->pool, trailer.len);
    if (b != NULL) {
        ngx_memcpy(b->pos, trailer.line, trailer.len);
        b->last  = b->pos + trailer.len;
        out.buf  = b;
        out.next = NULL;
        (void) ngx_http_output_filter(r, &out);
    }

    (void) ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, NGX_DONE);
}

/*
 * tpc_marker_finish — WHAT: orchestrate transfer completion once the thread has
 * signalled done.  WHY: the last marker must report the final size, the pull temp
 * must be committed or discarded, and the result recorded before the chunked body
 * closes.  HOW: a flat sequence — compute final bytes, emit progress + the final
 * marker, settle the temp (may flip failed), record result counters, send the
 * trailer.  All logic lives in the named helpers.
 */
static void
tpc_marker_finish(ngx_http_request_t *r, tpc_marker_ctx_t *ctx, int failed)
{
    time_t               now         = time(NULL);
    off_t                final_bytes = tpc_marker_final_bytes(ctx);
    tpc_marker_trailer_t trailer;

    (void) brix_tpc_progress_emit(ctx->transfer_id, final_bytes, final_bytes,
                                    failed ? BRIX_TPC_STATE_ERROR
                                           : BRIX_TPC_STATE_DONE,
                                    r->connection->log);
    tpc_marker_send_all(r, now, ctx);

    failed = tpc_marker_settle_temp(r, ctx, failed);

    trailer = tpc_marker_record_result(r, ctx, failed, final_bytes);
    tpc_marker_send_trailer(r, trailer);
}


void
tpc_marker_poll(ngx_event_t *ev)
{
    tpc_marker_ctx_t  *ctx      = ev->data;
    ngx_http_request_t *r       = ctx->r;
    tpc_ms_progress_t  *progress = ctx->progress;
    time_t              now;
    int                 completed;

    now       = time(NULL);
    completed = (int) progress->completed;

    if (ctx->marker_interval_secs > 0
        && (now - ctx->last_marker_time) >= (time_t) ctx->marker_interval_secs)
    {
        tpc_marker_send_all(r, now, ctx);
        ctx->last_marker_time = now;
    }

    if (completed) {
        int failed = (progress->result != NGX_OK
                      && progress->result != NGX_HTTP_CREATED
                      && progress->result != NGX_HTTP_NO_CONTENT);
        tpc_marker_finish(r, ctx, failed);
        return;
    }

    ngx_add_timer(ev, TPC_MARKER_POLL_MSEC);
}

/*
 * tpc_marker_thread_done — fires in the event loop when the thread completes.
 * Re-arms the poll timer with a 1 ms delay so it wakes up immediately to
 * detect progress->completed without waiting for the next 200 ms tick.
 */
void
tpc_marker_thread_done(ngx_event_t *ev)
{
    ngx_thread_task_t       *task = ev->data;
    tpc_marker_thread_ctx_t *tt   = task->ctx;
    tpc_marker_ctx_t        *ctx  = tt->marker_ctx;

    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }
    ngx_add_timer(&ctx->timer, 1);
}

void
tpc_marker_cleanup(void *data)
{
    tpc_marker_ctx_t *ctx = data;

    /*
     * Phase 39 (WS5): this pool cleanup fires when the request ends — including
     * when the client disconnects mid-COPY.  Signal the in-flight curl transfer
     * (by id) to abort promptly via its progress callback, instead of leaving the
     * thread-pool worker pulling into an abandoned destination until the
     * low-speed/transfer-timeout bound or the registry reaper reclaims it.  On a
     * normal completion the transfer is already gone, so this is a no-op.
     */
    if (ctx->transfer_id != 0) {
        (void) brix_tpc_registry_request_cancel(ctx->transfer_id);
    }

    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
        (void) unlink(ctx->tmp_path);  /* vfs-seam-allow: TPC in-progress transfer temp cleanup */
        ctx->tmp_path[0] = '\0';
    }
}
