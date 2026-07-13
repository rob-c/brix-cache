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

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Poll the transfer thread status every 200 ms. */
#define TPC_MARKER_POLL_MSEC  200u


/*
 * Event-loop side state for a 202-streaming TPC transfer.
 * Allocated from r->pool; accessed only from the nginx event loop thread.
 */
typedef struct {
    ngx_http_request_t  *r;
    tpc_ms_progress_t   *progress;         /* shared with transfer thread */
    ngx_event_t          timer;
    time_t               last_marker_time;
    ngx_uint_t           marker_interval_secs;
    char                 tmp_path[WEBDAV_MAX_PATH];   /* pull: in-progress file */
    char                 final_path[WEBDAV_MAX_PATH]; /* pull: commit target */
    const char          *root_canon;
    ngx_flag_t           overwrite;
    ngx_flag_t           existed;
    ngx_flag_t           is_pull;
    off_t                push_file_size;   /* push: local file size for final marker */
    uint64_t             transfer_id;
} tpc_marker_ctx_t;

/*
 * Thread task context — carries everything the transfer thread needs.
 * Allocated from r->pool before the task is posted; the thread only reads it.
 */
typedef struct {
    tpc_marker_ctx_t                  *marker_ctx;
    ngx_log_t                         *log;
    ngx_http_brix_webdav_loc_conf_t *conf;
    int                                is_push;
    char                               url[4096];
    char                               local_path[WEBDAV_MAX_PATH];
    ngx_array_t                       *transfer_headers;
    const char                        *user_cert; /* per-user pull-leg cert (r->pool, or NULL) */
    const char                        *user_key;  /* per-user pull-leg key  (r->pool, or NULL) */
} tpc_marker_thread_ctx_t;


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

static void
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


static void
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
static void
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

static void
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


static void
tpc_marker_thread_func(void *data, ngx_log_t *log)
{
    tpc_marker_thread_ctx_t *tt       = data;
    tpc_ms_progress_t       *progress = tt->marker_ctx->progress;
    ngx_int_t                rc;

    (void) log;  /* use tt->log for request-level context */

    /* SSRF preflight: resolve the remote URL and reject prohibited ranges. */
    {
        brix_net_target_t        net_target;
        brix_net_target_policy_t net_policy;
        ngx_str_t                  url_str;
        char                       ssrf_err[256];

        url_str.data = (u_char *) tt->url;
        url_str.len  = ngx_strlen(tt->url);

        ngx_memzero(&net_policy, sizeof(net_policy));
        net_policy.require_https      = 1;
        net_policy.allow_root_scheme  = 0;
        net_policy.allow_local        = tt->conf->tpc_allow_local;
        net_policy.allow_private      = tt->conf->tpc_allow_private;
        net_policy.default_https_port = 443;

        if (brix_net_target_parse(NULL, &url_str, &net_target,
                                    ssrf_err, sizeof(ssrf_err)) != NGX_OK
            || brix_net_target_check_dns(&net_target, &net_policy,
                                           ssrf_err, sizeof(ssrf_err)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, tt->log, 0,
                          "brix_webdav: HTTP-TPC SSRF blocked: %s", ssrf_err);
            progress->result = NGX_HTTP_FORBIDDEN;
            ngx_memory_barrier();
            progress->completed = 1;
            return;
        }
    }

    if (tt->is_push) {
        rc = webdav_tpc_run_curl_push(tt->log, tt->conf, tt->url,
                                      tt->local_path, tt->transfer_headers, 0);
    } else if (progress->n_streams > 1) {
        rc = webdav_tpc_run_curl_pull_multi(tt->log, tt->conf, tt->url,
                                            tt->local_path, tt->transfer_headers,
                                            progress->n_streams, 0, progress,
                                            tt->user_cert, tt->user_key);
    } else {
        rc = webdav_tpc_run_curl_pull(tt->log, tt->conf, tt->url,
                                      tt->local_path, tt->transfer_headers, 0,
                                      tt->user_cert, tt->user_key);
    }

    progress->result = rc;
    ngx_memory_barrier();
    progress->completed = 1;
}


/*
 * tpc_marker_start_args_t — WHAT: the immutable inputs to a 202-streaming TPC
 * start, bundled so the setup helpers take one struct instead of the 11-parameter
 * public argument list.  WHY: the public webdav_tpc_marker_start signature is a
 * frozen extern (declared in webdav_tpc.h, called from tpc.c) and cannot shed
 * params, but the file-local build steps become single-argument and testable when
 * the request-scoped inputs travel as one value.  HOW: filled once from the entry
 * point's parameters, then read-only for the remainder of setup.
 */
typedef struct {
    ngx_http_request_t              *r;
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_uint_t                        n_streams;
    const char                       *url;
    const char                       *tmp_path;
    const char                       *final_path;
    ngx_flag_t                        is_pull;
    ngx_flag_t                        overwrite;
    ngx_flag_t                        existed;
    ngx_array_t                      *transfer_headers;
    const char                       *user_cert;  /* per-user pull-leg cert (or NULL) */
    const char                       *user_key;   /* per-user pull-leg key  (or NULL) */
    uint64_t                          transfer_id;
} tpc_marker_start_args_t;

/*
 * tpc_marker_build_ctx — WHAT: allocate and populate the event-loop marker ctx
 * (with its shared progress counters).  WHY: the ctx is the single state object
 * the poll timer, thread-done handler and cleanup all key off; building it is one
 * responsibility.  HOW: pcalloc the progress + ctx from r->pool, copy the paths
 * with bounded ngx_cpystrn, and for a push record the source file size for the
 * final marker.  Returns the ctx, or NULL on allocation failure.
 */
static tpc_marker_ctx_t *
tpc_marker_build_ctx(const tpc_marker_start_args_t *a)
{
    ngx_http_request_t *r = a->r;
    tpc_ms_progress_t  *progress;
    tpc_marker_ctx_t   *ctx;

    progress = ngx_pcalloc(r->pool, sizeof(*progress));
    if (progress == NULL) {
        return NULL;
    }
    progress->n_streams  = a->n_streams;
    progress->total_size = -1;

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->r                    = r;
    ctx->progress             = progress;
    ctx->is_pull              = a->is_pull;
    ctx->overwrite            = a->overwrite;
    ctx->existed              = a->existed;
    ctx->root_canon           = a->conf->common.root_canon;
    ctx->transfer_id          = a->transfer_id;
    ctx->marker_interval_secs = a->conf->tpc_marker_interval;
    ctx->last_marker_time     = 0;

    ngx_cpystrn((u_char *) ctx->tmp_path,
                (u_char *) (a->tmp_path   ? a->tmp_path   : ""),
                sizeof(ctx->tmp_path));
    ngx_cpystrn((u_char *) ctx->final_path,
                (u_char *) (a->final_path ? a->final_path : ""),
                sizeof(ctx->final_path));

    if (!a->is_pull && a->tmp_path != NULL) {
        struct stat sb;
        if (stat(a->tmp_path, &sb) == 0) {  /* vfs-seam-allow: TPC push source temp size */
            ctx->push_file_size = sb.st_size;
        }
    }

    return ctx;
}

/*
 * tpc_marker_build_task — WHAT: allocate and populate the thread task that runs
 * the curl transfer.  WHY: the thread reads a private copy of the request inputs;
 * assembling it is a distinct step from the event-loop ctx.  HOW: alloc the task,
 * fill its ctx (marker back-pointer, log, conf, direction, headers, bounded url +
 * local path copies) and bind the thread + done handlers.  Returns the task, or
 * NULL on allocation failure.
 */
static ngx_thread_task_t *
tpc_marker_build_task(const tpc_marker_start_args_t *a, tpc_marker_ctx_t *ctx)
{
    ngx_http_request_t      *r = a->r;
    ngx_thread_task_t       *task;
    tpc_marker_thread_ctx_t *tt;

    task = ngx_thread_task_alloc(r->pool, sizeof(tpc_marker_thread_ctx_t));
    if (task == NULL) {
        return NULL;
    }
    tt                   = task->ctx;
    tt->marker_ctx        = ctx;
    tt->log               = r->connection->log;
    tt->conf              = a->conf;
    tt->is_push           = !a->is_pull;
    tt->transfer_headers  = a->transfer_headers;
    tt->user_cert         = a->user_cert;
    tt->user_key          = a->user_key;
    ngx_cpystrn((u_char *) tt->url,
                (u_char *) (a->url      ? a->url      : ""), sizeof(tt->url));
    ngx_cpystrn((u_char *) tt->local_path,
                (u_char *) (a->tmp_path ? a->tmp_path : ""),
                sizeof(tt->local_path));

    brix_task_bind(task, tpc_marker_thread_func, tpc_marker_thread_done);
    task->event.log = r->connection->log;

    return task;
}

/*
 * tpc_marker_arm_lifecycle — WHAT: register the request-destruction cleanup and
 * initialise the poll timer for a marker ctx.  WHY: the cleanup aborts an
 * in-flight transfer if the client disconnects, and the timer drives marker
 * emission; both must be wired before the 202 is sent.  HOW: add a pool cleanup
 * bound to ctx, zero and configure the timer's handler/data/log.  Returns NGX_OK,
 * or NGX_HTTP_INTERNAL_SERVER_ERROR if the cleanup slot cannot be allocated.
 */
static ngx_int_t
tpc_marker_arm_lifecycle(ngx_http_request_t *r, tpc_marker_ctx_t *ctx)
{
    ngx_pool_cleanup_t *cln;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = tpc_marker_cleanup;
    cln->data    = ctx;

    ngx_memzero(&ctx->timer, sizeof(ctx->timer));
    ctx->timer.handler = tpc_marker_poll;
    ctx->timer.data    = ctx;
    ctx->timer.log     = r->connection->log;

    return NGX_OK;
}

/*
 * tpc_marker_send_accepted — WHAT: emit the 202 Accepted response head with the
 * X-Number-Of-Streams header and a chunked text/plain body.  WHY: FTS/RUCIO
 * expect the stream count and an open chunked body before the markers stream in;
 * this is the frozen wire shape.  HOW: push the header, format n_streams into it,
 * set the 202 status/content-type, and send the header.  Returns NGX_OK, or an
 * HTTP error code on allocation or header-send failure.
 */
static ngx_int_t
tpc_marker_send_accepted(ngx_http_request_t *r, ngx_uint_t n_streams)
{
    ngx_table_elt_t *h;
    ngx_int_t        rc;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "X-Number-Of-Streams");
    h->value.data = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->value.len = (size_t) (ngx_sprintf(h->value.data, "%ui", n_streams)
                             - h->value.data);

    r->headers_out.status            = 202;
    r->headers_out.content_length_n  = -1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len  = sizeof("text/plain") - 1;
    r->headers_out.content_type_len  = sizeof("text/plain") - 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc != NGX_ERROR ? rc : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_OK;
}

/*
 * webdav_tpc_marker_start — start a 202-streaming TPC transfer.
 *
 * Sends 202 Accepted immediately, posts the curl work to the thread pool, and
 * arms a poll timer that emits Performance-Marker blocks while the thread runs.
 * Returns NGX_DONE (202 sent) on success.
 * Returns NGX_DECLINED when no thread pool is configured (caller uses 201 path).
 * Returns an HTTP error code on allocation or header-send failure.
 *
 * For pull transfers: tmp_path is the staging file; final_path is the commit
 *   target.  Both must fit within WEBDAV_MAX_PATH.
 * For push transfers: tmp_path is the local source file; final_path is unused.
 *
 * Orchestrator only: builds the ctx + task, arms the lifecycle, sends the 202,
 * posts the thread, emits the first marker and starts the poll timer — each a
 * named helper.  (11 params: frozen public extern; the inputs travel internally
 * as a tpc_marker_start_args_t.)
 */
ngx_int_t
webdav_tpc_marker_start(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_uint_t n_streams,
    const char *url, const char *tmp_path, const char *final_path,
    ngx_flag_t is_pull, ngx_flag_t overwrite, ngx_flag_t existed,
    ngx_array_t *transfer_headers, uint64_t transfer_id,
    const char *user_cert, const char *user_key)
{
    tpc_marker_start_args_t  args;
    tpc_marker_ctx_t        *ctx;
    ngx_thread_task_t       *task;
    ngx_int_t                rc;

    if (conf->common.thread_pool == NULL) {
        return NGX_DECLINED;
    }

    if (n_streams == 0) n_streams = 1;
    if (n_streams > BRIX_TPC_MAX_STREAMS) n_streams = BRIX_TPC_MAX_STREAMS;

    ngx_memzero(&args, sizeof(args));
    args.r                = r;
    args.conf             = conf;
    args.n_streams        = n_streams;
    args.url              = url;
    args.tmp_path         = tmp_path;
    args.final_path       = final_path;
    args.is_pull          = is_pull;
    args.overwrite        = overwrite;
    args.existed          = existed;
    args.transfer_headers = transfer_headers;
    args.user_cert        = user_cert;
    args.user_key         = user_key;
    args.transfer_id      = transfer_id;

    ctx = tpc_marker_build_ctx(&args);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    task = tpc_marker_build_task(&args, ctx);
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = tpc_marker_arm_lifecycle(r, ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = tpc_marker_send_accepted(r, n_streams);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Post the thread task. */
    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Prevent request destruction until we call ngx_http_finalize_request. */
    r->main->count++;

    /* Emit the first Performance-Marker immediately. */
    ctx->last_marker_time = time(NULL);
    tpc_marker_send_all(r, ctx->last_marker_time, ctx);

    /* Start the poll timer. */
    ngx_add_timer(&ctx->timer, TPC_MARKER_POLL_MSEC);

    return NGX_DONE;
}
