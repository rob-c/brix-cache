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


static void
tpc_marker_finish(ngx_http_request_t *r, tpc_marker_ctx_t *ctx, int failed)
{
    time_t      now;
    off_t       final_bytes;
    ngx_buf_t  *b;
    ngx_chain_t out;
    const char *status_line;
    size_t      status_len;

    now = time(NULL);

    /* Determine final byte count for the last marker. */
    if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
        struct stat sb;
        final_bytes = (stat(ctx->tmp_path, &sb) == 0) ? sb.st_size : 0;  /* vfs-seam-allow: TPC in-progress transfer temp */
    } else {
        final_bytes = ctx->is_pull ? 0 : ctx->push_file_size;
    }

    (void) brix_tpc_progress_emit(ctx->transfer_id, final_bytes, final_bytes,
                                    failed ? BRIX_TPC_STATE_ERROR
                                           : BRIX_TPC_STATE_DONE,
                                    r->connection->log);
    tpc_marker_send_all(r, now, ctx);

    /* Atomically commit the pull temp file. */
    if (!failed && ctx->is_pull && ctx->tmp_path[0] != '\0') {
        if (!ctx->overwrite) {
            if (brix_link_confined_canon(r->connection->log, ctx->root_canon,
                                           ctx->tmp_path,
                                           ctx->final_path) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "brix_webdav: TPC marker link() failed");
                brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
                BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
                failed = 1;
            } else {
                brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
            }
        } else {
            if (brix_rename_confined_canon(r->connection->log, ctx->root_canon,
                                             ctx->tmp_path,
                                             ctx->final_path) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "brix_webdav: TPC marker rename() failed");
                brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
                BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
                failed = 1;
            } else {
                ctx->tmp_path[0] = '\0';
            }
        }
    } else if (failed && ctx->is_pull && ctx->tmp_path[0] != '\0') {
        brix_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                     ctx->tmp_path, 0);
        ctx->tmp_path[0] = '\0';
    }

    /* Registry + metrics. */
    (void) brix_tpc_registry_remove(ctx->transfer_id, r->connection->log);

    if (failed) {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_ERROR]);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV,
                                   ctx->is_pull ? BRIX_TPC_DIR_PULL
                                                : BRIX_TPC_DIR_PUSH,
                                   BRIX_TPC_METRIC_ERROR, 0,
                                   r->connection->log);
        brix_dashboard_http_error(r, "webdav TPC failed");
        status_line = "failure\r\n";
        status_len  = sizeof("failure\r\n") - 1;
    } else {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_SUCCESS]);
        if (ctx->is_pull) {
            BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_SUCCESS]);
            brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV,
                                       BRIX_TPC_DIR_PULL,
                                       BRIX_TPC_METRIC_SUCCESS,
                                       (size_t) final_bytes,
                                       r->connection->log);
        } else {
            BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PUSH_SUCCESS]);
            brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV,
                                       BRIX_TPC_DIR_PUSH,
                                       BRIX_TPC_METRIC_SUCCESS,
                                       (size_t) final_bytes,
                                       r->connection->log);
        }
        if (final_bytes > 0) {
            brix_dashboard_http_add(r, (ngx_atomic_int_t) final_bytes);
        }
        status_line = "success\r\n";
        status_len  = sizeof("success\r\n") - 1;
    }
    brix_dashboard_http_finish(r);

    b = ngx_create_temp_buf(r->pool, status_len);
    if (b != NULL) {
        ngx_memcpy(b->pos, status_line, status_len);
        b->last  = b->pos + status_len;
        out.buf  = b;
        out.next = NULL;
        (void) ngx_http_output_filter(r, &out);
    }

    (void) ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, NGX_DONE);
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
                                            progress->n_streams, 0, progress);
    } else {
        rc = webdav_tpc_run_curl_pull(tt->log, tt->conf, tt->url,
                                      tt->local_path, tt->transfer_headers, 0);
    }

    progress->result = rc;
    ngx_memory_barrier();
    progress->completed = 1;
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
 */
ngx_int_t
webdav_tpc_marker_start(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_uint_t n_streams,
    const char *url, const char *tmp_path, const char *final_path,
    ngx_flag_t is_pull, ngx_flag_t overwrite, ngx_flag_t existed,
    ngx_array_t *transfer_headers, uint64_t transfer_id)
{
    tpc_ms_progress_t       *progress;
    tpc_marker_ctx_t        *ctx;
    tpc_marker_thread_ctx_t *tt;
    ngx_thread_task_t       *task;
    ngx_pool_cleanup_t      *cln;
    ngx_table_elt_t         *h;
    ngx_int_t                rc;

    if (conf->common.thread_pool == NULL) {
        return NGX_DECLINED;
    }

    if (n_streams == 0) n_streams = 1;
    if (n_streams > BRIX_TPC_MAX_STREAMS) n_streams = BRIX_TPC_MAX_STREAMS;

    /* Shared progress counters (thread writes, event loop reads). */
    progress = ngx_pcalloc(r->pool, sizeof(*progress));
    if (progress == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    progress->n_streams  = n_streams;
    progress->total_size = -1;

    /* Event-loop marker context. */
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->r                    = r;
    ctx->progress             = progress;
    ctx->is_pull              = is_pull;
    ctx->overwrite            = overwrite;
    ctx->existed              = existed;
    ctx->root_canon           = conf->common.root_canon;
    ctx->transfer_id          = transfer_id;
    ctx->marker_interval_secs = conf->tpc_marker_interval;
    ctx->last_marker_time     = 0;

    ngx_cpystrn((u_char *) ctx->tmp_path,
                (u_char *) (tmp_path   ? tmp_path   : ""),
                sizeof(ctx->tmp_path));
    ngx_cpystrn((u_char *) ctx->final_path,
                (u_char *) (final_path ? final_path : ""),
                sizeof(ctx->final_path));

    if (!is_pull && tmp_path != NULL) {
        struct stat sb;
        if (stat(tmp_path, &sb) == 0) {  /* vfs-seam-allow: TPC push source temp size */
            ctx->push_file_size = sb.st_size;
        }
    }

    /* Thread task. */
    task = ngx_thread_task_alloc(r->pool, sizeof(tpc_marker_thread_ctx_t));
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tt                   = task->ctx;
    tt->marker_ctx        = ctx;
    tt->log               = r->connection->log;
    tt->conf              = conf;
    tt->is_push           = !is_pull;
    tt->transfer_headers  = transfer_headers;
    ngx_cpystrn((u_char *) tt->url,
                (u_char *) (url      ? url      : ""), sizeof(tt->url));
    ngx_cpystrn((u_char *) tt->local_path,
                (u_char *) (tmp_path ? tmp_path : ""), sizeof(tt->local_path));

    brix_task_bind(task, tpc_marker_thread_func, tpc_marker_thread_done);
    task->event.log     = r->connection->log;

    /* Pool cleanup: abort in-progress temp file on request destruction. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = tpc_marker_cleanup;
    cln->data    = ctx;

    /* Poll timer (event-loop side). */
    ngx_memzero(&ctx->timer, sizeof(ctx->timer));
    ctx->timer.handler = tpc_marker_poll;
    ctx->timer.data    = ctx;
    ctx->timer.log     = r->connection->log;

    /* Add X-Number-Of-Streams to response headers before sending 202. */
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

    /* 202 Accepted with chunked text/plain body. */
    r->headers_out.status            = 202;
    r->headers_out.content_length_n  = -1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len  = sizeof("text/plain") - 1;
    r->headers_out.content_type_len  = sizeof("text/plain") - 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc != NGX_ERROR ? rc : NGX_HTTP_INTERNAL_SERVER_ERROR;
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
