/*
 * tpc_marker_start.c — transfer-thread and start/setup cluster for the WebDAV
 * 202-streaming Performance-Marker path.
 *
 * Split out of tpc_marker.c (mechanical file-size split): this file holds the
 * curl transfer thread body and the webdav_tpc_marker_start orchestration that
 * builds the ctx + task, arms the request lifecycle, sends the 202 head and
 * posts the thread.  The marker/progress emission cluster remains in
 * tpc_marker.c.  Shared state lives in tpc_marker_internal.h.  No behaviour
 * change — functions moved verbatim.
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
