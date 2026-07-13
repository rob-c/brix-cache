/*
 * tpc_thread.c - thread-pool wrapper for HTTP-TPC blocking curl transfers.
 *
 * Moves the fork/waitpid blocking from the nginx event-loop worker to a
 * background thread so that other connections on the same worker are not
 * stalled for the duration of a large file transfer (which can be minutes).
 *
 * Compiled only when NGX_THREADS is defined (--with-threads configure flag).
 * When thread pool is not available at runtime (conf->common.thread_pool == NULL),
 * webdav_tpc_post_thread_task returns NGX_DECLINED and the caller falls back
 * to the synchronous path in tpc.c.
 */

#include "webdav.h"
#include "core/compat/net_target.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "tpc/common/metrics.h"
#include "core/aio/aio.h"          /* brix_task_bind */
#include "tpc/common/registry.h"
#include "fs/xfer/xfer.h"     /* unified transfer audit ledger (kind=tpc) */


#include <errno.h>
#include <sys/stat.h>

typedef struct {
    ngx_http_request_t                *r;
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_log_t                         *log;      /* r->connection->log snapshot */
    int                                is_push;  /* 0=pull, 1=push */
    ngx_flag_t                         existed;  /* pull: 1 if dest existed */
    ngx_flag_t                         overwrite;
    const char                        *url;      /* pool-alloc'd source or dest URL */
    char                               local_path[WEBDAV_MAX_PATH]; /* pull: tmp_path; push: src */
    char                               dest_path[WEBDAV_MAX_PATH];  /* pull: final dest; push: unused */
    char                               root_canon[WEBDAV_MAX_PATH];
    ngx_array_t                       *transfer_headers;  /* pool-alloc'd, safe while r lives */
    const char                        *user_cert;   /* per-user pull-leg cert (r->pool, or NULL) */
    const char                        *user_key;    /* per-user pull-leg key  (r->pool, or NULL) */
    ngx_int_t                          http_status;       /* set by thread func */
    off_t                              bytes_transferred;
    uint64_t                           transfer_id;
    ngx_uint_t                         n_streams;         /* 1 = single-stream pull */
} tpc_thread_ctx_t;

/*
 * Add this transfer to the cross-process TPC registry, mapping src/dst by
 * direction: push reads local_path and writes the remote `url`; pull reads `url`
 * and writes dest_path.  Returns the non-zero transfer id, or 0 if the registry
 * is full.
 */
static uint64_t
webdav_tpc_thread_register(ngx_http_request_t *r, int is_push,
                           const char *url, const char *local_path,
                           const char *dest_path)
{
    brix_tpc_transfer_t transfer;
    ngx_str_t             src;
    ngx_str_t             dst;

    ngx_memzero(&transfer, sizeof(transfer));

    if (is_push) {
        src.data = (u_char *) local_path;
        src.len = ngx_strlen(local_path);
        dst.data = (u_char *) url;
        dst.len = ngx_strlen(url);
        transfer.direction = BRIX_TPC_DIR_PUSH;
    } else {
        src.data = (u_char *) url;
        src.len = ngx_strlen(url);
        dst.data = (u_char *) dest_path;
        dst.len = ngx_strlen(dest_path);
        transfer.direction = BRIX_TPC_DIR_PULL;
    }

    transfer.protocol = BRIX_TPC_PROTO_WEBDAV;
    transfer.src_url = src;
    transfer.dst_path = dst;
    transfer.state = BRIX_TPC_STATE_PENDING;

    return brix_tpc_registry_add(&transfer, r->connection->log);
}

/*
 * WHAT: mark this transfer failed in the registry and bump the direction's
 *       TPC error metric, using the bytes recorded so far.
 * WHY:  every worker-body failure exit performs this identical two-call
 *       bookkeeping; centralising it keeps the ordering (registry then metric)
 *       and the counter values consistent across all exit paths.
 * HOW:  reads t->transfer_id / t->bytes_transferred / t->is_push and issues the
 *       registry ERROR update followed by the ERROR metric.  Thread-safe: both
 *       callees are thread-safe and no shared state is added.
 */
static void
tpc_thread_fail(tpc_thread_ctx_t *t)
{
    (void) brix_tpc_registry_update(t->transfer_id, t->bytes_transferred,
                                    BRIX_TPC_STATE_ERROR, t->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV,
                             t->is_push ? BRIX_TPC_DIR_PUSH
                                        : BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_ERROR,
                             t->bytes_transferred, t->log);
}

/*
 * WHAT: record the on-disk size of the local transfer file into
 *       t->bytes_transferred, leaving it unchanged if the stat fails.
 * WHY:  both the push success path and the pull post-curl path report the
 *       committed byte count from the temp/source file size.
 * HOW:  best-effort stat() of t->local_path (raw is correct here — the temp
 *       lives in the svc-owned staging domain, not an export path).
 */
static void
tpc_thread_record_size(tpc_thread_ctx_t *t)
{
    struct stat st;

    if (stat(t->local_path, &st) == 0) {  /* vfs-seam-allow: TPC local transfer temp */
        t->bytes_transferred = st.st_size;
    }
}

/*
 * WHAT: SSRF preflight for the remote URL; returns NGX_OK to proceed or
 *       NGX_ERROR after fully finalising the failure (status/registry/metric).
 * WHY:  getaddrinfo() blocks, so the resolve-and-vet must run on the worker
 *       thread before curl forks; a blocked address must be rejected exactly
 *       once with a 403 and error bookkeeping.
 * HOW:  parses the URL under the conf-derived policy, checks DNS, and on
 *       failure sets t->http_status=403 and calls tpc_thread_fail().  A NULL
 *       URL is treated as "nothing to vet" and returns NGX_OK.
 */
static ngx_int_t
tpc_thread_ssrf_preflight(tpc_thread_ctx_t *t)
{
    brix_net_target_t        net_target;
    brix_net_target_policy_t net_policy;
    ngx_str_t                  url_str;
    char                       ssrf_err[256];

    if (t->url == NULL) {
        return NGX_OK;
    }

    url_str.data = (u_char *) t->url;
    url_str.len  = ngx_strlen(t->url);

    ngx_memzero(&net_policy, sizeof(net_policy));
    net_policy.require_https      = 1;
    net_policy.allow_root_scheme  = 0;
    net_policy.allow_local        = t->conf->tpc_allow_local;
    net_policy.allow_private      = t->conf->tpc_allow_private;
    net_policy.default_https_port = 443;

    if (brix_net_target_parse(NULL, &url_str, &net_target,
                                ssrf_err, sizeof(ssrf_err)) == NGX_OK
        && brix_net_target_check_dns(&net_target, &net_policy,
                                       ssrf_err, sizeof(ssrf_err)) == NGX_OK)
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, t->log, 0,
                  "brix_webdav: HTTP-TPC SSRF check blocked "
                  "transfer to %s: %s",
                  t->url, ssrf_err);
    t->http_status = NGX_HTTP_FORBIDDEN;
    tpc_thread_fail(t);
    return NGX_ERROR;
}

/*
 * WHAT: run the push (local → remote) curl transfer and finalise its outcome.
 * WHY:  the push direction has its own success/error bookkeeping (byte count
 *       from the source file, PUSH_SUCCESS webdav metric, 201 status) distinct
 *       from pull; isolating it keeps the worker body flat.
 * HOW:  invokes webdav_tpc_run_curl_push; on NGX_OK records size, marks the
 *       registry DONE, bumps success metrics and sets 201; otherwise
 *       tpc_thread_fail() and propagates the curl status.  Preserves the exact
 *       marker/counter update order of the original inline branch.
 */
static void
tpc_thread_run_push(tpc_thread_ctx_t *t)
{
    ngx_int_t rc;

    rc = webdav_tpc_run_curl_push(t->log, t->conf, t->url,
                                  t->local_path, t->transfer_headers,
                                  t->transfer_id);
    if (rc != NGX_OK) {
        tpc_thread_fail(t);
        t->http_status = rc;
        return;
    }

    tpc_thread_record_size(t);
    (void) brix_tpc_registry_update(t->transfer_id, t->bytes_transferred,
                                    BRIX_TPC_STATE_DONE, t->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PUSH,
                             BRIX_TPC_METRIC_SUCCESS,
                             t->bytes_transferred, t->log);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PUSH_SUCCESS]);
    t->http_status = NGX_HTTP_CREATED;
}

/*
 * WHAT: run the pull (remote → local temp) curl transfer, single- or
 *       multi-stream; returns NGX_OK if bytes landed in the temp, else the
 *       failure status.
 * WHY:  the pull byte fetch is a distinct stage from the atomic commit; on
 *       failure the temp must be removed and the transfer marked errored before
 *       the commit stage is ever reached.
 * HOW:  dispatches to the multi- or single-stream curl runner by t->n_streams;
 *       on error unlinks the confined temp, calls tpc_thread_fail(), sets
 *       t->http_status and returns NGX_ERROR.  On success records the temp size
 *       and returns NGX_OK.
 */
static ngx_int_t
tpc_thread_pull_fetch(tpc_thread_ctx_t *t)
{
    ngx_int_t rc;

    if (t->n_streams > 1) {
        rc = webdav_tpc_run_curl_pull_multi(t->log, t->conf, t->url,
                                             t->local_path, t->transfer_headers,
                                             t->n_streams, t->transfer_id, NULL,
                                             t->user_cert, t->user_key);
    } else {
        rc = webdav_tpc_run_curl_pull(t->log, t->conf, t->url, t->local_path,
                                      t->transfer_headers, t->transfer_id,
                                      t->user_cert, t->user_key);
    }

    if (rc != NGX_OK) {
        (void) brix_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
        tpc_thread_fail(t);
        t->http_status = rc;
        return NGX_ERROR;
    }

    tpc_thread_record_size(t);
    return NGX_OK;
}

/*
 * WHAT: atomically commit the pull temp into dest_path; returns NGX_OK on
 *       success (with the final 201/204 status set) or NGX_ERROR after full
 *       failure bookkeeping.
 * WHY:  mirrors the synchronous path's commit policy — no-overwrite uses link()
 *       (EEXIST ⇒ 412 racing create), overwrite uses rename(); every failure
 *       unlinks the temp so no partial file is left and bumps COMMIT_ERROR.
 * HOW:  branches on t->overwrite, always unlinks the temp afterwards, and on
 *       any failure marks the commit-error metric, calls tpc_thread_fail() and
 *       sets the appropriate 4xx/5xx status.  On success sets 204 if the dest
 *       pre-existed else 201.
 */
static ngx_int_t
tpc_thread_pull_commit(tpc_thread_ctx_t *t)
{
    int err;

    if (!t->overwrite) {
        if (brix_link_confined_canon(t->log, t->root_canon,
                                       t->local_path, t->dest_path) != 0) {
            err = errno;
            (void) brix_unlink_confined_canon(t->log, t->root_canon,
                                                t->local_path, 0);
            BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
            tpc_thread_fail(t);
            t->http_status = (err == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                             : NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }
        (void) brix_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
    } else if (brix_rename_confined_canon(t->log, t->root_canon,
                                            t->local_path, t->dest_path) != 0) {
        brix_log_safe_path(t->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav: HTTP-TPC rename failed for: \"%s\"",
                             t->dest_path);
        (void) brix_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
        tpc_thread_fail(t);
        t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    t->http_status = t->existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    return NGX_OK;
}

/*
 * WHAT: run the full pull direction — fetch the remote bytes then atomically
 *       commit the temp into place, reporting success bookkeeping.
 * WHY:  keeps the two pull stages (fetch, commit) sequenced with a single
 *       success finaliser, matching the original inline flow.
 * HOW:  early-returns if either stage fails (each already finalised its own
 *       error); on full success marks the registry DONE, bumps the PULL_SUCCESS
 *       metrics.  The status was set by the commit stage.
 */
static void
tpc_thread_run_pull(tpc_thread_ctx_t *t)
{
    if (tpc_thread_pull_fetch(t) != NGX_OK) {
        return;
    }
    if (tpc_thread_pull_commit(t) != NGX_OK) {
        return;
    }

    (void) brix_tpc_registry_update(t->transfer_id, t->bytes_transferred,
                                    BRIX_TPC_STATE_DONE, t->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_SUCCESS,
                             t->bytes_transferred, t->log);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_SUCCESS]);
}

/*
 * Thread-pool worker body.  RUNS ON A BACKGROUND THREAD, not the nginx event
 * loop: it MUST NOT touch the event loop, send a response, or call most ngx_http
 * APIs.  Its only outputs are the t->* result fields (http_status,
 * bytes_transferred) plus the side-effecting registry/metrics/filesystem calls,
 * which are thread-safe.  tpc_thread_done (below) consumes the results back on
 * the event loop.  Performs the SSRF preflight, marks the transfer active, and
 * dispatches to the push or pull stage (pull atomically commits the temp file).
 */
static void
tpc_thread_func(void *data, ngx_log_t *log)
{
    tpc_thread_ctx_t *t = data;

    (void) log;  /* use t->log for request-level context */

    if (tpc_thread_ssrf_preflight(t) != NGX_OK) {
        return;
    }

    (void) brix_tpc_registry_update(t->transfer_id, 0,
                                      BRIX_TPC_STATE_ACTIVE, t->log);

    if (t->is_push) {
        tpc_thread_run_push(t);
    } else {
        tpc_thread_run_pull(t);
    }
}

/*
 * Completion handler — RUNS BACK ON THE EVENT LOOP after tpc_thread_func
 * finishes.  This is the async re-entry point: it reads the result fields the
 * worker set, removes the registry entry, and sends the final HTTP response
 * (201/204 on success, the error status otherwise), then finalizes the request.
 * Pairs with the r->main->count++ taken in webdav_tpc_post_thread_task.
 */
static void
tpc_thread_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task   = ev->data;
    tpc_thread_ctx_t   *t      = task->ctx;
    ngx_http_request_t *r      = t->r;
    ngx_int_t           status = t->http_status;

    (void) brix_tpc_registry_remove(t->transfer_id,
                                      r->connection != NULL
                                          ? r->connection->log : t->log);

    /* Unified transfer ledger: one audit line shared with STAGE/TAPE/WT. A push
     * sends a local object OUT to a remote dest; a pull brings data IN to the
     * local dest (for a pull, local_path is the staging temp, so the audited
     * object is dest_path). */
    {
        int          ok   = (status == NGX_HTTP_CREATED
                             || status == NGX_HTTP_NO_CONTENT);
        const char  *path = t->is_push
                            ? (t->local_path[0] ? t->local_path : t->url)
                            : (t->dest_path[0] ? t->dest_path : t->url);
        brix_xfer_finish(BRIX_XFER_TPC, t->is_push ? "out" : "in",
                           path, NULL, (size_t) t->bytes_transferred,
                           ok ? BRIX_XFER_OK
                              : (t->is_push ? BRIX_XFER_DST_ERR
                                            : BRIX_XFER_SRC_ERR),
                           0, t->log);
    }

    if (status == NGX_HTTP_CREATED || status == NGX_HTTP_NO_CONTENT) {
        if (t->bytes_transferred > 0) {
            brix_dashboard_http_add(r,
                (ngx_atomic_int_t) t->bytes_transferred);
        }
        brix_dashboard_http_finish(r);
        webdav_send_status_only(r, (ngx_uint_t) status);
    } else {
        brix_dashboard_http_error(r, "webdav TPC failed");
        brix_dashboard_http_finish(r);
        webdav_metrics_finalize_request(r, status);
    }
}

/*
 * WHAT: copy the caller-supplied paths (local, dest, conf root) into the task
 *       context's fixed buffers.
 * WHY:  the worker thread outlives the caller's stack, so stack-allocated path
 *       buffers must be copied into the context before posting.
 * HOW:  ngx_cpystrn into the bounded t->* buffers; dest_path is optional (push).
 */
static void
tpc_thread_ctx_copy_paths(tpc_thread_ctx_t *t,
                          ngx_http_brix_webdav_loc_conf_t *conf,
                          const char *local_path, const char *dest_path)
{
    ngx_cpystrn((u_char *) t->local_path, (u_char *) local_path,
                sizeof(t->local_path));
    if (dest_path != NULL) {
        ngx_cpystrn((u_char *) t->dest_path, (u_char *) dest_path,
                    sizeof(t->dest_path));
    }
    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));
}

/*
 * webdav_tpc_post_thread_task — post pull or push curl transfer to thread pool.
 *
 * Returns NGX_DONE on success (caller must return NGX_DONE to nginx).
 * Returns NGX_DECLINED when conf->common.thread_pool is NULL (caller uses sync path).
 * Returns NGX_ERROR on allocation or post failure.
 *
 * local_path and dest_path are copied into the task context so stack-allocated
 * caller buffers are safe to reuse after this call returns.
 */
ngx_int_t
webdav_tpc_post_thread_task(ngx_http_request_t *r,
                            ngx_http_brix_webdav_loc_conf_t *conf,
                            int is_push, ngx_flag_t existed, ngx_flag_t overwrite,
                            const char *url, const char *local_path,
                            const char *dest_path,
                            ngx_array_t *transfer_headers,
                            ngx_uint_t n_streams,
                            const char *user_cert, const char *user_key)
{
    ngx_thread_task_t  *task;
    tpc_thread_ctx_t   *t;

    if (conf->common.thread_pool == NULL) {
        return NGX_DECLINED;
    }

    if (url == NULL || local_path == NULL || (!is_push && dest_path == NULL)) {
        return NGX_ERROR;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(tpc_thread_ctx_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->r               = r;
    t->conf            = conf;
    t->log             = r->connection->log;
    t->is_push         = is_push;
    t->existed         = existed;
    t->overwrite       = overwrite;
    t->url             = url;
    t->transfer_headers = transfer_headers;
    t->user_cert       = user_cert;
    t->user_key        = user_key;
    t->n_streams       = (is_push || n_streams < 1) ? 1 : n_streams;
    t->transfer_id = webdav_tpc_thread_register(r, is_push, url, local_path,
                                                dest_path);
    if (t->transfer_id == 0) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    tpc_thread_ctx_copy_paths(t, conf, local_path, dest_path);

    brix_task_bind(task, tpc_thread_func, tpc_thread_done);
    task->event.log     = r->connection->log;

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) brix_tpc_registry_remove(t->transfer_id,
                                          r->connection->log);
        return NGX_ERROR;
    }

    /* Hold a reference on the request so nginx does not destroy it while the
     * transfer runs on the background thread; tpc_thread_done finalizes it,
     * releasing this count.  Returning NGX_DONE keeps the request alive. */
    r->main->count++;
    return NGX_DONE;
}
