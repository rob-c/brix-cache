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
#include "../compat/net_target.h"
#include "../dashboard/dashboard_tracking.h"
#include "../tpc/common/metrics.h"
#include "../aio/aio.h"          /* xrootd_task_bind */
#include "../tpc/common/registry.h"


#include <errno.h>
#include <sys/stat.h>

typedef struct {
    ngx_http_request_t                *r;
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_log_t                         *log;      /* r->connection->log snapshot */
    int                                is_push;  /* 0=pull, 1=push */
    ngx_flag_t                         existed;  /* pull: 1 if dest existed */
    ngx_flag_t                         overwrite;
    const char                        *url;      /* pool-alloc'd source or dest URL */
    char                               local_path[WEBDAV_MAX_PATH]; /* pull: tmp_path; push: src */
    char                               dest_path[WEBDAV_MAX_PATH];  /* pull: final dest; push: unused */
    char                               root_canon[WEBDAV_MAX_PATH];
    ngx_array_t                       *transfer_headers;  /* pool-alloc'd, safe while r lives */
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
    xrootd_tpc_transfer_t transfer;
    ngx_str_t             src;
    ngx_str_t             dst;

    ngx_memzero(&transfer, sizeof(transfer));

    if (is_push) {
        src.data = (u_char *) local_path;
        src.len = ngx_strlen(local_path);
        dst.data = (u_char *) url;
        dst.len = ngx_strlen(url);
        transfer.direction = XROOTD_TPC_DIR_PUSH;
    } else {
        src.data = (u_char *) url;
        src.len = ngx_strlen(url);
        dst.data = (u_char *) dest_path;
        dst.len = ngx_strlen(dest_path);
        transfer.direction = XROOTD_TPC_DIR_PULL;
    }

    transfer.protocol = XROOTD_TPC_PROTO_WEBDAV;
    transfer.src_url = src;
    transfer.dst_path = dst;
    transfer.state = XROOTD_TPC_STATE_PENDING;

    return xrootd_tpc_registry_add(&transfer, r->connection->log);
}

/*
 * Thread-pool worker body.  RUNS ON A BACKGROUND THREAD, not the nginx event
 * loop: it MUST NOT touch the event loop, send a response, or call most ngx_http
 * APIs.  Its only outputs are the t->* result fields (http_status,
 * bytes_transferred) plus the side-effecting registry/metrics/filesystem calls,
 * which are thread-safe.  tpc_thread_done (below) consumes the results back on
 * the event loop.  Performs the SSRF preflight, runs the blocking curl transfer,
 * and for pull atomically commits the temp file into place.
 */
static void
tpc_thread_func(void *data, ngx_log_t *log)
{
    tpc_thread_ctx_t *t = data;
    ngx_int_t         rc;
    int               err;

    (void) log;  /* use t->log for request-level context */

    /* SSRF preflight: resolve the remote URL and reject prohibited addresses
     * before forking curl.  Runs in the thread because getaddrinfo() blocks. */
    if (t->url != NULL) {
        xrootd_net_target_t        net_target;
        xrootd_net_target_policy_t net_policy;
        ngx_str_t                  url_str;
        char                       ssrf_err[256];

        url_str.data = (u_char *) t->url;
        url_str.len  = ngx_strlen(t->url);

        ngx_memzero(&net_policy, sizeof(net_policy));
        net_policy.require_https      = 1;
        net_policy.allow_root_scheme  = 0;
        net_policy.allow_local        = t->conf->tpc_allow_local;
        net_policy.allow_private      = t->conf->tpc_allow_private;
        net_policy.default_https_port = 443;

        if (xrootd_net_target_parse(NULL, &url_str, &net_target,
                                    ssrf_err, sizeof(ssrf_err)) != NGX_OK
            || xrootd_net_target_check_dns(&net_target, &net_policy,
                                           ssrf_err, sizeof(ssrf_err))
               != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, t->log, 0,
                          "xrootd_webdav: HTTP-TPC SSRF check blocked "
                          "transfer to %s: %s",
            t->url, ssrf_err);
            t->http_status = NGX_HTTP_FORBIDDEN;
            (void) xrootd_tpc_registry_update(t->transfer_id,
                                              t->bytes_transferred,
                                              XROOTD_TPC_STATE_ERROR,
                                              t->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                       t->is_push ? XROOTD_TPC_DIR_PUSH
                                                  : XROOTD_TPC_DIR_PULL,
                                       XROOTD_TPC_METRIC_ERROR,
                                       t->bytes_transferred, t->log);
            return;
        }
    }

    (void) xrootd_tpc_registry_update(t->transfer_id, 0,
                                      XROOTD_TPC_STATE_ACTIVE, t->log);

    if (t->is_push) {
        rc = webdav_tpc_run_curl_push(t->log, t->conf, t->url,
                                      t->local_path, t->transfer_headers,
                                      t->transfer_id);
        if (rc == NGX_OK) {
            struct stat st;
            if (stat(t->local_path, &st) == 0) {
                t->bytes_transferred = st.st_size;
            }
            (void) xrootd_tpc_registry_update(t->transfer_id,
                                              t->bytes_transferred,
                                              XROOTD_TPC_STATE_DONE,
                                              t->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                       XROOTD_TPC_DIR_PUSH,
                                       XROOTD_TPC_METRIC_SUCCESS,
                                       t->bytes_transferred, t->log);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PUSH_SUCCESS]);
            t->http_status = NGX_HTTP_CREATED;
        } else {
            (void) xrootd_tpc_registry_update(t->transfer_id,
                                              t->bytes_transferred,
                                              XROOTD_TPC_STATE_ERROR,
                                              t->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                       XROOTD_TPC_DIR_PUSH,
                                       XROOTD_TPC_METRIC_ERROR,
                                       t->bytes_transferred, t->log);
            t->http_status = rc;
        }
        return;
    }

    /* pull: run curl, then atomically commit tmp_path → dest_path */
    if (t->n_streams > 1) {
        rc = webdav_tpc_run_curl_pull_multi(t->log, t->conf, t->url,
                                             t->local_path, t->transfer_headers,
                                             t->n_streams, t->transfer_id, NULL);
    } else {
        rc = webdav_tpc_run_curl_pull(t->log, t->conf, t->url, t->local_path,
                                      t->transfer_headers, t->transfer_id);
    }
    if (rc != NGX_OK) {
        (void) xrootd_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
        (void) xrootd_tpc_registry_update(t->transfer_id,
                                          t->bytes_transferred,
                                          XROOTD_TPC_STATE_ERROR,
                                          t->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR,
                                   t->bytes_transferred, t->log);
        t->http_status = rc;
        return;
    }

    {
        struct stat st;
        if (stat(t->local_path, &st) == 0) {
            t->bytes_transferred = st.st_size;
        }
    }

    /* Atomic commit, same policy as the synchronous path in tpc.c:
     * no-overwrite -> link() (EEXIST means a racing create -> 412); overwrite ->
     * rename().  Every failure unlinks the temp so no partial file is left. */
    if (!t->overwrite) {
        if (xrootd_link_confined_canon(t->log, t->root_canon,
                                       t->local_path, t->dest_path) != 0) {
            err = errno;
            (void) xrootd_unlink_confined_canon(t->log, t->root_canon,
                                                t->local_path, 0);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
            (void) xrootd_tpc_registry_update(t->transfer_id,
                                              t->bytes_transferred,
                                              XROOTD_TPC_STATE_ERROR,
                                              t->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                       XROOTD_TPC_DIR_PULL,
                                       XROOTD_TPC_METRIC_ERROR,
                                       t->bytes_transferred, t->log);
            t->http_status = (err == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                             : NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }
        (void) xrootd_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
    } else if (xrootd_rename_confined_canon(t->log, t->root_canon,
                                            t->local_path, t->dest_path) != 0) {
        xrootd_log_safe_path(t->log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav: HTTP-TPC rename failed for: \"%s\"",
                             t->dest_path);
        (void) xrootd_unlink_confined_canon(t->log, t->root_canon,
                                            t->local_path, 0);
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
        (void) xrootd_tpc_registry_update(t->transfer_id,
                                          t->bytes_transferred,
                                          XROOTD_TPC_STATE_ERROR,
                                          t->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR,
                                   t->bytes_transferred, t->log);
        t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    (void) xrootd_tpc_registry_update(t->transfer_id, t->bytes_transferred,
                                      XROOTD_TPC_STATE_DONE, t->log);
    xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                               XROOTD_TPC_DIR_PULL,
                               XROOTD_TPC_METRIC_SUCCESS,
                               t->bytes_transferred, t->log);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_SUCCESS]);
    t->http_status = t->existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
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

    (void) xrootd_tpc_registry_remove(t->transfer_id,
                                      r->connection != NULL
                                          ? r->connection->log : t->log);

    if (status == NGX_HTTP_CREATED || status == NGX_HTTP_NO_CONTENT) {
        if (t->bytes_transferred > 0) {
            xrootd_dashboard_http_add(r,
                (ngx_atomic_int_t) t->bytes_transferred);
        }
        xrootd_dashboard_http_finish(r);
        r->headers_out.status           = (ngx_uint_t) status;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        webdav_metrics_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
    } else {
        xrootd_dashboard_http_error(r, "webdav TPC failed");
        xrootd_dashboard_http_finish(r);
        webdav_metrics_finalize_request(r, status);
    }
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
                            ngx_http_xrootd_webdav_loc_conf_t *conf,
                            int is_push, ngx_flag_t existed, ngx_flag_t overwrite,
                            const char *url, const char *local_path,
                            const char *dest_path,
                            ngx_array_t *transfer_headers,
                            ngx_uint_t n_streams)
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
    t->n_streams       = (is_push || n_streams < 1) ? 1 : n_streams;
    t->transfer_id = webdav_tpc_thread_register(r, is_push, url, local_path,
                                                dest_path);
    if (t->transfer_id == 0) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    ngx_cpystrn((u_char *) t->local_path, (u_char *) local_path,
                sizeof(t->local_path));
    if (dest_path != NULL) {
        ngx_cpystrn((u_char *) t->dest_path, (u_char *) dest_path,
                    sizeof(t->dest_path));
    }
    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));

    xrootd_task_bind(task, tpc_thread_func, tpc_thread_done);
    task->event.log     = r->connection->log;

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        (void) xrootd_tpc_registry_remove(t->transfer_id,
                                          r->connection->log);
        return NGX_ERROR;
    }

    /* Hold a reference on the request so nginx does not destroy it while the
     * transfer runs on the background thread; tpc_thread_done finalizes it,
     * releasing this count.  Returning NGX_DONE keeps the request alive. */
    r->main->count++;
    return NGX_DONE;
}
