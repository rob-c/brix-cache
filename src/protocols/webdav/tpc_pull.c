/*
 * tpc_pull.c - HTTP-TPC COPY staged pull execution for the WebDAV module.
 *
 * WHAT: Owns the pull direction of HTTP-TPC once the request has been parsed and
 *       authorized: confined-target probing/preparation, the atomic-commit staged
 *       temp file, the three execution tiers (202-streaming marker, thread-pool
 *       task, synchronous curl), the link-vs-rename commit, and success/error
 *       finalisation with registry, dashboard, metric, and audit-ledger updates.
 * WHY:  Split from tpc.c (which was over the 500-line cap) so the tiered pull
 *       state machine — the most intricate part of the COPY path — is grouped and
 *       individually reviewable, separate from the dispatcher, request parsing,
 *       and push handling.
 * HOW:  webdav_tpc_prepare_pull_target, webdav_tpc_pull_start_accounting, and
 *       webdav_tpc_pull_execute (declared in tpc_internal_split.h) are called by
 *       the COPY dispatcher in tpc.c in the same order as before. All the internal
 *       probe/url/tier/commit/finish helpers stay static here. Shared request
 *       helpers (authorize, register, session-xfer note, dashboard identity) live
 *       in tpc.c and are reached through the split header. No behaviour change: the
 *       first tier that does not return NGX_DECLINED owns the response, and every
 *       error path aborts the staged temp file so a failed pull never leaves a
 *       partial file behind.
 */

#include "tpc_internal_split.h"

#include "webdav.h"
#include "tpc_user_proxy.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_probe (confined stat via the VFS seam) */
#include "core/http/http_headers.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/sesslog/sesslog_ngx.h"
#include "fs/xfer/xfer.h"     /* unified transfer audit ledger (kind=tpc) */
#include "tpc/common/auth.h"
#include "tpc/common/metrics.h"
#include "tpc/common/registry.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Confined no-follow stat of `path` through the VFS probe, projected into the
 * struct stat fields the TPC handler reads (mode for the dir check, size for the
 * dashboard/registry/ledger). Non-metered. NGX_OK / NGX_DECLINED (errno kept). */
static ngx_int_t
webdav_tpc_probe(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path, struct stat *sb)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    brix_vfs_ctx_t   vctx;
    brix_vfs_stat_t  vst;
    int                is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK) {
        return NGX_DECLINED;
    }
    ngx_memzero(sb, sizeof(*sb));
    sb->st_mode  = (mode_t) vst.mode;
    sb->st_size  = vst.size;
    sb->st_mtime = vst.mtime;
    return NGX_OK;
}

/*
 * Extract just the path component of a (possibly scheme-qualified) URL for use
 * as an authorization scope, e.g. "https://host/a/b" -> "/a/b".
 * `out` points into the caller's `url` buffer (no copy); defaults to "/" when
 * the URL has no path.  Used to scope-check the remote endpoint of a TPC.
 */
static void
webdav_tpc_url_path(const char *url, ngx_str_t *out)
{
    const char *scheme;
    const char *path;

    out->data = (u_char *) "/";   /* default scope when URL has no path */
    out->len = 1;

    if (url == NULL) {
        return;
    }

    /* If "://" is present, the path is the first '/' after it; otherwise the
     * first '/' in the whole string. */
    scheme = strstr(url, "://");
    path = scheme != NULL ? strchr(scheme + 3, '/') : strchr(url, '/');
    if (path == NULL || *path == '\0') {
        return;
    }

    out->data = (u_char *) path;
    out->len = ngx_strlen(path);
}

ngx_int_t
webdav_tpc_prepare_pull_target(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    ngx_flag_t                       overwrite = pl->overwrite;
    char                            *path = pl->path;
    size_t                           path_len = pl->path_len;
    struct stat                     *sb = pl->sb;
    brix_staged_file_t              *staged = pl->staged;
    ngx_int_t rc;
    ngx_str_t src_scope;
    ngx_str_t dst_scope;

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                           path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    pl->existed = (webdav_tpc_probe(r, conf, path, sb) == NGX_OK) ? 1 : 0;
    if (pl->existed && S_ISDIR(sb->st_mode)) {
        return NGX_HTTP_CONFLICT;
    }
    if (pl->existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    webdav_tpc_url_path(source_url, &src_scope);
    dst_scope = r->uri;
    rc = webdav_tpc_authorize(r, &src_scope, &dst_scope);
    if (rc != NGX_OK) {
        return rc;
    }

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = conf->common.root_canon,
            .final_path = path,
            .open_flags = O_WRONLY,
            .mode       = 0600,
            .attempts   = 16,
        };
        if (brix_staged_open(r->connection->log, &oreq, staged) != NGX_OK) {
            return errno == ENAMETOOLONG ? NGX_HTTP_REQUEST_URI_TOO_LARGE
                                         : NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    ngx_close_file(staged->fd);
    staged->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

void
webdav_tpc_pull_start_accounting(ngx_http_request_t *r, const char *path,
    const char *source_url)
{
    (void) brix_dashboard_http_start_identity(r, path,
        webdav_dashboard_identity(r), "", BRIX_XFER_PROTO_WEBDAV,
        BRIX_XFER_DIR_TPC, "TPC_PULL", -1);
    brix_dashboard_http_tpc_remote(r, source_url, 0, 0);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_STARTED]);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_STARTED, 0, r->connection->log);
}

static ngx_int_t
webdav_tpc_pull_marker_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_uint_t                       n_streams = pl->n_streams;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_flag_t                       existed = pl->existed;
    ngx_int_t rc;
    uint64_t  transfer_id;

    if (conf->tpc_marker_interval <= 0) {
        return NGX_DECLINED;
    }
    transfer_id = webdav_tpc_register_transfer(r, BRIX_TPC_DIR_PULL,
                                               source_url, path, 0);
    if (transfer_id == 0) {
        brix_dashboard_http_error(r, "webdav TPC registry full");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    rc = webdav_tpc_marker_start(r, conf, n_streams, source_url,
                                 staged->tmp_path, path, 1, overwrite, existed,
                                 transfer_headers, transfer_id,
                                 pl->user_cert, pl->user_key);
    if (rc == NGX_DECLINED) {
        (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
        return NGX_DECLINED;
    }
    if (rc != NGX_DONE) {
        (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
        brix_dashboard_http_error(r, "webdav TPC marker start failed");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }
    return NGX_DONE;
}

static ngx_int_t
webdav_tpc_pull_thread_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_uint_t                       n_streams = pl->n_streams;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_flag_t                       existed = pl->existed;
    ngx_int_t rc = webdav_tpc_post_thread_task(r, conf, 0, existed, overwrite,
                                               source_url, staged->tmp_path,
                                               path, transfer_headers,
                                               n_streams, pl->user_cert,
                                               pl->user_key);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }
    if (rc != NGX_DONE) {
        brix_dashboard_http_error(r, "webdav TPC pull task post failed");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }
    return NGX_DONE;
}

static ngx_int_t
webdav_tpc_pull_sync_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_int_t rc;

    pl->transfer_id = webdav_tpc_register_transfer(r, BRIX_TPC_DIR_PULL,
                                                   source_url, path, 0);
    if (pl->transfer_id == 0) {
        brix_dashboard_http_error(r, "webdav TPC registry full");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    rc = webdav_tpc_run_curl_pull(r->connection->log, conf, source_url,
                                  staged->tmp_path, transfer_headers,
                                  pl->transfer_id, pl->user_cert, pl->user_key);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    (void) brix_tpc_registry_update(pl->transfer_id, 0, BRIX_TPC_STATE_ERROR,
                                    r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_ERROR, 0, r->connection->log);
    (void) brix_tpc_registry_remove(pl->transfer_id, r->connection->log);
    brix_dashboard_http_error(r, "webdav TPC pull failed");
    brix_dashboard_http_finish(r);
    brix_staged_abort(r->connection->log, conf->common.root_canon, staged, 1);
    brix_xfer_finish(BRIX_XFER_TPC, "in", path, NULL, 0,
                     BRIX_XFER_SRC_ERR, 0, r->connection->log);
    webdav_tpc_note_client_copy_xfer(r, 0, -1);
    return rc;
}

static ngx_int_t
webdav_tpc_commit_pulled_file(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    uint64_t                         transfer_id = pl->transfer_id;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_int_t status;

    if (!overwrite) {
        if (brix_link_confined_canon(r->connection->log, conf->common.root_canon,
                                     staged->tmp_path, path) == 0)
        {
            brix_staged_abort(r->connection->log, conf->common.root_canon,
                              staged, 1);
            return NGX_OK;
        }
        status = (errno == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                   : NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (brix_staged_commit(r->connection->log, conf->common.root_canon,
                                  staged, path) == NGX_OK) {
        return NGX_OK;
    } else {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                           "brix_webdav: HTTP-TPC rename failed for: \"%s\"",
                           path);
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
    brix_dashboard_http_error(r, "webdav TPC pull commit failed");
    brix_dashboard_http_finish(r);
    brix_staged_abort(r->connection->log, conf->common.root_canon, staged, 1);
    (void) brix_tpc_registry_update(transfer_id, 0, BRIX_TPC_STATE_ERROR,
                                    r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_ERROR, 0, r->connection->log);
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    return status;
}

static ngx_int_t
webdav_tpc_finish_pull_success(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *path = pl->path;
    struct stat                     *sb = pl->sb;
    uint64_t                         transfer_id = pl->transfer_id;
    ngx_flag_t                       existed = pl->existed;
    off_t completed_bytes = 0;

    if (webdav_tpc_probe(r, conf, path, sb) == NGX_OK) {
        completed_bytes = sb->st_size;
        brix_dashboard_http_add(r, (ngx_atomic_int_t) sb->st_size);
        (void) brix_tpc_registry_update(transfer_id, sb->st_size,
                                        BRIX_TPC_STATE_DONE,
                                        r->connection->log);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                                 BRIX_TPC_METRIC_SUCCESS, (size_t) sb->st_size,
                                 r->connection->log);
    } else {
        (void) brix_tpc_registry_update(transfer_id, 0, BRIX_TPC_STATE_DONE,
                                        r->connection->log);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                                 BRIX_TPC_METRIC_SUCCESS, 0,
                                 r->connection->log);
    }
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    brix_dashboard_http_finish(r);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_SUCCESS]);
    brix_xfer_finish(BRIX_XFER_TPC, "in", path, NULL, (size_t) completed_bytes,
                     BRIX_XFER_OK, 0, r->connection->log);
    webdav_tpc_note_client_copy_xfer(r, completed_bytes,
        completed_bytes > 0 ? (int64_t) completed_bytes : -1);
    return webdav_send_no_body(r, existed ? NGX_HTTP_NO_CONTENT
                                          : NGX_HTTP_CREATED);
}

/* ---- Run the staged pull to completion across the three execution tiers ----
 *
 * WHAT: Executes the prepared pull described by pl, then commits and finalises it.
 *       Returns the terminal NGX_HTTP_* / NGX_OK status from whichever tier or
 *       stage produced it.
 *
 * WHY:  Isolates the tiered pull-execute + commit + finish sequence from the COPY
 *       orchestrator so each is separately reviewable. Behaviour is unchanged: the
 *       first tier that does not return NGX_DECLINED owns the response, and any
 *       commit/finish error path aborts the staged temp file so a failed pull never
 *       leaves a partial file behind.
 *
 * HOW:  Pull executes via the first available of three tiers:
 *          (1) 202-streaming marker path when tpc_marker_interval > 0: async
 *              transfer that dribbles Performance-Marker lines to the client.
 *          (2) thread-pool task when a thread pool is configured.
 *          (3) synchronous curl (final fallback) that blocks the worker.
 *       Each tier returns NGX_DECLINED to mean "not applicable, try the next".
 *       1. Try the marker tier; return its status unless NGX_DECLINED.
 *       2. Try the thread tier; return its status unless NGX_DECLINED.
 *       3. Run the synchronous tier; return on error.
 *       4. Commit the staged temp file (link for no-overwrite, rename for
 *          overwrite); return on error.
 *       5. Finish with success accounting and the final response.
 */
ngx_int_t
webdav_tpc_pull_execute(webdav_tpc_pull_ctx_t *pl)
{
    ngx_int_t rc;

    rc = webdav_tpc_pull_marker_exec(pl);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = webdav_tpc_pull_thread_exec(pl);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = webdav_tpc_pull_sync_exec(pl);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_tpc_commit_pulled_file(pl);
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_tpc_finish_pull_success(pl);
}
