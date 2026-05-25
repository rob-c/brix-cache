/*
 * copy.c - WebDAV COPY handler (RFC 4918 §9.8).
 */

#include "webdav.h"
#include "fs/copy_engine.h"
#include "methods/copy_conditionals.h"
#include "../compat/http_conditionals.h"
#include "../compat/namespace_ops.h"
#include "../compat/tmp_path.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    ngx_http_request_t *r;
    ngx_log_t         *log;
    char               root_canon[WEBDAV_MAX_PATH];
    char               src_path[WEBDAV_MAX_PATH];
    char               dst_path[WEBDAV_MAX_PATH];
    mode_t             src_mode;
    ngx_flag_t         dst_existed;
    ngx_flag_t         dst_was_dir;
    ngx_flag_t         depth_infinity;
    ngx_int_t          http_status;
} webdav_copy_collection_task_t;

static ngx_int_t
webdav_copy_collection_execute(ngx_log_t *log, const char *root_canon,
    const char *src_path, const char *dst_path, mode_t src_mode,
    ngx_flag_t dst_existed, ngx_flag_t dst_was_dir,
    ngx_flag_t depth_infinity)
{
    char      tmp_path[WEBDAV_MAX_PATH];
    ngx_int_t rc;

    if (xrootd_make_tmp_path(dst_path, tmp_path, sizeof(tmp_path)) != NGX_OK) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    if (xrootd_mkdir_confined_canon(log, root_canon, tmp_path,
                                    src_mode & 0777) != 0)
    {
        if (errno == ENOENT) {
            return NGX_HTTP_CONFLICT;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    webdav_dead_props_copy(log, src_path, tmp_path);
    xrootd_ns_copy_fattrs(log, src_path, tmp_path);

    if (depth_infinity) {
        rc = webdav_copy_dir_recursive(log, root_canon, src_path, tmp_path);
    } else {
        rc = NGX_OK;
    }

    if (rc != NGX_OK) {
        (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (dst_existed && dst_was_dir) {
        if (webdav_delete_path_recursive(log, root_canon, dst_path) != NGX_OK) {
            (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (xrootd_rename_confined_canon(log, root_canon, tmp_path, dst_path) != 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav COPY: dir rename failed: \"%s\"",
                             dst_path);
        (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return dst_existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

static void
webdav_copy_collection_thread(void *data, ngx_log_t *log)
{
    webdav_copy_collection_task_t *t = data;

    (void) log;

    t->http_status = webdav_copy_collection_execute(t->log, t->root_canon,
                                                    t->src_path, t->dst_path,
                                                    t->src_mode,
                                                    t->dst_existed,
                                                    t->dst_was_dir,
                                                    t->depth_infinity);
}

static void
webdav_copy_collection_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    webdav_copy_collection_task_t *t = task->ctx;
    ngx_http_request_t            *r = t->r;
    ngx_int_t                      status = t->http_status;

    if (status == NGX_HTTP_CREATED || status == NGX_HTTP_NO_CONTENT) {
        r->headers_out.status = (ngx_uint_t) status;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                                 NGX_HTTP_LAST));
        return;
    }

    webdav_metrics_finalize_request(r, status);
}

static ngx_int_t
webdav_copy_collection_post_task(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *src_path,
    const char *dst_path, mode_t src_mode, ngx_flag_t dst_existed,
    ngx_flag_t dst_was_dir, ngx_flag_t depth_infinity)
{
    ngx_thread_task_t             *task;
    webdav_copy_collection_task_t *t;
    ngx_thread_pool_t             *pool;

    /* postconfig only visits server-level loc_conf; resolve lazily for nested
     * location blocks where conf->common.thread_pool may still be NULL. */
    pool = conf->common.thread_pool;
    if (pool == NULL) {
        static ngx_str_t default_name = ngx_string("default");
        ngx_str_t *pname = conf->common.thread_pool_name.len > 0
                           ? &conf->common.thread_pool_name : &default_name;
        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            conf->common.thread_pool = pool;
        }
    }
    if (pool == NULL) {
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_copy_collection_task_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->r = r;
    t->log = r->connection->log;
    t->src_mode = src_mode;
    t->dst_existed = dst_existed;
    t->dst_was_dir = dst_was_dir;
    t->depth_infinity = depth_infinity;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) dst_path,
                sizeof(t->dst_path));

    task->handler = webdav_copy_collection_thread;
    task->event.handler = webdav_copy_collection_done;
    task->event.data = task;
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: offloaded collection COPY to thread pool");

    r->main->count++;
    return NGX_DONE;
}

/* ---- Function: webdav_handle_copy() ----
 *
 * WHAT: Implements RFC 4918 §9.8 WebDAV COPY operation for server-side file/directory duplication within the same export root. Orchestrates the complete copy lifecycle: parses Destination/Overwrite/Depth headers, resolves both source and destination paths under root confinement, validates locks on destination, handles conditional checks (If-Match/If-None-Match), performs atomic copy via an intermediate staged temp path, then renames to final destination. Returns 201 Created when target didn't exist or 204 No Content when replacing existing resource; cleanup on failure ensures no orphaned temp files remain.
 *
 * WHY: WebDAV clients need an HTTP endpoint that can duplicate resources within the same filesystem namespace — unlike xrdcp native TPC which transfers between different servers, this COPY is local-only (same root). The tmp_path atomic rename strategy prevents partial copies from being visible to other clients; if copy fails the temp file is immediately deleted. Lock validation ensures no concurrent modifications interfere with the operation. Depth=0 means single-item copy; Depth=infinity recursively copies subdirectories (delegated to webdav_copy_dir_recursive in fs/copy_engine.c).
 *
 * HOW: Extracts and decodes Destination URI from request headers (strips scheme prefix to get filesystem path); resolves source via resolve_path() with root_canon confinement; resolves destination via webdav_resolve_destination_path(); checks both paths exist via stat(); validates locks on destination (including recursive child locks if depth=infinity); compares inode/dev numbers to reject self-copy attempt; applies Overwrite header semantics (F=don't overwrite, default=T=allow overwrite); runs copy_conditionals() for If-Match/If-None-Match; creates a staged temp file for file copies or a temp directory for collection copies; copies data via webdav_copy_file() or webdav_copy_dir_recursive(); commits temp→dst via confined rename. */
ngx_int_t
webdav_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t    *dest_hdr;
    ngx_table_elt_t    *depth_hdr;
    char                src_path[WEBDAV_MAX_PATH];
    char                dst_path[WEBDAV_MAX_PATH];
    char                dest_decoded[WEBDAV_MAX_PATH];
    const u_char       *dest_path_start;
    size_t              dest_path_len;
    struct stat         src_sb;
    struct stat         dst_sb;
    ngx_int_t           rc;
    int                 overwrite;
    int                 dst_existed;
    int                 depth_infinity = 1;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite = !xrootd_http_overwrite_forbidden(r);

    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr != NULL) {
        if (depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0') {
            depth_infinity = 0;
        }
    }

    dest_path_start = dest_hdr->value.data;
    dest_path_len = dest_hdr->value.len;
    rc = webdav_destination_extract_path(dest_path_start, dest_path_len,
                                         &dest_path_start, &dest_path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest_decoded, sizeof(dest_decoded));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                             src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(src_path, &src_sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_resolve_destination_path(r->connection->log, "COPY",
                                         conf->common.root_canon, dest_decoded,
                                         dst_path, sizeof(dst_path));
    if (rc != NGX_OK) {
        return rc;
    }

    dst_existed = (stat(dst_path, &dst_sb) == 0);

    rc = webdav_check_locks(r, dst_path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    if (dst_existed
        && src_sb.st_ino == dst_sb.st_ino
        && src_sb.st_dev == dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (dst_existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    rc = webdav_check_copy_conditionals(r, dst_path, dst_existed, &dst_sb);
    if (rc != NGX_OK) {
        return rc;
    }

    if (S_ISDIR(src_sb.st_mode)) {
        if (depth_infinity) {
            rc = webdav_copy_collection_post_task(r, conf, src_path, dst_path,
                                                  src_sb.st_mode, dst_existed,
                                                  dst_existed
                                                      && S_ISDIR(dst_sb.st_mode),
                                                  depth_infinity);
            if (rc == NGX_DONE) {
                return NGX_DONE;
            }
            if (rc == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        rc = webdav_copy_collection_execute(r->connection->log,
                                            conf->common.root_canon, src_path,
                                            dst_path, src_sb.st_mode,
                                            dst_existed,
                                            dst_existed
                                                && S_ISDIR(dst_sb.st_mode),
                                            depth_infinity);
        if (rc != NGX_HTTP_CREATED && rc != NGX_HTTP_NO_CONTENT) {
            return rc;
        }
    } else {
        /* File COPY: delegate to shared namespace_ops local-copy service.
         * Pre-delete destination directory if overwrite is enabled; rename(2)
         * cannot atomically replace a directory with a file. */
        xrootd_ns_copy_opts_t copy_opts;
        xrootd_ns_result_t    ns_res;

        if (dst_existed && S_ISDIR(dst_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->common.root_canon, dst_path);
        }

        ngx_memzero(&copy_opts, sizeof(copy_opts));
        copy_opts.overwrite     = overwrite;
        copy_opts.preserve_xattrs = 1;
        copy_opts.staged_commit = 1;

        ns_res = xrootd_ns_local_copy(r->connection->log, conf->common.root_canon,
                                      src_path, dst_path, &copy_opts);
        if (ns_res.status != XROOTD_NS_OK) {
            if (ns_res.status == XROOTD_NS_EXISTS) {
                return NGX_HTTP_PRECONDITION_FAILED;
            }
            if (ns_res.status == XROOTD_NS_NOT_FOUND) {
                return NGX_HTTP_CONFLICT;
            }
            if (ns_res.status == XROOTD_NS_TOO_LONG) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        webdav_dead_props_copy(r->connection->log, src_path, dst_path);
    }

    r->headers_out.status = dst_existed ? NGX_HTTP_NO_CONTENT
                                        : NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
