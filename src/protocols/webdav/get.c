/*
 * get.c - WebDAV GET with Range support, sendfile, and fd-cache fast path.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "core/compat/error_mapping.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"
#include "fs/cache/open.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "protocols/shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "protocols/root/zip/zip_http.h"   /* phase-57 W2: shared HTTP ZIP member serving */

/* GET range/bytes metrics — shared by the inline serve and the off-loop serve
 * completion (brix_http_serve_offload), so both report identically. */
static void
webdav_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result)
{
    if (result->range_result == BRIX_SERVE_RANGE_UNSATISFIED) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_UNSATISFIED]);
    } else if (result->range_result == BRIX_SERVE_RANGE_PARTIAL) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_PARTIAL]);
    } else {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_FULL]);
    }
    if (result->bytes_sent > 0) {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) result->bytes_sent);
        if (r->connection && r->connection->sockaddr) {
            if (r->connection->sockaddr->sa_family == AF_INET6) {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total,
                                         (size_t) result->bytes_sent);
            } else {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total,
                                         (size_t) result->bytes_sent);
            }
        }
    }
}

/* Re-entry trampoline for the off-event-loop cache fill: after the fill lands the
 * completion event re-runs the GET handler, which now finds a cache HIT and serves
 * it zero-copy. The fill helper carries no per-handler state (the request re-
 * resolves from r), so `data` is unused. */
static ngx_int_t
webdav_get_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return webdav_handle_get(r);
}

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static ngx_int_t
webdav_register_send_fd_cleanup(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    size_t                   path_len;
    u_char                  *name;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    path_len = ngx_strlen(path);
    name = ngx_pnalloc(r->pool, path_len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn(name, (u_char *) path, path_len + 1);

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name;
    clnf->log = r->pool->log;

    return NGX_OK;
}

static void
webdav_get_add_xrdhttp_headers(ngx_http_request_t *r, ngx_fd_t fd,
    off_t file_size, void *ud)
{
    struct stat *sb = ud;
    webdav_fadvise_willneed(r->connection->log, fd, 0, (size_t) file_size);
    xrdhttp_add_checksum_header(r, fd, sb);
    xrdhttp_add_response_headers(r, r->headers_out.status);
}

/*
 * webdav_handle_get — serve a file via HTTP GET with Range support.
 *
 * Fast path: if the fd-cache already holds an open fd for the requested URI
 * hash, the stat and open system calls are skipped entirely.  The cached fd
 * remains owned by the fd-cache; the cleanup handler registered below uses
 * NGX_INVALID_FILE so it does not close it a second time.
 *
 * Range handling: a single "bytes=start-end" or "bytes=-suffix" range is
 * parsed and served as 206 Partial Content.  Multi-range requests and
 * overlapping ranges are not supported; clients that send them receive the
 * full file (200 OK).
 *
 * ngx_http_send_header + r->header_only: after calling ngx_http_send_header(),
 * always check r->header_only.  If true, the client sent HEAD — return
 * immediately without sending a body.  The check at line ~244 handles this.
 *
 * Pool allocation: ngx_pcalloc(r->pool, ...) for ngx_buf_t and ngx_file_t —
 *   both are freed when the request pool is destroyed after the response
 *   is sent.
 *
 * Ownership of fd:
 *   - If fd came from the fd-cache (fd_from_table=1), the cleanup handler
 *     stores NGX_INVALID_FILE so the fd-cache retains ownership.
 *   - If fd was opened here (fd_from_table=0), the cleanup handler closes it.
 */
ngx_int_t
webdav_handle_get(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                path[WEBDAV_MAX_PATH];
    struct stat         sb;
    ngx_int_t           rc;
    ngx_fd_t            fd;
    ngx_fd_t            send_fd;
    ngx_http_brix_webdav_req_ctx_t *wctx;
    const char         *identity;
    brix_vfs_ctx_t    vctx;
    brix_vfs_file_t  *fh;
    brix_vfs_stat_t   vst;
    int                 vfs_err;
    ngx_uint_t          from_cache;
    const char         *cache_path;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Phase-57 W2: ZIP member access over HTTP GET.  Auth on the archive ran in
     * the access phase; serve the requested member instead of the whole file. */
    if (conf->zip_access) {
        char member[WEBDAV_MAX_PATH];
        int  zr = brix_zip_http_member_arg(r, member, sizeof(member));
        if (zr < 0) {
            return NGX_HTTP_BAD_REQUEST;
        }
        if (zr > 0) {
            return brix_zip_http_serve(r, conf->common.root_canon,
                                         conf->zip_cd_max_bytes, path, member);
        }
    }

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    {
        int is_tls = 0;
#if (NGX_HTTP_SSL)
        is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
        brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
            BRIX_PROTO_WEBDAV, conf->common.root_canon,
            conf->cache_root_canon, conf->common.allow_write, is_tls,
            (wctx != NULL) ? wctx->identity : NULL, path);
    }
    /* Route through the export's selected storage backend (NULL ⇒ default POSIX). */
    vctx.sd = brix_webdav_backend_instance(conf, r->connection->log);

    /* phase-64 SP3: serving from a socket-wire backend (a root:// primary backend
     * or a cache_store/stage_store served from one) cannot open/read on the event
     * loop. Run the whole open+read on the thread pool, materialise + sendfile.
     * NGX_DECLINED ⇒ not a socket serve; fall through to the local fast paths. */
    {
        const char              *identity =
            (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
        brix_http_serve_opts_t sopts;
        ngx_int_t                sr;

        ngx_memzero(&sopts, sizeof(sopts));
        sopts.xfer_proto = BRIX_XFER_PROTO_WEBDAV;
        sopts.op_name    = "GET";
        sopts.identity   = identity;
        sopts.etag_flags = BRIX_ETAG_WEAK;
        sopts.compress   = conf->common.compress;

        sr = brix_http_serve_offload_remote(r, vctx.sd,
            brix_vfs_export_relative(&vctx, path), path, &sopts,
            &conf->common, webdav_serve_metrics);
        if (sr == NGX_DONE) {
            return NGX_DONE;
        }
        if (sr == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* phase-64 SP2: a cache MISS whose fill reads a remote source or writes a
     * remote store would stall the worker inside brix_vfs_open's inline fill.
     * Offload it to the thread pool and re-enter (a cache hit) on completion;
     * NGX_DECLINED ⇒ no offload needed (hit / local tier) — open inline below. */
    {
        ngx_int_t fr = brix_http_cache_fill_if_needed(r, vctx.sd,
            brix_vfs_export_relative(&vctx, path), &conf->common,
            webdav_get_reenter, NULL);

        if (fr == NGX_DONE) {
            return NGX_DONE;
        }
        if (fr == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        if (vfs_err == ENOENT || vfs_err == ENOTDIR
            || vfs_err == ENAMETOOLONG)
        {
            xrdhttp_add_response_headers(r, NGX_HTTP_NOT_FOUND);
            return NGX_HTTP_NOT_FOUND;
        }

        /* EXDEV (".." escape) / ELOOP (escaping or magic symlink) are the
         * kernel RESOLVE_BENEATH confinement rejections — forbidden, never a
         * 500.  EACCES/EPERM map the same way.  Route the whole errno set
         * through the shared table so the codes stay consistent with S3. */
        if (vfs_err == EACCES || vfs_err == EPERM
            || vfs_err == EXDEV || vfs_err == ELOOP)
        {
            return NGX_HTTP_FORBIDDEN;
        }

        /* EAGAIN ⇒ a nearline (tape) recall is in flight (sd_frm/sd_cache, §9.2).
         * Answer 202 "staging" with a Retry-After so the client polls until the
         * object is recalled into the cache tier and served — never block the
         * worker for a minutes-to-hours MSS recall. */
        if (vfs_err == EAGAIN) {
            ngx_table_elt_t *ra = ngx_list_push(&r->headers_out.headers);

            if (ra != NULL) {
                ra->hash = 1;
                ngx_str_set(&ra->key, "Retry-After");
                ngx_str_set(&ra->value, "10");
            }
            r->headers_out.status           = NGX_HTTP_ACCEPTED;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, vfs_err,
                      ngx_open_file_n " \"%s\" failed", path);

        return (ngx_int_t) brix_http_errno_to_status(vfs_err);
    }

    if (brix_vfs_file_stat(fh, &vst) != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (vst.is_directory) {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_memzero(&sb, sizeof(sb));
    sb.st_size = vst.size;
    sb.st_mtime = vst.mtime;
    sb.st_ctime = vst.ctime;
    sb.st_mode = (mode_t) vst.mode;
    sb.st_ino = vst.ino;

    /* Zero-copy (sendfile) serve fd, gated on the backend's CAP_SENDFILE; a
     * non-sendfile backend returns NGX_INVALID_FILE and the dup below fails
     * closed instead of serving from a bogus descriptor. */
    fd = brix_vfs_file_sendfile_fd(fh);
    from_cache = brix_vfs_file_from_cache(fh);
    cache_path = brix_vfs_file_path(fh);

    /* XrdHttp: multi-range vector read (kXR_readv equivalent over HTTP).
     * A comma in the Range: value indicates multiple byte ranges — delegate
     * to the multipart/byteranges handler rather than the single-range path. */
    if (xrdhttp_request_is_multirange(r)) {
        send_fd = dup(fd);
        if (send_fd == NGX_INVALID_FILE) {
            brix_vfs_close(fh, r->connection->log);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (webdav_register_send_fd_cleanup(r, send_fd, path) != NGX_OK) {
            ngx_close_file(send_fd);
            brix_vfs_close(fh, r->connection->log);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        brix_vfs_close(fh, r->connection->log);
        rc = xrdhttp_handle_multipart_get(r, send_fd, &sb, 1);
        if (from_cache && rc == NGX_OK && !r->header_only) {
            (void) brix_cache_record_access(cache_path, (size_t) sb.st_size,
                                              r->connection->log);
        }
        return rc;
    }

    rc = brix_http_check_if_modified_since(r, sb.st_mtime);
    if (rc == NGX_HTTP_NOT_MODIFIED) {
        brix_vfs_close(fh, r->connection->log);
        r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return rc;
    }

    identity = (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    r->allow_ranges = 1;

    {
        brix_http_serve_opts_t   opts;
        brix_http_serve_result_t result;

        ngx_memzero(&opts, sizeof(opts));
        opts.xfer_proto      = BRIX_XFER_PROTO_WEBDAV;
        opts.op_name         = "GET";
        opts.identity        = identity;
        opts.etag_flags      = BRIX_ETAG_WEAK;
        opts.compress        = conf->common.compress;
        opts.pre_header_send = webdav_get_add_xrdhttp_headers;
        opts.pre_header_ud   = &sb;

        rc = brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
        webdav_serve_metrics(r, &result);
    }

    return rc;
}
