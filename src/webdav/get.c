/*
 * get.c - WebDAV GET with Range support, sendfile, and fd-cache fast path.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "../compat/etag.h"
#include "../compat/http_conditionals.h"
#include "../compat/http_file_response.h"
#include "../compat/range.h"
#include "../cache/open.h"
#include "../dashboard/dashboard_tracking.h"
#include "../fs/vfs.h"

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
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                path[WEBDAV_MAX_PATH];
    struct stat         sb;
    ngx_int_t           rc;
    ngx_fd_t            fd;
    ngx_fd_t            send_fd;
    off_t               range_start = 0;
    off_t               range_end = 0;
    off_t               send_len;
    int                 has_range = 0;
    ngx_http_xrootd_webdav_req_ctx_t *wctx;
    const char         *identity;
    xrootd_vfs_ctx_t    vctx;
    xrootd_vfs_file_t  *fh;
    xrootd_vfs_stat_t   vst;
    int                 vfs_err;
    ngx_uint_t          from_cache;
    const char         *cache_path;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&vctx, sizeof(vctx));
    vctx.pool = r->pool;
    vctx.log = r->connection->log;
    vctx.metrics_proto = XROOTD_PROTO_WEBDAV;
    vctx.root_canon = conf->common.root_canon;
    vctx.cache_root_canon = conf->cache_root_canon;
    vctx.cache_enabled = (conf->cache_root_canon[0] != '\0') ? 1 : 0;
    vctx.allow_write = conf->common.allow_write ? 1 : 0;
    vctx.resolved.resolved.data = (u_char *) path;
    vctx.resolved.resolved.len = ngx_strlen(path);
    vctx.resolved.is_confined = 1;

#if (NGX_HTTP_SSL)
    vctx.is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (wctx != NULL) {
        vctx.identity = wctx->identity;
    }

    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        if (vfs_err == ENOENT || vfs_err == ENOTDIR
            || vfs_err == ENAMETOOLONG)
        {
            xrdhttp_add_response_headers(r, NGX_HTTP_NOT_FOUND);
            return NGX_HTTP_NOT_FOUND;
        }

        if (vfs_err == EACCES || vfs_err == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, vfs_err,
                      ngx_open_file_n " \"%s\" failed", path);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (xrootd_vfs_file_stat(fh, &vst) != NGX_OK) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (vst.is_directory) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_memzero(&sb, sizeof(sb));
    sb.st_size = vst.size;
    sb.st_mtime = vst.mtime;
    sb.st_ctime = vst.ctime;
    sb.st_mode = (mode_t) vst.mode;
    sb.st_ino = vst.ino;

    fd = xrootd_vfs_file_fd(fh);
    from_cache = xrootd_vfs_file_from_cache(fh);
    cache_path = xrootd_vfs_file_path(fh);

    /* XrdHttp: multi-range vector read (kXR_readv equivalent over HTTP).
     * A comma in the Range: value indicates multiple byte ranges — delegate
     * to the multipart/byteranges handler rather than the single-range path. */
    if (xrdhttp_request_is_multirange(r)) {
        send_fd = dup(fd);
        if (send_fd == NGX_INVALID_FILE) {
            xrootd_vfs_close(fh, r->connection->log);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (webdav_register_send_fd_cleanup(r, send_fd, path) != NGX_OK) {
            ngx_close_file(send_fd);
            xrootd_vfs_close(fh, r->connection->log);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        xrootd_vfs_close(fh, r->connection->log);
        rc = xrdhttp_handle_multipart_get(r, send_fd, &sb, 1);
        if (from_cache && rc == NGX_OK && !r->header_only) {
            (void) xrootd_cache_record_access(cache_path, (size_t) sb.st_size,
                                              r->connection->log);
        }
        return rc;
    }

    rc = xrootd_http_check_if_modified_since(r, sb.st_mtime);
    if (rc == NGX_HTTP_NOT_MODIFIED) {
        xrootd_vfs_close(fh, r->connection->log);
        r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        xrootd_vfs_close(fh, r->connection->log);
        return rc;
    }

    {
        xrootd_http_range_t rng;
        xrootd_http_parse_range(
            r->headers_in.range ? r->headers_in.range->value.data : NULL,
            r->headers_in.range ? r->headers_in.range->value.len : 0,
            sb.st_size, &rng);

        if (rng.present && !rng.satisfiable) {
            xrootd_vfs_close(fh, r->connection->log);
            XROOTD_WEBDAV_METRIC_INC(
                range_total[XROOTD_WEBDAV_RANGE_UNSATISFIED]);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }

        range_start = rng.start;
        range_end   = rng.end;
        send_len    = (sb.st_size > 0) ? (range_end - range_start + 1) : 0;
        has_range   = rng.present;
    }

    if (has_range) {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_PARTIAL]);
    } else {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_FULL]);
    }

    if (send_len > 0) {
        webdav_fadvise_willneed(r->connection->log, fd, range_start,
                                (size_t) send_len);
    }

    r->allow_ranges = 1;

    rc = xrootd_http_set_file_headers(r, sb.st_mtime, sb.st_size, send_len,
                                      NULL,
                                      XROOTD_ETAG_WEAK,
                                      has_range, range_start, range_end);
    if (rc != NGX_OK) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* XrdHttp: add Digest: checksum header if the client requested one via
     * ?xrd.want.cksum=<algo>.  Computed inline before header flush. */
    xrdhttp_add_checksum_header(r, fd, &sb);

    /* XrdHttp: add X-Xrootd-Requuid / X-Xrootd-Status response headers. */
    xrdhttp_add_response_headers(r, r->headers_out.status);

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    identity = (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    (void) xrootd_dashboard_http_start_identity(r, path, identity, "",
        XROOTD_XFER_PROTO_WEBDAV, XROOTD_XFER_DIR_READ, "GET",
        (int64_t) send_len);

    send_fd = dup(fd);
    if (send_fd == NGX_INVALID_FILE) {
        xrootd_vfs_close(fh, r->connection->log);
        xrootd_dashboard_http_error(r, "webdav GET dup failed");
        xrootd_dashboard_http_finish(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    xrootd_vfs_close(fh, r->connection->log);

    rc = xrootd_http_send_file_range(r, send_fd, path, range_start, send_len, 1);
    if (rc == NGX_ERROR) {
        xrootd_dashboard_http_error(r, "webdav GET send failed");
        xrootd_dashboard_http_finish(r);
        return rc;
    }
    if (r->header_only) {
        xrootd_dashboard_http_finish(r);
        return rc;
    }

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) send_len);
    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) send_len);
    if (from_cache && send_len > 0) {
        (void) xrootd_cache_record_access(cache_path, (size_t) send_len,
                                          r->connection->log);
    }

    /* Track per-IP-version bytes for this GET body transfer. */
    if (r->connection && r->connection->sockaddr) {
        switch (r->connection->sockaddr->sa_family) {
        case AF_INET6:
            XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) send_len);
            break;
        default:
            XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) send_len);
            break;
        }
    }

    return rc;
}
