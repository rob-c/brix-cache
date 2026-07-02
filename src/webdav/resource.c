/*
 * resource.c - shared path resolution for WebDAV resource handlers.
 */

#include "webdav.h"
#include "fs/vfs_backend_registry.h"
#include "fs/vfs.h"

#include <errno.h>

/**
 * WHAT: Resolve the request URI to a canonicalised filesystem path then perform
 * stat(2) on the result — combines ngx_http_xrootd_webdav_resolve_path() and
 * stat(2) into a single helper for handlers needing both path and metadata.
 *
 * Calls the primary path resolver (ngx_http_xrootd_webdav_resolve_path()) to convert
 * r->uri into an absolute canonicalised path within root_canon, then immediately calls
 * stat(2) on that path to populate sb with file metadata. Returns NGX_OK if both steps
 * succeed; NGX_HTTP_NOT_FOUND (404) if the resolved path doesn't exist (ENOENT); any
 * other stat error returns NGX_HTTP_INTERNAL_SERVER_ERROR (500). The caller-supplied
 * path buffer must be at least WEBDAV_MAX_PATH bytes to accommodate the decoded and
 * canonicalised output. Used by GET, HEAD, PROPFIND handlers that need both the
 * resolved path and file metadata in a single atomic operation.
 *
 * WHY: Many WebDAV methods (GET, HEAD, PROPFIND) require both the resolved path AND
 * file metadata — calling resolve_path separately then stat would duplicate error
 * handling logic across multiple handler files. This helper provides an atomic
 * two-step operation with consistent error mapping. Per AGENTS.md INVARIANT #4: all
 * wire paths must go through resolve_path() before any filesystem operations — this
 * function enforces that invariant by embedding the resolution step into stat itself.
 * Security invariant: resolved path is confined to root_canon, preventing ../ traversal
 * attacks even if client supplies malicious URI components.
 *
 * HOW: Retrieves WebDAV location configuration via ngx_http_get_module_loc_conf(). Calls
 * ngx_http_xrootd_webdav_resolve_path() first — if resolution fails (invalid URI, outside
 * root_canon), returns immediately with that error code. On successful resolution calls
 * stat(2) on the resolved path — maps ENOENT to 404, all other errors to 500. Returns NGX_OK
 * only when both resolution and stat succeed. Caller must ensure path buffer has sufficient
 * capacity (WEBDAV_MAX_PATH). sb pointer may be NULL if caller needs path only without metadata. */
ngx_int_t
webdav_resolve_stat(ngx_http_request_t *r, char *path, size_t pathsz,
    struct stat *sb)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          rc;
    xrootd_vfs_ctx_t                   vctx;
    xrootd_vfs_stat_t                  vst;
    ngx_http_xrootd_webdav_req_ctx_t  *wctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
                                             pathsz);
    if (rc != NGX_OK) {
        return rc;
    }

    if (sb == NULL) {
        return NGX_OK;
    }

    ngx_memzero(&vctx, sizeof(vctx));
    vctx.rootfd = -1;
    vctx.pool = r->pool;
    vctx.log = r->connection->log;
    vctx.metrics_proto = XROOTD_PROTO_WEBDAV;
    vctx.root_canon = conf->common.root_canon;
    /* Hand-rolled ctx (not xrootd_vfs_ctx_init): resolve the storage backend so
     * stat routes through the driver on a non-POSIX export. */
    vctx.sd = xrootd_vfs_backend_resolve(conf->common.root_canon,
                                         r->connection->log);
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

    if (xrootd_vfs_stat(&vctx, &vst) != NGX_OK) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(sb, sizeof(*sb));
    sb->st_size = vst.size;
    sb->st_mtime = vst.mtime;
    sb->st_ctime = vst.ctime;
    sb->st_mode = (mode_t) vst.mode;
    sb->st_ino = vst.ino;

    return NGX_OK;
}
