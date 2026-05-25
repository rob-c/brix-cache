/*
 * resource.c - shared path resolution for WebDAV resource handlers.
 */

#include "webdav.h"

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

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
                                             pathsz);
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(path, sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
