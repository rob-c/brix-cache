/*
 * dashboard/vfs_browse.c — VFS export browser for the monitoring UI.
 *
 * WHAT: three admin-auth-only endpoints that browse the LOGICAL namespace of
 *       every registered export through the VFS (never raw POSIX):
 *
 *         GET /xrootd/api/v1/vfs                     the export census
 *         GET /xrootd/api/v1/vfs/files?export=&path= JSON directory listing
 *         GET /xrootd/api/v1/vfs/download?export=&path=  stream one file
 *
 * WHY:  the older /files browser (files.c) walks a HOST directory tree
 *       (xrootd_dashboard_browse_root) with raw readdir/statx — right for
 *       logs and spool dirs, wrong for storage: a pblock export's on-disk
 *       shape is catalog.db + packed blobs, and a ceph export has no host
 *       tree at all. Routing every namespace/data op through xrootd_vfs_*
 *       shows the export exactly as a client sees it, for ANY backend the
 *       registry composed (phase-62: the VFS is the sole storage truth).
 *
 * SECURITY:
 *   - Always admin-auth (ngx_http_xrootd_dashboard_check_auth) — never the
 *     anonymous tier: this surface exposes stored user data.
 *   - Opt-in: disabled (404) unless `xrootd_dashboard_vfs_browse on`.
 *   - Read-only by construction: the vctx binds with allow_write=0, so even
 *     a coding slip below cannot reach a write path.
 *   - Input path must be absolute, NUL-free, and ".."-free; the VFS then
 *     re-confines every open/stat to the export root at the kernel level
 *     (openat2 RESOLVE_IN_ROOT in the backends).
 */

#include "dashboard_http.h"
#include "dashboard_json.h"
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "protocols/shared/file_serve.h"
#include "core/http/etag.h"
#include "core/http/http_headers.h"   /* xrootd_http_source_offer (AGPL sec.13) */

#include <errno.h>
#include <jansson.h>
#include <limits.h>
#include <string.h>

#define DASHBOARD_VFS_MAX_ENTRIES 10000

/* errno → HTTP for a confined VFS namespace failure. */
static ngx_int_t
vfs_browse_status(int e)
{
    if (e == ENOENT || e == ENOTDIR) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (e == EACCES || e == EPERM || e == EXDEV || e == ELOOP) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/* Shared endpoint preamble: feature gate + admin auth + GET/HEAD only.
 * Returns NGX_OK to proceed, else the response status. */
static ngx_int_t
vfs_browse_preamble(ngx_http_request_t *r,
    ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    ngx_int_t rc;

    if (!conf->vfs_browse) {
        return NGX_HTTP_NOT_FOUND;   /* feature disabled (opt-in) */
    }
    rc = ngx_http_xrootd_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) {
        return rc;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    xrootd_http_source_offer(r);
    return NGX_OK;
}

/* Parse ?export=<uint> into a registry index. NGX_ERROR on absent/garbage/
 * out-of-range. */
static ngx_int_t
vfs_browse_get_export(ngx_http_request_t *r, ngx_uint_t *idx_out)
{
    ngx_str_t  raw;
    ngx_int_t  v;

    if (ngx_http_arg(r, (u_char *) "export", 6, &raw) != NGX_OK
        || raw.len == 0)
    {
        return NGX_ERROR;
    }
    v = ngx_atoi(raw.data, raw.len);
    if (v == NGX_ERROR || (ngx_uint_t) v >= xrootd_vfs_backend_export_count()) {
        return NGX_ERROR;
    }
    *idx_out = (ngx_uint_t) v;
    return NGX_OK;
}

/* Extract + URL-decode ?path= as an EXPORT-ABSOLUTE path ("/" default).
 * Rejects: non-absolute, embedded NUL, any ".." segment, over-long. The VFS
 * kernel confinement below is the real wall; this normalises + fails fast. */
static ngx_int_t
vfs_browse_get_path(ngx_http_request_t *r, char *out, size_t outsz)
{
    ngx_str_t   raw;
    u_char     *dst, *src;
    size_t      n, i;

    if (ngx_http_arg(r, (u_char *) "path", 4, &raw) != NGX_OK
        || raw.len == 0)
    {
        ngx_memcpy(out, "/", 2);
        return NGX_OK;
    }
    if (raw.len >= outsz) {
        return NGX_ERROR;
    }

    dst = (u_char *) out;
    src = raw.data;
    ngx_unescape_uri(&dst, &src, raw.len, 0);
    n = (size_t) (dst - (u_char *) out);
    out[n] = '\0';

    if (out[0] != '/' || strlen(out) != n) {
        return NGX_ERROR;            /* relative, or embedded NUL */
    }
    for (i = 0; i + 1 < n; i++) {
        if (out[i] == '.' && out[i + 1] == '.'
            && (i == 0 || out[i - 1] == '/')
            && (out[i + 2] == '/' || out[i + 2] == '\0'))
        {
            return NGX_ERROR;        /* ".." segment */
        }
    }
    /* strip a trailing '/' (except the root itself) for stable echo/joins */
    if (n > 1 && out[n - 1] == '/') {
        out[n - 1] = '\0';
    }
    return NGX_OK;
}

/* Join the export root and the export-absolute path into abs[]. A pure-cache
 * root of "/" must not double the slash (the cvmfs handler's rule). */
static ngx_int_t
vfs_browse_abs_path(const char *root_canon, const char *path,
    char *abs, size_t abssz)
{
    int n;

    if (root_canon[0] == '/' && root_canon[1] == '\0') {
        n = snprintf(abs, abssz, "%s", path);
    } else {
        n = snprintf(abs, abssz, "%s%s", root_canon,
                     (path[0] == '/' && path[1] == '\0') ? "" : path);
    }
    return (n > 0 && (size_t) n < abssz) ? NGX_OK : NGX_ERROR;
}

/* Bind a read-only vctx for `abs` on export `info`. */
static void
vfs_browse_ctx(ngx_http_request_t *r, const xrootd_vfs_backend_info_t *info,
    const char *abs, xrootd_vfs_ctx_t *vctx)
{
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_ROOT,
                        info->root_canon, "", /* allow_write */ 0, is_tls,
                        NULL, abs);
}

/* GET /xrootd/api/v1/vfs — the export census (index, root, backend, origin). */
ngx_int_t
ngx_http_xrootd_dashboard_vfs_exports_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    json_t     *root, *arr;
    ngx_uint_t  i, n;
    ngx_int_t   rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    rc = vfs_browse_preamble(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    root = json_object();
    arr  = json_array();
    if (root == NULL || arr == NULL) {
        if (root) { json_decref(root); }
        if (arr) { json_decref(arr); }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    n = xrootd_vfs_backend_export_count();
    for (i = 0; i < n; i++) {
        xrootd_vfs_backend_info_t  info;
        json_t                    *e;

        if (xrootd_vfs_backend_export_info(i, &info) != NGX_OK) {
            continue;
        }
        e = json_object();
        if (e == NULL) {
            continue;
        }
        json_object_set_new(e, "index",   json_integer((json_int_t) i));
        json_object_set_new(e, "root",    json_string(info.root_canon));
        json_object_set_new(e, "backend", json_string(info.backend));
        if (info.host[0] != '\0') {
            json_object_set_new(e, "origin_host", json_string(info.host));
            json_object_set_new(e, "origin_port",
                                json_integer((json_int_t) info.port));
        }
        json_object_set_new(e, "staging", info.staging ? json_true()
                                                       : json_false());
        if (json_array_append_new(arr, e) != 0) {
            continue;
        }
    }

    dashboard_json_set_schema(root);
    json_object_set_new(root, "exports", arr);
    return dashboard_json_send(r, NGX_HTTP_OK, root);
}

/* One listing entry via the VFS: kind from d_type, size/mtime from a confined
 * per-entry stat (skipped for OTHER — symlinks/specials are shown, never
 * followed). Returns NULL on alloc failure (caller skips the entry). */
static json_t *
vfs_browse_entry(ngx_http_request_t *r,
    const xrootd_vfs_backend_info_t *info, const char *abs_dir,
    const ngx_str_t *name, xrootd_vfs_dirent_kind_t kind)
{
    char               child[PATH_MAX];
    char               namez[NAME_MAX + 1];
    xrootd_vfs_ctx_t   cctx;
    xrootd_vfs_stat_t  st;
    json_t            *o;
    const char        *type;
    int                n;

    if (name->len > NAME_MAX) {
        return NULL;
    }
    ngx_memcpy(namez, name->data, name->len);
    namez[name->len] = '\0';

    ngx_memzero(&st, sizeof(st));
    if (kind != XROOTD_VFS_DT_OTHER) {
        n = snprintf(child, sizeof(child), "%s%s%s", abs_dir,
                     (abs_dir[strlen(abs_dir) - 1] == '/') ? "" : "/", namez);
        if (n <= 0 || (size_t) n >= sizeof(child)) {
            return NULL;
        }
        vfs_browse_ctx(r, info, child, &cctx);
        if (xrootd_vfs_stat(&cctx, &st) != NGX_OK) {
            ngx_memzero(&st, sizeof(st));   /* vanished mid-scan: list bare */
        }
        if (kind == XROOTD_VFS_DT_UNKNOWN) {
            kind = st.is_directory ? XROOTD_VFS_DT_DIR
                 : st.is_regular   ? XROOTD_VFS_DT_REG
                                   : XROOTD_VFS_DT_OTHER;
        }
    }
    type = (kind == XROOTD_VFS_DT_DIR) ? "dir"
         : (kind == XROOTD_VFS_DT_REG) ? "file" : "other";

    o = json_object();
    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "name",  json_string(namez));
    json_object_set_new(o, "type",  json_string(type));
    json_object_set_new(o, "size",  json_integer((json_int_t) st.size));
    json_object_set_new(o, "mtime", json_integer((json_int_t) st.mtime));
    return o;
}

/* GET /xrootd/api/v1/vfs/files?export=<i>&path=</...> */
ngx_int_t
ngx_http_xrootd_dashboard_vfs_files_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_vfs_backend_info_t  info;
    xrootd_vfs_ctx_t           vctx;
    xrootd_vfs_dir_t          *dh;
    char                       path[PATH_MAX];
    char                       abs[PATH_MAX];
    ngx_uint_t                 idx, count = 0;
    int                        err = 0, truncated = 0;
    json_t                    *root, *arr;
    ngx_int_t                  rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    rc = vfs_browse_preamble(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }
    if (vfs_browse_get_export(r, &idx) != NGX_OK
        || xrootd_vfs_backend_export_info(idx, &info) != NGX_OK
        || vfs_browse_get_path(r, path, sizeof(path)) != NGX_OK
        || vfs_browse_abs_path(info.root_canon, path, abs, sizeof(abs))
           != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    vfs_browse_ctx(r, &info, abs, &vctx);
    dh = xrootd_vfs_opendir(&vctx, &err);
    if (dh == NULL) {
        return vfs_browse_status(err);
    }

    root = json_object();
    arr  = json_array();
    if (root == NULL || arr == NULL) {
        if (root) { json_decref(root); }
        if (arr) { json_decref(arr); }
        xrootd_vfs_closedir(dh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for ( ;; ) {
        ngx_str_t                 name;
        xrootd_vfs_dirent_kind_t  kind;
        json_t                   *e;

        rc = xrootd_vfs_readdir_kind(dh, &name, &kind);
        if (rc == NGX_DONE) {
            break;
        }
        if (rc != NGX_OK) {
            break;                    /* stream error: serve what we have */
        }
        if (count >= DASHBOARD_VFS_MAX_ENTRIES) {
            truncated = 1;
            break;
        }
        e = vfs_browse_entry(r, &info, abs, &name, kind);
        if (e == NULL || json_array_append_new(arr, e) != 0) {
            continue;
        }
        count++;
    }
    xrootd_vfs_closedir(dh, r->connection->log);

    dashboard_json_set_schema(root);
    json_object_set_new(root, "export", json_integer((json_int_t) idx));
    json_object_set_new(root, "backend", json_string(info.backend));
    json_object_set_new(root, "path", json_string(path));
    json_object_set_new(root, "truncated", truncated ? json_true()
                                                     : json_false());
    json_object_set_new(root, "entries", arr);
    return dashboard_json_send(r, NGX_HTTP_OK, root);
}

/* GET /xrootd/api/v1/vfs/download?export=<i>&path=</.../file>
 * Streams via the shared VFS serve pipeline — the same path WebDAV GET uses —
 * so backend quirks (pblock's block-0-only sendfile gate, TLS memory-buffer
 * rule, ranges) are handled once. Tagged as a WEBDAV transfer for tracking:
 * it IS an HTTP GET of export data, just admin-initiated. */
ngx_int_t
ngx_http_xrootd_dashboard_vfs_download_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_vfs_backend_info_t   info;
    xrootd_vfs_ctx_t            vctx;
    xrootd_vfs_file_t          *fh;
    xrootd_vfs_stat_t           vst;
    xrootd_http_serve_opts_t    opts;
    xrootd_http_serve_result_t  result;
    char                        path[PATH_MAX];
    char                        abs[PATH_MAX];
    ngx_uint_t                  idx;
    int                         err = 0;
    ngx_int_t                   rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    rc = vfs_browse_preamble(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }
    if (vfs_browse_get_export(r, &idx) != NGX_OK
        || xrootd_vfs_backend_export_info(idx, &info) != NGX_OK
        || vfs_browse_get_path(r, path, sizeof(path)) != NGX_OK
        || (path[0] == '/' && path[1] == '\0')   /* the root is not a file */
        || vfs_browse_abs_path(info.root_canon, path, abs, sizeof(abs))
           != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    vfs_browse_ctx(r, &info, abs, &vctx);

    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &err);
    if (fh == NULL) {
        return vfs_browse_status(err);
    }
    if (xrootd_vfs_file_stat(fh, &vst) != NGX_OK || !vst.is_regular) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_NOT_FOUND;   /* only regular files are downloadable */
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto = XROOTD_XFER_PROTO_WEBDAV;
    opts.op_name    = "GET";
    opts.identity   = "dashboard-admin";
    opts.etag_flags = XROOTD_ETAG_WEAK;

    /* serve_file_ranged owns fh from here (closes it itself) */
    return xrootd_http_serve_file_ranged(r, fh, &vst, abs, &opts, &result);
}
