/*
 * methods_basic.c - OPTIONS and HEAD handlers.
 *
 * WHAT: Implements HTTP OPTIONS and HEAD responses for WebDAV resources. OPTIONS advertises supported DAV capabilities (version 1+2) and method Allow list derived from write permission configuration. HEAD returns resource metadata without body transfer. (PROPPATCH lives in the sibling methods_proppatch.c.)
 *
 * WHY: HTTP OPTIONS is required for pre-flight CORS validation (webdav_add_cors_headers integration) and DAV capability discovery. RFC 4918 §5.3 requires OPTIONS responses to include Allow header listing enabled methods. HEAD provides lightweight resource metadata access without body transfer overhead — essential for fd-cache optimization in GET operations (avoiding full file read).
 *
 * HOW: OPTIONS handler sets DAV: "1, 2" header, constructs Allow list from conf->common.allow_write (read-only vs write-enabled), pushes MS-Author-Via: "DAV" header for Microsoft client compatibility, sends via ngx_http_send_special with NGX_HTTP_LAST (no body). HEAD handler uses webdav_resolve_stat composition helper for path+stat, sets Content-Length based on file size (0 for directories), last_modified_time, allow_ranges flag (disabled for directories), Content-Type (httpd/unix-directory vs application/octet-stream), and optional ETag via webdav_add_etag.
 */

#include "webdav.h"
#include "fs/vfs/vfs.h"   /* confined read-open for the Want-Digest checksum */
#include "auth/impersonate/lifecycle.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/http/http_file_response.h"
#include "core/http/http_xml.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"

/*
 * WHAT: Handle HTTP OPTIONS request — advertise DAV capabilities (version 1+2) and method Allow list for this location.
 *
 * WHY: RFC 4918 §5.3 requires OPTIONS responses to include DAV header listing supported versions and Allow header listing enabled methods. CORS pre-flight validation depends on OPTIONS response (webdav_add_cors_headers integration). MS-Author-Via: "DAV" header enables Microsoft Office client compatibility for WebDAV-based document storage workflows.
 *
 * HOW: Set status 200 OK with zero Content-Length, push DAV: "1, 2" header (DAV version 1 and extension), construct Allow list from conf->common.allow_write flag (read-only: OPTIONS+GET+HEAD+PROPFIND; write-enabled: adds PUT+DELETE+MKCOL+MOVE+COPY), push MS-Author-Via: "DAV" for Microsoft client compatibility. Send headers via ngx_http_send_header() then complete with ngx_http_send_special(r, NGX_HTTP_LAST) — no body required for OPTIONS response.
 */
ngx_int_t
webdav_handle_options(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_table_elt_t                   *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1, 2, access-control");

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "DASL");
    ngx_str_set(&h->value, "<DAV:basicsearch>");

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    if (brix_http_operation_allow_header(r->pool,
            brix_webdav_operations, brix_webdav_operations_count,
            BRIX_WEBDAV_ALLOW_FLAGS(conf),
            &h->value) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "MS-Author-Via");
    ngx_str_set(&h->value, "DAV");

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * WHAT: Handle HTTP HEAD request — return resource metadata headers without body transfer. Uses webdav_resolve_stat composition helper for path+stat lookup.
 *
 * WHY: HEAD provides lightweight resource metadata access without full file read overhead — essential for fd-cache optimization in GET operations (avoiding expensive stat+open syscall pairs when cache already holds valid fd). Also enables pre-flight content length validation before body transfer decisions. The send_body parameter controls whether to proceed with body generation after header response (used by PROPFIND/PROPPATCH integration paths).
 *
 * HOW: Resolve path + stat via webdav_resolve_stat composition helper, set Content-Length based on file type (0 for directories, st_size for files), last_modified_time from sb.st_mtime, allow_ranges flag (disabled for directories per RFC 7233 §14.1). Set Content-Type (httpd/unix-directory vs application/octet-stream). Add ETag via webdav_add_etag only for non-directories. Send headers via ngx_http_send_header() — if send_body=0 or r->header_only=1, complete with NGX_HTTP_LAST without body transfer; otherwise return NGX_OK allowing downstream body generation.
 */
/*
 * WHAT: Set the resource-metadata response headers (status, content length,
 * last-modified, range support, Content-Type) for a stat'd HEAD/GET target.
 *
 * WHY: The status/length/type decision differs only by file-vs-directory and is
 * shared verbatim by the HEAD orchestrator; isolating it keeps the caller flat
 * and puts the directory-vs-file branching in one nameable place.
 *
 * HOW: Directories advertise zero length, no ranges, and the WebDAV
 * "httpd/unix-directory" Content-Type; regular files advertise their size,
 * range support, and defer Content-Type to the nginx types{} block. Returns
 * NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR on header-list allocation failure.
 */
static ngx_int_t
webdav_head_emit_metadata(ngx_http_request_t *r, const struct stat *sb)
{
    ngx_table_elt_t *h;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = S_ISDIR(sb->st_mode) ? 0 : sb->st_size;
    r->headers_out.last_modified_time = sb->st_mtime;
    r->allow_ranges = S_ISDIR(sb->st_mode) ? 0 : 1;

    if (S_ISDIR(sb->st_mode)) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Type");
        ngx_str_set(&h->value, "httpd/unix-directory");
        return NGX_OK;
    }

    ngx_http_set_content_type(r);  /* uses nginx types{} block */
    return NGX_OK;
}

/*
 * WHAT: Inject the RFC 3230 Digest: header for a HEAD request that carried a
 * Want-Digest: (XrdClHttp checksum pre-flight), doing nothing otherwise.
 *
 * WHY: Extracting the checksum branch removes the deepest nesting from the HEAD
 * handler. The file is opened only when a checksum was actually requested, via
 * the same confined VFS read open GET uses, so the Digest reflects exactly the
 * bytes GET would serve (including an in-export symlink target) and repeated
 * HEADs for one file stay cheap through the xattr cache.
 *
 * HOW: Return early unless the request context carries a want_cksum. Build a
 * metered, impersonation-aware VFS read context (mirroring GET), open the
 * resolved path, add the checksum header from the fd, and close. Open failure
 * is non-fatal (no Digest emitted). Returns nothing — Digest emission is
 * best-effort per the RFC.
 */
static void
webdav_head_emit_digest(ngx_http_request_t *r, const char *path,
    const struct stat *sb)
{
    xrdhttp_req_ctx_t *ctx;
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    brix_vfs_ctx_t   vctx;
    brix_vfs_file_t *fh;
    int              vfs_err = 0;
    int              is_tls  = 0;

    if (S_ISDIR(sb->st_mode)) {
        return;
    }

    ctx = xrdhttp_get_ctx(r);
    if (ctx == NULL || !ctx->want_cksum[0]) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    /* Open the same way GET does (confined VFS read open) so the Digest
     * reflects exactly the bytes a GET would serve — including an
     * in-export symlink target. Metered + impersonation-aware. */
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);

    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh != NULL) {
        (void) xrdhttp_add_checksum_header(r, brix_vfs_file_fd(fh), sb);
        brix_vfs_close(fh, r->connection->log);
    }
}

ngx_int_t
webdav_handle_head(ngx_http_request_t *r, int send_body)
{
    char                               path[WEBDAV_MAX_PATH];
    struct stat                        sb;
    ngx_int_t                          rc;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_head_emit_metadata(r, &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!S_ISDIR(sb.st_mode)) {
        rc = brix_http_add_etag_header(r, sb.st_mtime, sb.st_size,
                                         BRIX_ETAG_WEAK, 1);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* Inject Digest: header for Want-Digest: requests (RFC 3230 / XrdClHttp).
     * Opens the file only when a checksum was actually requested, uses xattr
     * cache so repeated HEAD requests for the same file are cheap. */
    webdav_head_emit_digest(r, path, &sb);

    ngx_http_send_header(r);

    if (!send_body || r->header_only) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    return NGX_OK;
}
