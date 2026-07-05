/*
 * webdav/webdav_path.h
 *
 * Path / URI / XML request-shaping utilities: the canonical confined path and
 * Destination resolvers, resolve+stat, percent-decode, Destination scheme strip,
 * XML text escaping, and the sole CORS entry point.  Split out of webdav.h so
 * the request-shaping surface is grouped by concern and individually reviewable.
 * Includes webdav.h for the shared request/config types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_PATH_H
#define NGX_HTTP_BRIX_WEBDAV_PATH_H

#include "webdav.h"

/* Path, URI, XML, and logging utilities */
/* Canonical helper (see HELPERS): url-decode r->uri, strip trailing slashes,
 * and resolve+confine under root_canon into out[outsz].  NGX_OK, else an
 * NGX_HTTP_* status (404/403/414/500/400-on-NUL). */
ngx_int_t ngx_http_brix_webdav_resolve_path(ngx_http_request_t *r,
    const char *root_canon, char *out, size_t outsz);
/* Resolve an already-decoded Destination path (COPY/MOVE target) under
 * root_canon.  Same as above but maps a non-existent parent to
 * NGX_HTTP_CONFLICT (409) per RFC 4918.  op_label/log are advisory. */
ngx_int_t webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path, char *out, size_t outsz);
/* resolve_path + stat in one call: fills path[pathsz] and, if sb != NULL,
 * sb (via the VFS layer).  NGX_OK; 404 if missing, 500 on other stat error,
 * or the resolve error.  sb fields beyond size/mtime/ctime/mode/ino are zeroed. */
ngx_int_t webdav_resolve_stat(ngx_http_request_t *r, char *path,
    size_t pathsz, struct stat *sb);
/* Percent-decode src[src_len] into NUL-terminated dst[dst_sz], rejecting
 * embedded NULs.  NGX_OK / 414 overflow / 400 NUL byte / 500. */
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);
/* Strip a leading scheme://authority from a Destination header value; on NGX_OK
 * *path_out points INTO dest_data (no copy) and *path_len_out is its length.
 * NGX_HTTP_BAD_REQUEST if the path part would be empty. */
ngx_int_t webdav_destination_extract_path(const u_char *dest_data,
    size_t dest_len, const u_char **path_out, size_t *path_len_out);
/* XML-escape a C string for response bodies (& < > " ' as entities, control
 * bytes as %XX).  Result allocated from `pool`; NULL on OOM or NULL args. */
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);
/* Sole CORS entry point (see HELPERS): emit Access-Control-* per the request
 * Origin and config.  Always NGX_OK (no/denied Origin folded to OK) except
 * NGX_ERROR on allocation failure. */
ngx_int_t webdav_add_cors_headers(ngx_http_request_t *r);

#endif /* NGX_HTTP_BRIX_WEBDAV_PATH_H */
