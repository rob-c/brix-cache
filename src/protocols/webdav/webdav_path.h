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
 * NGX_HTTP_CONFLICT (409) per RFC 4918.  op_label/log are advisory.
 * allow_internal: pass conf->common.cache_store_endpoint — non-zero on a trusted
 * cache-store endpoint permits reserved sidecar names as the destination; 0
 * everywhere else keeps them 404 (default-deny). */
ngx_int_t webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path, char *out, size_t outsz,
    ngx_flag_t allow_internal);
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


/* 1 iff `dst_path` names the same object as `src_path`, so a COPY/MOVE onto it
 * must be refused (RFC 4918 §9.8.5 / §9.9.4 -> 403).  Call it only when the
 * destination exists; both stats come from webdav_{copy,move}_probe.
 *
 * Path equality is the arm that always holds.  (dev,ino) equality additionally
 * catches a hardlink reached under a second name — but only where the backend
 * HAS inodes, and a REMOTE namespace has none: gsiftp, http, s3 and xroot never
 * fill brix_vfs_stat_t.ino/.dev, so every path on such an export stats as
 * (0,0).  An inode-only guard therefore read "source and destination are the
 * same file" for EVERY destination that already existed, and answered 403 to
 * every ordinary overwrite on every remote-backed export.  The inode arm is
 * consulted only when the backend supplied an identity to compare. */
static ngx_inline int
brix_webdav_same_object(const char *src_path, const char *dst_path,
    const struct stat *src_sb, const struct stat *dst_sb)
{
    if (ngx_strcmp(src_path, dst_path) == 0) {
        return 1;
    }
    if (src_sb->st_ino == 0 && src_sb->st_dev == 0) {
        return 0;                          /* no backend identity to compare */
    }
    return src_sb->st_ino == dst_sb->st_ino && src_sb->st_dev == dst_sb->st_dev;
}

#endif /* NGX_HTTP_BRIX_WEBDAV_PATH_H */
