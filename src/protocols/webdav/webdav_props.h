/*
 * webdav/webdav_props.h
 *
 * Dead WebDAV properties (persisted as filesystem extended attributes) —
 * PROPPATCH set/remove, PROPFIND value/empty/enumerate, the protected-DAV guard,
 * and COPY/MOVE property carry-over — plus the low-level file I/O helpers
 * (readahead hint, full write, spooled-file copy) used by the PUT/copy paths.
 * Split out of webdav.h so these surfaces are grouped by concern and
 * individually reviewable.  Includes webdav.h for the shared request types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_PROPS_H
#define NGX_HTTP_BRIX_WEBDAV_PROPS_H

#include "webdav.h"

/* Dead WebDAV properties persisted as filesystem extended attributes.
 * `xml` for set() must be already-escaped, well-formed XML — it is stored and
 * echoed back verbatim.  ns/local identify the property (namespace URI + local
 * name); head/tail are an ngx_chain_t accumulator for response XML. */
/* PROPPATCH set: store xml[xml_len] as the property's xattr value.  NGX_OK;
 * NGX_ERROR (errno ENAMETOOLONG if the name/value is over the cap). */
ngx_int_t webdav_dead_prop_set(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, const char *xml, size_t xml_len);
/* PROPPATCH remove: delete the property's xattr.  Idempotent (absent -> NGX_OK). */
ngx_int_t webdav_dead_prop_remove(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local);
/* PROPFIND: if the named property exists, append its stored XML and set *found=1;
 * a missing property is NGX_OK with *found=0 (caller reports 404 in-multistatus).
 * NGX_ERROR only on a real fault. */
ngx_int_t webdav_dead_prop_append_value(ngx_http_request_t *r,
    const char *path, const char *ns, const char *local,
    ngx_chain_t **head, ngx_chain_t **tail, ngx_flag_t *found);
/* PROPFIND propname: append an empty self-closing element for one name.
 * NGX_OK / NGX_ERROR. */
ngx_int_t webdav_dead_prop_append_empty(ngx_http_request_t *r,
    const char *ns, const char *local, ngx_chain_t **head,
    ngx_chain_t **tail);
/* PROPFIND allprop/propname: enumerate every dead property on `path`, appending
 * name (names_only) or name+value.  NGX_OK (incl. none present) / NGX_ERROR. */
ngx_int_t webdav_dead_props_append_all(ngx_http_request_t *r,
    const char *path, ngx_chain_t **head, ngx_chain_t **tail,
    ngx_flag_t names_only);
/* True if `local` is a protected (server-managed) DAV: property that PROPPATCH
 * may not touch; the caller has already matched the DAV: namespace, so this is
 * effectively a non-NULL guard returning 1. */
ngx_flag_t webdav_dead_prop_is_protected_dav(const char *local);
/* Copy all dead properties from src to dst (so they travel with COPY/MOVE);
 * best-effort, no return value. */
void webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst);

/* File I/O helpers */
/* Advisory POSIX_FADV_WILLNEED readahead hint; best-effort, no-op if
 * unsupported or len==0. */
void webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset,
    size_t len);
/* write(2) the whole buffer, retrying EINTR/short writes.  NGX_OK / NGX_ERROR
 * (errno set; EIO on a 0-byte write). */
ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len, off_t offset);
/* Copy a spooled PUT temp file (buf->file) into dst_fd, preferring zero-copy
 * copy_file_range with a pread+write fallback.  `scratch` is an optional reused
 * fallback buffer slot (may be ignored).  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, const char *path, u_char **scratch);

#endif /* NGX_HTTP_BRIX_WEBDAV_PROPS_H */
