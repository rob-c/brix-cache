#ifndef XROOTD_WEBDAV_UTIL_URI_H
#define XROOTD_WEBDAV_UTIL_URI_H

#include "webdav/webdav.h"

/*
 * webdav_urldecode — percent-decode a URI component, rejecting embedded null bytes.
 *
 * WHAT: Decodes a percent-encoded URI string (e.g. `/data/my%20file.root`) into a
 *       plain-text destination buffer. Rejects embedded null bytes per HTTP semantics.
 *
 * WHY: WebDAV clients send URIs in percent-encoded form. Null bytes in URIs indicate
 *      malformed input and must produce a 400 response rather than truncating the
 *      decoded string (which would cause incorrect path matching).
 *
 * HOW: Wraps `xrootd_http_urldecode()` from src/compat/uri.h with nginx status-code
 *      mapping. Overflow → 414, null byte → 400, other → 500. The compat function
 *      is called with XROOTD_URLDECODE_REJECT_NUL to enforce null-byte rejection.
 *
 * RETURN: NGX_OK on success; nginx error code on failure (never raw compat codes).
 */
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);

/*
 * webdav_destination_extract_path — strip the scheme://authority prefix from
 * a WebDAV Destination header value, returning a pointer into the original
 * buffer at the start of the path component.
 *
 * RFC 4918 §8.3 requires the Destination header to be an absolute URI but
 * allows the path-only form too.  Both COPY and MOVE must handle both cases.
 *
 * On success *path_out points into [dest_data, dest_data+dest_len) and
 * *path_len_out is the remaining length.  Returns NGX_HTTP_BAD_REQUEST if
 * the result would be empty.
 */
ngx_int_t webdav_destination_extract_path(const u_char *dest_data,
    size_t dest_len, const u_char **path_out, size_t *path_len_out);

#endif /* XROOTD_WEBDAV_UTIL_URI_H */
