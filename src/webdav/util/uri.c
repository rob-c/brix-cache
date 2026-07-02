/*
 * uri.c — WebDAV URI decoding and path extraction utilities.
 *
 * WHAT: Provides two helper functions for processing HTTP URIs in WebDAV requests:
 *       (1) `webdav_urldecode()` — percent-decodes a URI component into a destination
 *           buffer, rejecting embedded null bytes.  (2)
 *           `webdav_destination_extract_path()` — strips the scheme://authority prefix
 *           from a WebDAV Destination header value to isolate the path component.
 *
 * WHY: WebDAV clients send URIs in percent-encoded form (e.g. `/data/my%20file.root`).
 *      The Destination header for COPY/MOVE may be an absolute URI (`davs://host/path`)
 *      or a path-only form (`/path`). Both forms must be handled per RFC 4918 §8.3.
 *      Null bytes in URIs are forbidden by HTTP semantics and indicate malformed input.
 *
 * HOW:
 *   webdav_urldecode():
 *     Wraps `xrootd_http_urldecode()` from src/compat/uri.h with a WebDAV-specific
 *     error mapping. The compat function performs the actual percent-decoding; this
 *     wrapper converts its return codes into nginx status codes:
 *       XROOTD_URLDECODE_OK         → NGX_OK
 *       XROOTD_URLDECODE_OVERFLOW   → NGX_HTTP_REQUEST_URI_TOO_LARGE (414)
 *       XROOTD_URLDECODE_NUL_BYTE   → NGX_HTTP_BAD_REQUEST (400)
 *       default                    → NGX_HTTP_INTERNAL_SERVER_ERROR (500)
 *     The compat function is called with `XROOTD_URLDECODE_REJECT_NUL` so embedded
 *     null bytes produce a 400 response rather than truncating the decoded string.
 *
 *   webdav_destination_extract_path():
 *     Scans the Destination header value for a `scheme://authority` prefix by locating
 *     the first ':' and verifying that positions +1/+2 are "//". If found, it advances
 *     past the authority portion (host+port) to the first '/' in the path. If no scheme
 *     is present, the pointer starts at the beginning of the input buffer. Returns 400
 *     if the extracted path would be empty (p >= end). On success, *path_out points
 *     into the original dest_data buffer and *path_len_out gives the remaining length —
 *     no allocation required, zero-copy extraction.
 *
 * DEPENDENCIES: src/compat/uri.h (xrootd_http_urldecode), RFC 4918 §8.3 (Destination header)
 * SEE ALSO: webdav/copy.c, webdav/move.c (callers), compat/uri.c (urldecode implementation)
 */

#include "uri.h"
#include "core/compat/uri.h"

ngx_int_t
webdav_urldecode(const u_char *src, size_t src_len, char *dst, size_t dst_sz)
{
    switch (xrootd_http_urldecode(src, src_len, dst, dst_sz,
                                   XROOTD_URLDECODE_REJECT_NUL))
    {
    case XROOTD_URLDECODE_OK:       return NGX_OK;
    case XROOTD_URLDECODE_OVERFLOW: return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    case XROOTD_URLDECODE_NUL_BYTE: return NGX_HTTP_BAD_REQUEST;
    default:                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t
webdav_destination_extract_path(const u_char *dest_data, size_t dest_len,
    const u_char **path_out, size_t *path_len_out)
{
    const u_char *p   = dest_data;
    const u_char *end = p + dest_len;
    const u_char *scheme_end;

    /* Strip scheme://authority if present (RFC 4918 §8.3 absolute-URI form). */
    scheme_end = ngx_strlchr((u_char *) p, (u_char *) end, ':');
    if (scheme_end != NULL && scheme_end + 2 < end
        && scheme_end[1] == '/' && scheme_end[2] == '/')
    {
        p = scheme_end + 3;
        while (p < end && *p != '/') {
            p++;
        }
    }

    if (p >= end) {
        return NGX_HTTP_BAD_REQUEST;
    }

    *path_out     = p;
    *path_len_out = (size_t) (end - p);
    return NGX_OK;
}
