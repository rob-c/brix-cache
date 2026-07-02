/*
 * path.c - WebDAV URI-to-filesystem path confinement.
 */

#include "webdav.h"
#include "core/compat/path.h"

#include <limits.h>
#include <string.h>
#include <unistd.h>

/* Wrapper: maps xrootd_http_resolve_path() return codes to NGX_HTTP_*,
 * using 409 Conflict when the destination parent cannot be resolved
 * (RFC 4918 §9.8 — parent collection does not exist). */
static ngx_int_t
map_resolve_rc(int rc)
{
    switch (rc) {
    case 0:   return NGX_OK;
    case 403: return NGX_HTTP_FORBIDDEN;
    case 414: return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    case 500: return NGX_HTTP_INTERNAL_SERVER_ERROR;
    default:  return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t
webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    char   stripped[PATH_MAX];
    size_t dlen;
    int    rc;

    (void) log;
    (void) op_label;

    dlen = strlen(decoded_path);
    while (dlen > 1 && decoded_path[dlen - 1] == '/')
        dlen--;

    if (dlen >= sizeof(stripped))
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    memcpy(stripped, decoded_path, dlen);
    stripped[dlen] = '\0';

    rc = xrootd_http_resolve_path(root_canon, stripped, out, outsz);
    if (rc == 0)
        return NGX_OK;
    /* 404 from shared resolver → parent doesn't exist → 409 Conflict */
    if (rc == 404)
        return NGX_HTTP_CONFLICT;
    return map_resolve_rc(rc);
}

ngx_int_t
ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
                                    const char *root_canon,
                                    char *out, size_t outsz)
{
    char      uri_decoded[WEBDAV_MAX_PATH];
    ngx_int_t decode_rc;
    size_t    uri_dlen;
    int       rc;

    decode_rc = webdav_urldecode(r->uri.data, r->uri.len,
                                 uri_decoded, sizeof(uri_decoded));
    if (decode_rc != NGX_OK) {
        if (decode_rc == NGX_HTTP_BAD_REQUEST) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: rejecting URI with decoded NUL");
        }
        return decode_rc;
    }

    uri_dlen = strlen(uri_decoded);
    while (uri_dlen > 1 && uri_decoded[uri_dlen - 1] == '/')
        uri_decoded[--uri_dlen] = '\0';

    rc = xrootd_http_resolve_path(root_canon, uri_decoded, out, outsz);
    switch (rc) {
    case 0:   return NGX_OK;
    case 403: return NGX_HTTP_FORBIDDEN;
    case 404: return NGX_HTTP_NOT_FOUND;
    case 414: return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    default:  return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}
