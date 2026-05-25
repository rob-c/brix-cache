/*
 * util.c - shared helpers: path resolve, ETag, error response.
 */

#include "s3.h"
#include "../compat/etag.h"
#include "../compat/http_headers.h"
#include "../compat/http_xml.h"
#include "../compat/path.h"
#include "../compat/xml.h"

#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Response header helper
 * ---------------------------------------------------------------------- */

/*
 * s3_set_header — allocate and set an HTTP response header.
 *
 * Thin wrapper around xrootd_http_set_header(). key must be a string
 * literal (hash=1 optimization). val is copied into the request pool.
 */
ngx_int_t
s3_set_header(ngx_http_request_t *r, const char *key, const char *val)
{
    return xrootd_http_set_header(r, key, val, NULL);
}

/* -------------------------------------------------------------------------
 * Filesystem path resolution
 * ---------------------------------------------------------------------- */

int
/*
 * s3_resolve_key — resolve an S3 object key to a filesystem path.
 *
 * Steps:
 *   1. Strip leading slashes from the key (S3 URLs have /bucket/key).
 *   2. Prepend exactly one slash so decoded_path starts with /.
 *   3. Call xrootd_http_resolve_path() which canonicalizes, URL-decodes,
 *      and confines the path to root.
 *
 * Returns: 1 on success (path is confined), 0 if escape detected or
 * buffer overflow.
 */
s3_resolve_key(const char *root, const char *key, char *out, size_t outsz)
{
    char key_path[PATH_MAX];
    int  n;

    /* Strip leading slashes; prepend exactly one so decoded_path starts with /. */
    while (*key == '/')
        key++;

    n = snprintf(key_path, sizeof(key_path), "/%s", key);
    if (n < 0 || (size_t) n >= sizeof(key_path))
        return 0;

    return xrootd_http_resolve_path(root, key_path, out, outsz) == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * ETag generation  (synthetic: "mtime-size")
 * ---------------------------------------------------------------------- */

void
/*
 * s3_etag — generate an S3-style ETag from stat metadata.
 *
 * Format: "mtime-size" (quoted string containing modification time
 * and file size). This is a synthetic ETag since S3 normally uses
 * MD5 of content — here we use mtime+size as a stable identifier
 * consistent with XrdClS3 expectations.
 */
s3_etag(const struct stat *st, char *buf, size_t bufsz)
{
    xrootd_http_etag_str(buf, bufsz, st->st_mtime, st->st_size, 0);
}

/* -------------------------------------------------------------------------
 * XML error response
 * ---------------------------------------------------------------------- */

ngx_int_t
/*
 * s3_send_xml_error — S3 wrapper around xrootd_http_send_xml_error.
 *
 * Delegates XML building and sending to the compat-layer helper; increments the
 * S3 internal-error metric on OOM so S3 callers don't need to track that case.
 */
s3_send_xml_error(ngx_http_request_t *r,
                   ngx_uint_t status,
                   const char *code,
                   const char *message)
{
    ngx_int_t  rc;

    rc = xrootd_http_send_xml_error(r, status, code, message);
    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    }
    return rc;
}
