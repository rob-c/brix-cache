/*
 * zip_http.h — shared HTTP ZIP-member serving (phase-57 W2), used by WebDAV GET
 * and S3 GetObject.
 *
 * WHAT: Extract a "?xrdcl.unzip=<member>" query arg and serve that member of a
 *       ZIP archive over an HTTP response (stored via sendfile byte-range,
 *       deflate via in-RAM inflate, with single-Range support).
 * WHY:  HTTP/S3 clients cannot self-inflate a ZIP member (unlike root:// XrdCl),
 *       so the server must extract.  WebDAV and S3 share one implementation.
 * HOW:  Confined archive open + brix_zip_find_member (zip_dir.h) +
 *       brix_zip_extract_full for deflate; a dup'd fd kept alive by an
 *       ngx_pool_cleanup_file for the stored sendfile path.
 */
#ifndef BRIX_ZIP_HTTP_H
#define BRIX_ZIP_HTTP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Pull a validated member name from the request query "?xrdcl.unzip=<member>"
 * into out[outsz] (URL-decoded).  Returns 1 (serve member), 0 (no key present →
 * serve the object normally), or -1 (key present but invalid: empty / absolute /
 * traversal → caller returns 400).
 */
int brix_zip_http_member_arg(ngx_http_request_t *r, char *out, size_t outsz);

/*
 * Serve `member` of the archive at `archive_full` (a root_canon-prefixed absolute
 * path the caller already authorized) over the current HTTP GET.  `cd_max` caps
 * the central-directory read.  Returns an NGX_HTTP_* status, or the output-filter
 * result once the response is sent.
 */
ngx_int_t brix_zip_http_serve(ngx_http_request_t *r, const char *root_canon,
    size_t cd_max, const char *archive_full, const char *member);

#endif /* BRIX_ZIP_HTTP_H */
