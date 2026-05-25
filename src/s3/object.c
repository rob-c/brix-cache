#include "s3.h"
#include "../compat/http_file_response.h"
#include "../compat/range.h"
#include "../dashboard/dashboard_tracking.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * GET /bucket/key - file download with Range support
 * ---------------------------------------------------------------------- */

/* WHY: GET is the primary S3 data path — clients download object bytes via HTTP GET or byte-range requests. Range support (RFC 7233) enables resumable downloads and parallel chunked transfers, critical for large objects in HEP workflows where files often exceed gigabytes. The handler opens a confined fd, stat's the file to determine size/type, parses any Range header, sets appropriate status/headers (200 OK or 206 Partial Content with Content-Range), then delegates body transfer to xrootd_http_send_file_range(). Three OOM/error paths all increment internal_error metric and return NGX_HTTP_INTERNAL_SERVER_ERROR. */

/* HOW: Phase 1 — open fd via xrootd_open_confined_canon() (O_RDONLY). If invalid fd: ENOENT/ENOTDIR → NoSuchKey 404; other errno → mapped HTTP status code with internal_error metric. Phase 2 — fstat the fd to get size and mode; S_ISDIR → NoSuchKey 404 (S3 keys are objects, not directories). Phase 3 — parse Range header via xrootd_http_parse_range() using file size as upper bound: unsatisfiable range → 416 with metric; satisfiable → compute send_len = end - start + 1. Phase 4 — set status (200/206), content-length, last-modified, Content-Type=octet-stream, ETag from mtime+size via xrootd_http_add_etag_header(). If range present: add Content-Range header. Phase 5 — delegate body transfer to xrootd_http_send_file_range() with fd/fs_path/range parameters; on success increment bytes_tx_total by send_len. FD ownership: opened here, closed either immediately on error or via ngx_pool_cleanup_file registered on r->pool for async paths. */
/*
 * s3_handle_get - serve a file as an S3 GetObject response.
 *
 * Supports byte-range requests (RFC 7233).  After sending headers, checks
 * r->header_only so that HEAD requests (dispatched through s3_handle_head)
 * do not accidentally trigger a body send.
 *
 * Ownership: fd is opened here and closed either immediately on error or
 *   via an ngx_pool_cleanup_file registered on r->pool.
 *
 * Pool allocation: r->pool lifetime (request scope).
 */
ngx_int_t
s3_handle_get(ngx_http_request_t *r,
              const char *fs_path,
              ngx_http_s3_loc_conf_t *cf)
{
    struct stat         sb;
    ngx_fd_t            fd;
    off_t               range_start = 0, range_end = 0, send_len;
    int                 has_range = 0;
    ngx_int_t           rc;
    char                identity[128];

    fd = xrootd_open_confined_canon(r->connection->log, cf->common.root_canon,
                                    fs_path, O_RDONLY, 0);
    if (fd == NGX_INVALID_FILE) {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) xrootd_http_errno_to_status(ngx_errno);
    }

    if (fstat(fd, &sb) != 0) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey", "The specified key does not exist.");
    }

    /* Range parsing */
    {
        xrootd_http_range_t rng;
        xrootd_http_parse_range(
            r->headers_in.range ? r->headers_in.range->value.data : NULL,
            r->headers_in.range ? r->headers_in.range->value.len : 0,
            sb.st_size, &rng);

        if (rng.present && !rng.satisfiable) {
            ngx_close_file(fd);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_UNSATISFIED]);
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }

        range_start = rng.start;
        range_end   = rng.end;
        send_len    = (sb.st_size > 0) ? (range_end - range_start + 1) : 0;
        has_range   = rng.present;
    }

    if (has_range) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
    } else {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
    }

    if (xrootd_http_set_file_headers(r, sb.st_mtime, sb.st_size, send_len,
                                     NULL, 0,
                                     has_range, range_start, range_end)
        != NGX_OK)
    {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
        size_t n = cf->access_key.len < sizeof(identity) - 1
                   ? cf->access_key.len
                   : sizeof(identity) - 1;
        ngx_memcpy(identity, cf->access_key.data, n);
        identity[n] = '\0';
    } else {
        ngx_cpystrn((u_char *) identity, (u_char *) "anonymous",
                    sizeof(identity));
    }

    (void) xrootd_dashboard_http_start_identity(r, fs_path, identity, "",
        XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_READ, "GetObject",
        (int64_t) send_len);

    rc = xrootd_http_send_file_range(r, fd, fs_path, range_start, send_len, 1);
    if (rc != NGX_ERROR && !r->header_only) {
        xrootd_dashboard_http_add(r, (ngx_atomic_int_t) send_len);
        XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) send_len);
    } else if (rc == NGX_ERROR) {
        xrootd_dashboard_http_error(r, "s3 GetObject send failed");
        xrootd_dashboard_http_finish(r);
    } else if (r->header_only) {
        xrootd_dashboard_http_finish(r);
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * HEAD /bucket/key - metadata only
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_handle_head(ngx_http_request_t *r,
               const char *fs_path,
               ngx_http_s3_loc_conf_t *cf)
{
    struct stat  sb;
    int          fd;

    fd = xrootd_open_confined_canon(r->connection->log, cf->common.root_canon,
                                    fs_path, O_RDONLY, 0);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) xrootd_http_errno_to_status(errno);
    }

    if (fstat(fd, &sb) != 0) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey", "The specified key does not exist.");
    }

    if (xrootd_http_set_file_headers(r, sb.st_mtime, sb.st_size, sb.st_size,
                                     NULL, 0,
                                     0, 0, 0) != NGX_OK)
    {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_send_header(r);
    ngx_close_file(fd);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
/*
 * WHY: HEAD requests return object metadata without body — required by S3 spec for existence checks and pre-upload validation. Clients use HEAD to verify an object exists, check size/ETag before deciding whether to upload or download.
 *
 * HOW: Mirrors s3_handle_get's opening/fstat path but skips range parsing entirely. Sets status=200, content-length from st_size, last-modified from st_mtime, Content-Type and ETag headers. Sends header only via ngx_http_send_header() + ngx_http_send_special(r, NGX_HTTP_LAST), closes the fd immediately after (no body transfer). Does NOT register pool cleanup since the fd is closed synchronously.
 */

/* -------------------------------------------------------------------------
 * DELETE /bucket/key
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_handle_delete(ngx_http_request_t *r,
                 const char *fs_path,
                 ngx_http_s3_loc_conf_t *cf)
{
    xrootd_ns_result_t      res;
    xrootd_ns_delete_opts_t opts;

    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 1;
    opts.require_empty_dir  = 1;

    res = xrootd_ns_delete(r->connection->log, cf->common.root_canon, fs_path, &opts);

    if (res.status == XROOTD_NS_OK) {
        if (!res.existed) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DELETE_MISSING]);
        }
        r->headers_out.status           = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (res.status == XROOTD_NS_NOT_EMPTY) {
        return s3_send_xml_error(r, NGX_HTTP_CONFLICT,
                                 "BucketNotEmpty",
                                 "The directory is not empty.");
    }

    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 * WHY: S3 DELETE is idempotent — deleting a non-existent key returns 204 No Content (not 404), matching AWS behavior. This allows clients to safely retry delete operations without checking existence first.
 *
 * HOW: Calls xrootd_unlink_confined_canon() on the fs_path. If ENOENT: returns 204 immediately (idempotent). If EISDIR or EPERM: retries with recursive flag=1 — if that fails with ENOTEMPTY returns 409 BucketNotEmpty; otherwise 500. On success: sends 204 No Content header-only response via ngx_http_send_special(). Uses xrootd_unlink_confined_canon() (not unlink()) to respect the configured root confinement.
 */
