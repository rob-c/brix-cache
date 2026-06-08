#include "s3.h"
#include "../cache/open.h"
#include "../compat/http_file_response.h"
#include "../compat/range.h"
#include "../dashboard/dashboard_tracking.h"
#include "../fs/vfs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * GET /bucket/key - file download with Range support
 * ---------------------------------------------------------------------- */

static void
s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;

    ngx_memzero(vctx, sizeof(*vctx));
    vctx->pool = r->pool;
    vctx->log = r->connection->log;
    vctx->metrics_proto = XROOTD_PROTO_S3;
    vctx->root_canon = cf->common.root_canon;
    vctx->cache_root_canon = cf->cache_root_canon;
    vctx->cache_enabled = (cf->cache_root_canon[0] != '\0') ? 1 : 0;
    vctx->allow_write = cf->common.allow_write ? 1 : 0;
    vctx->resolved.resolved.data = (u_char *) fs_path;
    vctx->resolved.resolved.len = strlen(fs_path);
    vctx->resolved.is_confined = 1;

#if (NGX_HTTP_SSL)
    vctx->is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    if (s3ctx != NULL) {
        vctx->identity = s3ctx->identity;
    }
}

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
    xrootd_vfs_ctx_t    vctx;
    xrootd_vfs_file_t  *fh;
    xrootd_vfs_stat_t   vst;
    ngx_fd_t            send_fd;
    off_t               range_start = 0, range_end = 0, send_len;
    int                 has_range = 0;
    int                 vfs_err;
    ngx_int_t           rc;
    char                identity[128];
    ngx_http_s3_req_ctx_t *s3ctx;
    const char         *subject;
    ngx_uint_t          from_cache;
    const char         *cache_path;

    s3_vfs_ctx(r, fs_path, cf, &vctx);
    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        if (vfs_err == ENOENT || vfs_err == ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) xrootd_http_errno_to_status(vfs_err);
    }

    if (xrootd_vfs_file_stat(fh, &vst) != NGX_OK) {
        xrootd_vfs_close(fh, r->connection->log);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (vst.is_directory) {
        xrootd_vfs_close(fh, r->connection->log);
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
            vst.size, &rng);

        if (rng.present && !rng.satisfiable) {
            xrootd_vfs_close(fh, r->connection->log);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_UNSATISFIED]);
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }

        range_start = rng.start;
        range_end   = rng.end;
        send_len    = (vst.size > 0) ? (range_end - range_start + 1) : 0;
        has_range   = rng.present;
    }

    if (has_range) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
    } else {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
    }

    if (xrootd_http_set_file_headers(r, vst.mtime, vst.size, send_len,
                                     NULL, 0,
                                     has_range, range_start, range_end)
        != NGX_OK)
    {
        xrootd_vfs_close(fh, r->connection->log);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    subject = s3ctx != NULL ? xrootd_identity_subject_cstr(s3ctx->identity)
                            : "";
    if (subject[0] != '\0') {
        ngx_cpystrn((u_char *) identity, (u_char *) subject,
                    sizeof(identity));
    } else if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
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

    from_cache = xrootd_vfs_file_from_cache(fh);
    cache_path = xrootd_vfs_file_path(fh);
    send_fd = dup(xrootd_vfs_file_fd(fh));
    if (send_fd == NGX_INVALID_FILE) {
        xrootd_vfs_close(fh, r->connection->log);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    xrootd_vfs_close(fh, r->connection->log);

    rc = xrootd_http_send_file_range(r, send_fd, fs_path, range_start,
                                     send_len, 1);
    if (rc != NGX_ERROR && !r->header_only) {
        xrootd_dashboard_http_add(r, (ngx_atomic_int_t) send_len);
        XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) send_len);
        if (from_cache && rc == NGX_OK && send_len > 0) {
            (void) xrootd_cache_record_access(cache_path, (size_t) send_len,
                                              r->connection->log);
        }
        if (r->connection && r->connection->sockaddr
            && r->connection->sockaddr->sa_family == AF_INET6) {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv6_total, (size_t) send_len);
        } else {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv4_total, (size_t) send_len);
        }
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
    xrootd_vfs_ctx_t  vctx;
    xrootd_vfs_stat_t vst;

    s3_vfs_ctx(r, fs_path, cf, &vctx);
    if (xrootd_vfs_stat(&vctx, &vst) != NGX_OK) {
        if (errno == ENOENT || errno == ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) xrootd_http_errno_to_status(errno);
    }

    if (vst.is_directory) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey", "The specified key does not exist.");
    }

    if (xrootd_http_set_file_headers(r, vst.mtime, vst.size, vst.size,
                                     NULL, 0,
                                     0, 0, 0) != NGX_OK)
    {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_send_header(r);
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
