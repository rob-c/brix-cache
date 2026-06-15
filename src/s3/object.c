#include "s3.h"
#include "../cache/open.h"
#include "../compat/http_file_response.h"
#include "../compat/http_headers.h"
#include "../frm/frm.h"
#include "../dashboard/dashboard_tracking.h"
#include "../fs/vfs.h"
#include "../shared/file_serve.h"

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
    vctx->rootfd = -1;
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

/* WHY: GET is the primary S3 data path — clients download object bytes via HTTP GET or byte-range requests. Range support (RFC 7233) enables resumable downloads and parallel chunked transfers, critical for large objects in HEP workflows where files often exceed gigabytes. The range-parse → headers → body-send pipeline is shared with WebDAV GET via xrootd_http_serve_file_ranged() (src/shared/file_serve.c); this handler keeps only the S3-specific concerns: NoSuchKey XML errors, identity resolution, and S3 range/bytes metrics. */

/* HOW: Phase 1 — open the object through the VFS layer (xrootd_vfs_open, read-only, cache-aware). If the open fails: ENOENT/ENOTDIR → NoSuchKey 404 XML; other errno → xrootd_http_errno_to_status() with internal_error metric. Phase 2 — xrootd_vfs_file_stat(); a directory target → NoSuchKey 404 (S3 keys are objects, not directories). Phase 3 — resolve the display identity (token subject, else access key, else "anonymous"). Phase 4 — fill xrootd_http_serve_opts_t (xfer_proto=S3, op_name="GetObject", etag_flags=0) and delegate the entire range-parse/header/send pipeline to xrootd_http_serve_file_ranged(), which also takes ownership of the vfs handle. Phase 5 — from the returned result, increment the S3 range_total[FULL/PARTIAL/UNSATISFIED] counter and, on a non-zero body, bytes_tx_total plus the IPv4/IPv6 split. */
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
    int                 vfs_err;
    ngx_int_t           rc;
    char                identity[128];
    ngx_http_s3_req_ctx_t *s3ctx;
    const char         *subject;

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

    /*
     * Tape residency (phase-35): a GET of a nearline/offline object cannot be
     * served from disk — S3/Glacier semantics require an explicit restore first
     * (the WLCG Tape REST API). Report InvalidObjectState rather than blocking or
     * serving a stub. Absent xattr ⇒ ONLINE, so a plain disk export is unaffected.
     */
    {
        frm_residency_t res;
        if (frm_residency_probe(r->connection->log, fs_path, &res) == NGX_OK
            && (res.state == FRM_RES_NEARLINE || res.state == FRM_RES_OFFLINE))
        {
            xrootd_vfs_close(fh, r->connection->log);
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_ACCESS_DENIED]);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "InvalidObjectState",
                "The operation is not valid for the object's storage class.");
        }
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

    /*
     * AWS full-object checksum echo (x-amz-checksum-crc64nvme). Cache-only: emit
     * only when the value was stored at upload time, so the read path never pays
     * a full-file recompute. Set before serve sends the response headers; the
     * handle's fd stays valid until serve closes it.
     */
    {
        ngx_fd_t cfd = xrootd_vfs_file_fd(fh);
        char     b64[S3_CRC64NVME_B64_MAX];

        if (cfd != NGX_INVALID_FILE
            && s3_object_crc64nvme_b64(r, cfd, fs_path, 1, b64, sizeof(b64))
               == NGX_OK)
        {
            (void) s3_set_header(r, S3_HDR_CHECKSUM_CRC64NVME, b64);
            (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
        }
    }

    {
        xrootd_http_serve_opts_t   opts;
        xrootd_http_serve_result_t result;

        ngx_memzero(&opts, sizeof(opts));
        opts.xfer_proto = XROOTD_XFER_PROTO_S3;
        opts.op_name    = "GetObject";
        opts.identity   = identity;
        opts.etag_flags = 0;

        rc = xrootd_http_serve_file_ranged(r, fh, &vst, fs_path, &opts,
                                           &result);

        if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        }

        if (result.range_result == XROOTD_SERVE_RANGE_UNSATISFIED) {
            XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_UNSATISFIED]);
        } else if (result.range_result == XROOTD_SERVE_RANGE_PARTIAL) {
            XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
        } else {
            XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
        }

        if (result.bytes_sent > 0) {
            XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) result.bytes_sent);
            if (r->connection && r->connection->sockaddr
                && r->connection->sockaddr->sa_family == AF_INET6) {
                XROOTD_S3_METRIC_ADD(bytes_tx_ipv6_total,
                                     (size_t) result.bytes_sent);
            } else {
                XROOTD_S3_METRIC_ADD(bytes_tx_ipv4_total,
                                     (size_t) result.bytes_sent);
            }
        }
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

    /*
     * Tape residency (phase-35): advertise the GLACIER storage class for a
     * nearline object so clients learn a restore is required before a GET. HEAD
     * still returns 200 (metadata only); x-amz-restore reports no active restore
     * (the restore flow is the WLCG Tape REST API, not S3 GET).
     */
    {
        frm_residency_t res;
        if (frm_residency_probe(r->connection->log, fs_path, &res) == NGX_OK
            && (res.state == FRM_RES_NEARLINE || res.state == FRM_RES_OFFLINE))
        {
            (void) xrootd_http_set_header(r, "x-amz-storage-class",
                                          "GLACIER", NULL);
            (void) xrootd_http_set_header(r, "x-amz-restore",
                                          "ongoing-request=\"false\"", NULL);
        }
    }

    /*
     * AWS full-object checksum echo (x-amz-checksum-crc64nvme). Cache-only: a
     * cheap confined open + getxattr (no full-file read) emits the value stored
     * at upload time; absent ⇒ no header, exactly as AWS behaves when no checksum
     * was set at upload.
     */
    {
        int cfd = xrootd_open_confined_canon(r->connection->log,
                                             cf->common.root_canon, fs_path,
                                             O_RDONLY, 0);
        if (cfd >= 0) {
            char b64[S3_CRC64NVME_B64_MAX];

            if (s3_object_crc64nvme_b64(r, cfd, fs_path, 1, b64, sizeof(b64))
                == NGX_OK)
            {
                (void) s3_set_header(r, S3_HDR_CHECKSUM_CRC64NVME, b64);
                (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
            }
            close(cfd);
        }
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
 * HOW: Calls the Layer-3 namespace API xrootd_ns_delete() on fs_path with idempotent_missing=1 (a missing key still returns 204, AWS-style) and require_empty_dir=1. On XROOTD_NS_OK sends a 204 No Content header-only response via ngx_http_send_special() (incrementing DELETE_MISSING when the target did not exist); XROOTD_NS_NOT_EMPTY → 409 BucketNotEmpty; any other status → internal_error metric + 500. The namespace layer enforces root confinement internally.
 */
