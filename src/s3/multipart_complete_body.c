#include "s3.h"
#include "multipart_internal.h"

#include <string.h>

/*
 * multipart_complete_body.c — CompleteMultipartUpload async body handler.
 *
 * WHAT: One function: s3_multipart_complete_body_handler() — invoked as an async callback after
 *   ngx_http_read_client_request_body() completes (POST /bucket/key?uploadId=<id>). Responsibilities:
 *     1. Extract and validate upload_id from query param + hex-format check via mpu_validate_upload_id().
 *     2. Locate staging directory via s3_get_mpu_dir(), verify it exists with lstat() → NoSuchUpload 404 if missing.
 *     3. Open a temp file (fs_path.mputmp) confined to root_canon for atomic assembly.
 *     4. Concatenate part.1 through part.10000 in ascending order from staging dir — skip ENOENT parts, fail on I/O errors.
 *     5. fstat assembled temp → generate ETag via s3_etag(). Close fd, rename temp→final path atomically.
 *     6. Best-effort cleanup of staging directory (mpu_rmdir_recursive) — object is already visible if rename succeeded.
 *     7. Build CompleteMultipartUploadResult XML (Bucket + Key extracted from fs_path + ETag), send via ngx_chain_t → HTTP 200.
 *   The XML body in the request is informational only; concatenation order is deterministic regardless of part arrival order.
 *
 * WHY: Multipart uploads accumulate N staged files on disk — without completion they leave orphan parts consuming space.
 *      The ascending-order concatenation (part.1→part.10000) produces a deterministic final object regardless of the order
 *      parts were uploaded, matching AWS S3 semantics. Atomic rename (temp → final path) ensures clients never see a partial
 *      object — either the old object exists or the new one appears instantly. Staging dir cleanup is best-effort because
 *      once rename succeeds the object is visible; failure to remove staging files wastes disk but doesn't affect correctness.
 *      Metric tracking on I/O failures enables monitoring without log noise.
 *
 * HOW:
 *   1. Extract ctx (fs_path from r->ctx, cf from loc_conf), get method_slot for metrics.
 *   2. Parse uploadId query param → s3_get_query_param() → InvalidArgument 400 if missing/invalid.
 *   3. Build mpu_dir = fs_path + "/" + upload_id via s3_get_mpu_dir(). lstat(mpu_dir) → NoSuchUpload 404 if ENOENT.
 *   4. final_tmp = fs_path.mputmp (snprintf). Open with O_WRONLY|O_CREAT|O_TRUNC, mode 0644 via xrootd_open_confined_canon().
 *   5. Loop part_num=1..MPU_MAX_PART_NUMBER: snprintf(part_path = mpu_dir/part.%d), open O_RDONLY confined → ENOENT skip,
 *      read/write loop with copy_buf[65536] — write errors close both fds, unlink temp, metric_internal_error, return 500.
 *   6. fstat(final_fd) for ETag generation. Close fd. xrootd_rename_confined_canon(temp→fs_path) → rename error: unlink temp, 500.
 *   7. mpu_rmdir_recursive(mpu_dir) best-effort (WARN on failure, object already committed).
 *   8. s3_etag(&st, etag) → snprintf XML response with Bucket/Key(derived from strrchr(fs_path,'/')+1)/ETag into xml_buf[512].
 *      ngx_create_temp_buf(xml_len) → copy into buf → build ngx_chain_t → HTTP 200 + content_length_n = xml_len.
 */

/* -------------------------------------------------------------------------
 * POST /bucket/key?uploadId=<id>  →  CompleteMultipartUpload (body handler)
 * ---------------------------------------------------------------------- */

void
s3_multipart_complete_body_handler(ngx_http_request_t *r)
{
    char                   *fs_path;
    ngx_http_s3_loc_conf_t *cf;
    ngx_http_s3_req_ctx_t  *s3ctx;
    char                    upload_id[25];
    char                    mpu_dir[PATH_MAX];
    char                    final_tmp[PATH_MAX];
    char                    xml_buf[512];
    char                    part_path[PATH_MAX];
    ngx_buf_t              *b;
    int                     final_fd;
    int                     part_fd;
    int                     part_num;
    ssize_t                 n;
    char                    copy_buf[65536];
    struct stat             st;
    char                    etag[64];
    size_t                  xml_len;
    ngx_uint_t              method_slot;
    u_char                 *p;

    s3ctx       = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    fs_path     = s3ctx != NULL ? s3ctx->fs_path : NULL;
    cf          = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    method_slot = s3_metrics_method_slot(r);

    if (fs_path == NULL || fs_path[0] == '\0') {
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "InvalidArgument", "Missing uploadId."));
        return;
    }

    if (!mpu_validate_upload_id(upload_id)) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "InvalidArgument", "The uploadId is invalid."));
        return;
    }

    s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));

    /*
     * Confinement: mpu_dir is generated by s3_get_mpu_dir() from a validated
     * upload_id and an fs_path confined by s3_resolve_key(). Bare lstat is safe.
     */
    struct stat mpu_sb;
    if (lstat(mpu_dir, &mpu_sb) != 0 || !S_ISDIR(mpu_sb.st_mode)) {
        s3_metrics_finalize_request_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                              "NoSuchUpload",
                              "The specified upload does not exist."));
        return;
    }

    /* Build a temp path alongside the final object for atomic rename */
    p = ngx_snprintf((u_char *)final_tmp, sizeof(final_tmp) - 1,
                     "%s.mputmp", fs_path);
    *p = '\0';

    final_fd = xrootd_open_confined_canon(r->connection->log, cf->common.root_canon,
                                          final_tmp,
                                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (final_fd < 0) {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, errno,
                             "s3 complete_mpu: open(\"%s\") failed", final_tmp);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Concatenate part.1 through part.10000 in order, skipping missing ones */
    for (part_num = 1; part_num <= MPU_MAX_PART_NUMBER; part_num++) {
        p = ngx_snprintf((u_char *)part_path, sizeof(part_path) - 1,
                         "%s/part.%d", mpu_dir, part_num);
        *p = '\0';

        part_fd = xrootd_open_confined_canon(r->connection->log,
                                             cf->common.root_canon,
                                             part_path, O_RDONLY, 0);
        if (part_fd < 0) {
            if (errno == ENOENT) {
                continue;           /* part not uploaded — skip */
            }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                          "s3 complete_mpu: open part %d failed", part_num);
            close(final_fd);
            xrootd_unlink_confined_canon(r->connection->log, cf->common.root_canon,
                                         final_tmp, 0);
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            s3_metrics_finalize_request_method(r, method_slot,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        while ((n = read(part_fd, copy_buf, sizeof(copy_buf))) > 0) {
            if (write(final_fd, copy_buf, (size_t)n) != n) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                              "s3 complete_mpu: write to temp file failed");
                close(part_fd);
                close(final_fd);
                xrootd_unlink_confined_canon(r->connection->log,
                                             cf->common.root_canon, final_tmp, 0);
                XROOTD_S3_METRIC_INC(
                    events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                s3_metrics_finalize_request_method(
                    r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
        close(part_fd);

        if (n < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                          "s3 complete_mpu: read part %d failed", part_num);
            close(final_fd);
            xrootd_unlink_confined_canon(r->connection->log, cf->common.root_canon,
                                         final_tmp, 0);
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            s3_metrics_finalize_request_method(r, method_slot,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    /* Stat the assembled temp file before closing (for ETag) */
    if (fstat(final_fd, &st) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "s3 complete_mpu: fstat temp file failed");
        close(final_fd);
        xrootd_unlink_confined_canon(r->connection->log, cf->common.root_canon,
                                     final_tmp, 0);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    close(final_fd);

    /* Atomic rename: temp → final object path */
    if (xrootd_rename_confined_canon(r->connection->log, cf->common.root_canon,
                                     final_tmp, fs_path) != 0)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, errno,
                             "s3 complete_mpu: rename to \"%s\" failed", fs_path);
        xrootd_unlink_confined_canon(r->connection->log, cf->common.root_canon,
                                     final_tmp, 0);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Clean up staging directory (best-effort — object is already visible) */
    if (mpu_rmdir_recursive(r->connection->log, cf->common.root_canon, mpu_dir) != 0) {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_WARN, 0,
                             "s3 complete_mpu: cleanup of staging dir \"%s\" failed"
                             " (object committed successfully)", mpu_dir);
    }

    /* Build success XML response */
    s3_etag(&st, etag, sizeof(etag));

    xml_len = (size_t)snprintf(xml_buf, sizeof(xml_buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<CompleteMultipartUploadResult"
        " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
        "  <Bucket>%s</Bucket>\n"
        "  <Key>%s</Key>\n"
        "  <ETag>%s</ETag>\n"
        "</CompleteMultipartUploadResult>\n",
        cf->bucket.data ? (const char *)cf->bucket.data : "default",
        /* key is not available here — extract from fs_path */
        strrchr(fs_path, '/') ? strrchr(fs_path, '/') + 1 : fs_path,
        etag);

    if (xml_len >= sizeof(xml_buf)) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_memcpy(b->pos, xml_buf, xml_len);
    b->last = b->pos + xml_len;

    s3_metrics_finalize_request_method(r, method_slot,
        xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
            (ngx_str_t) ngx_string("application/xml"), b));
}
