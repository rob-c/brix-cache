#include "s3.h"
#include "multipart_internal.h"
#include "../impersonate/lifecycle.h"
#include "../path/path.h"
#include "../compat/copy_range.h"

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

static void s3_multipart_complete_body_handler_inner(ngx_http_request_t *r);

/*
 * Phase 40: the POST body is read asynchronously, so the dispatch wrapper has
 * already cleared the impersonation principal by the time this callback runs.
 * Re-establish it (mirrors s3_put_body_handler) so the assembled object is
 * created/renamed as the mapped user under the broker.  No-op unless map mode.
 */
void
s3_multipart_complete_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_multipart_complete_body_handler_inner(r);
    xrootd_imp_request_end();
}

/*
 * s3_mpu_assemble — the heavy CompleteMultipartUpload work (phase-46 W1c):
 * concatenate part.1..part.N into final_tmp (kernel copy_file_range), stat it
 * for the ETag, atomically rename to fs_path, clean the staging dir, and compute
 * the full-object CRC-64/NVME (a whole-file read).  This is all blocking I/O, so
 * it runs on the thread pool (or the synchronous fallback) — never the response
 * build, which stays on the event loop (s3_mpu_send_result).
 *
 * Logs via `log`; `r` is used read-only (the checksum helper's logging only).
 * Returns NGX_OK + fills *st_out + crc64_b64_out (""=none), or NGX_ERROR +
 * *http_status_out.
 */
static ngx_int_t
s3_mpu_assemble(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon,
    const char *mpu_dir, const char *final_tmp, const char *fs_path,
    struct stat *st_out, char *crc64_b64_out, size_t crc64_sz,
    int *http_status_out)
{
    char        part_path[PATH_MAX];
    int         final_fd, part_fd, part_num;
    off_t       dst_off = 0;
    struct stat pst;
    u_char     *p;

    *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;
    crc64_b64_out[0] = '\0';

    final_fd = xrootd_open_confined_canon(log, root_canon, final_tmp,
                                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (final_fd < 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, errno,
                             "s3 complete_mpu: open(\"%s\") failed", final_tmp);
        return NGX_ERROR;
    }

    /* Concatenate part.1 through part.10000 in order, skipping missing ones. */
    for (part_num = 1; part_num <= MPU_MAX_PART_NUMBER; part_num++) {
        p = ngx_snprintf((u_char *) part_path, sizeof(part_path) - 1,
                         "%s/part.%d", mpu_dir, part_num);
        *p = '\0';

        part_fd = xrootd_open_confined_canon(log, root_canon, part_path,
                                             O_RDONLY, 0);
        if (part_fd < 0) {
            if (errno == ENOENT) {
                continue;           /* part not uploaded — skip */
            }
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "s3 complete_mpu: open part %d failed", part_num);
            close(final_fd);
            xrootd_unlink_confined_canon(log, root_canon, final_tmp, 0);
            return NGX_ERROR;
        }

        if (fstat(part_fd, &pst) != 0) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "s3 complete_mpu: fstat part %d failed", part_num);
            close(part_fd);
            close(final_fd);
            xrootd_unlink_confined_canon(log, root_canon, final_tmp, 0);
            return NGX_ERROR;
        }

        if (pst.st_size > 0
            && xrootd_copy_range(log, part_fd, 0, final_fd, dst_off,
                                 (size_t) pst.st_size, part_path,
                                 final_tmp) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "s3 complete_mpu: copy part %d failed", part_num);
            close(part_fd);
            close(final_fd);
            xrootd_unlink_confined_canon(log, root_canon, final_tmp, 0);
            return NGX_ERROR;
        }
        dst_off += pst.st_size;
        close(part_fd);
    }

    if (fstat(final_fd, st_out) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "s3 complete_mpu: fstat temp file failed");
        close(final_fd);
        xrootd_unlink_confined_canon(log, root_canon, final_tmp, 0);
        return NGX_ERROR;
    }
    close(final_fd);

    if (xrootd_rename_confined_canon(log, root_canon, final_tmp, fs_path) != 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, errno,
                             "s3 complete_mpu: rename to \"%s\" failed", fs_path);
        xrootd_unlink_confined_canon(log, root_canon, final_tmp, 0);
        return NGX_ERROR;
    }

    /* Best-effort staging cleanup — the object is already visible. */
    if (mpu_rmdir_recursive(log, root_canon, mpu_dir) != 0) {
        xrootd_log_safe_path(log, NGX_LOG_WARN, 0,
                             "s3 complete_mpu: cleanup of staging dir \"%s\" failed"
                             " (object committed successfully)", mpu_dir);
    }

    /* Full-object CRC-64/NVME computed directly on the reassembled object (the
     * exact FULL_OBJECT value — no per-part combine), cached in the xattr. */
    {
        int cfd = xrootd_open_confined_canon(log, root_canon, fs_path,
                                             O_RDONLY, 0);
        if (cfd >= 0) {
            (void) s3_object_crc64nvme_b64(r, cfd, fs_path, 0, crc64_b64_out,
                                           crc64_sz);
            close(cfd);
        }
    }

    return NGX_OK;
}

/*
 * s3_mpu_send_result — build + send the CompleteMultipartUploadResult XML on the
 * event loop (sets the ETag + checksum headers).  Shared by the offload
 * completion and the synchronous fallback.
 */
static void
s3_mpu_send_result(ngx_http_request_t *r, ngx_uint_t method_slot,
    const ngx_str_t *bucket, const char *fs_path, const struct stat *st,
    const char *crc64_b64)
{
    char       crc64_xml[128];
    char       etag[64];
    char       xml_buf[512];
    size_t     xml_len;
    ngx_buf_t *b;

    crc64_xml[0] = '\0';
    if (crc64_b64[0] != '\0') {
        (void) s3_set_header(r, S3_HDR_CHECKSUM_CRC64NVME, crc64_b64);
        (void) s3_set_header(r, S3_HDR_CHECKSUM_TYPE, "FULL_OBJECT");
        (void) snprintf(crc64_xml, sizeof(crc64_xml),
            "  <ChecksumCRC64NVME>%s</ChecksumCRC64NVME>\n"
            "  <ChecksumType>FULL_OBJECT</ChecksumType>\n", crc64_b64);
    }

    s3_etag(st, etag, sizeof(etag));
    xml_len = (size_t) snprintf(xml_buf, sizeof(xml_buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<CompleteMultipartUploadResult"
        " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
        "  <Bucket>%s</Bucket>\n"
        "  <Key>%s</Key>\n"
        "  <ETag>%s</ETag>\n"
        "%s"
        "</CompleteMultipartUploadResult>\n",
        bucket->data ? (const char *) bucket->data : "default",
        strrchr(fs_path, '/') ? strrchr(fs_path, '/') + 1 : fs_path,
        etag, crc64_xml);

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

/* phase-46 W1c: thread-pool task wrapping s3_mpu_assemble. */
typedef struct {
    ngx_http_request_t *r;
    ngx_uint_t          method_slot;
    char                mpu_dir[PATH_MAX];
    char                final_tmp[PATH_MAX];
    char                fs_path[PATH_MAX];
    char                root_canon[PATH_MAX];
    ngx_str_t           bucket;           /* points to stable cf->bucket config  */
    ngx_int_t           rc;
    int                 http_status;
    struct stat         st;               /* filled by the worker (for the ETag) */
    char                crc64_b64[S3_CRC64NVME_B64_MAX];
} s3_mpu_aio_t;

static void
s3_mpu_aio_thread(void *data, ngx_log_t *log)
{
    s3_mpu_aio_t *t = data;

    t->rc = s3_mpu_assemble(t->r, log, t->root_canon, t->mpu_dir, t->final_tmp,
                            t->fs_path, &t->st, t->crc64_b64,
                            sizeof(t->crc64_b64), &t->http_status);
}

static void
s3_mpu_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_mpu_aio_t       *t = task->ctx;
    ngx_http_request_t *r = t->r;

    if (t->rc != NGX_OK) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, t->method_slot, t->http_status);
        return;
    }
    s3_mpu_send_result(r, t->method_slot, &t->bucket, t->fs_path, &t->st,
                       t->crc64_b64);
}

static void
s3_multipart_complete_body_handler_inner(ngx_http_request_t *r)
{
    char                   *fs_path;
    ngx_http_s3_loc_conf_t *cf;
    ngx_http_s3_req_ctx_t  *s3ctx;
    char                    upload_id[25];
    char                    mpu_dir[PATH_MAX];
    char                    final_tmp[PATH_MAX];
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
     * Confinement + impersonation: mpu_dir is generated by s3_get_mpu_dir() from
     * a validated upload_id and an fs_path confined by s3_resolve_key().  Under
     * MAP-mode impersonation the staging dir (and its parent) are owned 0700 by
     * the mapped user, so a raw worker lstat() EACCESes on the parent's search
     * bit and the legitimate owner's Complete spuriously 404s NoSuchUpload.  Route
     * through xrootd_lstat_confined_canon so the stat runs as the mapped user via
     * the broker (off impersonation it is a plain lstat — identical behaviour).
     */
    struct stat mpu_sb;
    if (xrootd_lstat_confined_canon(r->connection->log, cf->common.root_canon,
                                    mpu_dir, &mpu_sb, 1) != 0
        || !S_ISDIR(mpu_sb.st_mode))
    {
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

    /*
     * phase-46 W1c: assembly (concatenate up to 10 000 parts + the full-object
     * checksum) is heavy blocking I/O — offload it to the thread pool and build
     * the result XML in the completion on the event loop.  Falls back to a
     * synchronous assembly when no pool is configured.
     */
    {
        ngx_thread_pool_t *pool = s3_thread_pool(cf);

        if (pool != NULL) {
            ngx_thread_task_t *task =
                ngx_thread_task_alloc(r->pool, sizeof(s3_mpu_aio_t));
            s3_mpu_aio_t *t;

            if (task == NULL) {
                XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                s3_metrics_finalize_request_method(r, method_slot,
                                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            t = task->ctx;                  /* zeroed by ngx_thread_task_alloc */
            t->r           = r;
            t->method_slot = method_slot;
            t->bucket      = cf->bucket;    /* data lives in stable config memory */
            ngx_cpystrn((u_char *) t->mpu_dir, (u_char *) mpu_dir,
                        sizeof(t->mpu_dir));
            ngx_cpystrn((u_char *) t->final_tmp, (u_char *) final_tmp,
                        sizeof(t->final_tmp));
            ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path,
                        sizeof(t->fs_path));
            ngx_cpystrn((u_char *) t->root_canon,
                        (u_char *) cf->common.root_canon, sizeof(t->root_canon));
            task->handler       = s3_mpu_aio_thread;
            task->event.handler = s3_mpu_aio_done;
            task->event.data    = task;

            if (ngx_thread_task_post(pool, task) != NGX_OK) {
                XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                s3_metrics_finalize_request_method(r, method_slot,
                                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            r->main->count++;
            return;
        }

        /* Synchronous fallback (no thread pool): assemble inline, then respond. */
        {
            struct stat st2;
            char        crc[S3_CRC64NVME_B64_MAX];
            int         status = NGX_HTTP_INTERNAL_SERVER_ERROR;

            if (s3_mpu_assemble(r, r->connection->log, cf->common.root_canon,
                                mpu_dir, final_tmp, fs_path, &st2, crc,
                                sizeof(crc), &status) != NGX_OK)
            {
                XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                s3_metrics_finalize_request_method(r, method_slot, status);
                return;
            }
            s3_mpu_send_result(r, method_slot, &cf->bucket, fs_path, &st2, crc);
        }
    }
}
