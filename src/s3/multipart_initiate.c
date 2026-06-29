/*
 * WHAT: S3-compatible InitiateMultipartUpload endpoint. Handles POST /bucket/key?uploads
 * requests to create a new multipart upload session. Generates an opaque upload ID from
 * timestamp components, creates a staging directory for partial uploads, and returns
 * the AWS-standard XML response body with Bucket/Key/UploadId elements.
 */

/* WHY: Multipart uploads are essential for large file transfers (>5GB) where single PUT
 * operations would timeout or consume excessive memory. The upload ID provides a unique
 * session identifier that ties together all subsequent UploadPart and CompleteMultipartUpload
 * requests — each part must reference the same upload_id to be included in the final assembly.
 * Staging directory isolation (0700 permissions) prevents cross-upload contamination between
 * concurrent multipart sessions. */

/* HOW: Three-phase operation. Phase 1: Generate upload ID using ngx_gettimeofday() + pid —
 * three 8-hex-digit fields produce 96 bits of uniqueness (seconds + microseconds + nginx worker
 * PID). Note: initial attempt used ngx_snprintf with %l format; the fallback snprintf on lines
 * 40-44 uses plain %lx to avoid ngx_snprintf's trailing 'l' suffix characters. Phase 2: Create
 * staging directory via s3_get_mpu_dir() + xrootd_mkdir_confined_canon() — confined path ensures
 * staging stays under the export root with 0700 permissions for upload isolation. Phase 3: Build
 * AWS-standard XML response body using snprintf into 512-byte stack buffer, convert to ngx_buf_t
 * via ngx_create_temp_buf(), send header + output filter chain. Three OOM/error paths all return
 * NGX_HTTP_INTERNAL_SERVER_ERROR with metric increment. */

#include "s3.h"
#include "multipart_internal.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * POST /bucket/key?uploads  →  InitiateMultipartUpload
 * */

ngx_int_t
s3_handle_multipart_initiate(ngx_http_request_t *r,
                              const char *fs_path,
                              ngx_http_s3_loc_conf_t *cf,
                              const char *key_str)
{
    char        upload_id[25];  /* 8+8+8 hex digits + NUL */
    char        mpu_dir[PATH_MAX];
    char        xml_buf[512];
    ngx_buf_t  *b;
    struct timeval tv;
    u_char     *p;
    size_t      xml_len;

    /* Generate a simple opaque upload ID from timestamp + usec + pid.
     * Three 8-hex fields gives 96 bits of uniqueness — sufficient for a
     * staging token that is only valid for the lifetime of the upload. */
    ngx_gettimeofday(&tv);
    p = ngx_snprintf((u_char *)upload_id, sizeof(upload_id) - 1,
                     "%08xl%08xl%08xl",
                     (unsigned long)tv.tv_sec,
                     (unsigned long)tv.tv_usec,
                     (unsigned long)ngx_pid);
    *p = '\0';

    /* Trim the format suffix characters ('l') that ngx_snprintf emits for %l */
    /* Simpler: just use fixed hex with snprintf since upload_id is not a path */
    snprintf(upload_id, sizeof(upload_id), "%08lx%08lx%08lx",
             (unsigned long)tv.tv_sec,
             (unsigned long)tv.tv_usec,
             (unsigned long)ngx_pid);

    /* Phase 39 (WS8/HTTP-2): before creating this upload's staging dir,
     * opportunistically reap abandoned staging dirs in the SAME directory whose
     * mtime is idle past xrootd_s3_mpu_max_age (a client that never sent
     * Complete/Abort).  Bounded to one readdir; off (0) by default. */
    if (cf->mpu_max_age > 0) {
        (void) s3_mpu_reap_stale(r, cf, fs_path, (time_t) cf->mpu_max_age);
    }

    s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));

    if (xrootd_mkdir_confined_canon(r->connection->log, cf->common.root_canon,
                                    mpu_dir, 0700) != 0)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, errno,
                             "s3 initiate_mpu: mkdir(\"%s\") failed", mpu_dir);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Build the XML response body */
    xml_len = (size_t)snprintf(xml_buf, sizeof(xml_buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<InitiateMultipartUploadResult"
        " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
        "  <Bucket>%s</Bucket>\n"
        "  <Key>%s</Key>\n"
        "  <UploadId>%s</UploadId>\n"
        "</InitiateMultipartUploadResult>\n",
        cf->bucket.data ? (const char *)cf->bucket.data : "default",
        key_str,
        upload_id);

    if (xml_len >= sizeof(xml_buf)) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml_buf, xml_len);
    b->last     = b->pos + xml_len;
    b->last_buf = 1;

    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), b);
}

