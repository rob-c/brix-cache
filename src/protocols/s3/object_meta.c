#include "s3.h"
#include "usermeta.h"
#include "fs/cache/open.h"
#include "core/http/http_file_response.h"
#include "core/http/http_headers.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "protocols/shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "protocols/root/zip/zip_http.h"   /* phase-57 W2: ZIP member access over S3 GET */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "object_internal.h"

/*
 * HEAD /bucket/key - metadata only
 * */

ngx_int_t
s3_handle_head(ngx_http_request_t *r,
               const char *fs_path,
               ngx_http_s3_loc_conf_t *cf)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;

    s3_vfs_ctx(r, fs_path, cf, &vctx);
    if (brix_vfs_stat(&vctx, &vst) != NGX_OK) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           BRIX_S3_EVENT_NO_SUCH_KEY);
        }
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) brix_http_errno_to_status(errno);
    }

    if (vst.is_directory) {
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       BRIX_S3_EVENT_NO_SUCH_KEY);
    }

    /*
     * Tape residency (phase-64 VFS seam): advertise the GLACIER storage class for a
     * nearline object so clients learn a restore is required before a GET. HEAD
     * still returns 200 (metadata only); x-amz-restore reports no active restore
     * (the restore flow is the WLCG Tape REST API, not S3 GET).
     */
    {
        brix_sd_residency_t res;
        if (brix_vfs_residency(&vctx, &res, NULL) == NGX_OK
            && (res == BRIX_SD_RES_NEARLINE || res == BRIX_SD_RES_OFFLINE))
        {
            (void) brix_http_set_header(r, "x-amz-storage-class",
                                          "GLACIER", NULL);
            (void) brix_http_set_header(r, "x-amz-restore",
                                          "ongoing-request=\"false\"", NULL);
        }
    }

    /* Conditional HEAD (If-Match / If-None-Match / If-(Un)Modified-Since). */
    {
        ngx_int_t crc = s3_handle_conditional(r, vst.mtime, vst.size);
        if (crc != NGX_DECLINED) {
            return crc;
        }
    }

    /*
     * AWS full-object checksum echo (x-amz-checksum-crc64nvme). Cache-only: a
     * cheap confined open + getxattr (no full-file read) emits the value stored
     * at upload time; absent ⇒ no header, exactly as AWS behaves when no checksum
     * was set at upload.
     */
    {
        brix_vfs_ctx_t   vctx;
        brix_vfs_file_t *fh;

        s3_vfs_ctx(r, fs_path, cf, &vctx);
        fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, NULL);
        if (fh != NULL) {
            s3_echo_object_checksums(r, brix_vfs_file_fd(fh), fs_path);
            brix_vfs_close(fh, r->connection->log);
        }
    }

    /* User metadata (x-amz-meta-*): echo the stored set on HEAD. */
    s3_echo_user_metadata(r, fs_path);

    if (brix_http_set_file_headers(r, vst.mtime, vst.size, vst.size,
                                     NULL, 0,
                                     0, 0, 0) != NGX_OK)
    {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
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

/*
 * HEAD /bucket  -> HeadBucket
 * */

/*
 * s3_handle_head_bucket — answer a HEAD on the bucket root.
 *
 * WHAT: AWS SDKs (boto3, rclone, s5cmd, mc) issue HEAD /<bucket> at session
 *   start to confirm the bucket exists and learn its region before any object
 *   operation.  Returns 200 + x-amz-bucket-region when the configured export
 *   root is a directory, else 404 NoSuchBucket.
 * WHY:  Without this the empty-key guard answered 400 InvalidURI and an
 *   unmodified SDK client aborted the whole session.
 * HOW:  stat() the already-canonical, confinement-anchored export root (it is
 *   the bucket); no key is involved, so no per-request path resolution is
 *   needed.  Header-only response.
 */
ngx_int_t
s3_handle_head_bucket(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    struct stat st;

    if (cf->common.root_canon[0] == '\0'
        || stat(cf->common.root_canon, &st) != 0  /* vfs-seam-allow: HeadBucket stats the export root itself (the confinement anchor), not a path beneath it */
        || !S_ISDIR(st.st_mode))
    {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
        r->headers_out.status           = NGX_HTTP_NOT_FOUND;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (cf->region.len > 0) {
        char   region[64];
        size_t n = cf->region.len < sizeof(region) - 1
                   ? cf->region.len : sizeof(region) - 1;
        ngx_memcpy(region, cf->region.data, n);
        region[n] = '\0';
        (void) s3_set_header(r, "x-amz-bucket-region", region);
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * GET /bucket?location  -> GetBucketLocation
 * */

/*
 * s3_handle_get_bucket_location — answer GET /<bucket>?location.
 *
 * WHAT: Region-discovery probe.  Many SDKs call this to decide which endpoint
 *   to sign against; a failure aborts the client.  Emits the LocationConstraint
 *   document carrying the configured region (empty element for "us-east-1",
 *   matching AWS, since us-east-1 has no explicit constraint).
 * WHY:  Cheap probe-satisfier; pairs with HeadBucket so unmodified SDK clients
 *   complete their pre-flight.
 * HOW:  The region is config-supplied (trusted, no XML metacharacters), so it
 *   is appended directly into the element body.
 */
ngx_int_t
s3_handle_get_bucket_location(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    u_char    *xml;
    size_t     xml_len = 0;
    size_t     xml_capacity = 256 + cf->region.len;
    ngx_buf_t *response_buf;
    int        is_default;

    is_default = (cf->region.len == 0
                  || (cf->region.len == sizeof("us-east-1") - 1
                      && ngx_strncmp(cf->region.data,
                                     (u_char *) "us-east-1",
                                     cf->region.len) == 0));

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (is_default) {
        XML_APPEND("<LocationConstraint "
                   "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>");
    } else {
        XML_APPEND("<LocationConstraint "
                   "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">%.*s"
                   "</LocationConstraint>",
                   (int) cf->region.len, (const char *) cf->region.data);
    }

    response_buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (response_buf == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    response_buf->last = ngx_cpymem(response_buf->last, xml, xml_len);
    response_buf->last_buf = 1;

    BRIX_S3_METRIC_ADD(bytes_tx_total, xml_len);
    return brix_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), response_buf);
}

/*
 * DELETE /bucket/key
 * */

ngx_int_t
s3_handle_delete(ngx_http_request_t *r,
                 const char *fs_path,
                 ngx_http_s3_loc_conf_t *cf)
{
    brix_vfs_ctx_t vctx;
    ngx_int_t        rc;

    /* Route DELETE through the metered VFS unlink. brix_vfs_unlink unlinks a
     * file and rmdirs an (empty) directory — a non-empty dir surfaces as
     * ENOTEMPTY (S3 BucketNotEmpty), exactly as the old require_empty_dir path.
     * S3 DELETE is idempotent: a missing key (ENOENT) is still 204, and counts
     * as DELETE_MISSING. errno is read only on the NGX_ERROR branch. */
    s3_vfs_ctx(r, fs_path, cf, &vctx);
    rc = brix_vfs_unlink(&vctx);

    if (rc == NGX_OK || errno == ENOENT) {
        if (rc != NGX_OK) {   /* ENOENT: the object did not exist */
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_DELETE_MISSING]);
        }
        r->headers_out.status           = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (errno == ENOTEMPTY) {
        return s3_send_xml_error(r, NGX_HTTP_CONFLICT,
                                 "BucketNotEmpty",
                                 "The directory is not empty.");
    }

    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 * WHY: S3 DELETE is idempotent — deleting a non-existent key returns 204 No Content (not 404), matching AWS behavior. This allows clients to safely retry delete operations without checking existence first.
 *
 * HOW: Routes the delete through the metered VFS surface (brix_vfs_unlink, which
 * unlinks a file and rmdirs an empty directory under root confinement). On success
 * sends a 204 No Content header-only response via ngx_http_send_special(); a missing
 * key (ENOENT) is still 204 (AWS-style idempotency) and increments DELETE_MISSING; a
 * non-empty directory (ENOTEMPTY) → 409 BucketNotEmpty; any other errno → internal_error
 * metric + 500.
 */
