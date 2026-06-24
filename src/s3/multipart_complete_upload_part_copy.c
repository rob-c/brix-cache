/*
 * multipart_complete_upload_part_copy.c — S3 UploadPartCopy handler.
 *
 * WHAT: This fragment implements the PUT /bucket/key?partNumber=N&uploadId=<id> + x-amz-copy-source header
 *   → UploadPartCopy operation, which copies a part from a source object into the staging directory of an
 *   active multipart upload. It contains two components:
 *     - s3_find_request_header_value(): helper that locates a named request header via xrootd_http_find_header(),
 *       extracts its value bytes into a pool-allocated null-terminated string, and returns it for parsing.
 *     - s3_handle_upload_part_copy(): the main handler — parses x-amz-copy-source to extract source object key
 *       (stripping leading "/" then skipping bucket prefix), validates source path against root_canon with ".."
 *   check, opens source file for read and target part file for write, copies via 64KB buffered read/write loop
 *   with EINTR retry, emits CopyPartResult XML with ETag ("mtime-size") and LastModified (ISO 8601). On write
 *   failure: closes both fds, unlinks the partial part file, returns InternalError.
 *
 * WHY: Split from multipart.c to keep UploadPartCopy logic alongside its sibling fragments for CompleteMultipartUpload
 *      operations. The copy-source parsing and buffered file-copy loop are distinct enough from part enumeration and XML
 *   completion that separation keeps each fragment focused on one responsibility.
 */
#include "s3.h"
#include "multipart_internal.h"
#include "../path/path.h"
#include "../compat/http_headers.h"

#include <string.h>
#include "../compat/alloc_guard.h"

/* -------------------------------------------------------------------------
 * PUT /bucket/key?partNumber=N&uploadId=<id>  +  x-amz-copy-source header
 * →  UploadPartCopy
 * ---------------------------------------------------------------------- */

static const char *
s3_find_request_header_value(ngx_http_request_t *r, const char *name,
    size_t name_len)
{
    ngx_table_elt_t *h;
    u_char          *value;

    h = xrootd_http_find_header(r, name, name_len);
    if (h == NULL) {
        return NULL;
    }

    XROOTD_PNALLOC_OR_RETURN(value, r->pool, h->value.len + 1, NULL);

    ngx_memcpy(value, h->value.data, h->value.len);
    value[h->value.len] = '\0';

    return (const char *) value;
}

ngx_int_t
s3_handle_upload_part_copy(ngx_http_request_t *r,
                            const char *fs_path,
                            ngx_http_s3_loc_conf_t *cf,
                            const char *upload_id,
                            int part_num)
{
    const char  *copy_src_hdr;
    const char  *src_key;
    char         src_fs_path[PATH_MAX];
    char         mpu_dir[PATH_MAX];
    char         part_path[PATH_MAX];
    char         xml_buf[512];
    char         etag_buf[64];
    char         iso_buf[32];
    struct stat  src_sb, part_sb;
    int          src_fd, dst_fd;
    ssize_t      nr;
    char         iobuf[65536];
    ngx_buf_t   *b;
    size_t       xml_len;
    u_char      *p;

    copy_src_hdr = s3_find_request_header_value(
        r, "x-amz-copy-source", sizeof("x-amz-copy-source") - 1);
    if (copy_src_hdr == NULL) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Missing x-amz-copy-source header.");
    }

    /* Strip leading '/' then skip the bucket prefix component */
    src_key = copy_src_hdr;
    if (*src_key == '/') {
        src_key++;
    }
    {
        const char *slash = strchr(src_key, '/');
        if (slash != NULL) {
            src_key = slash + 1;
        }
    }

    /* Build and validate source path */
    if ((size_t) snprintf(src_fs_path, sizeof(src_fs_path), "%s/%s",
                          cf->common.root_canon, src_key) >= sizeof(src_fs_path)
        || strstr(src_fs_path, "/../") != NULL
        || strncmp(src_fs_path, cf->common.root_canon,
                   strlen(cf->common.root_canon)) != 0)
    {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Invalid copy source path.");
    }

    /* Confinement: stat the source through the confined resolver (openat2
     * RESOLVE_BENEATH, no-follow) — the strstr/strncmp checks above do NOT stop
     * a planted in-bucket symlink, so a raw stat() here would follow it out of
     * the export root (the same hole the open() below was hardened against). */
    if (xrootd_lstat_confined_canon(r->connection->log, cf->common.root_canon,
                                    src_fs_path, &src_sb, 1) != 0
        || !S_ISREG(src_sb.st_mode))
    {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey",
                                 "The specified copy source does not exist.");
    }

    if (!mpu_validate_upload_id(upload_id)) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "The uploadId is invalid.");
    }

    /* Confinement: mpu_dir from s3_get_mpu_dir() — validated upload_id + confined
     * fs_path. part_path is mpu_dir + "/part.<N>". Bare stat is safe. */
    s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));
    if (stat(mpu_dir, &part_sb) != 0) {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchUpload",
                                 "The specified upload does not exist.");
    }

    p = ngx_snprintf((u_char *) part_path, sizeof(part_path) - 1,
                     "%s/part.%z", mpu_dir, (size_t) part_num);
    *p = '\0';

    /* Copy source file → part file.  Open the source through the confined
     * resolver (openat2 RESOLVE_BENEATH): this refuses to follow a symlink out
     * of the export root and rejects any path that escapes it — the same
     * confinement every other read path uses.  A raw open() here followed a
     * planted in-bucket symlink straight to a host file (e.g. /etc/passwd),
     * which the string checks above (strstr/strncmp) do not catch. */
    src_fd = xrootd_open_confined_canon(r->connection->log,
                                        cf->common.root_canon, src_fs_path,
                                        O_RDONLY, 0);
    if (src_fd < 0) {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                                 "The specified copy source does not exist.");
    }

    dst_fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (dst_fd < 0) {
        close(src_fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((nr = read(src_fd, iobuf, sizeof(iobuf))) > 0) {
        char   *wbuf      = iobuf;
        ssize_t remaining = nr;
        while (remaining > 0) {
            ssize_t nw = write(dst_fd, wbuf, (size_t) remaining);
            if (nw <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(src_fd);
                close(dst_fd);
                unlink(part_path);
                XROOTD_S3_METRIC_INC(
                    events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            wbuf      += nw;
            remaining -= nw;
        }
    }
    close(src_fd);
    close(dst_fd);

    if (stat(part_path, &part_sb) != 0) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s3_etag(&part_sb, etag_buf, sizeof(etag_buf));
    xrootd_format_iso8601(part_sb.st_mtime, iso_buf, sizeof(iso_buf));

    xml_len = (size_t) snprintf(xml_buf, sizeof(xml_buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<CopyPartResult "
        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<ETag>%s</ETag>"
        "<LastModified>%s</LastModified>"
        "</CopyPartResult>",
        etag_buf, iso_buf);

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
