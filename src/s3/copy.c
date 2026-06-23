/*
 * copy.c — S3 CopyObject handler.
 *
 * PUT /bucket/dest-key  +  x-amz-copy-source: /bucket/src-key
 *
 * Performs a server-side copy using copy_file_range (with read/write fallback),
 * then returns a CopyObjectResult XML body containing the new object's ETag and
 * LastModified timestamp.  Source and destination are both confined to the
 * configured root_canon to prevent path-traversal.
 */
/* WHY: S3 CopyObject enables zero-copy server-side duplication — the source and
 * destination are both confined to root_canon, avoiding client download/upload
 * round-trip. copy_file_range provides kernel-level zero-copy when filesystems
 * support it; read/write fallback ensures portability across filesystem types.
 * Staged commit (write to temp file then rename) prevents partial writes from
 * being visible to concurrent readers. */

#include "s3.h"
#include "../compat/copy_range.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include "../compat/alloc_guard.h"

static const char *
s3_copy_find_header(ngx_http_request_t *r, const char *name, size_t nlen)
{
    ngx_table_elt_t *h;
    u_char          *value;

    h = xrootd_http_find_header(r, name, nlen);
    if (h == NULL) {
        return NULL;
    }

    XROOTD_PNALLOC_OR_RETURN(value, r->pool, h->value.len + 1, NULL);

    ngx_memcpy(value, h->value.data, h->value.len);
    value[h->value.len] = '\0';
    return (const char *) value;
}

ngx_int_t
s3_handle_copy_object(ngx_http_request_t *r,
                      const char *dst_fs_path,
                      ngx_http_s3_loc_conf_t *cf)
{
    const char           *copy_src_hdr;
    const char           *src_key;
    char                  src_fs_path[PATH_MAX];
    struct stat           dst_sb;
    xrootd_ns_result_t    res;
    xrootd_ns_copy_opts_t opts;
    char                  etag_buf[48];
    char                  iso_buf[32];
    char                  xml_buf[512];
    size_t                xml_len;
    ngx_buf_t            *b;

    copy_src_hdr = s3_copy_find_header(r, "x-amz-copy-source",
                                       sizeof("x-amz-copy-source") - 1);
    if (copy_src_hdr == NULL) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Missing x-amz-copy-source header.");
    }

    /* Strip optional leading '/' then skip the bucket prefix component */
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
    if (*src_key == '\0') {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Invalid copy source key.");
    }

    /* Resolve source path — must stay within root_canon */
    if (!s3_resolve_key(cf->common.root_canon, src_key, src_fs_path,
                        sizeof(src_fs_path)))
    {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_ACCESS_DENIED]);
        return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                 "AccessDenied",
                                 "Copy source path is not accessible.");
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.overwrite     = 1;
    opts.staged_commit = 1;

    res = xrootd_ns_local_copy(r->connection->log, cf->common.root_canon,
                               src_fs_path, dst_fs_path, &opts);

    if (res.status != XROOTD_NS_OK) {
        if (res.status == XROOTD_NS_NOT_FOUND) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey",
                                     "The copy source does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stat(dst_fs_path, &dst_sb) != 0) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s3_etag(&dst_sb, etag_buf, sizeof(etag_buf));
    xrootd_format_iso8601(dst_sb.st_mtime, iso_buf, sizeof(iso_buf));

    xml_len = (size_t) snprintf(xml_buf, sizeof(xml_buf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<CopyObjectResult "
        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<ETag>%s</ETag>"
        "<LastModified>%s</LastModified>"
        "</CopyObjectResult>",
        etag_buf, iso_buf);

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last     = ngx_cpymem(b->pos, xml_buf, xml_len);
    b->last_buf = 1;

    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), b);
}
