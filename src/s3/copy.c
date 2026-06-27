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
#include "../fs/vfs.h"
#include "../path/path.h"
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

/* Build a transient VFS ctx for a confined S3 op on `fs_path` (mirrors the
 * canonical s3_vfs_ctx in object.c). */
static void
s3_copy_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
}

ngx_int_t
s3_handle_copy_object(ngx_http_request_t *r,
                      const char *dst_fs_path,
                      ngx_http_s3_loc_conf_t *cf)
{
    const char            *copy_src_hdr;
    const char            *src_key;
    char                   src_fs_path[PATH_MAX];
    struct stat            dst_sb;
    xrootd_vfs_ctx_t       vctx;
    xrootd_vfs_copy_opts_t copy_opts;
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
        return s3_fail(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                       "Copy source path is not accessible.",
                       XROOTD_S3_EVENT_ACCESS_DENIED);
    }

    /* Route the single-file copy through the metered VFS surface (OP_COPY).
     * src = ctx path, dst passed explicitly; both confined under root_canon. */
    s3_copy_vfs_ctx(r, src_fs_path, cf, &vctx);
    ngx_memzero(&copy_opts, sizeof(copy_opts));
    copy_opts.overwrite     = 1;
    copy_opts.staged_commit = 1;

    if (xrootd_vfs_copy(&vctx, dst_fs_path, &copy_opts) != NGX_OK) {
        if (errno == ENOENT) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The copy source does not exist.",
                           XROOTD_S3_EVENT_NO_SUCH_KEY);
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Confined (no-follow) stat of the freshly-copied destination for the ETag —
     * dst_fs_path is under root_canon but a raw stat() would follow a symlink. */
    if (xrootd_lstat_confined_canon(r->connection->log, cf->common.root_canon,
                                    dst_fs_path, &dst_sb, 1) != 0) {
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
