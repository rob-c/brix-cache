/*
 * multipart_complete_upload_part_copy.c — S3 UploadPartCopy handler.
 *
 * WHAT: This fragment implements the PUT /bucket/key?partNumber=N&uploadId=<id> + x-amz-copy-source header
 *   → UploadPartCopy operation, which copies a part from a source object into the staging directory of an
 *   active multipart upload. It contains two components:
 *     - s3_find_request_header_value(): helper that locates a named request header via brix_http_find_header(),
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
#include "fs/vfs/vfs.h"   /* confined source open via the VFS seam */
#include "core/http/http_headers.h"
#include "fs/backend/sd.h"   /* route the part-copy byte move through the SD backend */

#include <string.h>
#include "core/compat/cstr.h"

/*
 * PUT /bucket/key?partNumber=N&uploadId=<id>  +  x-amz-copy-source header
 * →  UploadPartCopy
 * */

/*
 * s3_upcp_req_t — file-local bundle of the UploadPartCopy request inputs.
 *
 * WHAT: Groups the invariant per-request handles (request, loc conf, target
 *   fs_path, upload_id, part_num) so the resolve stages take one ctx pointer
 *   instead of a long positional argument list.
 * WHY: Keeps each helper at ≤5 params without introducing globals; the fields
 *   are exactly the handler's own arguments, passed by reference.
 * HOW: Populated once at the top of s3_handle_upload_part_copy() and shared
 *   read-only across the resolve helpers.
 */
typedef struct {
    ngx_http_request_t     *r;
    ngx_http_s3_loc_conf_t *cf;
    const char             *fs_path;
    const char             *upload_id;
    int                     part_num;
} s3_upcp_req_t;

static const char *
s3_find_request_header_value(ngx_http_request_t *r, const char *name,
    size_t name_len)
{
    ngx_table_elt_t *h;
    u_char          *value;

    h = brix_http_find_header(r, name, name_len);
    if (h == NULL) {
        return NULL;
    }

    value = (u_char *) brix_pstrdup_z(r->pool, &h->value);
    if (value == NULL) {
        return NULL;
    }

    return (const char *) value;
}

/*
 * s3_copy_source_key() — extract the source object key from x-amz-copy-source.
 *
 * WHAT: Strips a single leading '/' then skips the bucket-name prefix component
 *   (everything up to and including the first remaining '/'), returning a pointer
 *   into the header string at the start of the object key.
 * WHY: x-amz-copy-source names a source as "/bucket/key" (or "bucket/key"); the
 *   handler resolves paths relative to the export root, so only the key survives.
 * HOW: Pointer arithmetic over the caller-owned header buffer — no allocation,
 *   no mutation; the returned pointer aliases into copy_src_hdr.
 */
static const char *
s3_copy_source_key(const char *copy_src_hdr)
{
    const char *src_key = copy_src_hdr;
    const char *slash;

    if (*src_key == '/') {
        src_key++;
    }

    slash = strchr(src_key, '/');
    if (slash != NULL) {
        src_key = slash + 1;
    }

    return src_key;
}

/*
 * s3_resolve_copy_source() — build + validate + probe the copy-source object.
 *
 * WHAT: Composes the absolute source path from root_canon + key, applies the
 *   string escape checks ("/../" reject + root_canon prefix), then probes the
 *   source through the confined resolver (no-follow) requiring a regular file.
 *   On success fills *sctx (ready to open) and returns NGX_OK; on any failure it
 *   emits the appropriate S3 XML error and returns NGX_DONE.
 * WHY: This is the security-load-bearing source-auth stage. The string checks
 *   alone do NOT stop an in-bucket symlink, so the confined probe (openat2
 *   RESOLVE_BENEATH) is mandatory before the byte copy trusts the source.
 * HOW: snprintf into a caller-owned PATH_MAX buffer, early-return on each guard
 *   with the exact error mapping the original inline code used.
 */
static ngx_int_t
s3_resolve_copy_source(const s3_upcp_req_t *req, const char *src_key,
    char *src_fs_path, size_t src_fs_path_sz, brix_vfs_ctx_t *sctx)
{
    ngx_http_request_t     *r  = req->r;
    ngx_http_s3_loc_conf_t *cf = req->cf;
    brix_vfs_stat_t         svst;

    ngx_memzero(&svst, sizeof(svst));

    if ((size_t) snprintf(src_fs_path, src_fs_path_sz, "%s/%s",
                          cf->common.root_canon, src_key) >= src_fs_path_sz
        || strstr(src_fs_path, "/../") != NULL
        || strncmp(src_fs_path, cf->common.root_canon,
                   strlen(cf->common.root_canon)) != 0)
    {
        (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Invalid copy source path.");
        return NGX_DONE;
    }

    /* Confinement: stat the source through the confined resolver (openat2
     * RESOLVE_BENEATH, no-follow) — the strstr/strncmp checks above do NOT stop
     * a planted in-bucket symlink, so a raw stat() here would follow it out of
     * the export root (the same hole the open() below was hardened against). */
    s3_build_vfs_ctx(r, src_fs_path, cf, sctx);
    if (brix_vfs_probe(sctx, 1 /* no-follow */, &svst) != NGX_OK
        || !svst.is_regular)
    {
        (void) s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey",
                                 "The specified copy source does not exist.");
        return NGX_DONE;
    }

    return NGX_OK;
}

/*
 * s3_resolve_part_target() — validate uploadId, probe the MPU dir, build part path.
 *
 * WHAT: Validates the upload_id syntax, derives the staging directory, probes it
 *   through the VFS seam for existence, then formats the destination part path.
 *   Returns NGX_OK with part_path filled, or NGX_DONE after emitting the matching
 *   S3 XML error (InvalidArgument uploadId / NoSuchUpload).
 * WHY: The write target must exist as an active upload before we open the part
 *   file; keeping this validation together mirrors the original ordering exactly.
 * HOW: Reuses the request bundle's fs_path/upload_id/part_num; probes with a
 *   local vfs ctx so the source ctx is untouched; early-return on each guard.
 */
static ngx_int_t
s3_resolve_part_target(const s3_upcp_req_t *req, char *part_path,
    size_t part_path_sz)
{
    ngx_http_request_t     *r  = req->r;
    ngx_http_s3_loc_conf_t *cf = req->cf;
    char                    mpu_dir[PATH_MAX];
    brix_vfs_ctx_t          uctx;
    brix_vfs_stat_t         svst;
    u_char                 *p;

    ngx_memzero(&svst, sizeof(svst));

    if (!mpu_validate_upload_id(req->upload_id)) {
        (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "The uploadId is invalid.");
        return NGX_DONE;
    }

    /* Confinement + existence: mpu_dir from s3_get_mpu_dir() (validated upload_id +
     * confined fs_path). Probe it through the VFS seam rather than a raw stat —
     * absent → 404 NoSuchUpload. */
    s3_get_mpu_dir(req->fs_path, req->upload_id, mpu_dir, sizeof(mpu_dir));
    s3_build_vfs_ctx(r, mpu_dir, cf, &uctx);
    if (brix_vfs_probe(&uctx, 1 /* nofollow */, &svst) != NGX_OK) {
        (void) s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchUpload",
                                 "The specified upload does not exist.");
        return NGX_DONE;
    }

    p = ngx_snprintf((u_char *) part_path, part_path_sz - 1,
                     "%s/part.%z", mpu_dir, (size_t) req->part_num);
    *p = '\0';

    return NGX_OK;
}

/*
 * s3_copy_bytes() — stream the source object into the destination part fd.
 *
 * WHAT: Reads the confined source fd and writes the destination fd via the SD
 *   driver pread/pwrite seam in 64KB positional chunks with EINTR retry, until
 *   the source is exhausted. Returns 0 on success, -1 on an unrecoverable write
 *   error (caller handles cleanup + metric + error status).
 * WHY: Isolating the copy loop keeps the driver-level byte move (backend↔backend,
 *   POSIX today, positional so a non-POSIX backend slots in) in one focused unit.
 * HOW: Nested read/write loops over a caller-supplied fd pair; no ownership of
 *   the fds and no error emission — purely the transfer with a boolean outcome.
 */
static int
s3_copy_bytes(int src_fd, int dst_fd, char *iobuf, size_t iobuf_sz)
{
    off_t         src_off = 0, dst_off = 0;
    ssize_t       nr;
    brix_sd_obj_t src_obj, dst_obj;

    brix_sd_posix_wrap(&src_obj, src_fd);
    brix_sd_posix_wrap(&dst_obj, dst_fd);

    while ((nr = src_obj.driver->pread(&src_obj, iobuf, iobuf_sz,
                                       src_off)) > 0) {
        char   *wbuf      = iobuf;
        ssize_t remaining = nr;
        while (remaining > 0) {
            ssize_t nw = dst_obj.driver->pwrite(&dst_obj, wbuf,
                                                (size_t) remaining, dst_off);
            if (nw <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            wbuf      += nw;
            remaining -= nw;
            dst_off   += nw;
        }
        src_off += nr;
    }

    return 0;
}

/*
 * s3_send_copy_part_result() — build + send the CopyPartResult XML body.
 *
 * WHAT: Derives ETag ("mtime-size") and ISO 8601 LastModified from the written
 *   part's stat, formats the CopyPartResult document into a pool buffer, and
 *   sends it as application/xml with 200 OK.
 * WHY: The success response is a self-contained rendering stage with no I/O side
 *   effects, so it composes cleanly at the edge after the byte move completes.
 * HOW: snprintf into a local buffer, copy into an ngx pool temp buf, delegate to
 *   the shared XML sender; returns its status (or InternalError on OOM).
 */
static ngx_int_t
s3_send_copy_part_result(ngx_http_request_t *r, const struct stat *part_sb)
{
    char       xml_buf[512];
    char       etag_buf[64];
    char       iso_buf[32];
    ngx_buf_t *b;
    size_t     xml_len;

    s3_etag(part_sb, etag_buf, sizeof(etag_buf));
    brix_format_iso8601(part_sb->st_mtime, iso_buf, sizeof(iso_buf));

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
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml_buf, xml_len);
    b->last     = b->pos + xml_len;
    b->last_buf = 1;

    return brix_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), b);
}

ngx_int_t
s3_handle_upload_part_copy(ngx_http_request_t *r,
                            const char *fs_path,
                            ngx_http_s3_loc_conf_t *cf,
                            const char *upload_id,
                            int part_num)
{
    const char      *copy_src_hdr;
    const char      *src_key;
    char             src_fs_path[PATH_MAX];
    char             part_path[PATH_MAX];
    char             iobuf[65536];
    struct stat      part_sb;    /* fstat of the written part fd (ETag size/mtime) */
    brix_vfs_ctx_t   sctx;       /* copy SOURCE ctx (probe + open below)          */
    brix_vfs_file_t *fh_src;
    int              dst_fd;
    ngx_int_t        rc;
    s3_upcp_req_t    req;

    ngx_memzero(&part_sb, sizeof(part_sb));

    req.r         = r;
    req.cf        = cf;
    req.fs_path   = fs_path;
    req.upload_id = upload_id;
    req.part_num  = part_num;

    copy_src_hdr = s3_find_request_header_value(
        r, "x-amz-copy-source", sizeof("x-amz-copy-source") - 1);
    if (copy_src_hdr == NULL) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                 "InvalidArgument",
                                 "Missing x-amz-copy-source header.");
    }

    src_key = s3_copy_source_key(copy_src_hdr);

    /* Source-object auth (security-load-bearing): validate + confined-probe the
     * copy source BEFORE the upload target is resolved or opened. */
    rc = s3_resolve_copy_source(&req, src_key, src_fs_path,
                                sizeof(src_fs_path), &sctx);
    if (rc != NGX_OK) {
        return NGX_OK;   /* error already emitted (returns NGX_OK to nginx) */
    }

    rc = s3_resolve_part_target(&req, part_path, sizeof(part_path));
    if (rc != NGX_OK) {
        return NGX_OK;   /* error already emitted */
    }

    /* Copy source file → part file.  Open the source through the confined
     * resolver (openat2 RESOLVE_BENEATH): this refuses to follow a symlink out
     * of the export root and rejects any path that escapes it. */
    fh_src = brix_vfs_open(&sctx, BRIX_VFS_O_READ, NULL);
    if (fh_src == NULL) {
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                                 "The specified copy source does not exist.");
    }

    dst_fd = brix_vfs_open_fd(r->connection->log, cf->common.root_canon,
                               part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                               0600);
    if (dst_fd < 0) {
        brix_vfs_close(fh_src, r->connection->log);
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (s3_copy_bytes(brix_vfs_file_fd(fh_src), dst_fd,
                      iobuf, sizeof(iobuf)) != 0) {
        brix_vfs_close(fh_src, r->connection->log);
        close(dst_fd);
        (void) brix_vfs_unlink_path(r->connection->log,
                                    cf->common.root_canon, part_path);
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_vfs_close(fh_src, r->connection->log);

    /* ETag/mtime from the part fd we just wrote (metadata on a VFS-opened confined
     * fd — no raw path stat) before we release it. */
    if (fstat(dst_fd, &part_sb) != 0) {
        close(dst_fd);
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    close(dst_fd);

    return s3_send_copy_part_result(r, &part_sb);
}
