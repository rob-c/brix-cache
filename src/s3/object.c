#include "s3.h"
#include "usermeta.h"
#include "fs/cache/open.h"
#include "core/compat/http_file_response.h"
#include "core/compat/http_headers.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs.h"
#include "shared/file_serve.h"
#include "shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "zip/zip_http.h"   /* phase-57 W2: ZIP member access over S3 GET */

/* GetObject range/bytes metrics — shared by the inline serve and the off-loop
 * serve completion (xrootd_http_serve_offload), so both report identically. */
static void
s3_serve_metrics(ngx_http_request_t *r,
    const xrootd_http_serve_result_t *result)
{
    if (result->range_result == XROOTD_SERVE_RANGE_UNSATISFIED) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_UNSATISFIED]);
    } else if (result->range_result == XROOTD_SERVE_RANGE_PARTIAL) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
    } else {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
    }
    if (result->bytes_sent > 0) {
        XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) result->bytes_sent);
        if (r->connection && r->connection->sockaddr
            && r->connection->sockaddr->sa_family == AF_INET6) {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv6_total, (size_t) result->bytes_sent);
        } else {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv4_total, (size_t) result->bytes_sent);
        }
    }
}

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * GET /bucket/key - file download with Range support
 * */

static void
s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    int                    is_tls = 0;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
}

/* Re-entry state for the off-event-loop cache fill: GetObject needs its absolute
 * fs_path + loc_conf to re-serve, so unlike WebDAV (which re-resolves from r) the
 * trampoline carries them. Both are copied onto r->pool so they outlive the
 * worker-thread fill. */
typedef struct {
    const char             *fs_path;
    ngx_http_s3_loc_conf_t *cf;
} s3_get_reenter_t;

static ngx_int_t
s3_get_reenter(ngx_http_request_t *r, void *data)
{
    s3_get_reenter_t *d = data;
    return s3_handle_get(r, d->fs_path, d->cf);
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

    /* Phase-57 W2: ZIP member access.  Auth/key resolution already happened in
     * the dispatcher; serve the requested member of the archive object. */
    if (cf->zip_access) {
        char member[PATH_MAX];
        int  zr = xrootd_zip_http_member_arg(r, member, sizeof(member));
        if (zr < 0) {
            return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                                     "invalid xrdcl.unzip member");
        }
        if (zr > 0) {
            ngx_int_t zs = xrootd_zip_http_serve(r, cf->common.root_canon,
                                                 cf->zip_cd_max_bytes,
                                                 fs_path, member);
            if (zs == NGX_HTTP_NOT_FOUND) {
                return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                               "The specified key does not exist.",
                               XROOTD_S3_EVENT_NO_SUCH_KEY);
            }
            return zs;
        }
    }

    s3_vfs_ctx(r, fs_path, cf, &vctx);

    /*
     * Tape residency (phase-64 VFS seam): a GET of a nearline/offline object cannot
     * be served from disk — S3/Glacier semantics require an explicit restore first
     * (the WLCG Tape REST API), so report InvalidObjectState rather than faulting a
     * recall. Checked BEFORE any open/fill so a tape-resident object never triggers
     * a stage on a plain GET. An export with no nearline tier ⇒ ONLINE (a plain
     * disk/object export is unaffected).
     */
    {
        xrootd_sd_residency_t res;
        if (xrootd_vfs_residency(&vctx, &res, NULL) == NGX_OK
            && (res == XROOTD_SD_RES_NEARLINE || res == XROOTD_SD_RES_OFFLINE))
        {
            return s3_fail(r, NGX_HTTP_FORBIDDEN, "InvalidObjectState",
                "The operation is not valid for the object's storage class.",
                XROOTD_S3_EVENT_ACCESS_DENIED);
        }
    }

    /* phase-64 SP3: serving from a socket-wire backend (a root:// primary backend
     * or a cache_store/stage_store served from one) cannot open/read on the event
     * loop - run the whole open+read off-loop, materialise + sendfile. See
     * webdav/get.c. NGX_DECLINED ⇒ not a socket serve; fall through. */
    {
        xrootd_http_serve_opts_t sopts;
        ngx_int_t                sr;

        ngx_memzero(&sopts, sizeof(sopts));
        sopts.xfer_proto = XROOTD_XFER_PROTO_S3;
        sopts.op_name    = "GetObject";
        sopts.identity   = "";
        sopts.etag_flags = 0;
        sopts.compress   = cf->common.compress;

        sr = xrootd_http_serve_offload_remote(r, vctx.sd,
            xrootd_vfs_export_relative(&vctx, fs_path), fs_path, &sopts,
            &cf->common, s3_serve_metrics);
        if (sr == NGX_DONE) {
            return NGX_DONE;
        }
        if (sr == NGX_ERROR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* phase-64 SP2: offload a remote cache MISS fill to the thread pool (it would
     * otherwise stall the worker inside xrootd_vfs_open's inline fill) and re-
     * enter on completion. See webdav/get.c. NGX_DECLINED ⇒ open inline below. */
    {
        s3_get_reenter_t *rd = ngx_palloc(r->pool, sizeof(*rd));
        char             *fp;
        size_t            fplen;
        ngx_int_t         fr;

        if (rd == NULL) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        fplen = ngx_strlen(fs_path);
        fp = (char *) ngx_pnalloc(r->pool, fplen + 1);
        if (fp == NULL) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(fp, fs_path, fplen + 1);
        rd->fs_path = fp;
        rd->cf      = cf;

        fr = xrootd_http_cache_fill_if_needed(r, vctx.sd,
            xrootd_vfs_export_relative(&vctx, fs_path), &cf->common,
            s3_get_reenter, rd);
        if (fr == NGX_DONE) {
            return NGX_DONE;
        }
        if (fr == NGX_ERROR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        if (vfs_err == ENOENT || vfs_err == ENOTDIR) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           XROOTD_S3_EVENT_NO_SUCH_KEY);
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
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       XROOTD_S3_EVENT_NO_SUCH_KEY);
    }

    /*
     * Conditional GET (If-Match / If-None-Match / If-(Un)Modified-Since).  On a
     * 304/412 short-circuit we must release the handle we opened above; on
     * NGX_DECLINED we fall through to serve the object.
     */
    {
        ngx_int_t crc = s3_handle_conditional(r, vst.mtime, vst.size);
        if (crc != NGX_DECLINED) {
            xrootd_vfs_close(fh, r->connection->log);
            return crc;
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

        if (cfd != NGX_INVALID_FILE) {
            s3_echo_object_checksums(r, cfd, fs_path);
        }
    }

    /* User metadata (x-amz-meta-*): echo the stored set before the response
     * headers are sent (the handle stays open until serve sends them). */
    s3_echo_user_metadata(r, fs_path);

    {
        xrootd_http_serve_opts_t   opts;
        xrootd_http_serve_result_t result;

        ngx_memzero(&opts, sizeof(opts));
        opts.xfer_proto = XROOTD_XFER_PROTO_S3;
        opts.op_name    = "GetObject";
        opts.identity   = identity;
        opts.etag_flags = 0;
        opts.compress   = cf->common.compress;
        /* phase-43 W3: apply response-* query overrides just before send. */
        opts.pre_header_send = s3_get_pre_header;

        rc = xrootd_http_serve_file_ranged(r, fh, &vst, fs_path, &opts,
                                           &result);

        if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        }
        s3_serve_metrics(r, &result);
    }

    return rc;
}

/*
 * HEAD /bucket/key - metadata only
 * */

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
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           XROOTD_S3_EVENT_NO_SUCH_KEY);
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) xrootd_http_errno_to_status(errno);
    }

    if (vst.is_directory) {
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       XROOTD_S3_EVENT_NO_SUCH_KEY);
    }

    /*
     * Tape residency (phase-64 VFS seam): advertise the GLACIER storage class for a
     * nearline object so clients learn a restore is required before a GET. HEAD
     * still returns 200 (metadata only); x-amz-restore reports no active restore
     * (the restore flow is the WLCG Tape REST API, not S3 GET).
     */
    {
        xrootd_sd_residency_t res;
        if (xrootd_vfs_residency(&vctx, &res, NULL) == NGX_OK
            && (res == XROOTD_SD_RES_NEARLINE || res == XROOTD_SD_RES_OFFLINE))
        {
            (void) xrootd_http_set_header(r, "x-amz-storage-class",
                                          "GLACIER", NULL);
            (void) xrootd_http_set_header(r, "x-amz-restore",
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
        xrootd_vfs_ctx_t   vctx;
        xrootd_vfs_file_t *fh;

        s3_vfs_ctx(r, fs_path, cf, &vctx);
        fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, NULL);
        if (fh != NULL) {
            s3_echo_object_checksums(r, xrootd_vfs_file_fd(fh), fs_path);
            xrootd_vfs_close(fh, r->connection->log);
        }
    }

    /* User metadata (x-amz-meta-*): echo the stored set on HEAD. */
    s3_echo_user_metadata(r, fs_path);

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
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INVALID_URI]);
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
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
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
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    response_buf->last = ngx_cpymem(response_buf->last, xml, xml_len);
    response_buf->last_buf = 1;

    XROOTD_S3_METRIC_ADD(bytes_tx_total, xml_len);
    return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
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
    xrootd_vfs_ctx_t vctx;
    ngx_int_t        rc;

    /* Route DELETE through the metered VFS unlink. xrootd_vfs_unlink unlinks a
     * file and rmdirs an (empty) directory — a non-empty dir surfaces as
     * ENOTEMPTY (S3 BucketNotEmpty), exactly as the old require_empty_dir path.
     * S3 DELETE is idempotent: a missing key (ENOENT) is still 204, and counts
     * as DELETE_MISSING. errno is read only on the NGX_ERROR branch. */
    s3_vfs_ctx(r, fs_path, cf, &vctx);
    rc = xrootd_vfs_unlink(&vctx);

    if (rc == NGX_OK || errno == ENOENT) {
        if (rc != NGX_OK) {   /* ENOENT: the object did not exist */
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DELETE_MISSING]);
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

    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 * WHY: S3 DELETE is idempotent — deleting a non-existent key returns 204 No Content (not 404), matching AWS behavior. This allows clients to safely retry delete operations without checking existence first.
 *
 * HOW: Routes the delete through the metered VFS surface (xrootd_vfs_unlink, which
 * unlinks a file and rmdirs an empty directory under root confinement). On success
 * sends a 204 No Content header-only response via ngx_http_send_special(); a missing
 * key (ENOENT) is still 204 (AWS-style idempotency) and increments DELETE_MISSING; a
 * non-empty directory (ENOTEMPTY) → 409 BucketNotEmpty; any other errno → internal_error
 * metric + 500.
 */
