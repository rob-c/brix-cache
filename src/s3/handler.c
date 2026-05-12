/*
 * handler.c — S3 content handler: URI parsing, auth gate, method dispatch,
 *              GET (file download), HEAD, and DELETE.
 */

#include "s3.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

/* -------------------------------------------------------------------------
 * Parse the request URI into bucket + key.
 *
 * Path-style: /<bucket>/<key>
 * List:       /<bucket>/?list-type=2[&prefix=...&delimiter=...&...]
 *
 * Returns:
 *   1  — success
 *   0  — malformed URI (→ 400 InvalidURI)
 *  -1  — bucket name mismatch (→ 404 NoSuchBucket)
 * ---------------------------------------------------------------------- */

static int
s3_parse_uri(ngx_http_request_t *r,
             ngx_http_s3_loc_conf_t *cf,
             u_char *key_out, size_t key_sz)
{
    const u_char *uri  = r->uri.data;
    size_t        ulen = r->uri.len;
    size_t        blen = cf->bucket.len;

    /* must start with "/" */
    if (ulen == 0 || uri[0] != '/') {
        return 0;
    }

    /* strip leading "/" then expect bucket name */
    uri++;
    ulen--;

    if (blen > 0) {
        if (ulen < blen || ngx_strncmp(uri, cf->bucket.data, blen) != 0) {
            /* The URI has a different bucket name — NoSuchBucket */
            return -1;
        }
        uri  += blen;
        ulen -= blen;

        if (ulen == 0 || uri[0] != '/') {
            return 0;
        }
        uri++;
        ulen--;
    }

    if (ulen == 0) {
        key_out[0] = '\0';
        return 1;
    }

    ssize_t dlen = s3_urldecode(uri, ulen, key_out, key_sz);
    if (dlen < 0) {
        return 0;
    }

    return 1;
}


static int
s3_is_list_request(ngx_http_request_t *r)
{
    static const u_char needle[] = "list-type=2";
    size_t              nlen = sizeof(needle) - 1;
    u_char             *search;
    size_t              slen;
    size_t              i;

    if (r->method != NGX_HTTP_GET || r->args.len == 0) {
        return 0;
    }

    search = r->args.data;
    slen = r->args.len;

    for (i = 0; i + nlen <= slen; i++) {
        if (ngx_strncmp(search + i, needle, nlen) == 0) {
            return 1;
        }
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Helper: set a response header (key is a string literal)
 * ---------------------------------------------------------------------- */

static ngx_int_t
s3_set_header(ngx_http_request_t *r, const char *key, const char *val)
{
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key.data  = (u_char *) key;
    h->key.len   = ngx_strlen(key);
    h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){
        ngx_strlen(val), (u_char *) val
    });
    h->value.len = ngx_strlen(val);
    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * GET /bucket/key — file download with Range support
 * ---------------------------------------------------------------------- */

/*
 * s3_handle_get — serve a file as an S3 GetObject response.
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
    struct stat         sb;
    ngx_fd_t            fd;
    off_t               range_start = 0, range_end = 0, send_len;
    int                 has_range = 0;
    ngx_buf_t          *b;
    ngx_chain_t         out;
    char                etag_buf[48];
    char                cr_buf[80];
    ngx_pool_cleanup_t *cln;
    ngx_pool_cleanup_file_t *clnf;
    ngx_int_t           rc;

    fd = xrootd_open_confined_canon(r->connection->log, cf->root_canon,
                                    fs_path, O_RDONLY, 0);
    if (fd == NGX_INVALID_FILE) {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (fstat(fd, &sb) != 0) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey", "The specified key does not exist.");
    }

    /* Range parsing */
    if (r->headers_in.range != NULL) {
        ngx_str_t rv = r->headers_in.range->value;
        if (rv.len > 6 && ngx_strncmp(rv.data, "bytes=", 6) == 0) {
            u_char *p   = rv.data + 6;
            u_char *end = rv.data + rv.len;
            u_char *dash = ngx_strlchr(p, end, '-');
            if (dash != NULL) {
                u_char *q;
                if (dash == p) {
                    off_t suffix = 0;
                    for (q = dash + 1; q < end; q++) {
                        suffix = suffix * 10 + (*q - '0');
                    }
                    range_start = (suffix >= sb.st_size) ? 0
                                                         : sb.st_size - suffix;
                    range_end = sb.st_size - 1;
                } else {
                    range_start = 0;
                    for (q = p; q < dash; q++) {
                        range_start = range_start * 10 + (*q - '0');
                    }
                    if (dash + 1 < end) {
                        range_end = 0;
                        for (q = dash + 1; q < end; q++) {
                            range_end = range_end * 10 + (*q - '0');
                        }
                    } else {
                        range_end = sb.st_size - 1;
                    }
                }
                has_range = 1;
            }
        }
    }

    if (!has_range) {
        range_start = 0;
        range_end   = (sb.st_size > 0) ? sb.st_size - 1 : 0;
        send_len    = sb.st_size;
    } else {
        if (range_end >= sb.st_size) {
            range_end = (sb.st_size > 0) ? sb.st_size - 1 : 0;
        }
        if (range_start > range_end && sb.st_size > 0) {
            ngx_close_file(fd);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            XROOTD_S3_METRIC_INC(
                range_total[XROOTD_S3_RANGE_UNSATISFIED]);
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }
        send_len = (sb.st_size > 0) ? range_end - range_start + 1 : 0;
    }

    if (has_range) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
    } else {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
    }

    s3_etag(&sb, etag_buf, sizeof(etag_buf));

    r->headers_out.status            = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                                  : NGX_HTTP_OK;
    r->headers_out.content_length_n  = send_len;
    r->headers_out.last_modified_time = sb.st_mtime;

    if (s3_set_header(r, "Content-Type", "application/octet-stream") != NGX_OK
        || s3_set_header(r, "ETag", etag_buf) != NGX_OK) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (has_range) {
        snprintf(cr_buf, sizeof(cr_buf), "bytes %lld-%lld/%lld",
                 (long long) range_start, (long long) range_end,
                 (long long) sb.st_size);
        if (s3_set_header(r, "Content-Range", cr_buf) != NGX_OK) {
            ngx_close_file(fd);
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_http_send_header(r);
    /* r->header_only is set for HEAD requests — never send a body. */
    if (rc == NGX_ERROR || r->header_only) {
        ngx_close_file(fd);
        return rc;
    }

    if (send_len == 0) {
        ngx_close_file(fd);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file->name.len  = ngx_strlen(fs_path);
    b->file->name.data = ngx_pnalloc(r->pool, b->file->name.len + 1);
    if (b->file->name.data == NULL) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_cpystrn(b->file->name.data, (u_char *) fs_path, b->file->name.len + 1);

    b->in_file       = 1;
    b->last_buf      = 1;
    b->last_in_chain = 1;
    b->file->fd      = fd;
    b->file->log     = r->connection->log;
    b->file_pos      = range_start;
    b->file_last     = range_start + send_len;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln != NULL) {
        cln->handler = ngx_pool_cleanup_file;
        clnf = cln->data;
        clnf->fd   = fd;
        clnf->name = b->file->name.data;
        clnf->log  = r->pool->log;
    }

    out.buf  = b;
    out.next = NULL;
    XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) send_len);
    return ngx_http_output_filter(r, &out);
}

/* -------------------------------------------------------------------------
 * HEAD /bucket/key — metadata only
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_handle_head(ngx_http_request_t *r,
               const char *fs_path,
               ngx_http_s3_loc_conf_t *cf)
{
    struct stat  sb;
    char         etag_buf[48];
    int          fd;

    fd = xrootd_open_confined_canon(r->connection->log, cf->root_canon,
                                    fs_path, O_RDONLY, 0);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
            return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                     "NoSuchKey", "The specified key does not exist.");
        }
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (fstat(fd, &sb) != 0) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
        return s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                 "NoSuchKey", "The specified key does not exist.");
    }

    s3_etag(&sb, etag_buf, sizeof(etag_buf));

    r->headers_out.status            = NGX_HTTP_OK;
    r->headers_out.content_length_n  = sb.st_size;
    r->headers_out.last_modified_time = sb.st_mtime;

    if (s3_set_header(r, "Content-Type", "application/octet-stream") != NGX_OK
        || s3_set_header(r, "ETag", etag_buf) != NGX_OK) {
        ngx_close_file(fd);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_send_header(r);
    ngx_close_file(fd);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* -------------------------------------------------------------------------
 * DELETE /bucket/key
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_handle_delete(ngx_http_request_t *r,
                 const char *fs_path,
                 ngx_http_s3_loc_conf_t *cf)
{
    if (xrootd_unlink_confined_canon(r->connection->log, cf->root_canon,
                                     fs_path, 0) != 0) {
        if (errno == ENOENT) {
            /* S3 DELETE is idempotent — 204 even if not found */
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DELETE_MISSING]);
            r->headers_out.status           = NGX_HTTP_NO_CONTENT;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }
        if (errno == EISDIR || errno == EPERM) {
            if (xrootd_unlink_confined_canon(r->connection->log,
                                             cf->root_canon, fs_path, 1) != 0)
            {
                if (errno == ENOTEMPTY) {
                    return s3_send_xml_error(r, NGX_HTTP_CONFLICT,
                                             "BucketNotEmpty",
                                             "The directory is not empty.");
                }
                XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    r->headers_out.status           = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* -------------------------------------------------------------------------
 * Main content handler — auth gate + method dispatch
 * ---------------------------------------------------------------------- */

/*
 * ngx_http_s3_handler — nginx HTTP content handler for the S3 API.
 *
 * Implements the AWS S3 path-style API subset needed by XrdClS3 and other
 * HEP data transfer tools.  Dispatch order:
 *
 *   1. Parse the URI into bucket + key using s3_parse_uri().
 *   2. Verify AWS SigV4 signature (s3_verify_sigv4).
 *   3. ListObjectsV2          (GET /<bucket>/?list-type=2) → s3_handle_list().
 *   4. ListMultipartUploads   (GET /<bucket>/?uploads)     → s3_handle_list_multipart_uploads().
 *   5. ListParts              (GET /<bucket>/<key>?uploadId=<id>) → s3_handle_list_parts().
 *   6. GetObject              (GET    /<bucket>/<key>) → s3_handle_get().
 *   7. HeadObject             (HEAD   /<bucket>/<key>) → s3_handle_head().
 *   8. PutObject / UploadPart (PUT    /<bucket>/<key>) → s3_put_body_handler().
 *   9. DeleteObject / Abort   (DELETE /<bucket>/<key>) → s3_handle_delete().
 *  10. CompleteMultipartUpload (POST  /<bucket>/<key>?uploadId=<id>) → s3_multipart_complete_body_handler().
 *  11. InitiateMultipartUpload (POST  /<bucket>/<key>?uploads) → s3_handle_multipart_initiate().
 *
 * The fs_path (filesystem path within conf->root_canon) is resolved by
 * s3_resolve_key() and stored in r->pool for the async PUT callback.
 *
 * Pool allocation: path_copy uses ngx_pnalloc(r->pool, PATH_MAX) so it
 *   survives until the PUT body callback fires after body reading completes.
 */
ngx_int_t
ngx_http_s3_handler(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    u_char                  key[S3_MAX_KEY];
    char                    fs_path[PATH_MAX];
    ngx_int_t               rc;
    int                     is_list_request;
    ngx_uint_t              method_slot;
    u_char                 *path_copy;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    if (!cf->enable) {
        return NGX_DECLINED;
    }

    /*
     * ListObjectsV2 is an HTTP GET on the wire, but it has very different
     * filesystem behavior from GetObject, so it gets a separate metrics slot.
     */
    is_list_request = s3_is_list_request(r);
    method_slot = is_list_request ? XROOTD_S3_METHOD_LIST
                                  : s3_metrics_method_slot(r);
    s3_metrics_request_method(method_slot);

    /* Track per-IP-version bytes for this S3 request. */
    if (r->connection && r->connection->sockaddr) {
        ngx_int_t ip_ver = AF_INET;
        switch (r->connection->sockaddr->sa_family) {
        case AF_INET6: ip_ver = AF_INET6; break;
        default:       ip_ver = AF_INET;  break;
        }

        if (ip_ver == AF_INET) {
            XROOTD_S3_METRIC_INC(bytes_rx_ipv4_total);
        } else {
            XROOTD_S3_METRIC_INC(bytes_rx_ipv6_total);
        }
    }

    /* Authentication */
    rc = s3_verify_sigv4(r, cf);
    if (rc != NGX_OK) {
        return s3_metrics_return_method(r, method_slot, rc);
    }

    /* Parse URI into key */
    {
        int parse_rc = s3_parse_uri(r, cf, key, sizeof(key));
        if (parse_rc == -1) {
            /* Bucket name in URI does not match configured bucket */
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INVALID_URI]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                  "NoSuchBucket",
                                  "The specified bucket does not exist."));
        }
        if (parse_rc == 0) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INVALID_URI]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                  "InvalidURI",
                                  "Couldn't parse the specified URI."));
        }
    }

    if (is_list_request) {
        return s3_metrics_return_method(r, method_slot, s3_handle_list(r, cf));
    }

    /*
     * ListMultipartUploads: GET /<bucket>/?uploads  (empty key, flag present)
     * Must be checked before the empty-key rejection below.
     */
    if (r->method == NGX_HTTP_GET
        && key[0] == '\0'
        && s3_has_query_flag(r, "uploads"))
    {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_list_multipart_uploads(r, cf));
    }

    /* Reject empty key for non-list operations */
    if (key[0] == '\0') {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INVALID_URI]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "InvalidURI", "Missing object key."));
    }

    /* Resolve key to filesystem path */
    if (!s3_resolve_key(cf->root_canon,
                        (const char *) key,
                        fs_path, sizeof(fs_path))) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_ACCESS_DENIED]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                              "AccessDenied", "Access Denied."));
    }

    /* Method dispatch */
    if (r->method == NGX_HTTP_GET) {
        /*
         * ListParts: GET /<bucket>/<key>?uploadId=<id>
         * Must be checked before the regular GetObject path so that the
         * query parameter distinguishes the two operations.
         */
        char list_parts_upload_id[128];
        if (s3_get_query_param(r, "uploadId",
                               list_parts_upload_id,
                               sizeof(list_parts_upload_id)))
        {
            return s3_metrics_return_method(
                r, method_slot,
                s3_handle_list_parts(r, fs_path, cf, (const char *) key));
        }
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get(r, fs_path, cf));
    }
    if (r->method == NGX_HTTP_HEAD) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_head(r, fs_path, cf));
    }
    if (r->method == NGX_HTTP_PUT) {
        if (!cf->allow_write) {
            XROOTD_S3_METRIC_INC(
                events_total[XROOTD_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        /* Check for multipart UploadPart: PUT /key?partNumber=N&uploadId=ID */
        char upload_id[25];
        char part_num_str[8];
        if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id)) &&
            s3_get_query_param(r, "partNumber", part_num_str, sizeof(part_num_str)))
        {
            /* Validate partNumber: must be a decimal integer 1–10000. */
            char *endptr;
            long part_num = strtol(part_num_str, &endptr, 10);
            if (*endptr != '\0' || part_num < 1 || part_num > 10000) {
                return s3_metrics_return_method(r, method_slot,
                    s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                      "InvalidArgument",
                                      "Part number must be an integer"
                                      " between 1 and 10000."));
            }
            /* Validate uploadId contains only safe hex characters. */
            if (!s3_has_query_flag(r, "uploads")) { /* reuse flag parser */
                const char *c;
                for (c = upload_id; *c != '\0'; c++) {
                    if (!((*c >= '0' && *c <= '9')
                          || (*c >= 'a' && *c <= 'f')))
                    {
                        return s3_metrics_return_method(r, method_slot,
                            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                              "InvalidArgument",
                                              "The uploadId is invalid."));
                    }
                }
            }
            char    mpu_dir[PATH_MAX];
            u_char *p;
            s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));
            /*
             * nginx's ngx_snprintf (ngx_sprintf) does NOT support the 'l'
             * length modifier — "%ld" is parsed as "%l" (read long, write
             * number) followed by a literal 'd' character, producing e.g.
             * "part.1d" instead of "part.1".  Use %z (ssize_t/size_t)
             * instead; on 64-bit Linux long and ssize_t are the same width.
             */
            p = ngx_snprintf((u_char *)fs_path, PATH_MAX - 1,
                             "%s/part.%z", mpu_dir, (size_t) part_num);
            *p = '\0';

            /* UploadPartCopy: x-amz-copy-source → server-side copy, no body */
            {
                ngx_list_part_t *hpart = &r->headers_in.headers.part;
                ngx_table_elt_t *hdr   = hpart->elts;
                ngx_uint_t       hi;
                int              has_copy_source = 0;
                for (hi = 0; ; hi++) {
                    if (hi >= hpart->nelts) {
                        if (hpart->next == NULL) break;
                        hpart = hpart->next; hdr = hpart->elts; hi = 0;
                    }
                    if (hdr[hi].key.len == sizeof("x-amz-copy-source") - 1
                        && ngx_strncasecmp(hdr[hi].key.data,
                                           (u_char *) "x-amz-copy-source",
                                           sizeof("x-amz-copy-source") - 1) == 0)
                    {
                        has_copy_source = 1; break;
                    }
                }
                if (has_copy_source) {
                    return s3_metrics_return_method(r, method_slot,
                        s3_handle_upload_part_copy(r, fs_path, cf,
                                                   upload_id, (int) part_num));
                }
            }
        }

        /* Store fs_path in the request pool so the body callback can reach it. */
        path_copy = ngx_pnalloc(r->pool, PATH_MAX);
        if (path_copy == NULL) {
            XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
            return s3_metrics_return_method(r, method_slot,
                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        ngx_cpystrn(path_copy, (u_char *) fs_path, PATH_MAX);
        r->request_body_in_single_buf = 1;
        ngx_http_set_ctx(r, path_copy, ngx_http_xrootd_s3_module);

        rc = ngx_http_read_client_request_body(r, s3_put_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return s3_metrics_return_method(r, method_slot, rc);
        }
        return NGX_DONE;
    }
    if (r->method == NGX_HTTP_DELETE) {
        if (!cf->allow_write) {
            XROOTD_S3_METRIC_INC(
                events_total[XROOTD_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        char upload_id[128];
        if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_multipart_abort(r, fs_path, cf, upload_id));
        }

        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_delete(r, fs_path, cf));
    }

    if (r->method == NGX_HTTP_POST) {
        if (!cf->allow_write) {
            XROOTD_S3_METRIC_INC(
                events_total[XROOTD_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        char upload_id[128];
        if (s3_has_query_flag(r, "uploads")) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_multipart_initiate(r, fs_path, cf, (const char *)key));
        } else if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
            path_copy = ngx_pnalloc(r->pool, PATH_MAX);
            if (path_copy == NULL) {
                XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
                return s3_metrics_return_method(r, method_slot, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            ngx_cpystrn(path_copy, (u_char *)fs_path, PATH_MAX);
            r->request_body_in_single_buf = 1;
            ngx_http_set_ctx(r, path_copy, ngx_http_xrootd_s3_module);
            
            rc = ngx_http_read_client_request_body(r, s3_multipart_complete_body_handler);
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return s3_metrics_return_method(r, method_slot, rc);
            }
            return NGX_DONE;
        }
    }

    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_METHOD_NOT_ALLOWED]);
    return s3_metrics_return_method(r, method_slot, NGX_HTTP_NOT_ALLOWED);
}
