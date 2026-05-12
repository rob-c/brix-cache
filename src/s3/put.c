/*
 * put.c — S3 PUT handler: body callback, directory-sentinel mkdir,
 *          atomic write via temp file + rename.
 */

#include "s3.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

/*
 * s3_mkdirs_for_confined — create the parent directory chain for filepath,
 * analogous to "mkdir -p", but confined to root_canon.
 *
 * Each intermediate component is created with mode 0755.  EEXIST is ignored
 * (another worker may have already created the directory).
 *
 * Preconditions: filepath must be an absolute path within root_canon.
 * Returns: 0 on success, -1 with errno set on failure.
 */
static int
s3_mkdirs_for_confined(ngx_log_t *log, const char *root_canon,
    const char *filepath)
{
    char    tmp[PATH_MAX];
    char   *p;
    char   *slash;
    size_t  len;
    size_t  root_len;

    len = strlen(filepath);
    if (len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, filepath, len + 1);

    slash = strrchr(tmp, '/');
    if (slash == NULL || slash == tmp) {
        errno = EINVAL;
        return -1;
    }
    *slash = '\0';

    root_len = strlen(root_canon);
    if (root_len == 1 && root_canon[0] == '/') {
        p = tmp + 1;
    } else {
        if (strncmp(tmp, root_canon, root_len) != 0
            || (tmp[root_len] != '\0' && tmp[root_len] != '/'))
        {
            errno = EXDEV;
            return -1;
        }
        if (tmp[root_len] == '\0') {
            return 0;
        }
        p = tmp + root_len + 1;
    }

    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (xrootd_mkdir_confined_canon(log, root_canon, tmp, 0755) != 0
                && errno != EEXIST)
            {
                return -1;
            }
            *p = '/';
        }
    }

    if (xrootd_mkdir_confined_canon(log, root_canon, tmp, 0755) != 0
        && errno != EEXIST)
    {
        return -1;
    }

    return 0;
}


static ngx_int_t
s3_write_all(ngx_http_request_t *r, int destination_fd, const u_char *data,
    size_t bytes_remaining)
{
    while (bytes_remaining > 0) {
        ssize_t n;

        n = write(destination_fd, data, bytes_remaining);
        if (n <= 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log,
                          n == 0 ? 0 : ngx_errno,
                          "s3: write to temp failed");
            return NGX_ERROR;
        }

        data += n;
        bytes_remaining -= (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
s3_write_request_body(ngx_http_request_t *r, int destination_fd,
    size_t *bytes_written_out, ngx_uint_t *body_mode_out)
{
    ngx_chain_t *in;
    int          has_memory = 0;
    int          has_spooled = 0;

    *bytes_written_out = 0;
    *body_mode_out = XROOTD_S3_PUT_EMPTY;

    if (r->request_body == NULL) {
        return NGX_OK;
    }

    for (in = r->request_body->bufs; in != NULL; in = in->next) {
        ngx_buf_t *buf;

        buf = in->buf;
        if (buf->in_file) {
            u_char tmp_buf[4096];
            off_t  file_off;

            /* nginx spilled this request-body buffer to a temporary file. */
            has_spooled = 1;
            file_off = buf->file_pos;
            while (file_off < buf->file_last) {
                size_t  bytes_to_read;
                ssize_t nr;

                bytes_to_read = sizeof(tmp_buf);
                if ((off_t) (file_off + (off_t) bytes_to_read)
                    > buf->file_last)
                {
                    bytes_to_read = (size_t) (buf->file_last - file_off);
                }

                nr = pread(buf->file->fd, tmp_buf, bytes_to_read, file_off);
                if (nr <= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "s3: read spooled body failed");
                    return NGX_ERROR;
                }

                if (s3_write_all(r, destination_fd, tmp_buf, (size_t) nr)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                *bytes_written_out += (size_t) nr;
                file_off += nr;
            }

            continue;
        }

        if (buf->pos < buf->last) {
            size_t buffer_bytes = (size_t) (buf->last - buf->pos);

            has_memory = 1;
            if (s3_write_all(r, destination_fd, buf->pos, buffer_bytes)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            *bytes_written_out += buffer_bytes;
        }
    }

    if (has_spooled && has_memory) {
        *body_mode_out = XROOTD_S3_PUT_MIXED;
    } else if (has_spooled) {
        *body_mode_out = XROOTD_S3_PUT_SPOOLED;
    } else if (has_memory) {
        *body_mode_out = XROOTD_S3_PUT_MEMORY;
    }

    return NGX_OK;
}


static void
s3_put_finalize_error(ngx_http_request_t *r)
{
    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
}


static void
s3_put_finalize_empty_ok(ngx_http_request_t *r)
{
    ngx_int_t rc;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT, rc);
}


static void
s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes,
    ngx_uint_t body_mode)
{
    XROOTD_S3_METRIC_ADD(bytes_rx_total, body_bytes);
    XROOTD_S3_METRIC_INC(put_body_total[body_mode]);
    s3_put_finalize_empty_ok(r);
}


/*
 * s3_put_body_handler — ngx_http_read_client_request_body() completion
 * callback for S3 PutObject.
 *
 * Retrieves the filesystem path from the per-request module context (set by
 * ngx_http_s3_handler before calling ngx_http_read_client_request_body).
 *
 * Special case — directory sentinels: S3 clients represent directories as
 * zero-byte objects whose key ends with the S3_DIR_SENTINEL suffix (typically
 * "_$folder$").  These are handled by creating the real directory rather than
 * a file.
 *
 * Normal case: write body to a temp file (O_EXCL for atomicity), then rename
 * onto the final path.  On any error the temp file is unlinked.
 *
 * Ownership: the response is finalised via s3_put_finalize_ok() which calls
 *   ngx_http_send_header() and ngx_http_send_special().  The function must not
 *   return NGX_DONE (the caller already incremented r->main->count via
 *   ngx_http_read_client_request_body).
 */
void
s3_put_body_handler(ngx_http_request_t *r)
{
    u_char              *fs_path;
    char                 tmp_path[PATH_MAX];
    ngx_http_s3_loc_conf_t *cf;
    int                  fd = -1;
    int                  is_sentinel;
    int                  rc_int;
    size_t               body_bytes = 0;
    ngx_uint_t           body_mode = XROOTD_S3_PUT_EMPTY;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    fs_path = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    if (fs_path == NULL) {
        s3_put_finalize_error(r);
        return;
    }

    /* Check for directory sentinel */
    {
        size_t plen = ngx_strlen(fs_path);
        size_t slen = sizeof(S3_DIR_SENTINEL) - 1;
        is_sentinel = (plen >= slen
            && ngx_strncmp(fs_path + plen - slen,
                           (u_char *) S3_DIR_SENTINEL, slen) == 0);
    }

    if (is_sentinel) {
        /* Create the directory that the sentinel lives in */
        char parent[PATH_MAX];
        size_t plen = ngx_strlen(fs_path);
        if (plen >= sizeof(parent)) {
            s3_put_finalize_error(r);
            return;
        }
        memcpy(parent, fs_path, plen + 1);
        char *slash = strrchr(parent, '/');
        if (slash != NULL) {
            *slash = '\0';
        }
        if (xrootd_mkdir_confined_canon(r->connection->log, cf->root_canon,
                                        parent, 0755) != 0
            && errno != EEXIST)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "s3: mkdir(\"%s\") failed", parent);
            s3_put_finalize_error(r);
            return;
        }

        /* Write the zero-byte sentinel */
        fd = xrootd_open_confined_canon(r->connection->log, cf->root_canon,
                                        (const char *) fs_path,
                                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "s3: open(\"%s\") for sentinel failed", fs_path);
            s3_put_finalize_error(r);
            return;
        }
        close(fd);

        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DIR_SENTINEL]);
        XROOTD_S3_METRIC_INC(put_body_total[XROOTD_S3_PUT_EMPTY]);
        s3_put_finalize_empty_ok(r);
        return;
    }

    /* Create parent directories if needed */
    if (s3_mkdirs_for_confined(r->connection->log, cf->root_canon,
                               (const char *) fs_path) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "s3: mkdirs_for(\"%s\") failed", fs_path);
        s3_put_finalize_error(r);
        return;
    }

    /* Write to a temp file then rename for atomicity.
     * O_EXCL ensures two concurrent PUTs for the same key don't corrupt each
     * other: only one worker can create the temp file; the rename is the
     * commit point.  Up to 16 attempts handle the rare EEXIST collision. */
    for (rc_int = 0; rc_int < 16; rc_int++) {
        int n;

        n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld.%u",
                     (const char *) fs_path, (long) getpid(),
                     (unsigned) ngx_random());
        if (n < 0 || (size_t) n >= sizeof(tmp_path)) {
            s3_put_finalize_error(r);
            return;
        }

        fd = xrootd_open_confined_canon(r->connection->log, cf->root_canon,
                                        tmp_path,
                                        O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0 || errno != EEXIST) {
            break;
        }
    }
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "s3: temp open(\"%s\") failed", tmp_path);
        s3_put_finalize_error(r);
        return;
    }

    if (s3_write_request_body(r, fd, &body_bytes, &body_mode) != NGX_OK) {
        close(fd);
        xrootd_unlink_confined_canon(r->connection->log, cf->root_canon,
                                     tmp_path, 0);
        s3_put_finalize_error(r);
        return;
    }

    close(fd);

    if (xrootd_rename_confined_canon(r->connection->log, cf->root_canon,
                                     tmp_path, (const char *) fs_path) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "s3: rename(\"%s\" -> \"%s\") failed",
                      tmp_path, fs_path);
        xrootd_unlink_confined_canon(r->connection->log, cf->root_canon,
                                     tmp_path, 0);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 API requires ETag on PutObject 200 response */
    {
        struct stat      final_sb;
        char             etag_buf[48];
        ngx_table_elt_t *h;
        ngx_str_t        etag_str;

        if (stat((const char *) fs_path, &final_sb) == 0) {
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));

            etag_str.len  = ngx_strlen(etag_buf);
            etag_str.data = (u_char *) etag_buf;

            h = ngx_list_push(&r->headers_out.headers);
            if (h != NULL) {
                h->hash       = 1;
                h->key.data   = (u_char *) "ETag";
                h->key.len    = sizeof("ETag") - 1;
                h->value.data = ngx_pstrdup(r->pool, &etag_str);
                h->value.len  = etag_str.len;
            }
        }
    }

    s3_put_finalize_ok(r, body_bytes, body_mode);
}
