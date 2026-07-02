/*
 * zip_http.c — shared HTTP ZIP-member serving (phase-57 W2). See zip_http.h.
 *
 * Read-only.  Stored members are served zero-copy by sendfile over the archive
 * byte range; deflate members are inflated into an r->pool buffer (capped) and
 * served from memory.  A single byte Range is honoured against the member's
 * UNCOMPRESSED length.  Shared by WebDAV GET and S3 GetObject.
 */
#include "zip_http.h"
#include "zip_dir.h"
#include "fs/vfs.h"   /* confined archive read-open via the VFS seam */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* Maximum deflate member inflated into RAM for one GET; stored members are
 * served by sendfile (no cap), a larger deflate member is refused (413). */
#define ZIP_HTTP_MEM_MAX  (512u * 1024u * 1024u)

static int
zip_http_name_ok(const char *out, size_t n)
{
    if (n == 0 || out[0] == '/' || ngx_strcmp(out, "..") == 0) {
        return 0;
    }
    if (n >= 3 && out[0] == '.' && out[1] == '.' && out[2] == '/') {
        return 0;
    }
    if (strstr(out, "/../") != NULL) {
        return 0;
    }
    if (n >= 3 && ngx_strcmp(out + n - 3, "/..") == 0) {
        return 0;
    }
    return 1;
}

int
xrootd_zip_http_member_arg(ngx_http_request_t *r, char *out, size_t outsz)
{
    ngx_str_t  raw;
    u_char    *d, *s;
    size_t     n;

    if (r->args.len == 0
        || ngx_http_arg(r, (u_char *) "xrdcl.unzip",
                        sizeof("xrdcl.unzip") - 1, &raw) != NGX_OK)
    {
        return 0;
    }
    if (raw.len == 0 || raw.len >= outsz) {
        return -1;
    }

    /* URL-decode the value in place into out (%2F → '/' for nested members). */
    d = (u_char *) out;
    s = raw.data;
    ngx_unescape_uri(&d, &s, raw.len, 0);
    *d = '\0';
    n = (size_t) ((char *) d - out);

    return zip_http_name_ok(out, n) ? 1 : -1;
}

/* Close the dup'd archive fd when the request pool is destroyed. */
static void
zip_http_close_fd(void *data)
{
    ngx_fd_t *fd = data;
    if (*fd != (ngx_fd_t) -1) {
        (void) close(*fd);
    }
}

ngx_int_t
xrootd_zip_http_serve(ngx_http_request_t *r, const char *root_canon,
    size_t cd_max, const char *archive_full, const char *member)
{
    int                  fd, send_fd, zrc;
    struct stat          ast;
    xrootd_zip_member_t  m;
    off_t                total, start, len;
    ngx_table_elt_t     *range;
    ngx_buf_t           *b;
    ngx_chain_t          out;
    ngx_int_t            rc;
    xrootd_vfs_ctx_t     vctx;
    xrootd_vfs_file_t   *fh;
    int                  vfs_err = 0;
    int                  is_tls  = 0;

    /* Open the archive through the confined VFS read surface (the member fd is
     * used transiently to read the central directory + extract/dup the member). */
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        root_canon, NULL, 0 /* allow_write */, is_tls, NULL, archive_full);
    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        errno = vfs_err;
        if (errno == ENOENT || errno == ENOTDIR) return NGX_HTTP_NOT_FOUND;
        if (errno == EACCES || errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    fd = xrootd_vfs_file_fd(fh);
    if (fstat(fd, &ast) != 0 || !S_ISREG(ast.st_mode)) {
        (void) xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cd_max == 0) {
        cd_max = 16 * 1024 * 1024;
    }
    zrc = xrootd_zip_find_member(fd, (off_t) ast.st_size, member, cd_max, &m);
    if (zrc != XROOTD_ZIP_OK) {
        (void) xrootd_vfs_close(fh, r->connection->log);
        if (zrc == XROOTD_ZIP_NOMEMBER) return NGX_HTTP_NOT_FOUND;
        return (zrc == XROOTD_ZIP_EIO) ? NGX_HTTP_INTERNAL_SERVER_ERROR
                                       : NGX_HTTP_NOT_IMPLEMENTED;
    }

    /* Single byte-range against the UNCOMPRESSED length. */
    total = (off_t) m.uncomp_size;
    start = 0;
    len   = total;
    range = r->headers_in.range;
    if (range != NULL && range->value.len > 7
        && ngx_strncasecmp(range->value.data, (u_char *) "bytes=", 6) == 0)
    {
        u_char *p = range->value.data + 6;
        u_char *eov = range->value.data + range->value.len;
        u_char *dash = (u_char *) ngx_strlchr(p, eov, '-');
        if (dash != NULL) {
            off_t a  = (dash > p) ? ngx_atoof(p, dash - p) : -1;
            off_t b2 = (dash + 1 < eov) ? ngx_atoof(dash + 1, eov - dash - 1)
                                        : -1;
            if (a >= 0) {                          /* bytes=a-[b] */
                start = a;
                len = (b2 >= 0 && b2 >= a) ? (b2 - a + 1) : (total - a);
            } else if (b2 > 0) {                   /* bytes=-suffix */
                start = (b2 < total) ? total - b2 : 0;
                len = total - start;
            }
            if (start >= total) {
                (void) xrootd_vfs_close(fh, r->connection->log);
                r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
                r->headers_out.content_length_n = 0;
                ngx_http_send_header(r);
                return ngx_http_send_special(r, NGX_HTTP_LAST);
            }
            if (start + len > total) {
                len = total - start;
            }
        }
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        (void) xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (m.method == XROOTD_ZIP_METHOD_STORE) {
        /* Zero-copy sendfile over the member's byte range; keep the fd alive
         * (async send) via a pool cleanup. */
        ngx_file_t        *f = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_fd_t));
        send_fd = dup(fd);
        (void) xrootd_vfs_close(fh, r->connection->log);
        if (f == NULL || cln == NULL || send_fd == (ngx_fd_t) -1) {
            if (send_fd != (ngx_fd_t) -1) (void) close(send_fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cln->handler = zip_http_close_fd;
        *(ngx_fd_t *) cln->data = send_fd;
        f->fd        = send_fd;
        f->log       = r->connection->log;
        b->in_file   = 1;
        b->file      = f;
        b->file_pos  = (off_t) m.data_off + start;
        b->file_last = (off_t) m.data_off + start + len;
    } else {
        u_char *mem;
        if (m.uncomp_size > ZIP_HTTP_MEM_MAX) {
            (void) xrootd_vfs_close(fh, r->connection->log);
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
        mem = ngx_palloc(r->pool, m.uncomp_size ? m.uncomp_size : 1);
        if (mem == NULL
            || xrootd_zip_extract_full(fd, &m, mem, m.uncomp_size) < 0)
        {
            (void) xrootd_vfs_close(fh, r->connection->log);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        (void) xrootd_vfs_close(fh, r->connection->log);
        b->memory = 1;
        b->pos    = mem + start;
        b->last   = mem + start + len;
    }
    b->last_buf      = 1;
    b->last_in_chain = 1;

    r->headers_out.status           = (len == total) ? NGX_HTTP_OK
                                                     : NGX_HTTP_PARTIAL_CONTENT;
    r->headers_out.content_length_n = len;
    r->allow_ranges                 = 1;
    ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (len != total) {
        ngx_table_elt_t *cr = ngx_list_push(&r->headers_out.headers);
        if (cr != NULL) {
            cr->hash = 1;
            ngx_str_set(&cr->key, "Content-Range");
            cr->value.data = ngx_pnalloc(r->pool,
                                 sizeof("bytes -/-") + 3 * NGX_OFF_T_LEN);
            if (cr->value.data != NULL) {
                cr->value.len = ngx_sprintf(cr->value.data, "bytes %O-%O/%O",
                                            start, start + len - 1, total)
                                - cr->value.data;
            }
        }
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
