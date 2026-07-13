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
#include "fs/vfs/vfs.h"   /* confined archive read-open via the VFS seam */

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
brix_zip_http_member_arg(ngx_http_request_t *r, char *out, size_t outsz)
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

/* Byte span served out of the member's UNCOMPRESSED data: [start, start+len)
 * of total.  Groups the range state so helpers stay within the param budget. */
typedef struct {
    off_t  total;   /* uncompressed member size */
    off_t  start;   /* first byte to serve */
    off_t  len;     /* number of bytes to serve */
} zip_http_span_t;

/*
 * WHAT: open the archive through the confined VFS read surface and verify it
 *       is a regular file.
 * WHY:  the member fd is used transiently to read the central directory and
 *       extract/dup the member; every failure maps to a distinct HTTP status.
 * HOW:  brix_vfs_open() under a WEBDAV read-only ctx, then fstat/S_ISREG.
 *       Returns NGX_OK with *fhp and *sizep set, or an HTTP status (fh
 *       already closed).
 */
static ngx_int_t
zip_http_open_archive(ngx_http_request_t *r, const char *root_canon,
    const char *archive_full, brix_vfs_file_t **fhp, off_t *sizep)
{
    struct stat        ast;
    brix_vfs_ctx_t   vctx;
    brix_vfs_file_t *fh;
    int                vfs_err = 0;
    int                is_tls  = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    /* triage (review-finding fixes, 2026-07-08): this IS a remote-capable
     * data-plane read (brix_vfs_open below can reach a driver backend), so it
     * belongs on the per-user-credential list in principle. Left NULL/unbound:
     * brix_zip_http_serve() takes only `ngx_http_request_t *r` — it has no
     * identity parameter, and both call sites (src/protocols/s3/object.c,
     * src/protocols/webdav/get.c) are HTTP-plane and outside this task's
     * touched-file scope, so threading identity here would require a public
     * signature change reaching two more files. Deferred, not a same-file fix. */
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        root_canon, NULL, 0 /* allow_write */, is_tls, NULL, archive_full);
    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        errno = vfs_err;
        if (errno == ENOENT || errno == ENOTDIR) return NGX_HTTP_NOT_FOUND;
        if (errno == EACCES || errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (fstat(brix_vfs_file_fd(fh), &ast) != 0 || !S_ISREG(ast.st_mode)) {
        (void) brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *fhp   = fh;
    *sizep = (off_t) ast.st_size;
    return NGX_OK;
}

/*
 * WHAT: locate `member` in the archive's central directory.
 * WHY:  isolates the CD walk and the brix_zip_* → HTTP status mapping.
 * HOW:  brix_zip_find_member() over the open archive fd; NOMEMBER → 404,
 *       EIO → 500, anything else (unsupported feature) → 501.  Returns NGX_OK
 *       with *m filled; the caller owns the archive handle on failure.
 */
static ngx_int_t
zip_http_locate_member(brix_vfs_file_t *fh, off_t archive_size,
    const char *member, size_t cd_max, brix_zip_member_t *m)
{
    int  zrc;

    zrc = brix_zip_find_member(brix_vfs_file_fd(fh), archive_size, member,
                               cd_max, m);
    if (zrc == BRIX_ZIP_OK) {
        return NGX_OK;
    }
    if (zrc == BRIX_ZIP_NOMEMBER) return NGX_HTTP_NOT_FOUND;
    return (zrc == BRIX_ZIP_EIO) ? NGX_HTTP_INTERNAL_SERVER_ERROR
                                   : NGX_HTTP_NOT_IMPLEMENTED;
}

/*
 * WHAT: apply a single client byte Range against the member's UNCOMPRESSED
 *       length.
 * WHY:  ZIP members are ranged on their logical (inflated) content, not the
 *       archive bytes, so the standard range filter cannot be used.
 * HOW:  parses "bytes=a-[b]" / "bytes=-suffix" from the Range header into
 *       sp->start/sp->len (pre-set to the whole span).  Returns NGX_OK, or
 *       NGX_ERROR when the range is unsatisfiable (start beyond total).
 */
static ngx_int_t
zip_http_parse_range(ngx_http_request_t *r, zip_http_span_t *sp)
{
    ngx_table_elt_t *range = r->headers_in.range;
    u_char          *p, *eov, *dash;

    if (range == NULL || range->value.len <= 7
        || ngx_strncasecmp(range->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return NGX_OK;
    }

    p    = range->value.data + 6;
    eov  = range->value.data + range->value.len;
    dash = (u_char *) ngx_strlchr(p, eov, '-');
    if (dash == NULL) {
        return NGX_OK;
    }

    {
        off_t a  = (dash > p) ? ngx_atoof(p, dash - p) : -1;
        off_t b2 = (dash + 1 < eov) ? ngx_atoof(dash + 1, eov - dash - 1)
                                    : -1;
        if (a >= 0) {                          /* bytes=a-[b] */
            sp->start = a;
            sp->len = (b2 >= 0 && b2 >= a) ? (b2 - a + 1) : (sp->total - a);
        } else if (b2 > 0) {                   /* bytes=-suffix */
            sp->start = (b2 < sp->total) ? sp->total - b2 : 0;
            sp->len = sp->total - sp->start;
        }
    }
    if (sp->start >= sp->total) {
        return NGX_ERROR;
    }
    if (sp->start + sp->len > sp->total) {
        sp->len = sp->total - sp->start;
    }
    return NGX_OK;
}

/*
 * WHAT: stage a STORE member for zero-copy sendfile over the archive range.
 * WHY:  stored members need no inflation — the response body IS a byte range
 *       of the archive file, so a dup'd fd + file-backed buf is cheapest.
 * HOW:  dup the archive fd (kept alive across the async send by a pool
 *       cleanup), close the VFS handle, point b at data_off + span.  Always
 *       consumes fh; returns NGX_OK or 500.
 */
static ngx_int_t
zip_http_stage_stored(ngx_http_request_t *r, brix_vfs_file_t *fh,
    const brix_zip_member_t *m, const zip_http_span_t *sp, ngx_buf_t *b)
{
    ngx_file_t         *f = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_fd_t));
    int                 send_fd;

    send_fd = dup(brix_vfs_file_fd(fh));
    (void) brix_vfs_close(fh, r->connection->log);
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
    b->file_pos  = (off_t) m->data_off + sp->start;
    b->file_last = (off_t) m->data_off + sp->start + sp->len;
    return NGX_OK;
}

/*
 * WHAT: stage a DEFLATE member by inflating it into an r->pool buffer.
 * WHY:  compressed members cannot be ranged/sent from the archive bytes;
 *       they are fully inflated (capped at ZIP_HTTP_MEM_MAX → 413) and served
 *       from memory.
 * HOW:  ngx_palloc + brix_zip_extract_full(), then point b at the requested
 *       span of the inflated data.  Always consumes fh; returns NGX_OK,
 *       413 (too large) or 500.
 */
static ngx_int_t
zip_http_stage_deflate(ngx_http_request_t *r, brix_vfs_file_t *fh,
    const brix_zip_member_t *m, const zip_http_span_t *sp, ngx_buf_t *b)
{
    u_char *mem;

    if (m->uncomp_size > ZIP_HTTP_MEM_MAX) {
        (void) brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    mem = ngx_palloc(r->pool, m->uncomp_size ? m->uncomp_size : 1);
    if (mem == NULL
        || brix_zip_extract_full(brix_vfs_file_fd(fh), m, mem,
                                 m->uncomp_size) < 0)
    {
        (void) brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    (void) brix_vfs_close(fh, r->connection->log);
    b->memory = 1;
    b->pos    = mem + sp->start;
    b->last   = mem + sp->start + sp->len;
    return NGX_OK;
}

/*
 * WHAT: fill the response headers for the (possibly partial) member body.
 * WHY:  200 vs 206 + Content-Range depend only on the served span, so the
 *       header block is a pure function of (r, span).
 * HOW:  sets status/content_length/content_type; on a partial span appends a
 *       "Content-Range: bytes a-b/total" header (allocation failures leave
 *       the header out, matching the original best-effort behaviour).
 */
static void
zip_http_set_headers(ngx_http_request_t *r, const zip_http_span_t *sp)
{
    r->headers_out.status           = (sp->len == sp->total)
                                          ? NGX_HTTP_OK
                                          : NGX_HTTP_PARTIAL_CONTENT;
    r->headers_out.content_length_n = sp->len;
    r->allow_ranges                 = 1;
    ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (sp->len != sp->total) {
        ngx_table_elt_t *cr = ngx_list_push(&r->headers_out.headers);
        if (cr != NULL) {
            cr->hash = 1;
            ngx_str_set(&cr->key, "Content-Range");
            cr->value.data = ngx_pnalloc(r->pool,
                                 sizeof("bytes -/-") + 3 * NGX_OFF_T_LEN);
            if (cr->value.data != NULL) {
                cr->value.len = ngx_sprintf(cr->value.data, "bytes %O-%O/%O",
                                            sp->start,
                                            sp->start + sp->len - 1,
                                            sp->total)
                                - cr->value.data;
            }
        }
    }
}

ngx_int_t
brix_zip_http_serve(ngx_http_request_t *r, const char *root_canon,
    size_t cd_max, const char *archive_full, const char *member)
{
    brix_zip_member_t  m;
    zip_http_span_t      sp;
    ngx_buf_t           *b;
    ngx_chain_t          out;
    ngx_int_t            rc;
    brix_vfs_file_t   *fh = NULL;
    off_t                archive_size = 0;

    rc = zip_http_open_archive(r, root_canon, archive_full, &fh,
                               &archive_size);
    if (rc != NGX_OK) {
        return rc;
    }

    if (cd_max == 0) {
        cd_max = 16 * 1024 * 1024;
    }
    rc = zip_http_locate_member(fh, archive_size, member, cd_max, &m);
    if (rc != NGX_OK) {
        (void) brix_vfs_close(fh, r->connection->log);
        return rc;
    }

    /* Single byte-range against the UNCOMPRESSED length. */
    sp.total = (off_t) m.uncomp_size;
    sp.start = 0;
    sp.len   = sp.total;
    if (zip_http_parse_range(r, &sp) != NGX_OK) {
        (void) brix_vfs_close(fh, r->connection->log);
        r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        (void) brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = (m.method == BRIX_ZIP_METHOD_STORE)
             ? zip_http_stage_stored(r, fh, &m, &sp, b)
             : zip_http_stage_deflate(r, fh, &m, &sp, b);
    if (rc != NGX_OK) {
        return rc;
    }
    b->last_buf      = 1;
    b->last_in_chain = 1;

    zip_http_set_headers(r, &sp);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
