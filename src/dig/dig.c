/*
 * dig.c — XrdDig remote diagnostics handler (§3). See dig.h.
 *
 * Security model (all enforced here, fail-closed):
 *   - default off (xrootd_webdav_dig off → handler declines → normal 404 path).
 *   - read-only: only GET/HEAD; any other method → 405.
 *   - confinement: the kernel openat2(RESOLVE_BENEATH) primitive
 *     (xrootd_open_beneath) anchored at the export's realpath — "../" and symlink
 *     escapes are impossible regardless of the requested relative path.
 *   - authorization: a principal→export allow-file; an anonymous principal, an
 *     unset/unreadable allow-file, or no matching rule all DENY (403).
 */

#include "dig.h"
#include "webdav/webdav.h"
#include "fs/path/beneath.h"
#include "fs/vfs.h"   /* serve diagnostics files through the VFS seam */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

/* The authenticated principal: token subject if present, else GSI DN; NULL when
 * the request is anonymous (no usable identity). */
static const char *
dig_principal(ngx_http_xrootd_webdav_req_ctx_t *ctx)
{
    const char *p;

    if (ctx == NULL || ctx->identity == NULL) {
        return NULL;
    }
    p = xrootd_identity_subject_cstr(ctx->identity);
    if (p != NULL && p[0] != '\0') {
        return p;
    }
    p = xrootd_identity_dn_cstr(ctx->identity);
    if (p != NULL && p[0] != '\0') {
        return p;
    }
    return NULL;
}

/*
 * dig_authorize — fail-closed allow-file check.
 *
 * Grammar (first matching rule wins; '#' starts a comment):
 *   <principal-or-*> <export>[,<export>...]
 * '*' matches any non-anonymous principal. Returns NGX_OK only on an explicit
 * match; every other outcome (no file, unopenable, anonymous, no rule) denies.
 */
static ngx_int_t
dig_authorize(const char *authfile, const char *principal, const char *export)
{
    FILE      *fp;
    char       line[1024];
    int        fd;
    ngx_int_t  verdict = NGX_ERROR;

    if (authfile == NULL || authfile[0] == '\0' || principal == NULL) {
        return NGX_ERROR;
    }
    fd = open(authfile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return NGX_ERROR;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return NGX_ERROR;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *hash = strchr(line, '#');
        char *who, *exports, *save = NULL, *save2 = NULL, *tok;
        int   matched = 0;

        if (hash != NULL) {
            *hash = '\0';
        }
        who     = strtok_r(line, " \t\r\n", &save);
        exports = strtok_r(NULL, " \t\r\n", &save);
        if (who == NULL || exports == NULL) {
            continue;
        }
        if (strcmp(who, "*") != 0 && strcmp(who, principal) != 0) {
            continue;
        }
        for (tok = strtok_r(exports, ",", &save2); tok != NULL;
             tok = strtok_r(NULL, ",", &save2))
        {
            if (strcmp(tok, export) == 0) {
                matched = 1;
                break;
            }
        }
        if (matched) {
            verdict = NGX_OK;
            break;
        }
    }
    fclose(fp);
    return verdict;
}

/* Map a confined-open errno to an HTTP status. A RESOLVE_BENEATH escape attempt
 * surfaces as EXDEV/ELOOP/EACCES → 403; a genuine miss → 404. */
static ngx_int_t
dig_open_status(int err)
{
    switch (err) {
    case ENOENT:
    case ENOTDIR:
        return NGX_HTTP_NOT_FOUND;
    default:
        return NGX_HTTP_FORBIDDEN;   /* EXDEV/ELOOP/EACCES/EPERM = blocked escape */
    }
}

ngx_int_t
xrootd_dig_handle(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    xrootd_dig_export_t               *exports, *match = NULL;
    const u_char                      *rest, *end, *sl;
    char                               export[128];
    char                               rel[PATH_MAX];
    char                               canon[PATH_MAX];
    const char                        *principal;
    size_t                             exlen, rlen;
    ngx_uint_t                         i;
    int                                fd;
    struct stat                        st;
    xrootd_vfs_ctx_t                   vctx;
    xrootd_vfs_file_t                 *fh;
    xrootd_vfs_stat_t                  vst;
    char                               full[PATH_MAX];
    int                                vfs_err = 0;
    int                                is_tls = 0;
    ngx_int_t                          rc;
    ngx_pool_cleanup_t                *cln;
    ngx_pool_cleanup_file_t           *clnf;
    ngx_file_t                        *file;
    ngx_buf_t                         *b;
    ngx_chain_t                        out;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (!conf->dig_enable) {
        return NGX_DECLINED;
    }
    if (r->uri.len <= XROOTD_DIG_PREFIX_LEN
        || ngx_strncmp(r->uri.data, (u_char *) XROOTD_DIG_PREFIX,
                       XROOTD_DIG_PREFIX_LEN) != 0)
    {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Split "<export>/<rel>" (r->uri is decoded but NOT NUL-terminated). */
    rest = r->uri.data + XROOTD_DIG_PREFIX_LEN;
    end  = r->uri.data + r->uri.len;
    sl   = memchr(rest, '/', (size_t) (end - rest));
    if (sl == NULL || sl == rest) {
        return NGX_HTTP_NOT_FOUND;             /* need both an export and a file */
    }
    exlen = (size_t) (sl - rest);
    rlen  = (size_t) (end - (sl + 1));
    if (exlen == 0 || exlen >= sizeof(export)
        || rlen == 0 || rlen >= sizeof(rel))
    {
        return NGX_HTTP_NOT_FOUND;
    }
    ngx_memcpy(export, rest, exlen);
    export[exlen] = '\0';
    ngx_memcpy(rel, sl + 1, rlen);
    rel[rlen] = '\0';

    /* Resolve the export name → its realpath anchor. */
    if (conf->dig_exports == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }
    exports = conf->dig_exports->elts;
    for (i = 0; i < conf->dig_exports->nelts; i++) {
        if (exports[i].name.len == exlen
            && ngx_strncmp(exports[i].name.data, (u_char *) export, exlen) == 0)
        {
            match = &exports[i];
            break;
        }
    }
    if (match == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* Authorize (fail-closed). */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    principal = dig_principal(ctx);
    if (dig_authorize((const char *) conf->dig_auth_file.data, principal,
                      export) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd dig: deny principal=\"%s\" export=\"%s\"",
                      principal ? principal : "(anonymous)", export);
        return NGX_HTTP_FORBIDDEN;
    }

    /* Serve through the VFS seam, confined under the export realpath
     * (xrootd_vfs_open uses the same kernel RESOLVE_BENEATH open underneath). */
    if (match->canon.len >= sizeof(canon)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(canon, match->canon.data, match->canon.len);
    canon[match->canon.len] = '\0';

    if ((size_t) snprintf(full, sizeof(full), "%s/%s", canon, rel)
        >= sizeof(full))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        canon, NULL, 0 /* allow_write */, is_tls, NULL, full);

    fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        return dig_open_status(vfs_err);
    }
    if (xrootd_vfs_file_stat(fh, &vst) != NGX_OK || !vst.is_regular) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_NOT_FOUND;            /* directories/specials not served */
    }
    ngx_memzero(&st, sizeof(st));
    st.st_size  = vst.size;
    st.st_mtime = vst.mtime;
    st.st_mode  = (mode_t) vst.mode;

    /* Zero-copy serve fd, gated on the backend's CAP_SENDFILE (the pool cleanup
     * below closes it; the VFS handle owns no other resource). */
    fd = xrootd_vfs_file_sendfile_fd(fh);
    if (fd == NGX_INVALID_FILE) {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Ensure the fd is closed when the request pool is destroyed (after the
     * response is fully sent, including across events for large files). */
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd   = fd;
    clnf->name = (u_char *) "dig";
    clnf->log  = r->connection->log;

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = st.st_size;
    r->headers_out.last_modified_time = st.st_mtime;
    r->headers_out.content_type.len   = sizeof("text/plain") - 1;
    r->headers_out.content_type.data  = (u_char *) "text/plain";
    r->headers_out.content_type_len   = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only || st.st_size == 0) {
        return rc;
    }

    file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    b    = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (file == NULL || b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    file->fd  = fd;
    file->log = r->connection->log;

    b->file        = file;
    b->file_pos    = 0;
    b->file_last   = st.st_size;
    b->in_file     = 1;
    b->last_buf    = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
