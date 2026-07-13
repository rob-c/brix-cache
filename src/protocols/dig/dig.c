/*
 * dig.c — XrdDig remote diagnostics handler (§3). See dig.h.
 *
 * Security model (all enforced here, fail-closed):
 *   - default off (brix_webdav_dig off → handler declines → normal 404 path).
 *   - read-only: only GET/HEAD; any other method → 405.
 *   - confinement: the kernel openat2(RESOLVE_BENEATH) primitive
 *     (brix_open_beneath) anchored at the export's realpath — "../" and symlink
 *     escapes are impossible regardless of the requested relative path.
 *   - authorization: a principal→export allow-file; an anonymous principal, an
 *     unset/unreadable allow-file, or no matching rule all DENY (403).
 */

#include "dig.h"
#include "protocols/webdav/webdav.h"
#include "fs/path/beneath.h"
#include "fs/vfs/vfs.h"   /* serve diagnostics files through the VFS seam */
#include "core/compat/cstr.h"

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
dig_principal(ngx_http_brix_webdav_req_ctx_t *ctx)
{
    const char *p;

    if (ctx == NULL || ctx->identity == NULL) {
        return NULL;
    }
    p = brix_identity_subject_cstr(ctx->identity);
    if (p != NULL && p[0] != '\0') {
        return p;
    }
    p = brix_identity_dn_cstr(ctx->identity);
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
    /* Read-only stream: no buffered writes can be lost, so a close error
     * cannot change the already-computed verdict. */
    (void) fclose(fp);
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

/*
 * dig_req_t — the small per-request working set threaded across the phase
 * helpers of brix_dig_handle().
 *
 * WHAT: carries the parsed target (export name + relative file), the matched
 *       export descriptor, the opened VFS handle + its stat, and the serve fd
 *       from one phase to the next.
 * WHY:  keeps each phase helper a single-responsibility step with explicit
 *       inputs/outputs (coding-standards §8) instead of a wall of locals in one
 *       giant function; state is passed, never reached for.
 * HOW:  the orchestrator zero-inits one on the stack and hands its address to
 *       each step, which fills the fields it owns.
 */
typedef struct {
    char                 export[128];       /* NUL-terminated export name       */
    char                 rel[PATH_MAX];      /* NUL-terminated relative file     */
    brix_dig_export_t   *match;              /* matched export descriptor        */
    brix_vfs_file_t     *fh;                 /* opened VFS handle                */
    brix_vfs_stat_t      vst;                /* stat of the opened file          */
    int                  fd;                 /* zero-copy serve fd               */
} dig_req_t;

/*
 * dig_precheck — decline/deny the request before any parsing work.
 *
 * WHAT: gates on the feature flag, the reserved URI prefix, and the read-only
 *       method allow-list (GET/HEAD).
 * WHY:  a single fail-fast gate keeps the security contract (default-off,
 *       read-only) in one auditable place at the top of the flow.
 * HOW:  returns NGX_DECLINED (not ours), NGX_HTTP_NOT_ALLOWED (bad method), or
 *       NGX_OK (proceed).
 */
static ngx_int_t
dig_precheck(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (!conf->dig_enable) {
        return NGX_DECLINED;
    }
    if (r->uri.len <= BRIX_DIG_PREFIX_LEN
        || ngx_strncmp(r->uri.data, (u_char *) BRIX_DIG_PREFIX,
                       BRIX_DIG_PREFIX_LEN) != 0)
    {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    return NGX_OK;
}

/*
 * dig_parse_target — split the URI tail into "<export>/<rel>".
 *
 * WHAT: extracts the export name and the relative file path from the decoded
 *       (but NOT NUL-terminated) r->uri, NUL-terminating both into req.
 * WHY:  pure parsing isolated from I/O so the length/bounds checks that keep
 *       the fixed buffers safe are trivially reviewable.
 * HOW:  finds the first '/' after the prefix; both halves must be non-empty and
 *       fit their buffers, else NGX_HTTP_NOT_FOUND.
 */
static ngx_int_t
dig_parse_target(ngx_http_request_t *r, dig_req_t *req)
{
    const u_char *rest, *end, *sl;
    size_t        exlen, rlen;

    rest = r->uri.data + BRIX_DIG_PREFIX_LEN;
    end  = r->uri.data + r->uri.len;
    sl   = memchr(rest, '/', (size_t) (end - rest));
    if (sl == NULL || sl == rest) {
        return NGX_HTTP_NOT_FOUND;             /* need both an export and a file */
    }
    exlen = (size_t) (sl - rest);
    rlen  = (size_t) (end - (sl + 1));
    if (exlen == 0 || exlen >= sizeof(req->export)
        || rlen == 0 || rlen >= sizeof(req->rel))
    {
        return NGX_HTTP_NOT_FOUND;
    }
    ngx_memcpy(req->export, rest, exlen);
    req->export[exlen] = '\0';
    ngx_memcpy(req->rel, sl + 1, rlen);
    req->rel[rlen] = '\0';
    return NGX_OK;
}

/*
 * dig_match_export — resolve the export name to its declared descriptor.
 *
 * WHAT: linear-scans the configured export list for a name equal to req->export
 *       and stores the match (the realpath BENEATH anchor lives on it).
 * WHY:  an unknown export is a genuine miss, not an error — keeping the lookup
 *       separate makes the 404 semantics explicit.
 * HOW:  NGX_OK with req->match set, or NGX_HTTP_NOT_FOUND.
 */
static ngx_int_t
dig_match_export(ngx_http_brix_webdav_loc_conf_t *conf, dig_req_t *req)
{
    brix_dig_export_t *exports;
    size_t             exlen;
    ngx_uint_t         i;

    if (conf->dig_exports == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }
    exlen   = ngx_strlen(req->export);
    exports = conf->dig_exports->elts;
    for (i = 0; i < conf->dig_exports->nelts; i++) {
        if (exports[i].name.len == exlen
            && ngx_strncmp(exports[i].name.data,
                           (u_char *) req->export, exlen) == 0)
        {
            req->match = &exports[i];
            return NGX_OK;
        }
    }
    return NGX_HTTP_NOT_FOUND;
}

/*
 * dig_authz — fail-closed authorization for the resolved export.
 *
 * WHAT: derives the request principal and checks it against the allow-file for
 *       the requested export, logging a WARN on denial.
 * WHY:  concentrates the fail-closed decision (anonymous / no file / no rule all
 *       deny) at one edge, with the deny log string frozen.
 * HOW:  NGX_OK on an explicit allow, else NGX_HTTP_FORBIDDEN.
 */
static ngx_int_t
dig_authz(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
    dig_req_t *req)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;
    const char                     *principal;

    ctx       = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    principal = dig_principal(ctx);
    if (dig_authorize((const char *) conf->dig_auth_file.data, principal,
                      req->export) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd dig: deny principal=\"%s\" export=\"%s\"",
                      principal ? principal : "(anonymous)", req->export);
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_OK;
}

/*
 * dig_open_confined — open the target file through the VFS seam.
 *
 * WHAT: builds the confined VFS context under the export realpath, opens the
 *       file, stats it (must be a regular file), and captures the serve fd.
 * WHY:  the confinement anchor (RESOLVE_BENEATH under match->canon) is the load-
 *       bearing security seam — keeping open+stat+fd together makes the handle
 *       lifecycle (close-on-failure) local and correct.
 * HOW:  on success stores req->fh / req->vst / req->fd and returns NGX_OK; on
 *       failure closes any partial handle and returns the mapped HTTP status.
 */
static ngx_int_t
dig_open_confined(ngx_http_request_t *r, dig_req_t *req)
{
    char           canon[PATH_MAX];
    char           full[PATH_MAX];
    brix_vfs_ctx_t vctx;
    int            vfs_err = 0;
    int            is_tls = 0;

    /* Serve through the VFS seam, confined under the export realpath
     * (brix_vfs_open uses the same kernel RESOLVE_BENEATH open underneath). */
    if (brix_str_cbuf(canon, sizeof(canon), &req->match->canon) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if ((size_t) snprintf(full, sizeof(full), "%s/%s", canon, req->rel)
        >= sizeof(full))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        canon, NULL, 0 /* allow_write */, is_tls, NULL, full);

    req->fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (req->fh == NULL) {
        return dig_open_status(vfs_err);
    }
    if (brix_vfs_file_stat(req->fh, &req->vst) != NGX_OK
        || !req->vst.is_regular)
    {
        brix_vfs_close(req->fh, r->connection->log);
        return NGX_HTTP_NOT_FOUND;            /* directories/specials not served */
    }

    /* Zero-copy serve fd, gated on the backend's CAP_SENDFILE (a pool cleanup
     * closes it; the VFS handle owns no other resource). */
    req->fd = brix_vfs_file_sendfile_fd(req->fh);
    if (req->fd == NGX_INVALID_FILE) {
        brix_vfs_close(req->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_OK;
}

/*
 * dig_register_fd_cleanup — tie the serve fd's lifetime to the request pool.
 *
 * WHAT: registers a pool cleanup that closes req->fd when the request pool is
 *       destroyed (after the response is fully sent, across events for large
 *       files).
 * WHY:  the fd must outlive this function (sendfile streams asynchronously) yet
 *       never leak — the pool cleanup is the correct owner.
 * HOW:  NGX_OK on success; on allocation failure closes the fd and returns
 *       NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
static ngx_int_t
dig_register_fd_cleanup(ngx_http_request_t *r, int fd)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;

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
    return NGX_OK;
}

/*
 * dig_send_response — emit headers and (for GET) stream the file body.
 *
 * WHAT: sets the 200 response headers from the captured stat, sends them, and —
 *       unless header-only or empty — appends a single sendfile buffer to the
 *       output chain.
 * WHY:  the response edge (all the side effects) lives in one place; the byte
 *       layout, content-type, and header set are frozen.
 * HOW:  returns the header rc directly when there is no body to stream, else the
 *       ngx_http_output_filter result.
 */
static ngx_int_t
dig_send_response(ngx_http_request_t *r, dig_req_t *req)
{
    ngx_file_t  *file;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;
    off_t        size = (off_t) req->vst.size;

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = size;
    r->headers_out.last_modified_time = (time_t) req->vst.mtime;
    r->headers_out.content_type.len   = sizeof("text/plain") - 1;
    r->headers_out.content_type.data  = (u_char *) "text/plain";
    r->headers_out.content_type_len   = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only || size == 0) {
        return rc;
    }

    file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    b    = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (file == NULL || b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    file->fd  = req->fd;
    file->log = r->connection->log;

    b->file        = file;
    b->file_pos    = 0;
    b->file_last   = size;
    b->in_file     = 1;
    b->last_buf    = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/*
 * brix_dig_handle — XrdDig diagnostics entry point (see dig.h).
 *
 * WHAT: orchestrates the fixed sequence precheck → parse → match → authorize →
 *       open (confined) → register fd cleanup → send response.
 * WHY:  each step is a single-responsibility helper; the handler reads as a flat
 *       rc-and-early-return chain (coding-standards §8), the complexity living
 *       in the named steps.
 * HOW:  any step returning non-NGX_OK is the final result (NGX_DECLINED / an
 *       HTTP status / the output-filter rc); NGX_OK means proceed.
 */
ngx_int_t
brix_dig_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    dig_req_t                        req;
    ngx_int_t                        rc;

    ngx_memzero(&req, sizeof(req));

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = dig_precheck(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = dig_parse_target(r, &req);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = dig_match_export(conf, &req);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = dig_authz(r, conf, &req);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = dig_open_confined(r, &req);
    if (rc != NGX_OK) {
        return rc;
    }
    rc = dig_register_fd_cleanup(r, req.fd);
    if (rc != NGX_OK) {
        return rc;
    }
    return dig_send_response(r, &req);
}
