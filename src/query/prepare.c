#include "query_internal.h"

#include <errno.h>
#include <sys/stat.h>

/*
 * kXR_prepare / kXR_QPrep: local-storage staging hint and status query.
 */

static ngx_flag_t
xrootd_prepare_has_forbidden_component(const char *path)
{
    const char *p = path;

    while (*p != '\0') {
        const char *seg;
        size_t      len;

        while (*p == '/') {
            p++;
        }

        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }

        len = (size_t) (p - seg);
        if ((len == 1 && seg[0] == '.')
            || (len == 2 && seg[0] == '.' && seg[1] == '.'))
        {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
xrootd_prepare_send_fail(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    xrootd_log_access(ctx, c, "PREPARE", path != NULL ? path : "-",
                      "-", 0, errcode, errmsg, 0);

    return xrootd_send_error(ctx, c, errcode, errmsg);
}


static ngx_int_t
xrootd_prepare_check_fail(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = xrootd_prepare_send_fail(ctx, c, path, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}


static ngx_int_t
xrootd_prepare_check_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const u_char *line, size_t line_len,
    ngx_flag_t noerrs, ngx_uint_t *missing)
{
    char         pathbuf[XROOTD_MAX_PATH + 1];
    char         resolved[PATH_MAX];
    struct stat  st;

    if (line_len > XROOTD_MAX_PATH) {
        return xrootd_prepare_check_fail(ctx, c, "-", kXR_ArgTooLong,
                                         "prepare path too long");
    }

    if (!xrootd_extract_path(c->log, line, line_len, pathbuf,
                             sizeof(pathbuf), 1)) {
        return xrootd_prepare_check_fail(ctx, c, "-", kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    if (xrootd_prepare_has_forbidden_component(pathbuf)) {
        return xrootd_prepare_check_fail(ctx, c, pathbuf, kXR_ArgInvalid,
                                         "invalid prepare path");
    }

    if (!xrootd_resolve_path(c->log, &conf->root, pathbuf, resolved,
                             sizeof(resolved))) {
        if (noerrs) {
            (*missing)++;
            return NGX_OK;
        }

        return xrootd_prepare_check_fail(ctx, c, pathbuf, kXR_NotFound,
                                         "file not found");
    }

    if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
        return xrootd_prepare_check_fail(ctx, c, resolved, kXR_NotAuthorized,
                                         "not authorized");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        return xrootd_prepare_check_fail(ctx, c, resolved, kXR_NotAuthorized,
                                         "VO not authorized");
    }

    if (xrootd_check_token_scope(ctx, pathbuf, 0) != NGX_OK) {
        return xrootd_prepare_check_fail(ctx, c, pathbuf, kXR_NotAuthorized,
                                         "token scope denied");
    }

    if (stat(resolved, &st) != 0) {
        if ((errno == ENOENT || errno == ENOTDIR) && noerrs) {
            (*missing)++;
            return NGX_OK;
        }

        if (errno == ENOENT || errno == ENOTDIR) {
            return xrootd_prepare_check_fail(ctx, c, pathbuf, kXR_NotFound,
                                             "file not found");
        }

        if (errno == EACCES || errno == EPERM) {
            return xrootd_prepare_check_fail(ctx, c, resolved, kXR_NotAuthorized,
                                             "not authorized");
        }

        return xrootd_prepare_check_fail(ctx, c, resolved, kXR_IOError,
                                         "prepare stat failed");
    }

    if (S_ISDIR(st.st_mode)) {
        if (noerrs) {
            (*missing)++;
            return NGX_OK;
        }

        return xrootd_prepare_check_fail(ctx, c, pathbuf, kXR_isDirectory,
                                         "prepare target is a directory");
    }

    return NGX_OK;
}


ngx_int_t
xrootd_handle_prepare(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientPrepareRequest *req;
    const u_char         *p;
    const u_char         *end;
    ngx_uint_t            paths = 0;
    ngx_uint_t            missing = 0;
    uint16_t              optionx;
    char                  detail[96];

    req = (ClientPrepareRequest *) ctx->hdr_buf;
    optionx = ntohs(req->optionX);

    if ((req->options & kXR_wmode) && !conf->allow_write) {
        return xrootd_prepare_send_fail(ctx, c, "-", kXR_fsReadOnly,
                                        "this is a read-only server");
    }

    if ((req->options & kXR_cancel) || (optionx & kXR_evict)) {
        snprintf(detail, sizeof(detail), "noop opts=0x%02x optx=0x%04x",
                 (unsigned int) req->options, (unsigned int) optionx);
        xrootd_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        return xrootd_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is missing");
    }

    p = ctx->payload;
    end = ctx->payload + ctx->cur_dlen;

    while (p < end) {
        const u_char *line;
        size_t        line_len;
        ngx_int_t     rc;

        line = p;
        while (p < end && *p != '\n') {
            p++;
        }

        line_len = (size_t) (p - line);
        if (p < end && *p == '\n') {
            p++;
        }

        while (line_len > 0
               && (line[line_len - 1] == '\r'
                   || line[line_len - 1] == '\0'))
        {
            line_len--;
        }

        if (line_len == 0) {
            continue;
        }

        paths++;

        rc = xrootd_prepare_check_path(ctx, c, conf, line, line_len,
                                       (req->options & kXR_noerrs) != 0,
                                       &missing);
        if (rc == NGX_DONE) {
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (paths == 0) {
        return xrootd_prepare_send_fail(ctx, c, "-", kXR_ArgMissing,
                                        "prepare file list is empty");
    }

    snprintf(detail, sizeof(detail),
             "paths=%u missing=%u opts=0x%02x optx=0x%04x",
             (unsigned int) paths, (unsigned int) missing,
             (unsigned int) req->options, (unsigned int) optionx);

    xrootd_log_access(ctx, c, "PREPARE", "-", detail, 1, kXR_ok, NULL, 0);

    /* kXR_stage: files are immediately on disk — return a fixed request ID
     * and save the path list so kXR_QPrep can report per-file status. */
    if (req->options & kXR_stage) {
        u_char *saved;

        saved = ngx_alloc((size_t) ctx->cur_dlen + 1, c->log);
        if (saved == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(saved, ctx->payload, ctx->cur_dlen);
        saved[ctx->cur_dlen] = '\0';

        if (ctx->prepare_paths != NULL) {
            ngx_free(ctx->prepare_paths);
        }

        ngx_memcpy(ctx->prepare_reqid, "0", 2);  /* reqid "0", NUL-terminated */
        ctx->prepare_paths     = saved;
        ctx->prepare_paths_len = ctx->cur_dlen;
        return xrootd_send_ok(ctx, c, (u_char *) "0", 1);
    }

    return xrootd_send_ok(ctx, c, NULL, 0);
}


/*
 * kXR_QPrep handler.
 *
 * Payload format (newline-separated):
 *   line 0: request ID (from kXR_prepare response)
 *   line 1+: optional paths to check (may be omitted; use stored path list)
 *
 * This server is disk-only — files are immediately staged or absent.
 * Response: one "A <path>" or "M <path>" line per file, NUL-terminated.
 */
ngx_int_t
xrootd_query_prep_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *src;
    size_t        src_len;
    const u_char *p;
    const u_char *end;
    u_char       *resp;
    u_char       *rp;
    size_t        resp_cap;
    int           has_inline_paths = 0;

    /* Parse the first line of the payload as the request ID (ignored). */
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_ok(ctx, c, (u_char *) "No information found.", 22);
    }

    p   = ctx->payload;
    end = ctx->payload + ctx->cur_dlen;

    /* Skip the reqid line. */
    while (p < end && *p != '\n') {
        p++;
    }
    if (p < end) {
        p++;  /* consume '\n' */
    }

    /* Determine which path list to use: inline paths (after reqid) or stored. */
    if (p < end) {
        src     = p;
        src_len = (size_t) (end - p);
        has_inline_paths = 1;
    } else if (ctx->prepare_paths != NULL && ctx->prepare_paths_len > 0) {
        src     = ctx->prepare_paths;
        src_len = ctx->prepare_paths_len;
    } else {
        /* No paths available — acknowledge the query as complete. */
        return xrootd_send_ok(ctx, c, (u_char *) "No information found.", 22);
    }

    (void) has_inline_paths;

    /* Allocate response buffer: worst case "A " + path + "\n" per line. */
    resp_cap = src_len * 2 + 64;
    resp = ngx_palloc(c->pool, resp_cap);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    rp = resp;

    p   = src;
    end = src + src_len;

    while (p < end) {
        const u_char *line;
        size_t        line_len;
        char          pathbuf[XROOTD_MAX_PATH + 1];
        char          resolved[PATH_MAX];
        struct stat   st;

        line = p;
        while (p < end && *p != '\n') {
            p++;
        }
        line_len = (size_t) (p - line);
        if (p < end) {
            p++;
        }
        while (line_len > 0
               && (line[line_len - 1] == '\r' || line[line_len - 1] == '\0'))
        {
            line_len--;
        }
        if (line_len == 0) {
            continue;
        }

        if (!xrootd_extract_path(c->log, line, line_len, pathbuf,
                                 sizeof(pathbuf), 1)) {
            continue;  /* skip malformed paths */
        }

        /* Check if available: resolve then stat. */
        if (xrootd_resolve_path(c->log, &conf->root, pathbuf,
                                resolved, sizeof(resolved))
            && stat(resolved, &st) == 0
            && S_ISREG(st.st_mode))
        {
            *rp++ = 'A';
        } else {
            *rp++ = 'M';
        }
        *rp++ = ' ';

        /* Copy logical path into response. */
        if ((size_t) (rp - resp) + line_len + 1 >= resp_cap) {
            break;  /* safety: truncate on overflow */
        }
        ngx_memcpy(rp, pathbuf, strlen(pathbuf));
        rp += strlen(pathbuf);
        *rp++ = '\n';
    }

    if (rp == resp) {
        return xrootd_send_ok(ctx, c, (u_char *) "No information found.", 22);
    }

    *rp = '\0';
    xrootd_log_access(ctx, c, "QPREP", "-", "-", 1, kXR_ok, NULL, 0);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (rp - resp + 1));
}
