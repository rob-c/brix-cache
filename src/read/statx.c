#include "statx.h"
#include "../ngx_xrootd_module.h"

#define XROOTD_STATX_MAX_PATHS  256
#define XROOTD_STATX_LINE_MAX   256
#define XROOTD_STATX_BUF_MAX    (XROOTD_STATX_MAX_PATHS * XROOTD_STATX_LINE_MAX)
#define XROOTD_STATX_ERR_LINE   "0 0 0 0\n"

static ngx_flag_t
xrootd_statx_next_path(const u_char **cursor, const u_char *end,
    char *path, size_t path_size)
{
    const u_char *path_start;
    size_t        path_len;

    path_start = *cursor;
    while (*cursor < end && **cursor != '\0') {
        (*cursor)++;
    }

    path_len = (size_t) (*cursor - path_start);
    if (*cursor < end) {
        (*cursor)++;
    }

    if (path_len == 0 || path_len >= path_size) {
        return 0;
    }

    ngx_memcpy(path, path_start, path_len);
    path[path_len] = '\0';

    return 1;
}


static ngx_int_t
xrootd_statx_append_line(u_char **response_cursor, u_char *response_end,
    const char *line, size_t line_len, ngx_flag_t append_newline)
{
    size_t required;

    required = line_len + (append_newline ? 1 : 0);
    if (*response_cursor + required >= response_end) {
        return NGX_ERROR;
    }

    ngx_memcpy(*response_cursor, line, line_len);
    *response_cursor += line_len;

    if (append_newline) {
        *(*response_cursor)++ = '\n';
    }

    return NGX_OK;
}


static ngx_flag_t
xrootd_statx_cached_copy_exists(ngx_stream_xrootd_srv_conf_t *conf,
    const char *request_path)
{
    char        cache_path[PATH_MAX];
    int         path_len;
    struct stat cache_stat;

    if (!conf->cache || conf->cache_root.len == 0) {
        return 0;
    }

    path_len = snprintf(cache_path, sizeof(cache_path), "%s%s",
                        (char *) conf->cache_root.data, request_path);
    if (path_len <= 0 || (size_t) path_len >= sizeof(cache_path)) {
        return 0;
    }

    return (stat(cache_path, &cache_stat) == 0
            && S_ISREG(cache_stat.st_mode));
}


ngx_int_t
xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *cursor, *end;
    u_char       *rsp_buf, *rsp_ptr;
    u_char       *rsp_end;
    char          reqpath_buf[XROOTD_MAX_PATH + 1];
    char          resolved[PATH_MAX];
    struct stat   st;
    char          stat_body[XROOTD_STATX_LINE_MAX];
    size_t        stat_len;
    int           n_paths = 0;

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_STATX);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    rsp_buf = ngx_palloc(c->pool, XROOTD_STATX_BUF_MAX);
    if (rsp_buf == NULL) {
        return NGX_ERROR;
    }

    rsp_ptr = rsp_buf;
    rsp_end = rsp_buf + XROOTD_STATX_BUF_MAX;
    cursor  = ctx->payload;
    end     = ctx->payload + ctx->cur_dlen;

    while (cursor < end && n_paths < XROOTD_STATX_MAX_PATHS) {
        if (!xrootd_statx_next_path(&cursor, end, reqpath_buf,
                                    sizeof(reqpath_buf)))
        {
            continue;
        }

        n_paths++;

        /* Resolve and stat the path. */
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath_buf, resolved, sizeof(resolved))
            || xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                    ctx->vo_list) != NGX_OK
            || xrootd_check_token_scope(ctx, reqpath_buf, 0) != NGX_OK
            || stat(resolved, &st) != 0)
        {
            /* Inaccessible or missing - emit error sentinel. */
            size_t errlen = sizeof(XROOTD_STATX_ERR_LINE) - 1;
            if (xrootd_statx_append_line(&rsp_ptr, rsp_end,
                                         XROOTD_STATX_ERR_LINE,
                                         errlen, 0) != NGX_OK)
            {
                break;
            }
            continue;
        }

        {
            int extra;

            extra = xrootd_statx_cached_copy_exists(conf, reqpath_buf)
                    ? kXR_cachersp : 0;
            xrootd_make_stat_body(&st, 0, extra, stat_body, sizeof(stat_body));
        }

        stat_len = strlen(stat_body);
        if (xrootd_statx_append_line(&rsp_ptr, rsp_end, stat_body,
                                     stat_len, 1) != NGX_OK)
        {
            break;
        }
    }

    /* Replace the last '\n' with '\0' per the XRootD stat wire protocol. */
    if (rsp_ptr > rsp_buf && *(rsp_ptr - 1) == '\n') {
        *(rsp_ptr - 1) = '\0';
    } else {
        *rsp_ptr++ = '\0';
    }

    {
        char detail[32];

        snprintf(detail, sizeof(detail), "%d_paths", n_paths);
        xrootd_log_access(ctx, c, "STATX", "-", detail, 1, 0, NULL, 0);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_STATX);

    return xrootd_send_ok(ctx, c, rsp_buf,
                          (uint32_t)((size_t)(rsp_ptr - rsp_buf)));
}
