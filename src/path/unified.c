#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "path_internal.h"
#include "unified.h"

static void
xrootd_path_result_init(xrootd_path_result_t *result)
{
    if (result == NULL) {
        return;
    }

    ngx_str_null(&result->resolved);
    result->type = XROOTD_PATH_TYPE_NOT_FOUND;
    result->depth = 0;
    result->is_confined = 0;
}

static void
xrootd_path_warn(ngx_log_t *log, const char *prefix, const char *path)
{
    if (log != NULL) {
        xrootd_log_path_warning(log, prefix, path);
    }
}

static ngx_uint_t
xrootd_count_components_cstr(const char *path)
{
    const char *p;
    ngx_uint_t  count;

    p = path;
    while (*p == '/') {
        p++;
    }

    if (*p == '\0') {
        return 0;
    }

    count = 0;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        count++;
        while (*p != '\0' && *p != '/') {
            p++;
        }
    }

    return count;
}

static ngx_uint_t
xrootd_count_components_ngx(const ngx_str_t *path)
{
    u_char     *p, *last;
    ngx_uint_t  count;

    if (path == NULL || path->len == 0) {
        return 0;
    }

    p = path->data;
    last = path->data + path->len;

    while (p < last && *p == '/') {
        p++;
    }

    count = 0;
    while (p < last) {
        while (p < last && *p == '/') {
            p++;
        }
        if (p == last) {
            break;
        }

        count++;
        while (p < last && *p != '/') {
            p++;
        }
    }

    return count;
}

static xrootd_path_status_t
xrootd_validate_components_cstr(ngx_log_t *log, const char *path)
{
    const char *p, *seg_start;
    size_t      seg_len;

    if (path == NULL) {
        return XROOTD_PATH_STATUS_INVALID;
    }

    if (strlen(path) > XROOTD_MAX_PATH) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    if (xrootd_count_path_depth(path) != NGX_OK) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: path depth exceeds limit");
        }
        return XROOTD_PATH_STATUS_INVALID;
    }

    p = path;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        seg_start = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }

        seg_len = (size_t) (p - seg_start);
        if (xrootd_path_component_forbidden(seg_start, seg_len)) {
            xrootd_path_warn(log, "xrootd: path traversal attempt", path);
            return XROOTD_PATH_STATUS_INVALID;
        }
    }

    return XROOTD_PATH_STATUS_OK;
}

static ngx_flag_t
xrootd_has_trailing_slash_cstr(const char *path)
{
    size_t len;

    if (path == NULL) {
        return 0;
    }

    len = strlen(path);
    return (len > 0 && path[len - 1] == '/');
}

static ngx_int_t
xrootd_validate_components_ngx(const ngx_str_t *path, ngx_log_t *log)
{
    u_char *p, *last, *seg_start;
    size_t  seg_len;

    if (path == NULL || path->len == 0 || path->len > XROOTD_MAX_PATH) {
        return NGX_ERROR;
    }

    if (xrootd_count_components_ngx(path) > XROOTD_MAX_WALK_DEPTH) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: path depth exceeds limit");
        }
        return NGX_ERROR;
    }

    p = path->data;
    last = path->data + path->len;

    while (p < last) {
        while (p < last && *p == '/') {
            p++;
        }
        if (p == last) {
            break;
        }

        seg_start = p;
        while (p < last && *p != '/') {
            if (*p == '\0') {
                if (log != NULL) {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                  "xrootd: rejecting path with embedded NUL");
                }
                return NGX_ERROR;
            }
            p++;
        }

        seg_len = (size_t) (p - seg_start);
        if (xrootd_path_component_forbidden((const char *) seg_start,
                                            seg_len))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static xrootd_path_status_t
xrootd_copy_cstr(char *dst, size_t dstsz, const char *src)
{
    size_t len;

    if (dst == NULL || dstsz == 0 || src == NULL) {
        return XROOTD_PATH_STATUS_ERROR;
    }

    len = strlen(src);
    if (len >= dstsz) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(dst, src, len + 1);
    return XROOTD_PATH_STATUS_OK;
}

static xrootd_path_status_t
xrootd_append_component(char *path, size_t pathsz, size_t *len,
                        const char *component, size_t component_len)
{
    if (*len > 1) {
        if (*len + 1 >= pathsz) {
            return XROOTD_PATH_STATUS_TOO_LONG;
        }
        path[(*len)++] = '/';
    }

    if (*len + component_len >= pathsz) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(path + *len, component, component_len);
    *len += component_len;
    path[*len] = '\0';

    return XROOTD_PATH_STATUS_OK;
}

static xrootd_path_status_t
xrootd_build_candidate(const char *root_canon, const char *req_path,
                       xrootd_path_opts_t opts, char *candidate,
                       size_t candidatesz, ngx_uint_t *depth_out)
{
    const char            *p, *seg_start;
    size_t                 len, root_len, seg_len;
    ngx_uint_t             depth;
    xrootd_path_status_t   rc;

    if (root_canon == NULL || root_canon[0] == '\0' || req_path == NULL) {
        return XROOTD_PATH_STATUS_INVALID;
    }

    root_len = strlen(root_canon);
    if (root_len == 0 || root_len >= candidatesz) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(candidate, root_canon, root_len);
    len = root_len;
    while (len > 1 && candidate[len - 1] == '/') {
        len--;
    }
    candidate[len] = '\0';

    depth = xrootd_count_components_cstr(req_path);
    if (depth_out != NULL) {
        *depth_out = depth;
    }

    if (depth == 0) {
        if (!opts.allow_root) {
            return XROOTD_PATH_STATUS_INVALID;
        }
        return XROOTD_PATH_STATUS_OK;
    }

    p = req_path;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        seg_start = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }

        seg_len = (size_t) (p - seg_start);
        if (seg_len == 0) {
            continue;
        }

        rc = xrootd_append_component(candidate, candidatesz, &len,
                                     seg_start, seg_len);
        if (rc != XROOTD_PATH_STATUS_OK) {
            return rc;
        }
    }

    return XROOTD_PATH_STATUS_OK;
}

static ngx_int_t
xrootd_stat_type_cstr(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return XROOTD_PATH_TYPE_NOT_FOUND;
        }
        return NGX_ERROR;
    }

    return (ngx_int_t) (st.st_mode & S_IFMT);
}

static xrootd_path_status_t
xrootd_finish_resolved(ngx_log_t *log, const char *root_canon,
                       const char *resolved_path, xrootd_path_opts_t opts,
                       char *resolved, size_t resolvsz,
                       xrootd_path_result_t *result, ngx_uint_t depth)
{
    ngx_int_t              type;
    xrootd_path_status_t   rc;

    if (!xrootd_path_within_root(root_canon, resolved_path)) {
        xrootd_path_warn(log, "xrootd: path traversal attempt", resolved_path);
        return XROOTD_PATH_STATUS_INVALID;
    }

    type = xrootd_stat_type_cstr(resolved_path);
    if (type == NGX_ERROR) {
        if (opts.allow_missing_tail || opts.allow_missing_parents) {
            type = XROOTD_PATH_TYPE_NOT_FOUND;
        } else {
            return XROOTD_PATH_STATUS_ERROR;
        }
    }

    if (opts.require_directory && type != S_IFDIR) {
        return XROOTD_PATH_STATUS_INVALID;
    }

    rc = xrootd_copy_cstr(resolved, resolvsz, resolved_path);
    if (rc != XROOTD_PATH_STATUS_OK) {
        return rc;
    }

    if (result != NULL) {
        result->resolved.data = (u_char *) resolved;
        result->resolved.len = strlen(resolved);
        result->type = type;
        result->depth = depth;
        result->is_confined = 1;
    }

    return XROOTD_PATH_STATUS_OK;
}

static xrootd_path_status_t
xrootd_resolve_missing_tail(ngx_log_t *log, const char *root_canon,
                            const char *candidate, char *resolved,
                            size_t resolvsz, xrootd_path_result_t *result,
                            ngx_uint_t depth)
{
    char                   parent[PATH_MAX];
    char                   parent_canon[PATH_MAX];
    char                   rebuilt[PATH_MAX];
    char                   base_buf[PATH_MAX];
    char                  *slash;
    const char            *base;
    size_t                 base_len;
    int                    n;
    xrootd_path_opts_t     final_opts;

    if (strlen(candidate) >= sizeof(parent)) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(parent, candidate, strlen(candidate) + 1);
    slash = strrchr(parent, '/');
    if (slash == NULL) {
        return XROOTD_PATH_STATUS_INVALID;
    }

    base = slash + 1;
    if (*base == '\0') {
        return XROOTD_PATH_STATUS_INVALID;
    }

    base_len = strlen(base);
    if (base_len >= sizeof(base_buf)) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }
    ngx_memcpy(base_buf, base, base_len + 1);

    if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }

    if (realpath(parent, parent_canon) == NULL) {
        if (errno == ENOENT) {
            return XROOTD_PATH_STATUS_NOT_FOUND;
        }
        return XROOTD_PATH_STATUS_ERROR;
    }

    if (!xrootd_path_within_root(root_canon, parent_canon)) {
        xrootd_path_warn(log, "xrootd: path traversal attempt in write",
                         parent_canon);
        return XROOTD_PATH_STATUS_INVALID;
    }

    n = snprintf(rebuilt, sizeof(rebuilt),
                 (strcmp(parent_canon, "/") == 0) ? "/%s" : "%s/%s",
                 parent_canon, base_buf);
    if (n < 0 || (size_t) n >= sizeof(rebuilt)) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    final_opts = (xrootd_path_opts_t) { 0 };
    final_opts.allow_missing_tail = 1;
    final_opts.is_write_operation = 1;

    return xrootd_finish_resolved(log, root_canon, rebuilt, final_opts,
                                  resolved, resolvsz, result, depth);
}

static xrootd_path_status_t
xrootd_resolve_missing_parents(ngx_log_t *log, const char *root_canon,
                               const char *candidate, char *resolved,
                               size_t resolvsz, xrootd_path_result_t *result,
                               ngx_uint_t depth)
{
    char                    ancestor[PATH_MAX];
    char                    ancestor_canon[PATH_MAX];
    char                    rebuilt[PATH_MAX];
    char                   *slash;
    const char             *suffix;
    size_t                  ancestor_len;
    int                     n;
    xrootd_path_opts_t      final_opts;

    if (strlen(candidate) >= sizeof(ancestor)) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(ancestor, candidate, strlen(candidate) + 1);

    for ( ;; ) {
        if (realpath(ancestor, ancestor_canon) != NULL) {
            break;
        }

        if (errno != ENOENT) {
            return XROOTD_PATH_STATUS_ERROR;
        }

        slash = strrchr(ancestor, '/');
        if (slash == NULL) {
            return XROOTD_PATH_STATUS_NOT_FOUND;
        }

        if (slash == ancestor) {
            slash[1] = '\0';
        } else {
            *slash = '\0';
        }

        if (strcmp(ancestor, "/") == 0) {
            if (realpath(ancestor, ancestor_canon) == NULL) {
                return XROOTD_PATH_STATUS_NOT_FOUND;
            }
            break;
        }
    }

    if (!xrootd_path_within_root(root_canon, ancestor_canon)) {
        xrootd_path_warn(log, "xrootd: path traversal attempt", ancestor_canon);
        return XROOTD_PATH_STATUS_INVALID;
    }

    ancestor_len = strlen(ancestor);
    suffix = candidate + ancestor_len;
    if (ancestor_len == 1 && ancestor[0] == '/') {
        suffix = candidate + 1;
        n = snprintf(rebuilt, sizeof(rebuilt),
                     (strcmp(ancestor_canon, "/") == 0) ? "/%s" : "%s/%s",
                     ancestor_canon, suffix);
    } else {
        n = snprintf(rebuilt, sizeof(rebuilt), "%s%s", ancestor_canon, suffix);
    }

    if (n < 0 || (size_t) n >= sizeof(rebuilt)) {
        return XROOTD_PATH_STATUS_TOO_LONG;
    }

    final_opts = (xrootd_path_opts_t) { 0 };
    final_opts.allow_missing_parents = 1;

    return xrootd_finish_resolved(log, root_canon, rebuilt, final_opts,
                                  resolved, resolvsz, result, depth);
}

xrootd_path_status_t
xrootd_path_resolve_cstr(ngx_log_t *log, const char *root_canon,
                         const char *req_path, xrootd_path_opts_t opts,
                         char *resolved, size_t resolvsz,
                         xrootd_path_result_t *result)
{
    char                    candidate[PATH_MAX];
    char                    canonical[PATH_MAX];
    ngx_uint_t              depth;
    xrootd_path_status_t    rc;

    xrootd_path_result_init(result);

    rc = xrootd_validate_components_cstr(log, req_path);
    if (rc != XROOTD_PATH_STATUS_OK) {
        return rc;
    }

    if (opts.allow_missing_tail && !opts.allow_missing_parents
        && xrootd_has_trailing_slash_cstr(req_path))
    {
        return XROOTD_PATH_STATUS_INVALID;
    }

    rc = xrootd_build_candidate(root_canon, req_path, opts, candidate,
                                sizeof(candidate), &depth);
    if (rc != XROOTD_PATH_STATUS_OK) {
        return rc;
    }

    if (realpath(candidate, canonical) != NULL) {
        return xrootd_finish_resolved(log, root_canon, canonical, opts,
                                      resolved, resolvsz, result, depth);
    }

    if (errno != ENOENT) {
        return XROOTD_PATH_STATUS_ERROR;
    }

    if (opts.allow_missing_parents) {
        return xrootd_resolve_missing_parents(log, root_canon, candidate,
                                             resolved, resolvsz, result,
                                             depth);
    }

    if (opts.allow_missing_tail) {
        return xrootd_resolve_missing_tail(log, root_canon, candidate,
                                           resolved, resolvsz, result, depth);
    }

    return XROOTD_PATH_STATUS_NOT_FOUND;
}

ngx_int_t
xrootd_path_resolve(ngx_conf_t *cf, const ngx_str_t *root_canon,
                    const ngx_str_t *req_path, xrootd_path_opts_t opts,
                    xrootd_path_result_t *result, ngx_log_t *log)
{
    char                    root_buf[PATH_MAX];
    char                    req_buf[XROOTD_MAX_PATH + 1];
    char                    resolved_buf[PATH_MAX];
    size_t                  len;
    xrootd_path_status_t    rc;
    xrootd_path_result_t    stack_result;

    if (cf == NULL || root_canon == NULL || req_path == NULL
        || result == NULL)
    {
        return NGX_ERROR;
    }

    xrootd_path_result_init(result);

    if (root_canon->len == 0 || root_canon->len >= sizeof(root_buf)
        || req_path->len == 0 || req_path->len >= sizeof(req_buf))
    {
        return NGX_DECLINED;
    }

    if (xrootd_validate_components_ngx(req_path, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_memcpy(root_buf, root_canon->data, root_canon->len);
    root_buf[root_canon->len] = '\0';

    ngx_memcpy(req_buf, req_path->data, req_path->len);
    req_buf[req_path->len] = '\0';

    rc = xrootd_path_resolve_cstr(log, root_buf, req_buf, opts,
                                  resolved_buf, sizeof(resolved_buf),
                                  &stack_result);
    if (rc == XROOTD_PATH_STATUS_ERROR) {
        return NGX_ERROR;
    }
    if (rc != XROOTD_PATH_STATUS_OK) {
        return NGX_DECLINED;
    }

    len = stack_result.resolved.len;
    result->resolved.data = ngx_pnalloc(cf->pool, len + 1);
    if (result->resolved.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(result->resolved.data, resolved_buf, len + 1);
    result->resolved.len = len;
    result->type = stack_result.type;
    result->depth = stack_result.depth;
    result->is_confined = stack_result.is_confined;

    return NGX_OK;
}

ngx_int_t
xrootd_path_validate(const ngx_str_t *root_canon, const ngx_str_t *req_path,
                     ngx_log_t *log)
{
    (void) root_canon;

    return xrootd_validate_components_ngx(req_path, log);
}

ngx_int_t
xrootd_path_get_type(const ngx_str_t *resolved_path)
{
    char path_buf[PATH_MAX];

    if (resolved_path == NULL || resolved_path->len == 0
        || resolved_path->len >= sizeof(path_buf))
    {
        return NGX_ERROR;
    }

    ngx_memcpy(path_buf, resolved_path->data, resolved_path->len);
    path_buf[resolved_path->len] = '\0';

    return xrootd_stat_type_cstr(path_buf);
}
