/*
 * unified.c — the shared realpath()-based path resolver for stream/WebDAV/S3.
 *
 * WHAT: Implements brix_path_resolve_cstr() (declared in unified.h) and its
 *       supporting static helpers. Given a canonical export root and a client
 *       request path, it validates components, builds a candidate filesystem
 *       path, canonicalises it with realpath(3), enforces export-root
 *       containment, stats the target for its type, and copies the confined
 *       result out — populating an optional brix_path_result_t. The
 *       brix_path_opts_t flags select per-protocol semantics: allow_root,
 *       require_directory, allow_missing_tail (write of a new leaf), and
 *       allow_missing_parents (recursive mkdir / HTTP PUT-style suffix).
 *
 * WHY:  This keeps ONE security-critical resolution+confinement implementation
 *       so stream, WebDAV, and S3 callers cannot drift apart on traversal
 *       defences. realpath() collapses ".."/symlinks to an authoritative path,
 *       and brix_path_within_root() then guarantees the result (and, for
 *       not-yet-existing targets, the deepest EXISTING ancestor) stays under the
 *       export root — defeating "/export" vs "/exportdata" prefix attacks and
 *       symlink escapes before any operation touches the target.
 *
 * HOW:  brix_validate_components_cstr() rejects oversized/over-deep paths and
 *       forbidden "."/".." components; brix_build_candidate() joins root+req;
 *       realpath() canonicalises. If the full path is missing (ENOENT) the
 *       resolver walks back to the nearest existing parent
 *       (brix_resolve_missing_tail / brix_resolve_missing_parents),
 *       canonicalises THAT, re-checks containment, and rebuilds the absolute
 *       target. Status flows back as brix_path_status_t. NOTE: this is the
 *       config-time / legacy resolver — hot runtime client paths now use the
 *       kernel-confined beneath API (beneath.c) instead (see Phase 8 notes).
 */
#include "core/ngx_brix_module.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "path_internal.h"
#include "unified.h"

static void
brix_path_result_init(brix_path_result_t *result)
{
    if (result == NULL) {
        return;
    }

    ngx_str_null(&result->resolved);
    result->type = BRIX_PATH_TYPE_NOT_FOUND;
    result->depth = 0;
    result->is_confined = 0;
}

static void
brix_path_warn(ngx_log_t *log, const char *prefix, const char *path)
{
    if (log != NULL) {
        brix_log_path_warning(log, prefix, path);
    }
}

static ngx_uint_t
brix_count_components_cstr(const char *path)
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

static brix_path_status_t
brix_validate_components_cstr(ngx_log_t *log, const char *path)
{
    const char *p, *seg_start;
    size_t      seg_len;

    if (path == NULL) {
        return BRIX_PATH_STATUS_INVALID;
    }

    if (strlen(path) > BRIX_MAX_PATH) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    if (brix_count_path_depth(path) != NGX_OK) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: path depth exceeds limit");
        }
        return BRIX_PATH_STATUS_INVALID;
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
        if (brix_path_component_forbidden(seg_start, seg_len)) {
            brix_path_warn(log, "xrootd: path traversal attempt", path);
            return BRIX_PATH_STATUS_INVALID;
        }
    }

    return BRIX_PATH_STATUS_OK;
}

static ngx_flag_t
brix_has_trailing_slash_cstr(const char *path)
{
    size_t len;

    if (path == NULL) {
        return 0;
    }

    len = strlen(path);
    return (len > 0 && path[len - 1] == '/');
}

static brix_path_status_t
brix_copy_cstr(char *dst, size_t dstsz, const char *src)
{
    size_t len;

    if (dst == NULL || dstsz == 0 || src == NULL) {
        return BRIX_PATH_STATUS_ERROR;
    }

    len = strlen(src);
    if (len >= dstsz) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(dst, src, len + 1);
    return BRIX_PATH_STATUS_OK;
}

static brix_path_status_t
brix_append_component(char *path, size_t pathsz, size_t *len,
                        const char *component, size_t component_len)
{
    if (*len > 1) {
        if (*len + 1 >= pathsz) {
            return BRIX_PATH_STATUS_TOO_LONG;
        }
        path[(*len)++] = '/';
    }

    if (*len + component_len >= pathsz) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(path + *len, component, component_len);
    *len += component_len;
    path[*len] = '\0';

    return BRIX_PATH_STATUS_OK;
}

static brix_path_status_t
brix_build_candidate(const char *root_canon, const char *req_path,
                       brix_path_opts_t opts, char *candidate,
                       size_t candidatesz, ngx_uint_t *depth_out)
{
    const char            *p, *seg_start;
    size_t                 len, root_len, seg_len;
    ngx_uint_t             depth;
    brix_path_status_t   rc;

    if (root_canon == NULL || root_canon[0] == '\0' || req_path == NULL) {
        return BRIX_PATH_STATUS_INVALID;
    }

    root_len = strlen(root_canon);
    if (root_len == 0 || root_len >= candidatesz) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(candidate, root_canon, root_len);
    len = root_len;
    while (len > 1 && candidate[len - 1] == '/') {
        len--;
    }
    candidate[len] = '\0';

    depth = brix_count_components_cstr(req_path);
    if (depth_out != NULL) {
        *depth_out = depth;
    }

    if (depth == 0) {
        if (!opts.allow_root) {
            return BRIX_PATH_STATUS_INVALID;
        }
        return BRIX_PATH_STATUS_OK;
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

        rc = brix_append_component(candidate, candidatesz, &len,
                                     seg_start, seg_len);
        if (rc != BRIX_PATH_STATUS_OK) {
            return rc;
        }
    }

    return BRIX_PATH_STATUS_OK;
}

static ngx_int_t
brix_stat_type_cstr(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return BRIX_PATH_TYPE_NOT_FOUND;
        }
        return NGX_ERROR;
    }

    return (ngx_int_t) (st.st_mode & S_IFMT);
}

static brix_path_status_t
brix_finish_resolved(ngx_log_t *log, const char *root_canon,
                       const char *resolved_path, brix_path_opts_t opts,
                       char *resolved, size_t resolvsz,
                       brix_path_result_t *result, ngx_uint_t depth)
{
    ngx_int_t              type;
    brix_path_status_t   rc;

    if (!brix_path_within_root(root_canon, resolved_path)) {
        brix_path_warn(log, "xrootd: path traversal attempt", resolved_path);
        return BRIX_PATH_STATUS_INVALID;
    }

    type = brix_stat_type_cstr(resolved_path);
    if (type == NGX_ERROR) {
        if (opts.allow_missing_tail || opts.allow_missing_parents) {
            type = BRIX_PATH_TYPE_NOT_FOUND;
        } else {
            return BRIX_PATH_STATUS_ERROR;
        }
    }

    if (opts.require_directory && type != S_IFDIR) {
        return BRIX_PATH_STATUS_INVALID;
    }

    rc = brix_copy_cstr(resolved, resolvsz, resolved_path);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    if (result != NULL) {
        result->resolved.data = (u_char *) resolved;
        result->resolved.len = strlen(resolved);
        result->type = type;
        result->depth = depth;
        result->is_confined = 1;
    }

    return BRIX_PATH_STATUS_OK;
}

static brix_path_status_t
brix_resolve_missing_tail(ngx_log_t *log, const char *root_canon,
                            const char *candidate, char *resolved,
                            size_t resolvsz, brix_path_result_t *result,
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
    brix_path_opts_t     final_opts;

    if (strlen(candidate) >= sizeof(parent)) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(parent, candidate, strlen(candidate) + 1);
    slash = strrchr(parent, '/');
    if (slash == NULL) {
        return BRIX_PATH_STATUS_INVALID;
    }

    base = slash + 1;
    if (*base == '\0') {
        return BRIX_PATH_STATUS_INVALID;
    }

    base_len = strlen(base);
    if (base_len >= sizeof(base_buf)) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }
    ngx_memcpy(base_buf, base, base_len + 1);

    if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }

    if (realpath(parent, parent_canon) == NULL) {
        if (errno == ENOENT) {
            return BRIX_PATH_STATUS_NOT_FOUND;
        }
        return BRIX_PATH_STATUS_ERROR;
    }

    if (!brix_path_within_root(root_canon, parent_canon)) {
        brix_path_warn(log, "xrootd: path traversal attempt in write",
                         parent_canon);
        return BRIX_PATH_STATUS_INVALID;
    }

    n = snprintf(rebuilt, sizeof(rebuilt),
                 (strcmp(parent_canon, "/") == 0) ? "/%s" : "%s/%s",
                 parent_canon, base_buf);
    if (n < 0 || (size_t) n >= sizeof(rebuilt)) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    final_opts = (brix_path_opts_t) { 0 };
    final_opts.allow_missing_tail = 1;
    final_opts.is_write_operation = 1;

    return brix_finish_resolved(log, root_canon, rebuilt, final_opts,
                                  resolved, resolvsz, result, depth);
}

static brix_path_status_t
brix_resolve_missing_parents(ngx_log_t *log, const char *root_canon,
                               const char *candidate, char *resolved,
                               size_t resolvsz, brix_path_result_t *result,
                               ngx_uint_t depth)
{
    char                    ancestor[PATH_MAX];
    char                    ancestor_canon[PATH_MAX];
    char                    rebuilt[PATH_MAX];
    char                   *slash;
    const char             *suffix;
    size_t                  ancestor_len;
    int                     n;
    brix_path_opts_t      final_opts;

    if (strlen(candidate) >= sizeof(ancestor)) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(ancestor, candidate, strlen(candidate) + 1);

    for ( ;; ) {
        if (realpath(ancestor, ancestor_canon) != NULL) {
            break;
        }

        if (errno != ENOENT) {
            return BRIX_PATH_STATUS_ERROR;
        }

        slash = strrchr(ancestor, '/');
        if (slash == NULL) {
            return BRIX_PATH_STATUS_NOT_FOUND;
        }

        if (slash == ancestor) {
            slash[1] = '\0';
        } else {
            *slash = '\0';
        }

        if (strcmp(ancestor, "/") == 0) {
            if (realpath(ancestor, ancestor_canon) == NULL) {
                return BRIX_PATH_STATUS_NOT_FOUND;
            }
            break;
        }
    }

    if (!brix_path_within_root(root_canon, ancestor_canon)) {
        brix_path_warn(log, "xrootd: path traversal attempt", ancestor_canon);
        return BRIX_PATH_STATUS_INVALID;
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
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    final_opts = (brix_path_opts_t) { 0 };
    final_opts.allow_missing_parents = 1;

    return brix_finish_resolved(log, root_canon, rebuilt, final_opts,
                                  resolved, resolvsz, result, depth);
}

/*
 * brix_path_resolve_cstr — public entry point: resolve and confine req_path
 * under the already-canonical root_canon, honouring the opts flags, and write
 * the confined absolute path into resolved[0..resolvsz). When result != NULL it
 * is filled with the resolved ngx_str_t, target type, depth, and is_confined.
 *
 * Returns an brix_path_status_t:
 *   OK        — resolved and confined (resolved/result populated).
 *   INVALID   — bad components, traversal attempt, or containment violation.
 *   NOT_FOUND — target (and required ancestors) do not exist.
 *   TOO_LONG  — a path/buffer bound was exceeded.
 *   ERROR     — an unexpected stat()/realpath() failure.
 *
 * Flow: validate → build candidate → realpath(); on ENOENT fall back to
 * missing-parents / missing-tail resolution per opts, otherwise propagate.
 */
brix_path_status_t
brix_path_resolve_cstr(ngx_log_t *log, const char *root_canon,
                         const char *req_path, brix_path_opts_t opts,
                         char *resolved, size_t resolvsz,
                         brix_path_result_t *result)
{
    char                    candidate[PATH_MAX];
    char                    canonical[PATH_MAX];
    ngx_uint_t              depth;
    brix_path_status_t    rc;

    brix_path_result_init(result);

    rc = brix_validate_components_cstr(log, req_path);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    if (opts.allow_missing_tail && !opts.allow_missing_parents
        && brix_has_trailing_slash_cstr(req_path))
    {
        return BRIX_PATH_STATUS_INVALID;
    }

    rc = brix_build_candidate(root_canon, req_path, opts, candidate,
                                sizeof(candidate), &depth);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    if (realpath(candidate, canonical) != NULL) {
        return brix_finish_resolved(log, root_canon, canonical, opts,
                                      resolved, resolvsz, result, depth);
    }

    if (errno != ENOENT) {
        return BRIX_PATH_STATUS_ERROR;
    }

    if (opts.allow_missing_parents) {
        return brix_resolve_missing_parents(log, root_canon, candidate,
                                             resolved, resolvsz, result,
                                             depth);
    }

    if (opts.allow_missing_tail) {
        return brix_resolve_missing_tail(log, root_canon, candidate,
                                           resolved, resolvsz, result, depth);
    }

    return BRIX_PATH_STATUS_NOT_FOUND;
}

/*
 * Note: the ngx_str_t-based config-time resolution wrappers
 * (brix_path_resolve / brix_path_validate / brix_path_get_type) were
 * removed once all callers migrated to the cstr-based API
 * (brix_path_resolve_cstr) and the Phase 3 runtime resolver
 * (brix_resolve_op_path).
 */
