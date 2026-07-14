/*
 * unified_build.c — component validation and candidate-path assembly for the
 * shared realpath()-based path resolver (split from unified.c, verbatim).
 *
 * WHAT: Implements the pre-canonicalisation stages of brix_path_resolve_cstr():
 *       component validation (brix_validate_components_cstr), the small string
 *       helpers (brix_copy_cstr, brix_has_trailing_slash_cstr), and candidate
 *       assembly (brix_build_candidate + its root-seed / component-append
 *       helpers).
 *
 * WHY:  Kept in a dedicated translation unit so each file stays small and
 *       single-purpose; behaviour is byte-for-byte identical to the original
 *       unified.c. The cross-file seam is declared in unified_internal.h.
 *
 * HOW:  See the per-function doc blocks; the public entry point in unified.c
 *       drives these in order (validate → build candidate) before handing the
 *       candidate to the resolution stage in unified_resolve.c.
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
#include "unified_internal.h"

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

brix_path_status_t
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
                          "brix: path depth exceeds limit");
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
            brix_path_warn(log, "brix: path traversal attempt", path);
            return BRIX_PATH_STATUS_INVALID;
        }
    }

    return BRIX_PATH_STATUS_OK;
}

ngx_flag_t
brix_has_trailing_slash_cstr(const char *path)
{
    size_t len;

    if (path == NULL) {
        return 0;
    }

    len = strlen(path);
    return (len > 0 && path[len - 1] == '/');
}

brix_path_status_t
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

/*
 * brix_candidate_init_root — seed the candidate buffer with the export root.
 *
 * WHAT: Copies root_canon into candidate, strips trailing slashes (keeping a
 *       lone "/"), null-terminates, and reports the resulting length via *len.
 *
 * WHY:  The candidate always begins as the normalised export root before any
 *       request component is appended; isolating this keeps brix_build_candidate
 *       focused on component iteration.
 *
 * HOW:  Bounds-checks root_len against candidatesz, memcpy's the root, then
 *       trims trailing '/' with the same >1 guard as the original inline code so
 *       "/" survives untouched.
 */
static brix_path_status_t
brix_candidate_init_root(const char *root_canon, char *candidate,
                           size_t candidatesz, size_t *len)
{
    size_t root_len;

    root_len = strlen(root_canon);
    if (root_len == 0 || root_len >= candidatesz) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(candidate, root_canon, root_len);
    while (root_len > 1 && candidate[root_len - 1] == '/') {
        root_len--;
    }
    candidate[root_len] = '\0';

    *len = root_len;
    return BRIX_PATH_STATUS_OK;
}

/*
 * brix_candidate_append_req — append each request component onto the candidate.
 *
 * WHAT: Walks req_path segment by segment (collapsing runs of '/'), skipping
 *       empties, and appends each via brix_append_component starting at *len.
 *
 * WHY:  Component joining is the sole variable-length stage of candidate
 *       building; extracting it drops brix_build_candidate below the complexity
 *       cap while preserving the exact join order and bounds behaviour.
 *
 * HOW:  Early-returns any non-OK append status; *len is updated in place so the
 *       caller need not track buffer position.
 */
static brix_path_status_t
brix_candidate_append_req(const char *req_path, char *candidate,
                            size_t candidatesz, size_t *len)
{
    const char          *p, *seg_start;
    size_t               seg_len;
    brix_path_status_t   rc;

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

        rc = brix_append_component(candidate, candidatesz, len,
                                     seg_start, seg_len);
        if (rc != BRIX_PATH_STATUS_OK) {
            return rc;
        }
    }

    return BRIX_PATH_STATUS_OK;
}

/*
 * brix_build_candidate — join the export root and request path into an
 * un-canonicalised candidate filesystem path, reporting the request depth.
 *
 * WHAT: Validates inputs, seeds the buffer with the normalised root
 *       (brix_candidate_init_root), records the component depth, and — for a
 *       non-empty request — appends every component (brix_candidate_append_req).
 *       A zero-depth request resolves to the root only when opts.allow_root.
 *
 * WHY:  This is the pre-realpath() assembly step; keeping the root-seed and
 *       component-append stages in dedicated helpers holds this coordinator
 *       under the complexity cap without altering the assembled path.
 *
 * HOW:  Early-returns on invalid args / bound overflow; out->depth is always set
 *       when out->depth_out is non-NULL, matching the original contract.
 */
brix_path_status_t
brix_build_candidate(const char *root_canon, const char *req_path,
                       brix_path_opts_t opts, brix_candidate_out_t *out)
{
    size_t                 len;
    ngx_uint_t             depth;
    brix_path_status_t   rc;

    if (root_canon == NULL || root_canon[0] == '\0' || req_path == NULL) {
        return BRIX_PATH_STATUS_INVALID;
    }

    rc = brix_candidate_init_root(root_canon, out->buf, out->bufsz, &len);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    depth = brix_count_components_cstr(req_path);
    if (out->depth_out != NULL) {
        *out->depth_out = depth;
    }

    if (depth == 0) {
        if (!opts.allow_root) {
            return BRIX_PATH_STATUS_INVALID;
        }
        return BRIX_PATH_STATUS_OK;
    }

    return brix_candidate_append_req(req_path, out->buf, out->bufsz, &len);
}
