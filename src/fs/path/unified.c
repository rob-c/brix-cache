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

/*
 * brix_resolve_ctx_t — file-local resolve context.
 *
 * WHAT: Bundles the invariant output/logging cluster threaded through every
 *       resolution stage: the log sink, the canonical export root, the caller's
 *       output buffer (resolved/resolvsz), the optional result record, and the
 *       request depth.
 *
 * WHY:  These same values flow unchanged from the public entry point down
 *       through candidate resolution, missing-tail/parent fallback, and the
 *       final confinement+stat step. Passing them as one context keeps each
 *       static helper at =<5 parameters without adding globals or changing any
 *       value or ordering.
 *
 * HOW:  Populated once in brix_path_resolve_cstr() and passed by const pointer
 *       to the helpers, which read root_canon/log/depth and write into
 *       resolved/result exactly as the pre-refactor by-value parameters did.
 */
typedef struct {
    ngx_log_t            *log;
    const char           *root_canon;
    char                 *resolved;
    size_t                resolvsz;
    brix_path_result_t   *result;
    ngx_uint_t            depth;
} brix_resolve_ctx_t;

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
 * brix_candidate_out_t — output sink for brix_build_candidate.
 *
 * WHAT: Bundles the candidate destination buffer (buf/bufsz) with the optional
 *       depth output pointer.
 *
 * WHY:  Groups the three tightly-coupled output arguments so brix_build_candidate
 *       stays at =<5 parameters without changing which values it writes or when.
 *
 * HOW:  Filled on the stack by the caller; buf/bufsz address the same fixed
 *       PATH_MAX buffer the pre-refactor code passed directly.
 */
typedef struct {
    char        *buf;
    size_t       bufsz;
    ngx_uint_t  *depth_out;
} brix_candidate_out_t;

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
static brix_path_status_t
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

/*
 * brix_finish_resolved — final confinement + stat + output for a canonical path.
 *
 * WHAT: Re-checks resolved_path against the export root, stats it for its type
 *       (tolerating absence under the missing-tail/parent opts), enforces
 *       require_directory, then copies the confined path into ctx->resolved and
 *       populates ctx->result.
 *
 * WHY:  Every resolution path (existing target, missing tail, missing parents)
 *       converges here so containment and result publication happen in exactly
 *       one place. Taking ctx collapses the former eight parameters to three.
 *
 * HOW:  Reads root_canon/log/depth from ctx; writes ctx->resolved/ctx->result.
 *       Ordering (within-root → stat → require_directory → copy → publish) is
 *       byte-for-byte unchanged from the pre-refactor implementation.
 */
static brix_path_status_t
brix_finish_resolved(const brix_resolve_ctx_t *ctx, const char *resolved_path,
                       brix_path_opts_t opts)
{
    ngx_int_t              type;
    brix_path_status_t   rc;

    if (!brix_path_within_root(ctx->root_canon, resolved_path)) {
        brix_path_warn(ctx->log, "brix: path traversal attempt", resolved_path);
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

    rc = brix_copy_cstr(ctx->resolved, ctx->resolvsz, resolved_path);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    if (ctx->result != NULL) {
        ctx->result->resolved.data = (u_char *) ctx->resolved;
        ctx->result->resolved.len = strlen(ctx->resolved);
        ctx->result->type = type;
        ctx->result->depth = ctx->depth;
        ctx->result->is_confined = 1;
    }

    return BRIX_PATH_STATUS_OK;
}

/*
 * brix_resolve_missing_tail — resolve a write target whose FINAL component does
 * not yet exist (create-a-new-leaf).
 *
 * WHAT: Splits candidate into parent dir + base name, canonicalises the parent
 *       with realpath(), confirms the parent is within the export root, rebuilds
 *       the absolute target (canonical parent + base), and finalises it under
 *       allow_missing_tail semantics via brix_finish_resolved.
 *
 * WHY:  New-leaf writes cannot realpath() the whole path, so containment is
 *       enforced on the existing parent instead. Taking ctx keeps this at three
 *       parameters while preserving the write-path confinement contract.
 *
 * HOW:  Copies into fixed PATH_MAX buffers with bounds checks; the lone-"/"
 *       parent and root-parent snprintf format selection are unchanged.
 */
static brix_path_status_t
brix_resolve_missing_tail(const brix_resolve_ctx_t *ctx, const char *candidate)
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

    if (!brix_path_within_root(ctx->root_canon, parent_canon)) {
        brix_path_warn(ctx->log, "brix: path traversal attempt in write",
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

    return brix_finish_resolved(ctx, rebuilt, final_opts);
}

/*
 * brix_walk_to_existing_ancestor — trim ancestor[] to its deepest EXISTING
 * component and canonicalise it.
 *
 * WHAT: Repeatedly realpath()s ancestor; on ENOENT strips the trailing
 *       component and retries, canonicalising into ancestor_canon once a real
 *       directory is reached (or the "/" root).
 *
 * WHY:  Missing-parents (recursive-mkdir/PUT) resolution must confine against
 *       the nearest existing ancestor. Extracting the walk loop keeps the caller
 *       under the complexity cap while preserving the exact climb order.
 *
 * HOW:  Mutates ancestor in place (trailing-slash rule unchanged) and writes the
 *       canonical form into ancestor_canon; returns NOT_FOUND/ERROR on failure,
 *       OK once ancestor_canon holds an existing path.
 */
static brix_path_status_t
brix_walk_to_existing_ancestor(char *ancestor, char *ancestor_canon)
{
    char *slash;

    for ( ;; ) {
        if (realpath(ancestor, ancestor_canon) != NULL) {
            return BRIX_PATH_STATUS_OK;
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
            return BRIX_PATH_STATUS_OK;
        }
    }
}

/*
 * brix_resolve_missing_parents — resolve a target whose intermediate parents do
 * not yet exist (recursive mkdir / HTTP PUT-style missing suffix).
 *
 * WHAT: Walks candidate back to its deepest existing, canonicalised ancestor
 *       (brix_walk_to_existing_ancestor), confirms containment, re-attaches the
 *       missing suffix to that canonical ancestor, and finalises under
 *       allow_missing_parents semantics.
 *
 * WHY:  With multiple absent components, confinement is enforced on the deepest
 *       real ancestor. Taking ctx keeps this at three parameters and preserves
 *       the suffix-splice and root-vs-nonroot format selection exactly.
 *
 * HOW:  Uses fixed PATH_MAX buffers with bounds checks; suffix offset math and
 *       snprintf format branch are byte-for-byte the pre-refactor logic.
 */
static brix_path_status_t
brix_resolve_missing_parents(const brix_resolve_ctx_t *ctx,
                               const char *candidate)
{
    char                    ancestor[PATH_MAX];
    char                    ancestor_canon[PATH_MAX];
    char                    rebuilt[PATH_MAX];
    const char             *suffix;
    size_t                  ancestor_len;
    int                     n;
    brix_path_status_t    rc;
    brix_path_opts_t      final_opts;

    if (strlen(candidate) >= sizeof(ancestor)) {
        return BRIX_PATH_STATUS_TOO_LONG;
    }

    ngx_memcpy(ancestor, candidate, strlen(candidate) + 1);

    rc = brix_walk_to_existing_ancestor(ancestor, ancestor_canon);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    if (!brix_path_within_root(ctx->root_canon, ancestor_canon)) {
        brix_path_warn(ctx->log, "brix: path traversal attempt", ancestor_canon);
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

    return brix_finish_resolved(ctx, rebuilt, final_opts);
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
    brix_resolve_ctx_t    ctx;
    brix_candidate_out_t  cand_out;

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

    depth = 0;
    cand_out.buf = candidate;
    cand_out.bufsz = sizeof(candidate);
    cand_out.depth_out = &depth;
    rc = brix_build_candidate(root_canon, req_path, opts, &cand_out);
    if (rc != BRIX_PATH_STATUS_OK) {
        return rc;
    }

    ctx.log = log;
    ctx.root_canon = root_canon;
    ctx.resolved = resolved;
    ctx.resolvsz = resolvsz;
    ctx.result = result;
    ctx.depth = depth;

    if (realpath(candidate, canonical) != NULL) {
        return brix_finish_resolved(&ctx, canonical, opts);
    }

    if (errno != ENOENT) {
        return BRIX_PATH_STATUS_ERROR;
    }

    if (opts.allow_missing_parents) {
        return brix_resolve_missing_parents(&ctx, candidate);
    }

    if (opts.allow_missing_tail) {
        return brix_resolve_missing_tail(&ctx, candidate);
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
