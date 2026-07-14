/*
 * unified_resolve.c — canonicalisation, confinement, and missing-tail/parent
 * fallback for the shared realpath()-based path resolver (split from unified.c,
 * verbatim).
 *
 * WHAT: Implements the post-candidate resolution stages of
 *       brix_path_resolve_cstr(): the final confinement+stat step
 *       (brix_finish_resolved), and the two ENOENT fallbacks —
 *       brix_resolve_missing_tail (new-leaf write) and
 *       brix_resolve_missing_parents (recursive mkdir / PUT-style suffix), plus
 *       the ancestor-walk helper.
 *
 * WHY:  Kept in a dedicated translation unit so each file stays small and
 *       single-purpose; behaviour is byte-for-byte identical to the original
 *       unified.c. The cross-file seam is declared in unified_internal.h.
 *
 * HOW:  See the per-function doc blocks; the public entry point in unified.c
 *       hands a built candidate here after realpath() succeeds or ENOENTs.
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
brix_path_status_t
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
brix_path_status_t
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
brix_path_status_t
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
