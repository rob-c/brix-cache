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
 *
 *       The validation/candidate-build stages live in unified_build.c and the
 *       canonicalisation/confinement/fallback stages in unified_resolve.c; the
 *       cross-file seam (shared structs + non-static helpers) is declared in
 *       unified_internal.h. This file keeps the public entry point and the
 *       shared logging/init helpers.
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

void
brix_path_warn(ngx_log_t *log, const char *prefix, const char *path)
{
    if (log != NULL) {
        brix_log_path_warning(log, prefix, path);
    }
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
