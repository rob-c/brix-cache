/*
 * unified_internal.h — cross-file declarations for the unified path resolver.
 *
 * WHAT: Shared structs and non-static function declarations for the split of
 *       unified.c into three cohesive translation units — unified.c (public
 *       entry + shared logging), unified_build.c (component validation +
 *       candidate assembly), and unified_resolve.c (canonicalisation,
 *       confinement, and missing-tail/parent fallback). Any symbol DEFINED in
 *       one of those files but REFERENCED from another is declared here.
 *
 * WHY:  The three files were mechanically split from a single 729-line source
 *       with zero behaviour change. Declaring the cross-file seam in one header
 *       keeps the link contract explicit while leaving file-local helpers
 *       static in their owning translation unit.
 *
 * HOW:  Include-guarded; pulls in the module core (ngx types) and the public
 *       unified.h (brix_path_* types) so it is self-contained.
 */
#ifndef BRIX_FS_PATH_UNIFIED_INTERNAL_H
#define BRIX_FS_PATH_UNIFIED_INTERNAL_H

#include "core/ngx_brix_module.h"
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

/* Defined in unified.c, referenced from unified_build.c + unified_resolve.c. */
void brix_path_warn(ngx_log_t *log, const char *prefix, const char *path);

/* Defined in unified_build.c, referenced from unified.c / unified_resolve.c. */
brix_path_status_t brix_copy_cstr(char *dst, size_t dstsz, const char *src);
brix_path_status_t brix_validate_components_cstr(ngx_log_t *log,
    const char *path);
ngx_flag_t brix_has_trailing_slash_cstr(const char *path);
brix_path_status_t brix_build_candidate(const char *root_canon,
    const char *req_path, brix_path_opts_t opts, brix_candidate_out_t *out);

/* Defined in unified_resolve.c, referenced from unified.c. */
brix_path_status_t brix_finish_resolved(const brix_resolve_ctx_t *ctx,
    const char *resolved_path, brix_path_opts_t opts);
brix_path_status_t brix_resolve_missing_tail(const brix_resolve_ctx_t *ctx,
    const char *candidate);
brix_path_status_t brix_resolve_missing_parents(const brix_resolve_ctx_t *ctx,
    const char *candidate);

#endif /* BRIX_FS_PATH_UNIFIED_INTERNAL_H */
