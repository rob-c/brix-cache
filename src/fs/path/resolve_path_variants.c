/*
 * resolve_path_variants.c — ngx_str_t-rooted convenience wrappers over the
 *                           unified cstr resolver (config-time use only).
 *
 * WHAT: Thin adapters that take an nginx ngx_str_t export root, canonicalise it,
 *       and forward to brix_path_resolve_cstr() (unified.c) with a preset
 *       brix_path_opts_t. The internal brix_resolve_with_opts() does the
 *       canonicalise-then-resolve dance; the only surviving public variant is
 *       brix_resolve_path_noexist() (write semantics, parents may be missing).
 *
 * WHY:  Most runtime client-path resolution moved off realpath() to the kernel-
 *       confined beneath API in Phase 8 (see the note further down). What remains
 *       here is intentionally limited to TRUSTED, CONFIG-TIME callers — namely
 *       brix_finalize_path_rules() canonicalising VO/group policy rule paths
 *       once at startup — where a realpath()-based canonicalisation is correct
 *       and is deliberately NOT migrated to the beneath API.
 *
 * HOW:  brix_resolve_with_opts() calls brix_get_canonical_root() (canonical.c)
 *       then brix_path_resolve_cstr(); a TOO_LONG status is logged as a warning
 *       and any non-OK status maps to a 0 (false) return. _noexist() sets
 *       allow_missing_parents + is_write_operation before delegating.
 */
#include "core/ngx_brix_module.h"

#include <limits.h>

#include "path_internal.h"
#include "unified.h"

static int
brix_resolve_with_opts(ngx_log_t *log, const ngx_str_t *root,
                         const char *reqpath, brix_path_opts_t opts,
                         char *resolved, size_t resolvsz)
{
    char                  root_canon[PATH_MAX];
    brix_path_status_t  rc;

    if (!brix_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    rc = brix_path_resolve_cstr(log, root_canon, reqpath, opts,
                                  resolved, resolvsz, NULL);
    if (rc == BRIX_PATH_STATUS_TOO_LONG) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
    }

    return rc == BRIX_PATH_STATUS_OK;
}

int
brix_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
                            const char *reqpath, char *resolved,
                            size_t resolvsz)
{
    brix_path_opts_t opts;

    opts = (brix_path_opts_t) { 0 };
    opts.allow_missing_parents = 1;
    opts.is_write_operation = 1;

    return brix_resolve_with_opts(log, root, reqpath, opts,
                                    resolved, resolvsz);
}

/*
 * Phase 8: brix_resolve_path() (EXISTING) and brix_resolve_path_write()
 * (WRITE) were removed — all runtime client-path callers (op_path.c, write/mv.c,
 * the WebDAV/S3 adapter compat/path.c) now resolve without realpath() via
 * brix_path_resolve_beneath()/brix_beneath_full_path(), with confinement
 * enforced by openat2(RESOLVE_BENEATH) at the operation.
 *
 * Only brix_resolve_path_noexist() remains, and only for CONFIG-TIME use:
 * brix_finalize_path_rules() (src/path/helpers.c) canonicalises VO/group
 * policy rule paths once at startup.  That is a trusted, non-client path, so a
 * realpath()-based canonicalisation is appropriate there and is intentionally
 * NOT migrated to the beneath API.
 */
