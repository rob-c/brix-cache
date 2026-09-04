#ifndef BRIX_ROOT_PREPARE_H
#define BRIX_ROOT_PREPARE_H

#include "core/ngx_brix_module.h"

/*
 * brix_export_root_opts_t — caller-supplied policy for export-root preparation.
 *
 *   directive_name  NUL-terminated directive name for error messages (e.g. "brix_root")
 *   allow_write     non-zero: require W_OK in addition to R_OK | X_OK
 *   required        non-zero: return NGX_CONF_ERROR when root is empty/unset
 *   canon_size      size of the caller-supplied root_canon buffer (must be >= PATH_MAX)
 */
typedef struct {
    const char *directive_name;
    ngx_flag_t  allow_write;
    ngx_flag_t  required;
    size_t      canon_size;
} brix_export_root_opts_t;

/*
 * brix_prepare_export_root — validate and canonicalize an export root path.
 *
 * Called from protocol merge_loc_conf callbacks.  The helper:
 *   1. Returns NGX_CONF_OK immediately if root is empty and required == 0.
 *   2. Returns NGX_CONF_ERROR with NGX_LOG_EMERG if root is empty and required != 0.
 *   3. Rejects root.len >= opts->canon_size (path too long).
 *   4. Calls brix_validate_path() to verify the path is a readable directory
 *      with write access when opts->allow_write is set.
 *   5. Calls realpath(3) to resolve symlinks and store the canonical form.
 *   6. Writes the NUL-terminated canonical path into root_canon.
 *
 * Returns NGX_CONF_OK on success, NGX_CONF_ERROR on any failure (after emitting
 * an NGX_LOG_EMERG log message via ngx_conf_log_error).
 */
char *brix_prepare_export_root(ngx_conf_t *cf,
    const ngx_str_t *root, const brix_export_root_opts_t *opts,
    char *root_canon);

/*
 * brix_prepare_cache_root — lower brix_cache_root into the composable cache.
 * Canonicalizes the shared preamble's POSIX cache directory, requires it to be
 * writable, enforces the HARD outside-export guard, and turns it into a
 * `posix:<canonical-path>` brix_cache_store before tier registration. The
 * legacy cache-root fields are cleared so only one cache engine runs. A config
 * that names both forms is rejected as ambiguous. No-op when cache_root is
 * unset. One helper for every HTTP protocol's merge keeps the policy uniform.
 */
char *brix_prepare_cache_root(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common);

/*
 * brix_prepare_spill_scratch — validate and register the writer's reorder
 * spill scratch (phase-107 C1) for this export.  Order of authority:
 *   1. brix_vfs_spill_path when set — must be absolute, an existing writable
 *      directory, and OUTSIDE the export root (all three are nginx -t emergs);
 *   2. else `stage_dir_canon` (the export's prepared brix_stage_dir canonical
 *      path; pass NULL/"" when the surface has none) — already validated by
 *      its own preparation;
 *   3. else no scratch: a reordered upload on a staged-only backend is
 *      refused ENOSPC at the moment the writer would spill.
 * Also enforces brix_vfs_spill_max in {0} ∪ [1 MiB, ∞) and registers the
 * chosen root with the owned-temp reaper.  Call AFTER the export root and any
 * stage dir are prepared, in every protocol merge that anchors an export.
 * Phase-107 C3 rides the same hook: a merged `brix_durable_publish off` is
 * registered with the backend registry here, so the publish barrier is
 * skipped for this export (absence = durable).
 */
char *brix_prepare_spill_scratch(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common, const char *stage_dir_canon);

#endif /* BRIX_ROOT_PREPARE_H */
