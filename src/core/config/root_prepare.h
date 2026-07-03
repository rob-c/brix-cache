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

#endif /* BRIX_ROOT_PREPARE_H */
