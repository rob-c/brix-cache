#ifndef XROOTD_PATH_OP_PATH_H
#define XROOTD_PATH_OP_PATH_H

/*
 * Path resolution strategy for namespace operations (Phase 8: existence is
 * verified with xrootd_stat_beneath, not realpath; confinement is the kernel's
 * RESOLVE_BENEATH at the op).
 *
 * EXISTING  — target must already exist.  Read-side ops (stat, locate,
 *             open-read) and rm/chmod.
 * WRITE     — parent dir must exist, target may not; creating a new file.
 * NOEXIST   — full path may not exist; no existence gate; recursive mkdir.
 * EITHER    — parent-exists (WRITE) OR target-exists (EXISTING); truncate, rmdir.
 *
 * NOTE: defined before the module include below so this header stays usable from
 * the op_table.h / ngx_xrootd_module.h include cycle (op_table embeds a mode).
 */
typedef enum {
    XROOTD_PATH_EXISTING,
    XROOTD_PATH_WRITE,
    XROOTD_PATH_NOEXIST,
    XROOTD_PATH_EITHER,
} xrootd_path_mode_t;

#include "ngx_xrootd_module.h"

/*
 * xrootd_resolve_op_path — extract, depth-check, and resolve a path from the
 * current request payload in a single call.
 *
 * On success: reqpath and resolved are filled; returns NGX_OK.
 * On failure: sends the appropriate kXR error wire response, stores the nginx
 *             return code in ctx->write_rc, and returns NGX_DONE.
 *             The caller must return ctx->write_rc immediately.
 *
 * Parameters:
 *   ctx         — connection context (payload + cur_dlen consumed here)
 *   c           — nginx connection (for logging and error sending)
 *   op_id       — XROOTD_OP_* constant for metric tracking
 *   op_name     — verb for the access log ("MKDIR", "RMDIR", etc.)
 *   conf        — server config (root, depth limit)
 *   mode        — path resolution strategy (see xrootd_path_mode_t above)
 *   reqpath     — caller buffer, XROOTD_MAX_PATH+1 bytes; filled on NGX_OK
 *   reqpath_sz  — sizeof(reqpath)
 *   resolved    — caller buffer, PATH_MAX bytes; filled on NGX_OK
 *   resolved_sz — sizeof(resolved)
 *
 * Usage:
 *   if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_MKDIR, "MKDIR", conf,
 *                               XROOTD_PATH_WRITE,
 *                               reqpath, sizeof(reqpath),
 *                               resolved, sizeof(resolved)) != NGX_OK) {
 *       return ctx->write_rc;
 *   }
 */
ngx_int_t xrootd_resolve_op_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                                   ngx_uint_t op_id, const char *op_name,
                                   ngx_stream_xrootd_srv_conf_t *conf,
                                   xrootd_path_mode_t mode,
                                   char *reqpath, size_t reqpath_sz,
                                   char *resolved, size_t resolved_sz);

/*
 * xrootd_op_path_forbidden_component — returns 1 if reqpath contains a "." or
 * ".." path component (the validation the retired realpath resolver did).
 * Shared with direct multi-path callers (e.g. kXR_mv) that don't route through
 * xrootd_resolve_op_path.  RESOLVE_BENEATH still blocks an escaping "..", but
 * this preserves the historical rejection of any "." / ".." segment.
 */
int xrootd_op_path_forbidden_component(const char *reqpath);

/*
 * xrootd_reject_dotdot_path — for the EXTRACT-based ops (stat/open/dirlist/
 * locate) that resolve straight through the kernel RESOLVE_BENEATH and so do
 * NOT pass through xrootd_path_resolve_beneath's "."/".." rejection. If `reqpath`
 * contains a ".." component, this logs the traversal warning + access line and
 * sends a kXR_ArgInvalid error (exactly as xrootd_resolve_op_path does for the
 * op-table ops), then returns 1; the caller must `return ctx->write_rc`. Returns
 * 0 (and does nothing) when the path is clean. Only ".." is rejected — a lone
 * "." is collapsed by the kernel and accepted, matching the reference for these
 * read/metadata ops.
 */
int xrootd_reject_dotdot_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                              ngx_uint_t op_id, const char *op_name,
                              const char *reqpath);

/*
 * xrootd_path_resolve_beneath — realpath-free path validation + per-mode
 * existence gate, filling `resolved` with the confined root_canon+reqpath join.
 * The shared core of xrootd_resolve_op_path(); also called directly by kXR_mv
 * (two paths in one payload).  reqpath must already be extracted.
 *   NGX_OK       — valid, existence requirement met, resolved filled.
 *   NGX_DECLINED — well-formed but missing (EXISTING target / WRITE parent) → 404.
 *   NGX_ERROR    — malformed (depth / "."/".." / WRITE trailing slash / overflow).
 */
ngx_int_t xrootd_path_resolve_beneath(ngx_stream_xrootd_srv_conf_t *conf,
                                      ngx_log_t *log,
                                      const char *reqpath,
                                      xrootd_path_mode_t mode,
                                      char *resolved, size_t resolved_sz);

#endif /* XROOTD_PATH_OP_PATH_H */
