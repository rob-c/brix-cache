/* ------------------------------------------------------------------ */
/* File Deletion — kXR_rm handler                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_rm opcode — removing (unlinking) a file within the export root. The handler performs three-phase deletion: shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level), token scope write gate check, and confined unlink via xrootd_unlink_confined() enforcing export root boundary preventing post-unlink path escape attacks.
 *
 * WHY: File deletion is a mutating namespace operation requiring authentication AND explicit write permission. Unlike directory removal (rmdir.c which requires emptiness), file deletion succeeds regardless of content — the file simply ceases to exist after unlink(2). The xrootd_unlink_confined() helper enforces export root boundary preventing post-unlink path escape attacks, ensuring only files within the configured export root can be deleted.
 *
 * HOW: Three-phase deletion → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — confined unlink via xrootd_unlink_confined() enforcing export root boundary — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/* ------------------------------------------------------------------ */
/* Section: Confined Unlink Enforcement                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_unlink_confined() enforces export root boundary during file deletion, preventing post-unlink path escape attacks. Unlike raw unlink(2) which could theoretically operate on paths outside the configured export root, this confined helper ensures only files within conf->common.root can be deleted — providing additional security layer beyond canonical path resolution. The second parameter (0 = false) indicates single-file unlink mode for file deletion versus recursive unlink in rmdir.c for directory removal.
 *
 * WHY: Provides defense-in-depth against path escape attacks where malicious clients could attempt to delete files outside the export root boundary using crafted path payloads. Canonical resolution alone may not prevent all escape scenarios; confined unlink adds kernel-level enforcement ensuring only authorized paths can be modified regardless of client input. */

/* ---- Function: xrootd_handle_rm() ----
 *
 * WHAT: Handles the kXR_rm opcode — removes (unlinks) a file within the export root performing three-phase deletion: shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level), token scope write gate check, confined unlink via xrootd_unlink_confined() enforcing export root boundary preventing post-unlink path escape attacks. Returns kXR_ok on success with access-log detail "-" and byte count 0. Unlike rmdir.c which requires emptiness as precondition, rm.c succeeds regardless of file content — the file simply ceases to exist after unlink(2).
 *
 * WHY: Provides safe file deletion requiring authentication AND explicit write permission. Confinement enforcement ensures only files within export root can be deleted regardless of client input, providing defense-in-depth against path escape attacks beyond canonical resolution alone. Unlike directory removal which requires emptiness as precondition, file deletion succeeds regardless of content — the file simply ceases to exist after unlink(2).
 *
 * HOW: Three-phase deletion → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — confined unlink via xrootd_unlink_confined() enforcing export root boundary — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/*
 * rm.c — kXR_rm opcode handler: unlink a file within the export root.
 */
#include "ngx_xrootd_module.h"
#include "../compat/error_mapping.h"
#include "../compat/namespace_ops.h"

/*
 * xrootd_handle_rm — remove a file named in the request payload.
 *
 * The path is extracted, resolved under conf->common.root (must exist), checked
 * against VO ACLs and token write scope, then unlinked via
 * xrootd_ns_delete which enforces the export root boundary and handles
 * directory retry behavior.
 *
 * EACCES/EPERM are mapped to kXR_NotAuthorized; other errors to kXR_IOError.
 */
ngx_int_t
xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  ngx_stream_xrootd_srv_conf_t *conf)
{
    char                    reqpath[XROOTD_MAX_PATH + 1];
    char                    resolved[PATH_MAX];
    ngx_int_t               rc;
    xrootd_ns_result_t      res;
    xrootd_ns_delete_opts_t opts;

    if (!xrootd_write_resolve_existing_path(ctx, c, conf, "RM",
                                            XROOTD_OP_RM, "file not found",
                                            XROOTD_AUTH_DELETE,
                                            reqpath, sizeof(reqpath),
                                            resolved, sizeof(resolved), &rc)) {
        return rc;
    }

    if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RM, "RM", reqpath, "-",
                          kXR_NotAuthorized, "token scope denied");
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 0;
    opts.recursive          = 0;
    opts.require_empty_dir  = 0;

    res = xrootd_ns_delete(c->log, conf->common.root_canon, resolved, &opts);

    if (res.status != XROOTD_NS_OK) {
        /*
         * Retry with recursive flag if it was a directory (native kXR_rm
         * behavior: attempt rmdir if unlink fails with EISDIR).
         */
        if (res.was_dir) {
            opts.recursive = 1;
            res = xrootd_ns_delete(c->log, conf->common.root_canon, resolved, &opts);
            if (res.status == XROOTD_NS_OK) {
                XROOTD_RETURN_OK(ctx, c, XROOTD_OP_RM, "RM", resolved, "-", 0);
            }
            if (res.status == XROOTD_NS_NOT_EMPTY) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RM, "RM", resolved, "-",
                                  kXR_FSError, "directory not empty");
            }
        }

        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RM, "RM", resolved, "-",
                          xrootd_kxr_from_errno(res.sys_errno),
                          res.status == XROOTD_NS_DENIED ? "permission denied"
                                                       : strerror(res.sys_errno));
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_RM, "RM", resolved, "-", 0);
}
