/* ------------------------------------------------------------------ */
/* Directory Removal — kXR_rmdir handler                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_rmdir opcode — removing an empty directory within the export root. The handler performs four-phase removal: path extraction + canonical resolution (xrootd_write_resolve_existing_path), VO ACL + token scope write gate check, confined unlink via xrootd_unlink_confined() enforcing export root boundary, and errno-to-kXR mapping for error responses.
 *
 * WHY: Directory removal is a mutating namespace operation requiring authentication AND explicit write permission. Unlike rm.c (file deletion), rmdir.c additionally validates that the directory is actually empty before allowing removal — preventing accidental deletion of directories containing important data. The xrootd_unlink_confined() helper enforces export root boundary preventing post-unlink path escape attacks, ensuring only directories within the configured export root can be removed.
 *
 * HOW: Three-phase removal → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — confined unlink via xrootd_unlink_confined() enforcing export root boundary — errno-to-kXR mapping: ENOTEMPTY/EEXIST → kXR_FSError "directory not empty", EACCES/EPERM → kXR_NotAuthorized, ENOTDIR → kXR_NotFile, all others → kXR_IOError. */

/* ------------------------------------------------------------------ */
/* Section: Empty Directory Validation                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: rmdir only succeeds when the target directory is empty (ENOTEMPTY/EEXIST from unlink(2) indicates non-empty). This validation prevents accidental deletion of directories containing important data — operators must explicitly remove contents before attempting directory removal. Unlike rm.c which deletes files regardless of content, rmdir.c requires emptiness as a precondition for successful removal.
 *
 * WHY: Prevents catastrophic data loss by requiring manual emptying before directory removal. In production deployments where large datasets may be stored in hierarchical directories, this safety mechanism ensures operators cannot accidentally delete entire dataset hierarchies without first removing individual files or subdirectories within them. */

/* ------------------------------------------------------------------ */
/* Section: Confined Unlink Enforcement                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_unlink_confined() enforces export root boundary during directory removal, preventing post-unlink path escape attacks. Unlike raw unlink(2) which could theoretically operate on paths outside the configured export root, this confined helper ensures only directories within conf->common.root can be removed — providing additional security layer beyond canonical path resolution. The second parameter (1 = true) indicates recursive unlink mode for directory removal versus single-file unlink in rm.c.
 *
 * WHY: Provides defense-in-depth against path escape attacks where malicious clients could attempt to remove files or directories outside the export root boundary using crafted path payloads. Canonical resolution alone may not prevent all escape scenarios; confined unlink adds kernel-level enforcement ensuring only authorized paths can be modified regardless of client input. */

/* ---- Function: xrootd_handle_rmdir() ----
 *
 * WHAT: Handles the kXR_rmdir opcode — removes an empty directory within the export root performing four-phase removal: shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level), token scope write gate check, confined unlink via xrootd_unlink_confined() enforcing export root boundary, and errno-to-kXR mapping for error responses. Only succeeds when target directory is empty; ENOTEMPTY/EEXIST returns kXR_FSError "directory not empty". Confined unlink prevents post-unlink path escape attacks beyond canonical resolution alone.
 *
 * WHY: Provides safe directory removal requiring emptiness as precondition — prevents accidental deletion of directories containing important data in production deployments where large datasets may be stored hierarchically. Confinement enforcement ensures only directories within export root can be removed regardless of client input, providing defense-in-depth against path escape attacks.
 *
 * HOW: Three-phase removal → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_DELETE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — confined unlink via xrootd_unlink_confined() enforcing export root boundary — errno-to-kXR mapping: ENOTEMPTY/EEXIST → kXR_FSError "directory not empty", EACCES/EPERM → kXR_NotAuthorized, ENOTDIR → kXR_NotFile, all others → kXR_IOError. */

/*
 * rmdir.c â kXR_rmdir opcode handler: remove an empty directory.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_rmdir â remove a directory named in the request payload.
 *
 * Fails with kXR_FSError if the directory is not empty (ENOTEMPTY / EEXIST),
 * kXR_NotFile if the path is not a directory (ENOTDIR), and kXR_NotAuthorized
 * for permission errors.  All other syscall errors map to kXR_IOError.
 */
ngx_int_t
xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
					ngx_stream_xrootd_srv_conf_t *conf)
{
	char reqpath[XROOTD_MAX_PATH + 1];
	char resolved[PATH_MAX];
	ngx_flag_t exists;

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
	}

	if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
							 reqpath, sizeof(reqpath), 1)) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", "-", "-",
						  kXR_ArgInvalid, "invalid path payload");
	}

	exists = xrootd_resolve_path(c->log, &conf->common.root, reqpath,
								 resolved, sizeof(resolved));
	if (!exists &&
		!xrootd_resolve_path_noexist(c->log, &conf->common.root, reqpath,
									 resolved, sizeof(resolved))) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", reqpath, "-",
						  kXR_NotFound, "invalid path");
	}

	if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_DELETE) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
						  kXR_NotAuthorized, "authdb denied");
	}

	if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
							ctx->identity) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
						  kXR_NotAuthorized, "VO not authorized");
	}

	if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", reqpath, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (!exists) {
		XROOTD_RETURN_OK(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-", 0);
	}

	if (xrootd_unlink_confined(c->log, &conf->common.root, resolved, 1) != 0) {
		int err = errno;

		/* Map common namespace errors to protocol-level directory semantics. */
		if (err == ENOTEMPTY || err == EEXIST) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
							  kXR_FSError, "directory not empty");
		}
		if (err == EACCES || err == EPERM) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
							  kXR_NotAuthorized, "permission denied");
		}
		if (err == ENOTDIR) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
							  kXR_NotFile, "not a directory");
		}
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-",
						  kXR_IOError, strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_RMDIR, "RMDIR", resolved, "-", 0);
}
