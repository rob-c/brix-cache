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
	ngx_int_t rc;

	if (!xrootd_write_resolve_existing_path(ctx, c, conf, "RMDIR",
											XROOTD_OP_RMDIR, "directory not found",
											XROOTD_AUTH_DELETE,
											reqpath, sizeof(reqpath),
											resolved, sizeof(resolved), &rc)) {
		return rc;
	}

	if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", reqpath, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (xrootd_unlink_confined(c->log, &conf->root, resolved, 1) != 0) {
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
