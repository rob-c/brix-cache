/*
 * rm.c â kXR_rm opcode handler: unlink a file within the export root.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_rm â remove a file named in the request payload.
 *
 * The path is extracted, resolved under conf->root (must exist), checked
 * against VO ACLs and token write scope, then unlinked via
 * xrootd_unlink_confined which enforces the export root boundary.
 *
 * EACCES/EPERM are mapped to kXR_NotAuthorized; other errors to kXR_IOError.
 */
ngx_int_t
xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
				  ngx_stream_xrootd_srv_conf_t *conf)
{
	char reqpath[XROOTD_MAX_PATH + 1];
	char resolved[PATH_MAX];
	ngx_int_t rc;

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

	if (xrootd_unlink_confined(c->log, &conf->root, resolved, 0) != 0) {
		int err = errno;
		if (err == EACCES || err == EPERM) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RM, "RM", resolved, "-",
							  kXR_NotAuthorized, "permission denied");
		}
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RM, "RM", resolved, "-",
						  kXR_IOError, strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_RM, "RM", resolved, "-", 0);
}
