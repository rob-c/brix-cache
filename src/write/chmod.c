/*
 * chmod.c â kXR_chmod opcode handler.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_chmod â change file permission bits.
 *
 * Wire format (ClientChmodRequest): mode is big-endian uint16_t; only the
 * low 9 bits (0777) are used.  File type bits from the client are never
 * applied.  A client-supplied mode of 0 is substituted with 0644.
 *
 * Uses chmod(2) rather than fchmod(2) because the handle may not be open.
 */
ngx_int_t
xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
					ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientChmodRequest *req = (ClientChmodRequest *) ctx->hdr_buf;
	char    reqpath[XROOTD_MAX_PATH + 1];
	char    resolved[PATH_MAX];
	mode_t  mode;
	ngx_int_t rc;

	mode = ntohs(req->mode) & 0777;
	if (mode == 0) {
		mode = 0644;  /* sensible default if client sends 0 */
	}

	/* chmod uses only the low permission bits; file type bits are never client-controlled. */

	if (!xrootd_write_resolve_existing_path(ctx, c, conf, "CHMOD",
											XROOTD_OP_CHMOD, "file not found",
											XROOTD_AUTH_UPDATE,
											reqpath, sizeof(reqpath),
											resolved, sizeof(resolved), &rc)) {

		return rc;
	}

	if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "CHMOD", reqpath, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (chmod(resolved, mode) != 0) {
		int err = errno;
		if (err == EACCES || err == EPERM) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-",
							  kXR_NotAuthorized, "permission denied");
		}
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-",
						  kXR_IOError, strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-", 0);
}
