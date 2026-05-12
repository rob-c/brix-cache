/*
 * truncate.c â kXR_truncate opcode handler.
 */
#include "ngx_xrootd_module.h"

#include <fcntl.h>

/*
 * xrootd_handle_truncate â set the length of a file to the given offset.
 *
 * Wire format (ClientTruncateRequest):
 *   fhandle[4]: open handle (only meaningful when dlen == 0)
 *   offset:     big-endian int64 â the new file length in bytes
 *   dlen:       0 means handle-based truncate; >0 means path-based truncate
 *
 * Handle-based path: uses the fd already open on the slot.
 * Path-based path:   resolves the path, opens it O_WRONLY, calls ftruncate,
 *   then closes the temporary fd.
 *
 * Token scope: write scope is required for both paths.
 */
ngx_int_t
xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
						ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientTruncateRequest *req = (ClientTruncateRequest *) ctx->hdr_buf;
	int64_t  length = (int64_t) be64toh((uint64_t) req->offset);
	char     detail[64];
	int      rc;

	snprintf(detail, sizeof(detail), "%lld", (long long) length);

	if (ctx->cur_dlen > 0) {
		/* Path-based truncate */
		char resolved[PATH_MAX];
		char reqpath[XROOTD_MAX_PATH + 1];
		if (ctx->payload == NULL) {
			return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
		}
		if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
								 reqpath, sizeof(reqpath), 0)) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE", "-",
							  detail, kXR_ArgInvalid, "invalid path payload");
		}
		if (!xrootd_resolve_path_write(c->log, &conf->root,
									   reqpath,
									   resolved, sizeof(resolved))) {
			  /*
			   * write-style resolution handles the common "target may not exist" case.
			   * If that fails, fall back to the normal resolver so existing files with
			   * canonical paths still truncate correctly.
			   */
			if (!xrootd_resolve_path(c->log, &conf->root,
									 reqpath,
									 resolved, sizeof(resolved))) {
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
								  reqpath, detail, kXR_NotFound, "file not found");
			}
		}
		if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_NotAuthorized, "authdb denied");
		}

		if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
								 ctx->vo_list) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_NotAuthorized, "VO not authorized");
		}
		if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  reqpath, detail, kXR_NotAuthorized, "token scope denied");
		}
		rc = xrootd_open_confined(c->log, &conf->root, resolved,
								  O_WRONLY | O_NOCTTY, 0);
		if (rc < 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_IOError, strerror(errno));
		}
		if (ftruncate(rc, (off_t) length) != 0) {
			int err = errno;
			close(rc);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_IOError, strerror(err));
		}
		close(rc);
		xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
						  1, 0, NULL, 0);
	} else {
		/* Handle-based truncate bypasses path resolution and uses the already-open fd. */
		int idx = (int)(unsigned char) req->fhandle[0];
		ngx_int_t validate_rc;

		if (!xrootd_validate_file_handle(ctx, c, idx, "TRUNCATE",
										 XROOTD_OP_TRUNCATE, &validate_rc)) {
			return validate_rc;
		}
		rc = ftruncate(ctx->files[idx].fd, (off_t) length);
		if (rc != 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  ctx->files[idx].path, detail,
							  kXR_IOError, strerror(errno));
		}
		xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
						  1, 0, NULL, 0);
	}

	XROOTD_OP_OK(ctx, XROOTD_OP_TRUNCATE);
	return xrootd_send_ok(ctx, c, NULL, 0);
}
