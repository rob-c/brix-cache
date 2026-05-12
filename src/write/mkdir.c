/*
 * mkdir.c â kXR_mkdir opcode handler.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_mkdir â create a directory within the export root.
 *
 * Wire format (ClientMkdirRequest):
 *   options[0]: bitfield; kXR_mkdirpath (0x01) requests recursive mkdir.
 *   mode:       big-endian uint16_t; low 9 bits set the permission mask.
 *               Defaults to 0755 if the client sends 0.
 *
 * Path resolution strategy:
 *   kXR_mkdirpath set:  xrootd_resolve_path_noexist â no realpath(3) call
 *     because intermediate directories do not yet exist.
 *   kXR_mkdirpath clear: xrootd_resolve_path_write â parent must exist,
 *     target may not.
 *
 * EEXIST is treated as success for both paths (idempotent mkdir).
 */
ngx_int_t
xrootd_handle_mkdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
					 ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientMkdirRequest *req = (ClientMkdirRequest *) ctx->hdr_buf;
	char     reqpath[XROOTD_MAX_PATH + 1];
	char     resolved[PATH_MAX];
	mode_t   mode;
	int      recursive;

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
	}

	recursive = (req->options[0] & kXR_mkdirpath) ? 1 : 0;
	mode      = ntohs(req->mode) & 0777;
	if (mode == 0) {
		mode = 0755;
	}

	/* kXR_mkdirpath changes only namespace creation strategy, not permission handling. */

	if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
							 reqpath, sizeof(reqpath), 0)) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", "-", "-",
						  kXR_ArgInvalid, "invalid path payload");
	}

	/*
	 * Resolve the target path.  For recursive mkdir intermediate directories
	 * do not exist yet, so we use xrootd_resolve_path_noexist (no realpath).
	 * For a single-level mkdir the parent must exist, so use the write resolver.
	 */
	if (recursive) {
		if (!xrootd_resolve_path_noexist(c->log, &conf->root,
										  reqpath,
										  resolved, sizeof(resolved))) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
							  kXR_NotFound, "invalid path");
		}
	} else {
		if (!xrootd_resolve_path_write(c->log, &conf->root,
									   reqpath,
									   resolved, sizeof(resolved))) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
							  kXR_NotFound, "invalid path");
		}
	}

	if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_MKDIR) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
						  kXR_NotAuthorized, "authdb denied");
	}

	if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
							 ctx->vo_list) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
						  kXR_NotAuthorized, "VO not authorized");
	}

	if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (recursive) {
		if (xrootd_mkdir_recursive_confined(c->log, &conf->root,
											resolved, mode, conf->group_rules) != 0
			&& errno != EEXIST)
		{
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
							  kXR_IOError, strerror(errno));
		}
	} else {
		/* Non-recursive mkdir maps directly to one root-confined mkdirat(2). */
		if (xrootd_mkdir_confined(c->log, &conf->root, resolved, mode) != 0) {
			int err = errno;
			if (err == EEXIST) {
				/* Not an error — directory already exists */
			} else if (err == EACCES) {
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
								  kXR_NotAuthorized, "permission denied");
			} else {
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
								  kXR_IOError, strerror(err));
			}
		}
		/* Align ownership/group-bits of new directory with parent dir policy. */
		if (conf->group_rules != NULL) {
			xrootd_apply_parent_group_policy_path(c->log, resolved,
												  conf->group_rules);
		}
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-", 0);
}
