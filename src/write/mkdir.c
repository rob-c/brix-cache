/*
 * mkdir.c — kXR_mkdir opcode.  See each function's docblock below.
 */

#include "ngx_xrootd_module.h"
#include "../compat/error_mapping.h"

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
	xrdw_mkdir_req_t req;
	char     reqpath[XROOTD_MAX_PATH + 1];
	char     resolved[PATH_MAX];
	mode_t   mode;
	int      recursive;

	xrdw_mkdir_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
	recursive = (req.options & kXR_mkdirpath) ? 1 : 0;
	mode      = req.mode & 0777;
	if (mode == 0) {
		mode = 0755;
	}

	{
		xrootd_path_mode_t pmode = recursive ? XROOTD_PATH_NOEXIST
		                                     : XROOTD_PATH_WRITE;
		if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_MKDIR, "MKDIR", conf,
								   pmode,
								   reqpath, sizeof(reqpath),
								   resolved, sizeof(resolved)) != NGX_OK) {
			return ctx->write_rc;
		}
	}

	if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "MKDIR",
						  reqpath, resolved, conf,
						  XROOTD_AUTH_MKDIR, 1) != NGX_OK) {
		return ctx->write_rc;
	}

	{
		xrootd_ns_result_t res;

		res = xrootd_ns_mkdir(c->log, conf->common.root_canon,
		                      resolved, mode, recursive);
		/* Idempotency follows the reference do_Mkdir: only kXR_mkdirpath
		 * (mkdir -p) tolerates an existing target. A plain mkdir of a path that
		 * already exists must fail with kXR_ItExists — stock xrdfs reports
		 * "Unable to mkdir <p>; file exists". Our recursive helper never returns
		 * EXISTS (mkpath is inherently idempotent), so EXISTS only arises here on
		 * the single-level path. */
		if (res.status == XROOTD_NS_EXISTS && !recursive) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
			                  kXR_ItExists, "file exists");
		}
		if (res.status != XROOTD_NS_OK && res.status != XROOTD_NS_EXISTS) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
			                  xrootd_kxr_map_ns_status(res.status, res.sys_errno),
			                  res.status == XROOTD_NS_DENIED ? "permission denied"
			                                                 : strerror(res.sys_errno));
		}
		/* Apply parent group policy after successful single-level mkdir. */
		if (!recursive && res.created && conf->group_rules != NULL) {
			xrootd_apply_parent_group_policy_path(c->log, resolved,
			                                      conf->group_rules);
		}
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-", 0);
}
