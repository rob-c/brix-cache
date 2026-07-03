/*
 * mkdir.c — kXR_mkdir opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/error_mapping.h"
#include "fs/vfs/vfs.h"   /* mkdir via the VFS seam */
#include "fs/vfs/vfs_backend_registry.h"   /* POSIX-vs-driver export check for group policy */

/*
 * brix_handle_mkdir â create a directory within the export root.
 *
 * Wire format (ClientMkdirRequest):
 *   options[0]: bitfield; kXR_mkdirpath (0x01) requests recursive mkdir.
 *   mode:       big-endian uint16_t; low 9 bits set the permission mask.
 *               Defaults to 0755 if the client sends 0.
 *
 * Path resolution strategy:
 *   kXR_mkdirpath set:  brix_resolve_path_noexist â no realpath(3) call
 *     because intermediate directories do not yet exist.
 *   kXR_mkdirpath clear: brix_resolve_path_write â parent must exist,
 *     target may not.
 *
 * EEXIST is treated as success for both paths (idempotent mkdir).
 */
ngx_int_t
brix_handle_mkdir(brix_ctx_t *ctx, ngx_connection_t *c,
					 ngx_stream_brix_srv_conf_t *conf)
{
	xrdw_mkdir_req_t req;
	char     reqpath[BRIX_MAX_PATH + 1];
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
		brix_path_mode_t pmode = recursive ? BRIX_PATH_NOEXIST
		                                     : BRIX_PATH_WRITE;
		if (brix_resolve_op_path(ctx, c, BRIX_OP_MKDIR, "MKDIR", conf,
								   pmode,
								   reqpath, sizeof(reqpath),
								   resolved, sizeof(resolved)) != NGX_OK) {
			return ctx->write_rc;
		}
	}

	if (brix_auth_gate(ctx, c, BRIX_OP_MKDIR, "MKDIR",
						  reqpath, resolved, conf,
						  BRIX_AUTH_MKDIR, 1) != NGX_OK) {
		return ctx->write_rc;
	}

	{
		brix_vfs_ctx_t vctx;
		ngx_int_t        rc;

		brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
			conf->common.root_canon, NULL, conf->common.allow_write,
			0 /* is_tls */, NULL, resolved);
		rc = brix_vfs_mkdir(&vctx, mode, recursive);
		if (rc != NGX_OK) {
			int err = errno;

			/* Idempotency follows the reference do_Mkdir: only kXR_mkdirpath
			 * (mkdir -p) tolerates an existing target — and the recursive helper
			 * is itself idempotent (returns NGX_OK), so EEXIST only arises on a
			 * plain single-level mkdir, which must fail kXR_ItExists. */
			if (err == EEXIST && !recursive) {
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_MKDIR, "MKDIR", resolved, "-",
				                  kXR_ItExists, "file exists");
			}
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_MKDIR, "MKDIR", resolved, "-",
			                  brix_kxr_from_errno(err),
			                  (err == EACCES || err == EPERM)
			                      ? "permission denied" : strerror(err));
		}
		/* NGX_OK ⟺ the directory was created (not pre-existing); apply parent
		 * group policy after a successful single-level mkdir. setgid group
		 * inheritance is a real-filesystem (POSIX) semantic enforced with raw
		 * chmod/chown — meaningless for a non-POSIX backend whose namespace lives
		 * in a catalog, so it is skipped there (the driver owns that mode). */
		if (!recursive && conf->group_rules != NULL
		    && brix_vfs_backend_resolve(conf->common.root_canon, c->log) == NULL) {
			brix_apply_parent_group_policy_path(c->log, resolved,
			                                      conf->group_rules);
		}
	}

	BRIX_RETURN_OK(ctx, c, BRIX_OP_MKDIR, "MKDIR", resolved, "-", 0);
}
