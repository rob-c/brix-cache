/* ------------------------------------------------------------------ */
/* Directory Creation — kXR_mkdir handler                                 */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_mkdir opcode — creating directories within the export root. Supports both single-level directory creation and recursive mkdir via kXR_mkdirpath flag (0x01). The client specifies a path, optional recursion flag, and permission mode bits (low 9 bits of uint16_t; defaults to 0755 if client sends 0). Path resolution uses xrootd_resolve_path_noexist for recursive creation (intermediate directories may not exist yet) or xrootd_resolve_path_write for single-level creation (parent must exist, target may not).
 *
 * WHY: Directory creation is fundamental for namespace organization and staging scenarios. Recursive mkdir enables bulk directory structure setup without requiring parent directories to pre-exist — critical for staging uploads where client creates entire path hierarchy in a single request. EEXIST treated as success provides idempotent behavior allowing clients to retry failed attempts without error propagation (directory either exists or creation succeeds).
 *
 * HOW: Two-phase creation → parse wire format (options[0] bitfield, mode bits) — extract/clean/resolve path based on kXR_mkdirpath flag — apply parent group policy if configured — mkdir(2) syscall with permission mask — EEXIST treated as success for idempotent behavior — return kXR_ok response. */

/* ------------------------------------------------------------------ */
/* Section: Recursive vs Single-Level Resolution                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Path resolution strategy differs based on kXR_mkdirpath flag presence. When recursive (kXR_mkdirpath set): uses xrootd_resolve_path_noexist — no realpath(3) call because intermediate directories do not yet exist, allowing creation of entire path hierarchy in one request. When single-level (kXR_mkdirpath clear): uses xrootd_resolve_path_write — parent must exist, target may not, ensuring only direct children of existing directories can be created without recursive expansion.
 *
 * WHY: Different resolution strategies prevent security issues while supporting both use cases. Recursive creation allows staging uploads to create entire directory hierarchies in one request; single-level creation ensures clients cannot bypass path hierarchy by creating arbitrary intermediate directories that should exist under parent supervision. */

/* ------------------------------------------------------------------ */
/* Section: Permission Mask Handling                                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Client-supplied mode bits are masked to low 9 bits (0777) — file type bits from the client are never applied, ensuring only permission bits (user/group/other read/write/executable) can be specified. A client-supplied mode of 0 is substituted with 0644 as sensible default for newly created directories. kXR_mkdirpath changes only namespace creation strategy, not permission handling — both modes apply identical permission masking logic.
 *
 * WHY: Prevents clients from specifying inappropriate file type bits (directory vs regular file flags) that could confuse filesystem metadata. Only permission bits are accepted; the mkdir(2) syscall automatically sets S_ISDIR flag regardless of client input. 0644 default provides sensible permissions for newly created directories without requiring explicit mode specification in common use cases. */

/* ---- Function: xrootd_handle_mkdir() ----
 *
 * WHAT: Handles the kXR_mkdir opcode — creates a directory within the export root supporting both single-level and recursive creation via kXR_mkdirpath flag (0x01). Parses wire format (options bitfield, mode bits), extracts/cleans/resolves path based on recursion flag, applies parent group policy if configured, performs mkdir(2) syscall with permission mask, treats EEXIST as success for idempotent behavior, returns kXR_ok response. Recursive creation uses xrootd_resolve_path_noexist allowing entire hierarchy creation in one request; single-level creation uses xrootd_resolve_path_write requiring parent to exist.
 *
 * WHY: Enables namespace organization and staging scenarios by creating directory hierarchies at various levels. Recursive mkdir enables bulk directory structure setup without requiring parent directories to pre-exist — critical for staging uploads where client creates entire path hierarchy in a single request. EEXIST treated as success provides idempotent behavior allowing clients to retry failed attempts without error propagation.
 *
 * HOW: Two-phase creation → parse wire format (options[0] bitfield, mode bits) — extract/clean/resolve path based on kXR_mkdirpath flag — apply parent group policy if configured — mkdir(2) syscall with permission mask — EEXIST treated as success for idempotent behavior — return kXR_ok response. */

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
	if (xrootd_count_path_depth(reqpath) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
						  kXR_ArgInvalid, "path exceeds maximum depth");
	}

	/*
	 * Resolve the target path.  For recursive mkdir intermediate directories
	 * do not exist yet, so we use xrootd_resolve_path_noexist (no realpath).
	 * For a single-level mkdir the parent must exist, so use the write resolver.
	 */
	if (recursive) {
		if (!xrootd_resolve_path_noexist(c->log, &conf->common.root,
										  reqpath,
										  resolved, sizeof(resolved))) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
							  kXR_NotFound, "invalid path");
		}
	} else {
		if (!xrootd_resolve_path_write(c->log, &conf->common.root,
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
		if (xrootd_mkdir_recursive_confined(c->log, &conf->common.root,
											resolved, mode, conf->group_rules) != 0
			&& errno != EEXIST)
		{
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
							  kXR_IOError, strerror(errno));
		}
	} else {
		/* Non-recursive mkdir maps directly to one root-confined mkdirat(2). */
		if (xrootd_mkdir_confined(c->log, &conf->common.root, resolved, mode) != 0) {
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
