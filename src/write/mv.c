/*
 * mv.c — kXR_mv opcode.  See each function's docblock below.
 */

#include "ngx_xrootd_module.h"
#include "../compat/error_mapping.h"
#include "../path/op_path.h"

/*
 * xrootd_handle_mv â rename a file or directory.
 *
 * Wire format: the payload is src + ' ' + dst.
 * ClientMvRequest.arg1len carries the source path length (not null-terminated).
 * The byte at payload[arg1len] must be 0x20 (space) — any other separator
 * is rejected with kXR_ArgInvalid.
 *
 * Both source and destination are independently path-extracted, resolved, and
 * VO/token-scope-checked.  The source must exist (xrootd_resolve_path); the
 * destination uses xrootd_resolve_path_write so a non-existent target is
 * accepted.  The actual rename is done via xrootd_ns_rename (which performs a
 * confined renameat under the export root) to close the TOCTOU race between
 * realpath and rename(2).
 */
ngx_int_t
xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
				 ngx_stream_xrootd_srv_conf_t *conf)
{
	xrdw_twopath_req_t req;
	char src_resolved[PATH_MAX];
	char dst_resolved[PATH_MAX];
	char src_buf[XROOTD_MAX_PATH + 1];
	char dst_buf[XROOTD_MAX_PATH + 1];
	int16_t  src_len;
	size_t   dst_len;

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
	}

	/*
	 * Wire format (from XrdClFileSystem.cc):
	 *   arg1len = source.length()       (NOT including any terminator)
	 *   dlen    = src.length() + dst.length() + 1
	 *   payload = src[arg1len] + ' ' + dst[...]
	 * The separator between source and destination is a single space (0x20).
	 */
	xrdw_twopath_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
	src_len = req.arg1len;
	if (src_len < 0 || (uint32_t) src_len >= ctx->cur_dlen) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid arg1len for mv");
	}

	/* arg1len == 0: the reference do_Mv (XrdXrootdXeq.cc) splits the buffer on
	 * the FIRST space itself ("old new") rather than rejecting.  Reproduce that
	 * autosplit so a well-formed space-separated buffer with arg1len=0 works. */
	if (src_len == 0) {
		u_char *sp = memchr(ctx->payload, ' ', (size_t) ctx->cur_dlen);
		if (sp == NULL || sp == ctx->payload
			|| (size_t)(sp - ctx->payload) > 0x7fff) {
			return xrootd_send_error(ctx, c, kXR_ArgInvalid,
									 "invalid path specification");
		}
		src_len = (int16_t)(sp - ctx->payload);
	}

	/* Separator byte at src_len must be a space, with a non-empty dst after it. */
	if ((uint32_t)(src_len + 1) >= ctx->cur_dlen
		|| ctx->payload[src_len] != ' ') {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "mv payload separator not a space");
	}
	dst_len = (size_t) ctx->cur_dlen - (size_t) src_len - 1;
	if (dst_len == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "missing destination path");
	}

	/* Parse each half independently so embedded-NUL and traversal checks apply to both. */
	if (!xrootd_extract_path(c->log, ctx->payload, (size_t) src_len,
							 src_buf, sizeof(src_buf), 1)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid source path payload");
	}

	if (!xrootd_extract_path(c->log, ctx->payload + src_len + 1, dst_len,
							 dst_buf, sizeof(dst_buf), 1)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid destination path payload");
	}

	/* Source must exist (EXISTING).  Confinement is the kernel RESOLVE_BENEATH
	 * inside xrootd_ns_rename below; this gate only reproduces the historical
	 * "source not found" 404 without a realpath() call. */
	if (xrootd_path_resolve_beneath(conf, src_buf, XROOTD_PATH_EXISTING,
									src_resolved, sizeof(src_resolved)) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "no such file or directory");
	}

	/* XrdAcc: the move SOURCE requires Rename; the destination requires Insert. */
	if (xrootd_auth_gate_op(ctx, c, XROOTD_OP_MV, "MV",
						  src_buf, src_resolved, conf,
						  XROOTD_AUTH_DELETE, 1, XROOTD_AOP_RENAME) != NGX_OK) {
		return ctx->write_rc;
	}

	/* POSIX trailing-slash on the destination, matching stock do_Mv/rename(2):
	 * rename(X, "Y/") requires X to be a directory.  A FILE source with a
	 * "/"-terminated dest is ENOENT; a DIRECTORY source renames to the stripped
	 * name.  (Without this our parent-creation below would create "Y" as a dir
	 * and the rename would then report kXR_isDirectory — diverging from stock.) */
	{
		size_t      dl = ngx_strlen(dst_buf);
		struct stat sst;
		if (dl > 1 && dst_buf[dl - 1] == '/') {
			if (xrootd_lstat_beneath(conf->rootfd, src_buf, &sst) == 0
				&& !S_ISDIR(sst.st_mode)) {
				/* rename(file, "dst/") → ENOTDIR (a "/"-terminated target must be
				 * a directory).  Stock reports the "not a directory" category. */
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
								  xrootd_kxr_from_errno(ENOTDIR),
								  strerror(ENOTDIR));
			}
			while (dl > 1 && dst_buf[dl - 1] == '/') {
				dst_buf[--dl] = '\0';
			}
		}
	}

	/* Create the destination parent chain if missing, matching the reference
	 * rename (XrdOss makes the target path) — verified against stock xrdfs, which
	 * lands a move into a not-yet-existing directory. Confined beneath the export
	 * root by xrootd_mkdir_recursive_policy; the source RENAME auth above has
	 * already gated the operation. A component that is an existing non-dir fails
	 * here and the WRITE resolve below then reports the error. */
	{
		char  dst_full[PATH_MAX];
		char *slash;
		xrootd_beneath_full_path(conf->common.root_canon, dst_buf,
								 dst_full, sizeof(dst_full));
		slash = strrchr(dst_full, '/');
		if (slash && slash > dst_full) {
			*slash = '\0';
			xrootd_mkdir_recursive_policy(dst_full, 0755, c->log,
										  conf->group_rules);
		}
	}

	/* Destination parent must exist; the tail may not (WRITE). */
	if (xrootd_path_resolve_beneath(conf, dst_buf, XROOTD_PATH_WRITE,
									dst_resolved, sizeof(dst_resolved)) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "invalid destination path");
	}

	if (xrootd_auth_gate_op(ctx, c, XROOTD_OP_MV, "MV",
						  dst_buf, dst_resolved, conf,
						  XROOTD_AUTH_UPDATE, 1, XROOTD_AOP_INSERT) != NGX_OK) {
		return ctx->write_rc;
	}

	{
		xrootd_ns_result_t res;

		res = xrootd_ns_rename(c->log, conf->common.root_canon,
		                       src_resolved, dst_resolved, 0);
		if (res.status != XROOTD_NS_OK) {
			int         kxr;
			const char *msg;

			/* NS_EXISTS (rename onto an existing target) and NS_DENIED carry no
			 * errno, so strerror(res.sys_errno) would print "Success" on an error
			 * response. Map each status to a meaningful kXR code + message; an
			 * existing-directory destination mirrors stock's kXR_isDirectory
			 * "is a directory". */
			if (res.status == XROOTD_NS_DENIED) {
				kxr = kXR_NotAuthorized;
				msg = "permission denied";
			} else if (res.status == XROOTD_NS_EXISTS) {
				kxr = res.was_dir ? kXR_isDirectory : kXR_ItExists;
				msg = res.was_dir ? "destination is a directory"
				                  : "destination already exists";
			} else {
				kxr = xrootd_kxr_map_ns_status(res.status, res.sys_errno);
				msg = res.sys_errno ? strerror(res.sys_errno) : "rename failed";
			}
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
			                  kxr, msg);
		}
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MV, "MV", src_resolved, dst_resolved, 0);
}
