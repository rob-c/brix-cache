/*
 * mv.c — kXR_mv opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/error_mapping.h"
#include "protocols/root/path/op_path.h"
#include "protocols/root/write/backend_async_root.h"  /* backend-async mv park */
#include "fs/vfs/vfs.h"   /* brix_vfs_rename_path (thread-safe confined rename) */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend resolve */

/*
 * mv_req_t — per-request path state threaded through the mv helpers.
 *
 * WHAT: The two request paths (as extracted from the wire) and their
 *       resolved absolute forms, bundled so each helper takes one pointer
 *       instead of four buffers.
 * WHY:  Keeps every helper under the 5-parameter gate with explicit data
 *       flow (no globals, no hidden state).
 * HOW:  Filled left-to-right: mv_parse_paths sets src_buf/dst_buf, the
 *       resolve steps in brix_handle_mv fill src_resolved/dst_resolved.
 */
typedef struct {
	char src_buf[BRIX_MAX_PATH + 1];
	char dst_buf[BRIX_MAX_PATH + 1];
	char src_resolved[PATH_MAX];
	char dst_resolved[PATH_MAX];
} mv_req_t;

/*
 * mv_fail — error access-log triplet for the MV op, helper-return form.
 *
 * WHAT: Emits the mandatory error triplet (brix_log_access + BRIX_OP_ERR +
 *       brix_send_error) for a failed MV, storing the send result in
 *       ctx->write_rc.
 * WHY:  BRIX_RETURN_ERR embeds a `return`, which from inside a helper would
 *       leave the caller unable to forward the nginx rc; this mirrors the
 *       brix_auth_gate_op convention (respond, stash rc in ctx->write_rc,
 *       return non-NGX_OK) so the orchestrator just `return ctx->write_rc`.
 * HOW:  Same three calls in the same order as BRIX_RETURN_ERR, verb "MV",
 *       detail "-"; always returns NGX_ERROR.
 */
static ngx_int_t
mv_fail(brix_ctx_t *ctx, ngx_connection_t *c, const char *path,
		int kxr, const char *msg)
{
	brix_log_access(ctx, c, "MV", path, "-", 0, kxr, msg, 0);
	BRIX_OP_ERR(ctx, BRIX_OP_MV);
	ctx->write_rc = brix_send_error(ctx, c, kxr, msg);
	return NGX_ERROR;
}

/*
 * mv_parse_paths — decode the kXR_mv payload into two request paths.
 *
 * WHAT: Validates the wire payload, splits it at the space separator and
 *       extracts source + destination into mv->src_buf / mv->dst_buf.
 * WHY:  The mv wire format (from XrdClFileSystem.cc) is:
 *         arg1len = source.length()       (NOT including any terminator)
 *         dlen    = src.length() + dst.length() + 1
 *         payload = src[arg1len] + ' ' + dst[...]
 *       The separator between source and destination is a single space
 *       (0x20).  arg1len == 0: the reference do_Mv (XrdXrootdXeq.cc) splits
 *       the buffer on the FIRST space itself ("old new") rather than
 *       rejecting, so a well-formed space-separated buffer with arg1len=0
 *       is autosplit the same way.
 * HOW:  Early-return on each malformed shape with the historical (plain,
 *       untripleted) brix_send_error stored in ctx->write_rc; each half is
 *       parsed independently via brix_extract_path so embedded-NUL and
 *       traversal checks apply to both.  Returns NGX_OK when both request
 *       paths are extracted; NGX_ERROR after responding otherwise.
 */
static ngx_int_t
mv_parse_paths(brix_ctx_t *ctx, ngx_connection_t *c, mv_req_t *mv)
{
	xrdw_twopath_req_t req;
	int16_t  src_len;
	size_t   dst_len;

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgMissing,
										  "no paths given");
		return NGX_ERROR;
	}

	xrdw_twopath_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	src_len = req.arg1len;
	if (src_len < 0 || (uint32_t) src_len >= ctx->recv.cur_dlen) {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
										  "invalid arg1len for mv");
		return NGX_ERROR;
	}

	if (src_len == 0) {
		u_char *sp = memchr(ctx->recv.payload, ' ', (size_t) ctx->recv.cur_dlen);
		if (sp == NULL || sp == ctx->recv.payload
			|| (size_t)(sp - ctx->recv.payload) > 0x7fff) {
			ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
											  "invalid path specification");
			return NGX_ERROR;
		}
		src_len = (int16_t)(sp - ctx->recv.payload);
	}

	/* Separator byte at src_len must be a space, with a non-empty dst after it. */
	if ((uint32_t)(src_len + 1) >= ctx->recv.cur_dlen
		|| ctx->recv.payload[src_len] != ' ') {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
										  "mv payload separator not a space");
		return NGX_ERROR;
	}
	dst_len = (size_t) ctx->recv.cur_dlen - (size_t) src_len - 1;
	if (dst_len == 0) {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
										  "missing destination path");
		return NGX_ERROR;
	}

	if (!brix_extract_path(c->log, ctx->recv.payload, (size_t) src_len,
							 mv->src_buf, sizeof(mv->src_buf), 1)) {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
										  "invalid source path payload");
		return NGX_ERROR;
	}

	if (!brix_extract_path(c->log, ctx->recv.payload + src_len + 1, dst_len,
							 mv->dst_buf, sizeof(mv->dst_buf), 1)) {
		ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
										  "invalid destination path payload");
		return NGX_ERROR;
	}

	return NGX_OK;
}

/*
 * mv_bind_vfs — build a request-identity VFS context for one mv sub-step.
 *
 * WHAT: Initializes *vctx for the export root and binds the backend
 *       credential + delegated identity for this connection.
 * WHY:  The mv handler needs the identical ctx_init + bind_backend_cred +
 *       bind_deleg triple at three sites (trailing-slash pre-check, rename,
 *       EEXIST classification probe); one helper keeps the REQUESTING
 *       USER's credential threading uniform (not the shared service
 *       credential) for a remote-backed export.
 * HOW:  Pure setup, no I/O: brix_vfs_ctx_init for BRIX_PROTO_ROOT on the
 *       given resolved path, then credential-dir/fallback bind and
 *       brix_root_vfs_bind_deleg.
 */
static void
mv_bind_vfs(brix_ctx_t *ctx, ngx_connection_t *c,
			ngx_stream_brix_srv_conf_t *conf, const char *path,
			brix_vfs_ctx_t *vctx)
{
	brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
		conf->common.root_canon, NULL, conf->common.allow_write,
		0 /* is_tls */, ctx->identity, path);
	brix_vfs_ctx_bind_backend_cred(vctx,
		&conf->common.storage_credential_dir,
		conf->common.storage_credential_fallback);
	brix_root_vfs_bind_deleg(ctx, conf, vctx);
}

/*
 * mv_dst_slash_precheck — apply POSIX trailing-slash semantics to the dest.
 *
 * WHAT: Rejects a FILE source when the destination is "/"-terminated, then
 *       strips the trailing slashes from mv->dst_buf.
 * WHY:  Matches stock do_Mv/rename(2): rename(X, "Y/") requires X to be a
 *       directory.  A FILE source with a "/"-terminated dest is ENOENT; a
 *       DIRECTORY source renames to the stripped name.  (Without this our
 *       parent-creation step would create "Y" as a dir and the rename would
 *       then report kXR_isDirectory — diverging from stock.)
 * HOW:  Only engages when dst_buf ends in '/': probes the (already
 *       resolved) source no-follow; a non-directory source fails with the
 *       ENOTDIR category ("not a directory"), exactly as stock reports.
 *       Returns NGX_OK to continue (dst_buf stripped in place), NGX_ERROR
 *       after responding via mv_fail.
 */
static ngx_int_t
mv_dst_slash_precheck(brix_ctx_t *ctx, ngx_connection_t *c,
					  ngx_stream_brix_srv_conf_t *conf, mv_req_t *mv)
{
	size_t dl = ngx_strlen(mv->dst_buf);
	brix_vfs_ctx_t  sctx;
	brix_vfs_stat_t svst;

	if (dl <= 1 || mv->dst_buf[dl - 1] != '/') {
		return NGX_OK;
	}

	mv_bind_vfs(ctx, c, conf, mv->src_resolved, &sctx);
	if (brix_vfs_probe(&sctx, 1 /* no-follow */, &svst) == NGX_OK
		&& !svst.is_directory) {
		/* rename(file, "dst/") → ENOTDIR (a "/"-terminated target must be
		 * a directory).  Stock reports the "not a directory" category. */
		return mv_fail(ctx, c, mv->src_buf,
					   brix_kxr_from_errno(ENOTDIR), strerror(ENOTDIR));
	}
	while (dl > 1 && mv->dst_buf[dl - 1] == '/') {
		mv->dst_buf[--dl] = '\0';
	}
	return NGX_OK;
}

/*
 * mv_make_dst_parents — best-effort creation of the destination parent chain.
 *
 * WHAT: Creates any missing parent directories of the destination path,
 *       through the backend driver namespace for a non-POSIX backend or via
 *       brix_mkdir_recursive_policy on a real filesystem.
 * WHY:  Matches the reference rename (XrdOss makes the target path) —
 *       verified against stock xrdfs, which lands a move into a
 *       not-yet-existing directory.  Confined beneath the export root by
 *       brix_mkdir_recursive_policy; the source RENAME auth in the caller
 *       has already gated the operation.  A component that is an existing
 *       non-dir fails here and the WRITE resolve in the caller then reports
 *       the error — so this helper never responds itself.
 * HOW:  Non-POSIX backend: mkpath the export-relative parent (setgid group
 *       policy is a real-FS-only semantic and is intentionally not applied
 *       for a catalog/object backend).  POSIX: expand to the full beneath
 *       path and recursive-mkdir the parent with the export's group rules.
 */
static void
mv_make_dst_parents(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
					const char *dst_buf)
{
	if (brix_vfs_backend_resolve(conf->common.root_canon, c->log) != NULL) {
		char   rel[BRIX_MAX_PATH + 1];
		char  *slash;
		size_t rl = ngx_strlen(dst_buf);
		if (rl < sizeof(rel)) {
			ngx_memcpy(rel, dst_buf, rl + 1);
			slash = strrchr(rel, '/');
			if (slash && slash > rel) {
				*slash = '\0';
				(void) brix_vfs_backend_mkpath(conf->common.root_canon, rel,
												 0755, c->log);
			}
		}
	} else {
		char  dst_full[PATH_MAX];
		char *slash;
		/* phase72-fp: dst_buf is the request path, dst_full the output buf. */
		brix_beneath_full_path(conf->common.root_canon, dst_buf,  /* NOLINT(readability-suspicious-call-argument) */
								 dst_full, sizeof(dst_full));
		slash = strrchr(dst_full, '/');
		if (slash && slash > dst_full) {
			*slash = '\0';
			brix_mkdir_recursive_policy(dst_full, 0755, c->log,
										  conf->group_rules);
		}
	}
}

/*
 * mv_execute — perform the confined rename and map failure to a kXR error.
 *
 * WHAT: Renames src_resolved → dst_resolved through the ctx-bound VFS
 *       surface and, on failure, translates errno into the exact historical
 *       kXR code + message and responds.
 * WHY:  Rename goes through brix_vfs_rename (not the pool-less
 *       brix_vfs_rename_path) so ctx->identity + the backend credential
 *       bind make a remote-backed export see the REQUESTING USER's
 *       credential for the rename call, matching every other data/namespace
 *       op in this file.  The namespace status is conveyed as errno (1:1
 *       with the old brix_ns_status_t); the switch mirrors
 *       brix_kxr_map_ns_status exactly.
 * HOW:  Builds a fresh VFS ctx (unconditionally in scope, unlike the
 *       trailing-slash pre-check's conditional one) and a confined
 *       dst_result, then calls brix_vfs_rename.  brix_vfs_rename does not
 *       compute was_dir itself (no post-rename stat for the driver case),
 *       so on the EEXIST branch the destination is probed inline to
 *       classify kXR_isDirectory vs kXR_ItExists — extra syscall only on
 *       that error path.  Returns NGX_OK on success, NGX_ERROR after
 *       responding via mv_fail.
 */
static ngx_int_t
mv_execute(brix_ctx_t *ctx, ngx_connection_t *c,
		   ngx_stream_brix_srv_conf_t *conf, mv_req_t *mv)
{
	brix_vfs_ctx_t     rvctx;
	brix_path_result_t dst_result;
	int                e;
	int                kxr;
	const char        *msg;

	mv_bind_vfs(ctx, c, conf, mv->src_resolved, &rvctx);

	ngx_memzero(&dst_result, sizeof(dst_result));
	dst_result.is_confined = 1;
	dst_result.resolved.data = (u_char *) mv->dst_resolved;
	dst_result.resolved.len = ngx_strlen(mv->dst_resolved);

	if (brix_vfs_rename(&rvctx, &dst_result,
	                      0 /* kXR_mv: never replace a dir dest */) == NGX_OK) {
		return NGX_OK;
	}

	e = errno;
	if (e == EACCES || e == EPERM) {           /* NS_DENIED */
		kxr = kXR_NotAuthorized;
		msg = "permission denied";
	} else if (e == EISDIR) {
		/* rename(file, existing-dir) → EISDIR straight from the kernel
		 * (no EEXIST detour, so the was_dir probe below never runs).
		 * Stock reports kXR_isDirectory ("… is a directory") — match it. */
		kxr = kXR_isDirectory;
		msg = "destination is a directory";
	} else if (e == EEXIST) {                  /* NS_EXISTS */
		/* was_dir source changed: brix_vfs_rename does not report it,
		 * so probe the (still-existing) destination directly to
		 * classify kXR_isDirectory vs kXR_ItExists. */
		brix_vfs_ctx_t  dctx;
		brix_vfs_stat_t dvst;
		int             was_dir;

		mv_bind_vfs(ctx, c, conf, mv->dst_resolved, &dctx);
		was_dir = (brix_vfs_probe(&dctx, 1 /* no-follow */, &dvst) == NGX_OK)
			&& dvst.is_directory;

		kxr = was_dir ? kXR_isDirectory : kXR_ItExists;
		msg = was_dir ? "destination is a directory"
		              : "destination already exists";
	} else {
		/* Mirror brix_kxr_map_ns_status exactly via the 1:1 errno. */
		switch (e) {
		case ENOENT:       kxr = kXR_NotFound;   break; /* NOT_FOUND  */
		case ENOTDIR:      kxr = kXR_FSError;    break; /* CONFLICT   */
		case ENOTEMPTY:    kxr = kXR_ItExists;   break; /* NOT_EMPTY  */
		case ENOSPC:       kxr = kXR_NoSpace;    break; /* NO_SPACE   */
#ifdef EDQUOT
		case EDQUOT:       kxr = kXR_NoSpace;    break; /* NO_SPACE   */
#endif
		case ENAMETOOLONG: kxr = kXR_ArgTooLong; break; /* TOO_LONG   */
		default:           kxr = brix_kxr_from_errno(e); break;
		}
		msg = strerror(e);
	}
	return mv_fail(ctx, c, mv->src_resolved, kxr, msg);
}

/*
 * brix_handle_mv â rename a file or directory.
 *
 * Wire format: the payload is src + ' ' + dst.
 * ClientMvRequest.arg1len carries the source path length (not null-terminated).
 * The byte at payload[arg1len] must be 0x20 (space) — any other separator
 * is rejected with kXR_ArgInvalid.
 *
 * Both source and destination are independently path-extracted, resolved, and
 * VO/token-scope-checked.  The source must exist (brix_resolve_path); the
 * destination uses brix_resolve_path_write so a non-existent target is
 * accepted.  The actual rename is done via brix_ns_rename (which performs a
 * confined renameat under the export root) to close the TOCTOU race between
 * realpath and rename(2).
 *
 * Orchestrator only: parse → resolve/auth source → dest trailing-slash
 * pre-check → dest parent creation → resolve/auth dest → rename.  Each
 * helper responds itself on failure (rc stashed in ctx->write_rc).
 */
ngx_int_t
brix_handle_mv(brix_ctx_t *ctx, ngx_connection_t *c,
				 ngx_stream_brix_srv_conf_t *conf)
{
	mv_req_t mv;

	if (mv_parse_paths(ctx, c, &mv) != NGX_OK) {
		return ctx->write_rc;
	}

	/* Source must exist (EXISTING).  Confinement is the kernel RESOLVE_BENEATH
	 * inside brix_ns_rename below; this gate only reproduces the historical
	 * "source not found" 404 without a realpath() call. */
	if (brix_path_resolve_beneath(conf, c->log, mv.src_buf, BRIX_PATH_EXISTING,
									mv.src_resolved, sizeof(mv.src_resolved)) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_MV, "MV", mv.src_buf, "-",
						  kXR_NotFound, "no such file or directory");
	}

	/* XrdAcc: the move SOURCE requires Rename; the destination requires Insert. */
	if (brix_auth_gate_op(ctx, c, BRIX_OP_MV, "MV",
						  mv.src_buf, mv.src_resolved, conf,
						  BRIX_AUTH_DELETE, 1, BRIX_AOP_RENAME) != NGX_OK) {
		return ctx->write_rc;
	}

	if (mv_dst_slash_precheck(ctx, c, conf, &mv) != NGX_OK) {
		return ctx->write_rc;
	}

	mv_make_dst_parents(c, conf, mv.dst_buf);

	/* Destination parent must exist; the tail may not (WRITE). */
	if (brix_path_resolve_beneath(conf, c->log, mv.dst_buf, BRIX_PATH_WRITE,
									mv.dst_resolved, sizeof(mv.dst_resolved)) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_MV, "MV", mv.src_buf, "-",
						  kXR_NotFound, "invalid destination path");
	}

	if (brix_auth_gate_op(ctx, c, BRIX_OP_MV, "MV",
						  mv.dst_buf, mv.dst_resolved, conf,
						  BRIX_AUTH_UPDATE, 1, BRIX_AOP_INSERT) != NGX_OK) {
		return ctx->write_rc;
	}

	/* brix_backend_async: a fresh-destination rename (dst does not yet exist) is a
	 * pure create — enqueue it on the durable queue and park the connection until
	 * the batch flushes, mirroring the kXR_rm/kXR_rmdir park. Scoped to a NON-
	 * existent destination: a probe here that finds nothing means the queue's
	 * overwrite=0 rename can only succeed or fail source-side (whose generic
	 * errno→kXR mapping matches mv_execute), so the dst-exists ladder never
	 * diverges. Both auth gates have passed, so the mutation is fully authorised
	 * before it reaches the queue. Any failure to park falls through to
	 * mv_execute — strictly fail-safe. */
	if (conf->backend_async) {
		brix_vfs_ctx_t  dprobe;
		brix_vfs_stat_t dst_st;

		mv_bind_vfs(ctx, c, conf, mv.dst_resolved, &dprobe);
		if (brix_vfs_probe(&dprobe, 1 /* no-follow */, &dst_st) != NGX_OK
			&& brix_root_backend_async_mv_try(ctx, c, conf, mv.src_resolved,
											   mv.dst_resolved)) {
			return NGX_OK;
		}
	}

	if (mv_execute(ctx, c, conf, &mv) != NGX_OK) {
		return ctx->write_rc;
	}

	BRIX_RETURN_OK(ctx, c, BRIX_OP_MV, "MV", mv.src_resolved, mv.dst_resolved, 0);
}
