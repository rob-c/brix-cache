/* ------------------------------------------------------------------ */
/* Permission Change — kXR_chmod handler                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_chmod opcode — changing file permission bits within the export root. The wire format uses mode as big-endian uint16_t; only low 9 bits (0777) are applied for user/group/other read/write/executable permissions. File type bits from the client are never applied, ensuring only permission bits can be specified. A client-supplied mode of 0 is substituted with 0644 as sensible default for newly modified files. Uses chmod(2) rather than fchmod(2) because the handle may not be open — path-based permission change works regardless of whether file was previously opened by this session.
 *
 * WHY: Permission modification enables operators to adjust file access controls without requiring filesystem-level intervention. Unlike raw chmod system calls which require root privileges, nginx-xrootd provides controlled permission modification through authentication gates (authdb + VO ACL + token scope) ensuring only authorized clients can change permissions on files within the export root. Path-based operation (chmod(2)) rather than handle-based (fchmod(2)) works regardless of whether file was previously opened by this session — enabling permission changes without requiring prior file open.
 *
 * HOW: Three-phase modification → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_UPDATE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — chmod(2) syscall on resolved path using masked mode bits (low 9 bits only, file type bits ignored) — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/* ------------------------------------------------------------------ */
/* Section: Permission Mask Filtering                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Client-supplied mode bits are masked to low 9 bits (0777) — file type bits from the client are never applied, ensuring only permission bits (user/group/other read/write/executable) can be specified. A client-supplied mode of 0 is substituted with 0644 as sensible default for newly modified files. The chmod(2) syscall automatically sets appropriate file type flags regardless of client input — only permission bits are accepted and modified through this opcode.
 *
 * WHY: Prevents clients from specifying inappropriate file type bits (regular file vs directory vs special device flags) that could confuse filesystem metadata or cause unexpected behavior. Only permission bits are accepted; the chmod(2) syscall automatically sets S_ISREG flag for regular files regardless of client input. 0644 default provides sensible permissions for modified files without requiring explicit mode specification in common use cases where operators simply want to "make file readable by everyone." */

/* ------------------------------------------------------------------ */
/* Section: Path-Based vs Handle-Based Permission                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_chmod() uses chmod(2) rather than fchmod(2) because the handle may not be open. This enables permission changes regardless of whether file was previously opened by this session — path-based operation works on any file within the export root without requiring prior kXR_open call. Handle-based fchmod(2) would only work on files already opened in the current session, limiting permission modification scope to currently active handles.
 *
 * WHY: Path-based chmod(2) provides broader permission modification capability — operators can adjust permissions on any file within the export root regardless of whether it was previously opened by this session. This enables bulk permission changes across multiple files without requiring individual open/close cycles for each target file, reducing overhead in production deployments where permission adjustments affect many files simultaneously. */

/* ---- Function: xrootd_handle_chmod() ----
 *
 * WHAT: Handles the kXR_chmod opcode — changes file permission bits within the export root performing three-phase modification: shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_UPDATE privilege level), token scope write gate check, chmod(2) syscall on resolved path using masked mode bits (low 9 bits only, file type bits ignored). Uses chmod(2) rather than fchmod(2) because handle may not be open — enables permission changes regardless of whether file was previously opened by this session. Client-supplied mode of 0 substituted with 0644 as sensible default. Returns kXR_ok on success with access-log detail "-" and byte count 0.
 *
 * WHY: Enables operators to adjust file access controls without requiring filesystem-level intervention. Unlike raw chmod system calls which require root privileges, nginx-xrootd provides controlled permission modification through authentication gates (authdb + VO ACL + token scope) ensuring only authorized clients can change permissions on files within the export root. Path-based operation (chmod(2)) rather than handle-based (fchmod(2)) works regardless of whether file was previously opened by this session — enabling permission changes without requiring prior file open.
 *
 * HOW: Three-phase modification → shared path resolution (xrootd_write_resolve_existing_path with XROOTD_AUTH_UPDATE privilege level) — token scope write gate check (xrootd_check_token_scope with need_write=1) — chmod(2) syscall on resolved path using masked mode bits (low 9 bits only, file type bits ignored) — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/*
 * chmod.c â kXR_chmod opcode handler.
 */
#include "ngx_xrootd_module.h"
#include "../compat/error_mapping.h"

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
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-",
						  xrootd_kxr_from_errno(err),
						  err == EACCES || err == EPERM ? "permission denied"
						                               : strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-", 0);
}
