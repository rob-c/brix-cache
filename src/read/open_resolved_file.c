#include "open.h"
#include "../compat/tmp_path.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../session/registry.h"

#include <string.h>
#include <unistd.h>

/* ---- Function: xrootd_open_resolved_file() ----
 *
 * WHAT: Opens the actual file on disk and allocates a file handle (fhandle). Called after path resolution.
 *       This function performs the POSIX open(2) call with proper security guarantees including:
 *       - POSC mode: staging temp file for persist-on-successful-close writes
 *       - Confined open: xrootd_open_confined() prevents post-open path escape attacks
 *       - Handle allocation: xrootd_alloc_fhandle() assigns a slot (0–255) in fd_table.c
 *       - Bookkeeping initialization: readable/writable flags, cache origin, inode/device tracking,
 *         byte counters, timestamps, read-ahead state.
 *
 * WHY: This is the bridge between path resolution and data transfer. The resolved file handle
 *      carries all metadata reused by subsequent opcodes (read/pgread/readv/write/close). POSC
 *      protects against crash loss of partial writes; confined open prevents symlink escapes;
 *      handle allocation enforces the 0–255 fd-table limit.
 *
 * HOW: Determine POSIX flags from options/mode_bits → build POSC staging path if kXR_posc set →
 *      allocate fhandle slot → open via O_CLOEXEC (cache) or xrootd_open_confined() (non-cache) →
 *      stat the fd to validate regular file and populate handle metadata → set fhandle path field +
 *      posc_final_path if POSC active → apply parent group policy on write opens → evaluate WT
 *      decision policy at open time → build ServerOpenBody with fhandle + optional retstat → queue response.
 */

ngx_int_t
xrootd_open_resolved_file(xrootd_ctx_t *ctx, ngx_connection_t *c,
						  ngx_stream_xrootd_srv_conf_t *conf,
						  const char *resolved, uint16_t options,
						  uint16_t mode_bits, ngx_flag_t is_write)
{
	int                idx, fd, oflags;
	int                is_readable;
	ServerOpenBody     body;
	struct stat        st;
	char               statbuf[256];
	u_char            *buf;
	size_t             bodylen, total;
	ngx_flag_t         want_stat;
	ngx_flag_t         from_cache;
	/*
	 * POSC (persist-on-successful-close): when kXR_posc is set on a write
	 * open we stage writes to a temp file and rename to the final path only
	 * on a clean kXR_close.  If the session drops mid-write the temp file is
	 * unlinked by xrootd_free_fhandle() (via the path field + posc_final_path
	 * sentinel).  We build posc_temp_path here; it is used as the actual
	 * filesystem target for the open(2) call below.
	 */
	char               posc_temp_path[PATH_MAX];
	ngx_flag_t         use_posc = (is_write && (options & kXR_posc)) ? 1 : 0;

	want_stat = (options & kXR_retstat) ? 1 : 0;
	from_cache = (conf->cache
	              && conf->cache_root.len > 0
	              && ngx_strncmp((u_char *) resolved,
	                             conf->cache_root.data,
	                             conf->cache_root.len) == 0);

	/*
	 * Build the POSC staging temp path: same directory as the final path,
	 * with a ".posc.<pid>.<random>" suffix appended.  This keeps the temp
	 * file on the same filesystem as the destination so rename(2) is atomic.
	 */
	if (use_posc) {
		if (xrootd_make_tmp_path(resolved, posc_temp_path,
		                         sizeof(posc_temp_path)) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", resolved, "wr",
			                  0, kXR_ServerError,
			                  "POSC temp path too long", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
			return xrootd_send_error(ctx, c, kXR_ServerError,
			                         "POSC temp path too long");
		}
	}

	if (!is_write) {
		if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
			xrootd_log_access(ctx, c, "OPEN", resolved, "rd",
							  0, kXR_isDirectory, "is a directory", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_isDirectory,
									 "is a directory");
		}

		oflags = O_RDONLY | O_NOCTTY;
		is_readable = 1;
	} else {
		if (options & kXR_open_updt) {
			oflags = O_RDWR;
			is_readable = 1;
		} else if (options & kXR_open_apnd) {
			oflags = O_WRONLY | O_APPEND;
			is_readable = 0;
		} else {
			oflags = O_WRONLY;
			is_readable = 0;
		}

		if (options & kXR_new) {
			oflags |= O_CREAT;
			if (!(options & kXR_delete)) {
				oflags |= O_EXCL;
			}
		}
		if (options & kXR_delete) {
			oflags |= O_CREAT | O_TRUNC;
		}

		oflags |= O_NOCTTY;
	}

	/* Convert XRootD mode bits (Unix permission bits in low 9 bits). */
	mode_t create_mode = (mode_bits & 0777);
	if (create_mode == 0) {
		create_mode = 0644;
	}

	idx = xrootd_alloc_fhandle(ctx);
	if (idx < 0) {
		xrootd_log_access(ctx, c, "OPEN", resolved,
						  is_write ? "wr" : "rd",
						  0, kXR_ServerError, "too many open files", 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_ServerError,
								 "too many open files");
	}

	{
		/* When POSC is active, open the staging temp path instead of the
		 * final path.  The O_CREAT flag is forced so the temp file is
		 * always created fresh; O_EXCL is intentionally omitted so that a
		 * previous crash leaving a stale temp file does not block a retry. */
		const char *open_path = use_posc ? posc_temp_path : resolved;

		/* POSC always needs O_CREAT on the staging temp path. */
		int effective_oflags = oflags | (use_posc ? O_CREAT : 0);

		if (from_cache) {
			/* cache_root files are pre-validated; use O_CLOEXEC to prevent
			 * FD leakage into any forked child (e.g. tpc_curl). */
			fd = open(open_path, effective_oflags | O_CLOEXEC, create_mode);
		} else {
			fd = xrootd_open_confined(c->log, &conf->common.root, open_path,
			                          effective_oflags, create_mode);
		}
	}
	if (fd < 0) {
		int err = errno;
		const char *mode_str = is_write ? "wr" : "rd";

		if (err == ENOENT || err == ENOTDIR) {
			xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
							  0, kXR_NotFound, "file not found", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotFound,
									 "file not found");
		}
		if (err == EEXIST) {
			xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
							  0, kXR_FileLocked, "file already exists", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_FileLocked,
									 "file already exists");
		}
		if (err == EACCES) {
			xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
							  0, kXR_NotAuthorized, "permission denied", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "permission denied");
		}
		if (err == EISDIR) {
			xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
							  0, kXR_isDirectory, "is a directory", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_isDirectory,
									 "is a directory");
		}
		xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
						  0, kXR_IOError, strerror(err), 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
	}

	if (fstat(fd, &st) != 0) {
		int err = errno;

		close(fd);
		xrootd_log_access(ctx, c, "OPEN", resolved,
						  is_write ? "wr" : "rd",
						  0, kXR_IOError, strerror(err), 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
	}

	if (S_ISDIR(st.st_mode)) {
		close(fd);
		xrootd_log_access(ctx, c, "OPEN", resolved,
						  is_write ? "wr" : "rd",
						  0, kXR_isDirectory, "is a directory", 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_isDirectory,
								 "is a directory");
	}

	ctx->files[idx].fd          = fd;
	ctx->files[idx].readable    = is_readable;
	ctx->files[idx].writable    = is_write;
	ctx->files[idx].from_cache  = from_cache;
	ctx->files[idx].is_regular  = S_ISREG(st.st_mode) ? 1 : 0;
	ctx->files[idx].device      = st.st_dev;
	ctx->files[idx].inode       = st.st_ino;
	ctx->files[idx].cached_size = (off_t) st.st_size;
	ctx->files[idx].read_last_end  = -1;
	ctx->files[idx].read_ahead_end = 0;
	ctx->files[idx].wt_enabled = 0;
	ctx->files[idx].wt_policy = XROOTD_WT_DECISION_DENY;
	ctx->files[idx].wt_mode_bits = create_mode;
	ctx->files[idx].wt_dirty_offset = -1;
	ctx->files[idx].wt_bytes_written = 0;
	ctx->files[idx].wt_flush_task = NULL;
	ctx->files[idx].wt_flush_pending = 0;
	ctx->files[idx].dashboard_slot = -1;

	/* Register the open file with the live transfer monitor. */
	if (ngx_xrootd_dashboard_shm_zone != NULL) {
		xrootd_transfer_table_t *dash_tbl = ngx_xrootd_dashboard_shm_zone->data;
		const char *dash_identity = ctx->dn[0] ? ctx->dn : "anonymous";
		uint8_t     dash_dir = is_write ? XROOTD_XFER_DIR_WRITE
		                                : XROOTD_XFER_DIR_READ;
		ctx->files[idx].dashboard_slot = xrootd_transfer_slot_alloc(
		    dash_tbl, ctx->sessid, ctx->peer_ip,
		    dash_identity, resolved, dash_dir,
		    XROOTD_XFER_PROTO_ROOT, (int64_t) ngx_current_msec);
	}

	/*
	 * POSC: store the temp path in the path field so that a non-clean close
	 * (handled by xrootd_free_fhandle → unlink(path)) discards the partial
	 * upload.  Store the final target in posc_final_path; xrootd_handle_close
	 * will rename() on clean close and then clear this field before freeing.
	 */
	if (use_posc) {
		if (xrootd_set_fhandle_path(ctx, c, idx, posc_temp_path) != NGX_OK) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ctx->files[idx].posc_final_path = ngx_alloc(strlen(resolved) + 1,
		                                             c->log);
		if (ctx->files[idx].posc_final_path == NULL) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ngx_cpystrn((u_char *) ctx->files[idx].posc_final_path,
		            (u_char *) resolved, strlen(resolved) + 1);
	} else {
		if (xrootd_set_fhandle_path(ctx, c, idx, resolved) != NGX_OK) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
	}

	if (is_write && conf->group_rules != NULL) {
		xrootd_apply_parent_group_policy_fd(c->log, fd, resolved,
											conf->group_rules);
	}

	statbuf[0] = '\0';
	if (want_stat) {
		if (fstat(fd, &st) == 0) {
			int stat_flags = 0;
			if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
				stat_flags |= kXR_readable;
			}
			if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
				stat_flags |= kXR_writable;
			}
			if (ctx->files[idx].from_cache) {
				stat_flags |= kXR_cachersp;
			}
			snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
					 (unsigned long long) st.st_ino,
					 (long long) st.st_size,
					 stat_flags,
					 (long) st.st_mtime);
		} else {
			want_stat = 0;
		}
	}

	if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
		char log_path[512];

		xrootd_sanitize_log_string(resolved, log_path, sizeof(log_path));
		ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
					   "xrootd: kXR_open handle=%d path=%s mode=%s retstat=%d",
					   idx, log_path, is_write ? "wr" : "rd",
					   (int) want_stat);
	}

	/* ---- Write-through decision evaluation (mirrors XrdPfc::Cache::Decide()) ----
	 *
	 * WHAT: Evaluate write-through policy at kXR_open time and cache the result on the handle.
	 *       This is called once per open — the cached wt_policy determines close-time flush behavior.
	 *
	 * WHY: Mirrors XrdPfcDecision::Decide() from official XRootD PFC module (Cache::Attach()).
	 *      Caching at open time avoids repeated policy evaluation for every write operation,
	 *      reduces latency, and ensures consistent close-time behavior across the session.
	 *
	 * HOW: Policy callback flow (src/cache/writethrough_decision.h):
	 *   1. conf->wt_decision.fn(resolved, options, &conf->wt_decision) — default is xrootd_wt_default_decide()
	 *   2. Default engine checks: size filter → deny prefixes → allow prefixes → ALLOW_ASYNC (default)
	 *   3. Cache result on handle: ctx->files[idx].wt_policy = decision, wt_enabled = (decision != DENY),
	 *      wt_dirty_offset = -1 (clean state), wt_bytes_written = 0
	 *
	 * Decision outcomes are cached for a future close-time write-back implementation:
	 *   DENY       → no write-back; local-only writes, handle treated as non-WT
	 *   ALLOW_SYNC → synchronous flush to origin before closing handle (blocks)
	 *   ALLOW_ASYNC→ schedule async thread-pool flush, return immediately to client */

/* ---- WT decision policy engine (default: prefix-based) ----
 *
 * WHAT: xrootd_wt_default_decide() — built-in prefix-based policy engine.
 *       External plugins can provide their own fn pointer for custom policies.
 *
 * WHY: Provides sensible defaults for most deployments without requiring external plugin setup.
 *      Prefix-based matching is O(n) where n = prefix length — acceptable for typical paths (/data/, /atlas/).
 *
 * HOW: Decision logic order (src/cache/writethrough_decision.c):
 *   1. Size filter: if file > max_write_through_bytes AND no include regex match → DENY
 *   2. Deny prefixes: any deny_prefix matches → DENY (deny takes precedence)
 *   3. Allow prefixes: if allow list configured AND none match → DENY (whitelist mode)
 *   4. Default: ALLOW_ASYNC (mirrors XrdPfcAllowDecision, sync preferred for local origins) */

	if (is_write && conf->wt_enable) {
		xrootd_wt_decision_t decision = XROOTD_WT_DECISION_DENY;

		if (conf->wt_decision.fn != NULL) {
			decision = conf->wt_decision.fn(resolved, options, &conf->wt_decision);
		}

		ctx->files[idx].wt_enabled  = (decision != XROOTD_WT_DECISION_DENY) ? 1 : 0;
		ctx->files[idx].wt_policy   = decision;
		ctx->files[idx].wt_mode_bits = create_mode;
		ctx->files[idx].wt_dirty_offset = -1; /* no dirty writes yet */
		ctx->files[idx].wt_bytes_written    = 0;

		ctx->files[idx].wt_flush_task     = NULL;
		ctx->files[idx].wt_flush_pending  = 0;

		if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
			char wt_log_path[512];

			xrootd_sanitize_log_string(resolved, wt_log_path,
			                           sizeof(wt_log_path));
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			               "xrootd: wt decision=%s path=%s",
			               decision == XROOTD_WT_DECISION_DENY ? "DENY" :
			               decision == XROOTD_WT_DECISION_ALLOW_SYNC ? "ALLOW_SYNC" : "ALLOW_ASYNC",
			               wt_log_path);
		}
	}

	bodylen = sizeof(ServerOpenBody);
	if (want_stat) {
		bodylen += strlen(statbuf) + 1;
	}

	total = XRD_RESPONSE_HDR_LEN + bodylen;
	buf   = ngx_palloc(c->pool, total);
	if (buf == NULL) {
		xrootd_free_fhandle(ctx, idx);
		return NGX_ERROR;
	}

	xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
						  (uint32_t) bodylen,
						  (ServerResponseHdr *) buf);

	ngx_memzero(&body, sizeof(body));
	body.fhandle[0] = (u_char) idx;
	body.cpsize     = 0;
	ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

	if (want_stat) {
		size_t slen = strlen(statbuf) + 1;
		ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
				   statbuf, slen);
	}

	ctx->files[idx].bytes_read    = 0;
	ctx->files[idx].bytes_written = 0;
	ctx->files[idx].open_time     = ngx_current_msec;

	if (!ctx->is_bound) {
		xrootd_session_handle_publish(ctx->sessid, idx, &ctx->files[idx]);
	}

	xrootd_log_access(ctx, c, "OPEN", resolved,
					  is_write ? "wr" : "rd", 1, 0, NULL, 0);
	XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);

	return xrootd_queue_response(ctx, c, buf, total);
}
