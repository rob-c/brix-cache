#include "open.h"
#include <string.h>
#include <unistd.h>
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"
#include "../session/registry.h"

/*
 * Extract the opaque query string (everything after '?') from the raw open
 * payload into out[].  Returns 1 if a '?' was found, 0 otherwise.
 */
static int
open_extract_opaque(const u_char *payload, size_t payload_len, char *out,
    size_t out_size)
{
    const u_char *question_mark;
    const u_char *opaque_start;
    size_t        opaque_len;

    out[0] = '\0';
    question_mark = memchr(payload, '?', payload_len);
    if (question_mark == NULL) {
        return 0;
    }

    opaque_start = question_mark + 1;
    opaque_len = payload_len - (size_t) (opaque_start - payload);

    /* Trim trailing NUL byte that kXR_open payloads may carry. */
    if (opaque_len > 0 && opaque_start[opaque_len - 1] == '\0') {
        opaque_len--;
    }
    if (opaque_len == 0 || opaque_len >= out_size) {
        return 0;
    }

    memcpy(out, opaque_start, opaque_len);
    out[opaque_len] = '\0';
    return 1;
}

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
		int n = snprintf(posc_temp_path, sizeof(posc_temp_path),
		                 "%s.posc.%d.%lx",
		                 resolved, (int) getpid(),
		                 (unsigned long) ngx_random());
		if (n <= 0 || n >= (int) sizeof(posc_temp_path)) {
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
			fd = xrootd_open_confined(c->log, &conf->root, open_path,
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

ngx_int_t
xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
				   ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientOpenRequest *req = (ClientOpenRequest *) ctx->hdr_buf;
	uint16_t           options;
	uint16_t           mode_bits;
	char               resolved[PATH_MAX];
	char               clean_path[PATH_MAX];  /* path with CGI query stripped */
	int                is_write;

	options   = ntohs(req->options);
	mode_bits = ntohs(req->mode);

	/*
	 * open is the densest request in the read-side path because it bridges
	 * protocol semantics (flags, mkpath, retstat) with POSIX open(2) details
	 * and also seeds the per-handle bookkeeping reused by later read/close ops.
	 */

	/* Determine whether this is a write-mode open */
	is_write = (options & (kXR_new | kXR_delete | kXR_open_updt |
						   kXR_open_wrto | kXR_open_apnd)) ? 1 : 0;

	/*
	 * TPC (Third-Party Copy) detection.
	 *
	 * The XRootD TPC protocol embeds transfer-context parameters in the open
	 * path as CGI-style opaque strings:
	 *
	 *   TPC destination (we pull FROM source):
	 *     write open + tpc.src=root://host//path + tpc.key=<token>
	 *     We connect outbound to the source, stream the file locally, and
	 *     return the fhandle only after the pull completes.
	 *
	 *   TPC source (destination connects TO us):
	 *     read open with tpc.key=<token> (+ optional tpc.dst= for logging)
	 *     We serve the file normally — the caller is a TPC destination server.
	 *     No special handling required beyond logging the TPC context.
	 *
	 * Parse opaque params here so the TPC destination path can act before the
	 * normal path-resolution and open logic below.
	 */
	{
		char                 opaque[XROOTD_MAX_PATH + 1];
		xrootd_tpc_params_t  tpc;

		if (ctx->payload != NULL && ctx->cur_dlen > 0
		    && open_extract_opaque(ctx->payload, ctx->cur_dlen,
		                           opaque, sizeof(opaque))
		    && xrootd_tpc_parse_opaque(opaque, &tpc) == 0)
		{
			if (is_write && tpc.has_src && tpc.src_host[0] != '\0') {
				/*
				 * TPC destination role: pull the file from tpc.src and write
				 * it to our local storage.  The open response (fhandle or
				 * error) is deferred until the pull completes in the thread
				 * pool.
				 */
				char tpc_resolved[PATH_MAX];
				char tpc_clean[PATH_MAX];

				if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
				                         tpc_clean, sizeof(tpc_clean), 1)) {
					xrootd_log_access(ctx, c, "OPEN", "-", "tpc-pull",
					                  0, kXR_ArgInvalid,
					                  "invalid TPC dst path", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_ArgInvalid,
					                         "invalid TPC destination path");
				}

				/* Manager mode: generate TPC key and redirect to a data server. */
				if (conf->manager_mode) {
					char     redir_host[256];
					uint16_t redir_port;

					if (xrootd_srv_select(tpc_clean, 1, redir_host,
					                      sizeof(redir_host), &redir_port)) {
						char tpc_key[XROOTD_TPC_KEY_LEN];

						xrootd_tpc_generate_key(tpc_key, sizeof(tpc_key));
						xrootd_tpc_key_register(tpc_key, conf->tpc_key_ttl_ms);
						xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-redirect",
						                  1, 0, NULL, 0);
						XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_WR);
						return xrootd_send_redirect_tpc(ctx, c, redir_host,
						                                redir_port, tpc_key);
					}
						xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
						                  0, kXR_Overloaded,
						                  "no data server for TPC", 0);
						XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
						return xrootd_send_error(ctx, c, kXR_Overloaded,
						                         "no data server available for TPC");
				}

				if (!conf->allow_write) {
					xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
					                  0, kXR_fsReadOnly,
					                  "read-only server", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_fsReadOnly,
					                         "this is a read-only server");
				}

				if (xrootd_check_token_scope(ctx, tpc_clean, 1) != NGX_OK) {
					xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
					                  0, kXR_NotAuthorized,
					                  "token scope denied", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_NotAuthorized,
					                         "token scope denied");
				}

				if (options & kXR_mkpath) {
					if (!xrootd_resolve_path_noexist(
					        c->log, &conf->root, tpc_clean,
					        tpc_resolved, sizeof(tpc_resolved))) {
						XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
						return xrootd_send_error(ctx, c, kXR_NotFound,
						                         "invalid TPC destination path");
					}
				} else {
					if (!xrootd_resolve_path_write(
					        c->log, &conf->root, tpc_clean,
					        tpc_resolved, sizeof(tpc_resolved))) {
						XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
						return xrootd_send_error(ctx, c, kXR_NotFound,
						                         "invalid TPC destination path");
					}
				}

				if (xrootd_check_authdb(ctx, tpc_resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
					xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
					                  0, kXR_NotAuthorized,
					                  "authdb denied", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_NotAuthorized,
					                         "authdb denied");
				}

				if (xrootd_check_vo_acl(c->log, tpc_resolved, conf->vo_rules,
				                         ctx->vo_list) != NGX_OK) {
					xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
					                  0, kXR_NotAuthorized,
					                  "VO not authorized", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_NotAuthorized,
					                         "VO not authorized");
				}

				if (options & kXR_mkpath) {
					char  parent[PATH_MAX];
					char *slash;
					ngx_cpystrn((u_char *) parent, (u_char *) tpc_resolved,
					            sizeof(parent));
					slash = strrchr(parent, '/');
					if (slash && slash > parent) {
						*slash = '\0';
						xrootd_mkdir_recursive_policy(parent, 0755, c->log,
						                              conf->group_rules);
					}
				}

				return xrootd_tpc_prepare_pull(ctx, c, conf, &tpc,
				                               tpc_resolved, options, mode_bits);

			} else if (!is_write && (tpc.has_key || tpc.has_dst || tpc.has_org)) {
				/*
				 * TPC source role.
				 *
				 * XrdCl drives full native TPC as a two-step source rendezvous:
				 * first the initiating client opens the source with tpc.dst and
				 * the shared key, then the destination server opens the same
				 * source with tpc.org and that key.  Register the first form and
				 * consume the second before serving bytes.
				 */
				ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
				               "xrootd: TPC source open key=%s dst=%s org=%s",
				               tpc.has_key ? tpc.key : "-",
				               tpc.has_dst ? tpc.dst : "-",
				               tpc.has_org ? tpc.org : "-");

				if (tpc.has_key && tpc.key[0] != '\0' && tpc.has_dst
				    && !tpc.has_org) {
					xrootd_tpc_key_register(tpc.key, conf->tpc_key_ttl_ms);
					ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
					               "xrootd: TPC source key=%s registered",
					               tpc.key);

				} else if (tpc.has_key && tpc.key[0] != '\0'
				           && tpc.has_org) {
					if (xrootd_tpc_key_consume(tpc.key)) {
						ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
						               "xrootd: TPC source key=%s consumed",
						               tpc.key);
					} else {
						xrootd_log_access(ctx, c, "OPEN",
						                  ctx->payload ? (char *) ctx->payload : "-",
						                  "tpc-source", 0, kXR_NotAuthorized,
						                  "TPC authorization missing or expired", 0);
						XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
						return xrootd_send_error(ctx, c, kXR_NotAuthorized,
						                         "TPC authorization missing or expired");
					}
				}
			}
		}
	}

	/*
	 * In XRootD the presence of any write-style option changes the semantics of
	 * the open, even if the path lookup portion still looks read-like.
	 */

	if (is_write && !conf->allow_write) {
		xrootd_log_access(ctx, c, "OPEN",
						  ctx->payload ? (char *) ctx->payload : "-", "wr",
						  0, kXR_fsReadOnly, "read-only server", 0);
		XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
		return xrootd_send_error(ctx, c, kXR_fsReadOnly,
								 "this is a read-only server");
	}

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		xrootd_log_access(ctx, c, "OPEN", "-",
						  is_write ? "wr" : "rd",
						  0, kXR_ArgMissing, "no path given", 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
	}

	/*
	 * clean_path is the protocol-facing pathname after stripping client-side
	 * query metadata. resolved is the server's canonical or validated target.
	 */
	/* Strip XRootD CGI query string ("?oss.asize=N" etc.) from the path.
	 * xrdcp and other clients append these for metadata; they are not part
	 * of the filesystem path. */
	if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
							 clean_path, sizeof(clean_path), 1)) {
		xrootd_log_access(ctx, c, "OPEN", "-",
						  is_write ? "wr" : "rd",
						  0, kXR_ArgInvalid, "invalid path payload", 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid path payload");
	}

	/* Dynamic manager mode: redirect to best registered server. */
	if (conf->manager_mode) {
		char     redir_host[256];
		uint16_t redir_port;
		if (xrootd_srv_select(clean_path, is_write, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			xrootd_log_access(ctx, c, "OPEN", clean_path, "registry",
			                  1, 0, NULL, 0);
			XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_redirect(ctx, c, redir_host, redir_port);
		}

		/* Registry miss — ask the CMS parent via kYR_locate. */
		if (conf->cms_ctx != NULL) {
			uint32_t  streamid;

			streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
			if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
			                               clean_path) == NGX_OK
			    && xrootd_pending_insert(streamid, ngx_pid, c->fd,
			                             conf->cms_locate_timeout) == NGX_OK)
			{
				ctx->cms_wait_streamid = streamid;
				ctx->state = XRD_ST_WAITING_CMS;
				ngx_add_timer(c->read, conf->cms_locate_timeout);
				return NGX_AGAIN;
			}
			/* Fall through to static-map / local resolve / error. */
		}
	}

	/* Manager-mode mapping: redirect opens for configured prefixes. */
	if (conf->manager_map != NULL) {
		const xrootd_manager_map_t *m = xrootd_find_manager_map(clean_path,
																conf->manager_map);
		if (m != NULL) {
			xrootd_log_access(ctx, c, "OPEN", clean_path, "redirect",
							  1, 0, NULL, 0);
			XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_redirect(ctx, c, (const char *) m->host.data,
										m->port);
		}
	}

	/* Resolve the path.
	 * For read opens the file must already exist (realpath check).
	 * For write opens with kXR_mkpath the parent dirs may not exist yet,
	 * so use xrootd_resolve_path_noexist; otherwise use the write resolver
	 * which requires the parent to exist. */
	if (!is_write) {
		if (conf->cache) {
			return xrootd_open_cached_read(ctx, c, conf, clean_path,
			                               options, mode_bits);
		}

		/* Read opens are strict: the final target must already exist and canonicalize. */
		if (!xrootd_resolve_path(c->log, &conf->root,
								 clean_path, resolved, sizeof(resolved))) {
				/* No local file - query upstream redirector if configured */
			if (conf->upstream_host.len > 0) {
				xrootd_log_access(ctx, c, "OPEN", clean_path,
								  "upstream", 1, 0, NULL, 0);
				XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
				return xrootd_upstream_start(ctx, c, conf);
			}
			xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
							  0, kXR_NotFound, "file not found", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
		}

		if (xrootd_check_authdb(ctx, resolved, is_write ? XROOTD_AUTH_UPDATE : XROOTD_AUTH_READ) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", resolved, is_write ? "wr" : "rd",
							  0, kXR_NotAuthorized, "authdb denied", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "authdb denied");
		}

		if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
								 ctx->vo_list) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", resolved, "rd",
							  0, kXR_NotAuthorized, "VO not authorized", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "VO not authorized");
		}

		if (xrootd_check_token_scope(ctx, clean_path, 0) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
							  0, kXR_NotAuthorized, "token scope denied", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "token scope denied");
		}

		/* Reject opening a directory as a file */
		{
			struct stat st;
			if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
				xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
								  0, kXR_isDirectory, "is a directory", 0);
				XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
				return xrootd_send_error(ctx, c, kXR_isDirectory,
										 "is a directory");
			}
		}
	} else {
		int ok;
		/*
		 * Write opens are more permissive because the leaf may be created by
		 * the open itself. The exact resolver depends on whether the client also
		 * asked us to materialize missing parent directories.
		 */
		if (options & kXR_mkpath) {
				/* Parent dirs may not exist yet - validate without realpath */
			ok = xrootd_resolve_path_noexist(c->log, &conf->root,
											  clean_path, resolved,
											  sizeof(resolved));
		} else {
			ok = xrootd_resolve_path_write(c->log, &conf->root,
										   clean_path, resolved,
										   sizeof(resolved));
		}
		if (!ok) {
			xrootd_log_access(ctx, c, "OPEN", clean_path, "wr",
							  0, kXR_NotFound, "invalid path", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
			return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
		}

		if (xrootd_check_authdb(ctx, resolved, is_write ? XROOTD_AUTH_UPDATE : XROOTD_AUTH_READ) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", resolved, is_write ? "wr" : "rd",
							  0, kXR_NotAuthorized, "authdb denied", 0);
			XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "authdb denied");
		}

		if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
								 ctx->vo_list) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", resolved, "wr",
							  0, kXR_NotAuthorized, "VO not authorized", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "VO not authorized");
		}

		if (xrootd_check_token_scope(ctx, clean_path, 1) != NGX_OK) {
			xrootd_log_access(ctx, c, "OPEN", clean_path, "wr",
							  0, kXR_NotAuthorized, "token scope denied", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "token scope denied");
		}

		/* Create parent directories if kXR_mkpath is set */
		if (options & kXR_mkpath) {
			char  parent[PATH_MAX];
			char *slash;
			ngx_cpystrn((u_char *) parent, (u_char *) resolved, sizeof(parent));
			slash = strrchr(parent, '/');
			if (slash && slash > parent) {
				*slash = '\0';
				/* mode 0755 for new directories; propagate group policy */
				xrootd_mkdir_recursive_policy(parent, 0755, c->log,
											  conf->group_rules);
			}
		}
	}

	return xrootd_open_resolved_file(ctx, c, conf, resolved, options,
									 mode_bits, is_write);
}
