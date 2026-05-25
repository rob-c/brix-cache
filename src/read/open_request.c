#include "open.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../session/registry.h"
#include "../cms/cms_internal.h"

#include <string.h>
#include <unistd.h>

/* Opaque extraction helper — defined in open_overview.c */
extern int open_extract_opaque(const u_char *payload, size_t payload_len, char *out, size_t out_size);

/* ---- Function: xrootd_handle_open() ----
 *
 * WHAT: Protocol-level entry point for kXR_open. Parses ClientOpenRequest from wire,
 *       validates permissions through security gates (manager mode redirect, authdb, VO ACL,
 *       token scope), resolves paths to canonical filesystem location based on read/write mode,
 *       detects TPC transfer context embedded as opaque parameters in the path string,
 *       and dispatches to either cached-read handler or xrootd_open_resolved_file().
 *
 * WHY: kXR_open is the densest request in the protocol — it bridges four layers:
 *      1. Protocol semantics (kXR_new/create, kXR_mkpath/make-parent-dirs, kXR_retstat)
 *      2. POSIX open(2) with confined path validation and fd allocation
 *      3. Per-handle bookkeeping (readable/writable flags, byte counters, timestamps)
 *      4. TPC context detection for third-party server-to-server transfers.
 *      All bookkeeping is reused by subsequent read/pgread/readv/write/close opcodes.
 *
 * HOW: Parse options/mode from wire → detect write-mode (kXR_new/delete/updt/wrto/apnd) →
 *      parse opaque query string for TPC params → if TPC destination (write + tpc.src): validate,
 *      resolve, check authdb/VO ACL/token scope, mkpath dirs, delegate to xrootd_tpc_prepare_pull;
 *      if TPC source (read + tpc.key): register/consume key → return NGX_AGAIN on consume failure.
 *      Normal path: strip CGI query from path → validate depth → manager_mode redirect or CMS locate
 *      → static map prefix redirect → read resolve (cache-aware or realpath) → write resolver →
 *      authdb/VO ACL/token scope gates → reject directories → delegate to xrootd_open_resolved_file().
 */

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
	 * including confined-path validation and fd allocation, and seeds per-handle
	 * bookkeeping (readable/writable flags, byte counters, timestamps) that all
	 * subsequent opcodes (read, pgread, readv, write, close) reuse.
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
				if (xrootd_count_path_depth(tpc_clean) != NGX_OK) {
					xrootd_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
					                  0, kXR_ArgInvalid,
					                  "path exceeds maximum depth", 0);
					XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
					return xrootd_send_error(ctx, c, kXR_ArgInvalid,
					                         "path exceeds maximum depth");
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

				if (!conf->common.allow_write) {
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
					        c->log, &conf->common.root, tpc_clean,
					        tpc_resolved, sizeof(tpc_resolved))) {
						XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
						return xrootd_send_error(ctx, c, kXR_NotFound,
						                         "invalid TPC destination path");
					}
				} else {
					if (!xrootd_resolve_path_write(
					        c->log, &conf->common.root, tpc_clean,
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
	 * In XRootD the presence of any write-style option (kXR_new, delete,
	 * updt, wrto, apnd) changes the semantics of open even when the path
	 * lookup portion still looks read-like.  This flag gates whether the
	 * server's allow_write policy applies and which resolver is used below.
	 */

	if (is_write && !conf->common.allow_write) {
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
	 * clean_path: protocol-facing pathname after stripping client-side
	 * query metadata (e.g. "?oss.asize=N" for XCache size hints).  resolved:
	 * server's canonical or validated target on the POSIX filesystem.
	 * Two-path separation lets ACL/token-scope checks run against the exact
	 * wire path while file operations use the confirmed canonical location.
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

	if (xrootd_count_path_depth(clean_path) != NGX_OK) {
		xrootd_log_access(ctx, c, "OPEN", clean_path,
						  is_write ? "wr" : "rd",
						  0, kXR_ArgInvalid,
						  "path exceeds maximum depth", 0);
		XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "path exceeds maximum depth");
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
			if (xrootd_pending_insert(streamid, ngx_pid, c->fd,
			                          c->number,
			                          ctx->cur_streamid,
			                          conf->cms_locate_timeout) == NGX_OK)
			{
				ctx->cms_wait_streamid = streamid;
				ctx->state = XRD_ST_WAITING_CMS;
				ngx_add_timer(c->read, conf->cms_locate_timeout);
				if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
				                               clean_path) == NGX_OK)
				{
					return NGX_AGAIN;
				}
				ngx_del_timer(c->read);
				ctx->state = XRD_ST_REQ_HEADER;
				xrootd_pending_remove(streamid, ngx_pid);
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
		if (!xrootd_resolve_path(c->log, &conf->common.root,
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
	 * Write opens are more permissive because the leaf file may be created
	 * by the open itself (kXR_new), so realpath cannot find it yet.
	 * The exact resolver depends on whether the client also asked us to
	 * materialize missing parent directories (kXR_mkpath).
	 *
	 * kXR_mkpath → resolve_path_noexist: validate path structure without
	 * requiring any component to exist on disk.  No mkpath →
	 * resolve_path_write: leaf must already exist, parents must exist.
	 */
		if (options & kXR_mkpath) {
				/* Parent dirs may not exist yet - validate without realpath */
			ok = xrootd_resolve_path_noexist(c->log, &conf->common.root,
											  clean_path, resolved,
											  sizeof(resolved));
		} else {
			ok = xrootd_resolve_path_write(c->log, &conf->common.root,
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
