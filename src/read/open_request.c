#include "open.h"
#include "../manager/registry.h"
#include "../manager/redir_cache.h"
#include "../manager/pending.h"
#include "../frm/waiter.h"
#include "../session/registry.h"
#include "../cms/cms_internal.h"

#include <string.h>
#include <unistd.h>

/* Opaque extraction helper — defined in open_overview.c */
extern int open_extract_opaque(const u_char *payload, size_t payload_len, char *out, size_t out_size);

/* SciTags echo timer (phase-34): periodically emit an "ongoing" firefly for a
 * long-lived marked connection.  ev->data is the xrootd_ctx_t; re-arms itself
 * until the connection is torn down (the timer is cancelled in on_disconnect). */
static void
xrootd_pmark_echo_timer(ngx_event_t *ev)
{
    xrootd_ctx_t *ctx = ev->data;

    if (ctx == NULL || ctx->destroyed || ctx->pmark_flow == NULL) {
        return;
    }
    xrootd_pmark_flow_echo(ctx->pmark_flow, ev->log);
    if (ctx->pmark_echo_ms > 0) {
        ngx_add_timer(ev, ctx->pmark_echo_ms);
    }
}

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
	char               full_path[PATH_MAX];
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
				char tpc_full_path[PATH_MAX];
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
					XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
					                  tpc_clean, "tpc-pull", kXR_ArgInvalid,
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

				{
					ngx_str_t tpc_src_scope;
					ngx_str_t tpc_dst_scope;

					tpc_src_scope.data = (u_char *) tpc.src_path;
					tpc_src_scope.len = ngx_strlen(tpc.src_path);
					tpc_dst_scope.data = (u_char *) tpc_clean;
					tpc_dst_scope.len = ngx_strlen(tpc_clean);

					if (xrootd_tpc_check_authz(ctx->identity, &tpc_src_scope,
					                           &tpc_dst_scope, c->log)
					    != NGX_OK)
					{
						XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
						                  tpc_clean, "tpc-pull",
						                  kXR_NotAuthorized,
						                  "TPC authorization denied");
					}
				}

				xrootd_beneath_full_path(conf->common.root_canon, tpc_clean,
				                          tpc_full_path, sizeof(tpc_full_path));

				/* Format-aware authz (xrdacc engine or native authdb); the TPC
				 * pull creates the dest file (AOP_Create). */
				if (xrootd_authz_check(ctx, c, conf, tpc_clean, tpc_full_path,
				                       "OPEN", XROOTD_AUTH_UPDATE,
				                       XROOTD_AOP_CREATE) != NGX_OK) {
					XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
					                  tpc_clean, "tpc-pull", kXR_NotAuthorized,
					                  "authdb denied");
				}

				if (xrootd_check_vo_acl_identity(c->log, tpc_full_path,
				                                 conf->vo_rules,
				                                 ctx->identity) != NGX_OK) {
					XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
					                  tpc_clean, "tpc-pull", kXR_NotAuthorized,
					                  "VO not authorized");
				}

				if (options & kXR_mkpath) {
					char  parent[PATH_MAX];
					char *slash;
					ngx_cpystrn((u_char *) parent, (u_char *) tpc_full_path,
					            sizeof(parent));
					slash = strrchr(parent, '/');
					if (slash && slash > parent) {
						*slash = '\0';
						xrootd_mkdir_recursive_policy(parent, 0755, c->log,
						                              conf->group_rules);
					}
				}

				return xrootd_tpc_prepare_pull(ctx, c, conf, &tpc,
				                               tpc_full_path, options, mode_bits);

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
						XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
						                  ctx->payload ? (char *) ctx->payload : "-",
						                  "tpc-source", kXR_NotAuthorized,
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

	/* In manager_mode writes are forwarded to registered data servers;
	 * the allow_write check applies only to local file serving. */
	if (is_write && !conf->common.allow_write && !conf->manager_mode) {
		xrootd_log_access(ctx, c, "OPEN",
						  ctx->payload ? (char *) ctx->payload : "-", "wr",
						  0, kXR_fsReadOnly, "read-only server", 0);
		XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
		return xrootd_send_error(ctx, c, kXR_fsReadOnly,
								 "this is a read-only server");
	}

	/* metadata_only without a manager_map: serve namespace only, no file I/O. */
	if (conf->metadata_only && conf->manager_map == NULL) {
		xrootd_log_access(ctx, c, "OPEN",
						  ctx->payload ? (char *) ctx->payload : "-",
						  is_write ? "wr" : "rd",
						  0, kXR_Unsupported, "metadata-only server", 0);
		return xrootd_send_error(ctx, c, kXR_Unsupported,
								 "open not available on metadata-only server");
	}

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", "-", is_write ? "wr" : "rd",
						  kXR_ArgMissing, "no path given");
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
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", "-", is_write ? "wr" : "rd",
						  kXR_ArgInvalid, "invalid path payload");
	}

	if (xrootd_count_path_depth(clean_path) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", clean_path, is_write ? "wr" : "rd",
						  kXR_ArgInvalid, "path exceeds maximum depth");
	}

	/* Dynamic manager mode: redirect to best registered server. */
	if (conf->manager_mode) {
		char     redir_host[256];
		uint16_t redir_port;

		/* tried/triedrc: a read whose client has already visited every server
		 * holding this path (all returned enoent) must get not-found, not yet
		 * another redirect — otherwise it loops to the client redirect limit.
		 * Writes are excluded: they create the file on the selected server. */
		if (!is_write
		    && xrootd_manager_tried_exhausted(ctx->payload, ctx->cur_dlen,
		                                      clean_path)) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
			                  "rd", kXR_NotFound,
			                  "file not found on any data server");
		}

		/* Collapse-redir cache: serve reads from cache to skip CMS. */
		if (!is_write && conf->collapse_redir
		    && xrootd_redir_cache_lookup(clean_path, redir_host,
		                                 sizeof(redir_host), &redir_port)) {
			XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
			                    clean_path, "redir-cache",
			                    redir_host, redir_port);
		}

		if (xrootd_srv_select(clean_path, is_write, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			if (!is_write && conf->collapse_redir) {
				xrootd_redir_cache_insert(clean_path, redir_host, redir_port,
				                          conf->collapse_redir_ttl);
			}
			XROOTD_RETURN_REDIR(ctx, c,
			                    is_write ? XROOTD_OP_OPEN_WR
			                             : XROOTD_OP_OPEN_RD,
			                    "OPEN", clean_path, "registry",
			                    redir_host, redir_port);
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
			XROOTD_RETURN_REDIR(ctx, c,
							  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
							  "OPEN", clean_path, "redirect",
							  (const char *) m->host.data, m->port);
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

		/* Read opens: verify the file exists within root using kernel confinement,
		 * then build the absolute path string for auth checks. */
		xrootd_beneath_full_path(conf->common.root_canon, clean_path,
		                          full_path, sizeof(full_path));
		{
			struct stat _exist_st;
			if (xrootd_stat_beneath(conf->rootfd, clean_path, &_exist_st) != 0) {
				if (conf->upstream_host.len > 0) {
					xrootd_log_access(ctx, c, "OPEN", clean_path,
									  "upstream", 1, 0, NULL, 0);
					XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_RD);
					return xrootd_upstream_start(ctx, c, conf);
				}
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
								  clean_path, "rd", kXR_NotFound,
								  "file not found");
			}
			if (S_ISDIR(_exist_st.st_mode)) {
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
								  clean_path, "rd", kXR_isDirectory,
								  "is a directory");
			}
		}

		if (xrootd_auth_gate(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
							  clean_path, full_path, conf,
							  XROOTD_AUTH_READ, 0) != NGX_OK) {
			return ctx->write_rc;
		}

		/* Phase 35: residency gate. A nearline file (on the backend, not on
		 * disk) is recalled and the client stalled with kXR_wait-and-retry.
		 * Runs AFTER auth so an unauthorized caller never learns residency. */
		if (conf->frm.enable && conf->frm.queue != NULL) {
			frm_residency_t _res;
			if (frm_residency_probe(c->log, full_path, &_res) == NGX_OK
			    && _res.state == FRM_RES_OFFLINE)
			{
				/* A failed/unretrievable recall — do not spin; surface an
				 * error so the client re-prepares or gives up. */
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
				                  clean_path, "rd", kXR_FSError,
				                  "file is offline (recall failed)");
			}
			if (frm_residency_probe(c->log, full_path, &_res) == NGX_OK
			    && _res.state == FRM_RES_NEARLINE)
			{
				frm_req_view_t _v;
				char           _rq[FRM_REQID_LEN];
				ngx_memzero(&_v, sizeof(_v));
				_v.lfn        = full_path;
				_v.options    = FRM_OPT_STAGE;
				_v.selector   = "stage";      /* F4/F2: activity class       */
				_v.queue      = 0;            /* stgQ (XRootD numQ default)   */
				_v.requester_dn = (ctx->dn[0] != '\0') ? ctx->dn : NULL;
				_v.tod_expire = (int64_t) ngx_time()
				              + (int64_t) (conf->frm.stage_ttl / 1000);
				(void) frm_request_add(conf->frm.queue, &_v, _rq,
				                       sizeof(_rq), c->log);
				frm_stage_kick();

				/* Phase 3: when async recall is on, park the open with
				 * kXR_waitresp and wake it in place via kXR_attn(asynresp) on
				 * completion. Falls back to the Phase-1 kXR_wait poll model if
				 * async is off or the waiter table is full. */
				if (conf->frm.async_recall
				    && frm_waiter_add(_rq, options, ctx->cur_streamid,
				                      c->fd, c->number, ngx_pid,
				                      conf->frm.stage_ttl) == NGX_OK)
				{
					XROOTD_FRM_METRIC_INC(waitresp_total);
					xrootd_log_access(ctx, c, "OPEN", clean_path,
					                  "staging-async", 1, 0, NULL, 0);
					(void) xrootd_send_waitresp(ctx, c);
					ctx->state = XRD_ST_WAITING_FRM;
					ngx_add_timer(c->read, conf->frm.stage_ttl);
					return NGX_AGAIN;
				}

				xrootd_log_access(ctx, c, "OPEN", clean_path, "staging",
				                  1, kXR_wait, NULL, 0);
				return xrootd_send_wait(ctx, c, conf->frm.stage_wait);
			}
		}
	} else {
		xrootd_beneath_full_path(conf->common.root_canon, clean_path,
		                          full_path, sizeof(full_path));

		/* XrdAcc distinguishes creating a NEW file (needs Insert) from
		 * updating an existing one; kXR_new is the create intent. */
		if (xrootd_auth_gate_op(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
							  clean_path, full_path, conf,
							  XROOTD_AUTH_UPDATE, 1,
							  (options & kXR_new) ? XROOTD_AOP_CREATE
							                      : XROOTD_AOP_UPDATE) != NGX_OK) {
			return ctx->write_rc;
		}

		/* Create parent directories if kXR_mkpath is set */
		if (options & kXR_mkpath) {
			char  parent[PATH_MAX];
			char *slash;
			ngx_cpystrn((u_char *) parent, (u_char *) full_path, sizeof(parent));
			slash = strrchr(parent, '/');
			if (slash && slash > parent) {
				*slash = '\0';
				/* mode 0755 for new directories; propagate group policy */
				xrootd_mkdir_recursive_policy(parent, 0755, c->log,
											  conf->group_rules);
			}
		}
	}

	/*
	 * SciTags packet marking (phase-34): begin a flow on the FIRST local data
	 * open of this connection (like XRootD, which begins on open and reuses the
	 * handle for all I/O).  Redirect/manager/cached paths returned earlier and
	 * are intentionally not marked here.  Fail-open: a NULL result just means the
	 * flow is not marked.  The client may override codes via a scitag.flow opaque.
	 */
	if (ctx->pmark_flow == NULL && conf->common.pmark.enable) {
		char        opq[XROOTD_MAX_PATH + 1];
		const char *cgi = NULL;
		if (ctx->payload != NULL && ctx->cur_dlen > 0
		    && open_extract_opaque(ctx->payload, ctx->cur_dlen, opq, sizeof(opq)))
		{
			cgi = opq;
		}
		ctx->pmark_flow = xrootd_pmark_flow_begin(&conf->common.pmark, c->pool, c,
			is_write,
			ctx->identity ? xrootd_identity_vo_csv_cstr(ctx->identity) : "",
			ctx->identity ? xrootd_identity_dn_cstr(ctx->identity) : "",
			clean_path, cgi, c->log);

		/* Arm the periodic "ongoing" firefly echo for this connection's flow
		 * (phase-34), if configured.  Cancelled in xrootd_on_disconnect. */
		if (ctx->pmark_flow != NULL && conf->common.pmark.echo > 0
		    && !ctx->pmark_echo_ev.timer_set)
		{
			ctx->pmark_echo_ms          = conf->common.pmark.echo;
			ctx->pmark_echo_ev.handler  = xrootd_pmark_echo_timer;
			ctx->pmark_echo_ev.data     = ctx;
			ctx->pmark_echo_ev.log      = c->log;
			ngx_add_timer(&ctx->pmark_echo_ev, ctx->pmark_echo_ms);
		}
	}

	return xrootd_open_resolved_file(ctx, c, conf, full_path, options,
									 mode_bits, is_write);
}
