#include "open_internal.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"

#include <string.h>

/*
 * open_tpc.c — kXR_open TPC (third-party-copy) context detection, split from
 * open_request.c.  The XRootD TPC protocol embeds transfer-context parameters in
 * the open path as CGI-style opaque strings:
 *
 *   TPC destination (we pull FROM source): write open + tpc.src=root://host//path
 *     + tpc.key=<token>.  Connect outbound to the source, stream the file
 *     locally, and return the fhandle only after the pull completes.
 *
 *   TPC source (destination connects TO us): read open with tpc.key=<token>
 *     (+ optional tpc.dst=/tpc.org= for the two-step rendezvous).  Register the
 *     first form and consume the second before serving bytes.
 *
 * Must act BEFORE the normal path-resolution/open logic, so it runs first from
 * brix_handle_open.  Bodies are moved verbatim; the early-returns are unchanged.
 */

/*
 * TPC destination role: pull the file from tpc->src and write it to our local
 * storage.  The open response (fhandle or error) is deferred until the pull
 * completes in the thread pool.  Always returns a response rc (redirect, error,
 * or the deferred prepare-pull).
 */
static ngx_int_t
tpc_handle_dest(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    uint16_t options, uint16_t mode_bits)
{
	char tpc_full_path[PATH_MAX];
	char tpc_clean[PATH_MAX];

	if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
	                         tpc_clean, sizeof(tpc_clean), 1)) {
		brix_log_access(ctx, c, "OPEN", "-", "tpc-pull",
		                  0, kXR_ArgInvalid,
		                  "invalid TPC dst path", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
		return brix_send_error(ctx, c, kXR_ArgInvalid,
		                         "invalid TPC destination path");
	}
	if (brix_count_path_depth(tpc_clean) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
		                  tpc_clean, "tpc-pull", kXR_ArgInvalid,
		                  "path exceeds maximum depth");
	}

	/* Manager mode: generate TPC key and redirect to a data server. */
	if (conf->manager_mode) {
		char     redir_host[256];
		uint16_t redir_port;

		if (brix_srv_select(tpc_clean, 1, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			char tpc_key[BRIX_TPC_KEY_LEN];

			brix_tpc_generate_key(tpc_key, sizeof(tpc_key));
			brix_tpc_key_register(tpc_key, conf->tpc_key_ttl_ms);
			brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-redirect",
			                  1, 0, NULL, 0);
			BRIX_OP_OK(ctx, BRIX_OP_OPEN_WR);
			return brix_send_redirect_tpc(ctx, c, redir_host,
			                                redir_port, tpc_key);
		}
			brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
			                  0, kXR_Overloaded,
			                  "no data server for TPC", 0);
			BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
			return brix_send_error(ctx, c, kXR_Overloaded,
			                         "no data server available for TPC");
	}

	if (!conf->common.allow_write) {
		brix_log_access(ctx, c, "OPEN", tpc_clean, "tpc-pull",
		                  0, kXR_fsReadOnly,
		                  "read-only server", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
		return brix_send_error(ctx, c, kXR_fsReadOnly,
		                         "this is a read-only server");
	}

	{
		ngx_str_t tpc_src_scope;
		ngx_str_t tpc_dst_scope;

		tpc_src_scope.data = (u_char *) tpc->src_path;
		tpc_src_scope.len = ngx_strlen(tpc->src_path);
		tpc_dst_scope.data = (u_char *) tpc_clean;
		tpc_dst_scope.len = ngx_strlen(tpc_clean);

		if (brix_tpc_check_authz(ctx->identity, &tpc_src_scope,
		                           &tpc_dst_scope, c->log)
		    != NGX_OK)
		{
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  tpc_clean, "tpc-pull",
			                  kXR_NotAuthorized,
			                  "TPC authorization denied");
		}
	}

	brix_beneath_full_path(conf->common.root_canon, tpc_clean,
	                          tpc_full_path, sizeof(tpc_full_path));

	/* Format-aware authz (xrdacc engine or native authdb); the TPC pull creates
	 * the dest file (AOP_Create). */
	if (brix_authz_check(ctx, c, conf, tpc_clean, tpc_full_path,
	                       "OPEN", BRIX_AUTH_UPDATE,
	                       BRIX_AOP_CREATE) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
		                  tpc_clean, "tpc-pull", kXR_NotAuthorized,
		                  "authdb denied");
	}

	if (brix_check_vo_acl_identity(c->log, tpc_full_path,
	                                 conf->vo_rules,
	                                 ctx->identity) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
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
			brix_mkdir_recursive_policy(parent, 0755, c->log,
			                              conf->group_rules);
		}
	}

	return brix_tpc_prepare_pull(ctx, c, conf, tpc,
	                               tpc_full_path, options, mode_bits);
}

/*
 * TPC source role.  XrdCl drives full native TPC as a two-step source
 * rendezvous: first the initiating client opens the source with tpc.dst and the
 * shared key, then the destination server opens the same source with tpc.org and
 * that key.  Register the first form and consume the second before serving
 * bytes.  NGX_DECLINED to serve the file normally; an error rc on a bad consume.
 */
static ngx_int_t
tpc_handle_source(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc)
{
	ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
	               "brix: TPC source open key=%s dst=%s org=%s",
	               tpc->has_key ? tpc->key : "-",
	               tpc->has_dst ? tpc->dst : "-",
	               tpc->has_org ? tpc->org : "-");

	if (tpc->has_key && tpc->key[0] != '\0' && tpc->has_dst
	    && !tpc->has_org) {
		brix_tpc_key_register(tpc->key, conf->tpc_key_ttl_ms);
		ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
		               "brix: TPC source key=%s registered",
		               tpc->key);

	} else if (tpc->has_key && tpc->key[0] != '\0'
	           && tpc->has_org) {
		if (brix_tpc_key_consume(tpc->key)) {
			ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
			               "brix: TPC source key=%s consumed",
			               tpc->key);
		} else {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
			                  ctx->recv.payload ? (char *) ctx->recv.payload : "-",
			                  "tpc-source", kXR_NotAuthorized,
			                  "TPC authorization missing or expired");
		}
	}

	return NGX_DECLINED;
}

ngx_int_t
brix_open_handle_tpc(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, uint16_t options,
    uint16_t mode_bits)
{
	char                 opaque[BRIX_MAX_PATH + 1];
	brix_tpc_params_t  tpc;

	if (!(ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0
	      && open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                             opaque, sizeof(opaque))
	      && brix_tpc_parse_opaque(opaque, &tpc) == 0))
	{
		return NGX_DECLINED;
	}

	if (is_write && tpc.has_src && tpc.src_host[0] != '\0') {
		return tpc_handle_dest(ctx, c, conf, &tpc, options, mode_bits);
	}

	if (!is_write && (tpc.has_key || tpc.has_dst || tpc.has_org)) {
		return tpc_handle_source(ctx, c, conf, &tpc);
	}

	return NGX_DECLINED;
}
