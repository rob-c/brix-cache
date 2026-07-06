#include "open.h"
#include "protocols/ssi/ssi.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "net/manager/redir_cache.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_request_registry.h"
#include "fs/xfer/stage_waiter.h"
#include "fs/vfs/vfs.h"                   /* brix_vfs_residency (sd_frm seam) */
#include "protocols/root/session/registry.h"
#include "net/cms/cms_internal.h"
#include "core/compat/codec_core.h"
#include "protocols/root/protocol/open_flags.h"   /* shared kXR_open option-bit semantics */
#include "protocols/root/zip/zip_member.h"        /* phase-57 W2: ZIP member access */
#include "fs/vfs/vfs_backend_registry.h" /* Layer 3: per-export storage driver */
#include "fs/vfs/vfs_internal.h"         /* brix_vfs_export_relative_root */
#include "fs/backend/sd.h"           /* driver stat for read existence check */
#include "fs/backend/cache/sd_cache.h" /* slow-tier miss offload probe (SP2) */

#include <string.h>
#include <unistd.h>

/* Opaque extraction helper — defined in open_overview.c */
extern int open_extract_opaque(const u_char *payload, size_t payload_len, char *out, size_t out_size);

/* Layer 3 — read-open existence + directory probe.
 *
 * A driver-backed export (block-striped / object store) keeps its namespace in
 * the driver: the physical tree under conf->rootfd holds no data files, so a
 * POSIX confined stat would spuriously report ENOENT for a file that the driver
 * actually has. Probe the driver on the export-root-relative key when a driver
 * is bound; otherwise fall back to the confined fd-relative POSIX stat (the
 * unchanged default-export path). Returns 1 if the path exists (and sets
 * *is_dir accordingly), 0 if absent. */
static int
brix_open_read_probe(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
    const char *clean_path, const char *full_path, int *is_dir)
{
    brix_sd_instance_t *sd =
        brix_vfs_backend_resolve(conf->common.root_canon, log);

    *is_dir = 0;

    if (sd != NULL && sd->driver->stat != NULL) {
        brix_sd_stat_t  sst;
        const char       *key =
            brix_vfs_export_relative_root(full_path, conf->common.root_canon);

        /* Slow-tier composed-cache MISS (phase-64 SP2): a source stat here would
         * be a blocking wire round-trip on the event loop. Report the path as
         * provisionally existing (a regular file) and let the OFFLOADED fill
         * resolve the truth — a missing origin object surfaces as kXR_NotFound
         * from the parked open's done callback. A COMPLETE hit answers below via
         * the decorator's cinfo-backed stat (no source touch). */
        if (brix_sd_cache_fill_needs_offload(sd, key)) {
            *is_dir = 0;
            return 1;
        }

        if (sd->driver->stat(sd, key, &sst) != NGX_OK) {
            return 0;
        }
        *is_dir = sst.is_dir ? 1 : 0;
        return 1;
    }

    {
        struct stat est;

        if (brix_stat_beneath(conf->rootfd, clean_path, &est) != 0) {
            return 0;
        }
        *is_dir = S_ISDIR(est.st_mode) ? 1 : 0;
        return 1;
    }
}

/*
 *
 * WHAT: Phase-42 W4/W5 — negotiate an inline-compression codec from the kXR_open
 *       opaque.  Returns the codec ordinal (brix_codec_id_t) to use for this
 *       handle, or BRIX_CODEC_IDENTITY (0) when compression is disabled for the
 *       direction, no "?xrootd.compress=" opaque is present, or the requested
 *       codec is unknown/unavailable.  Direction is chosen by is_write: a READ
 *       open gates on brix_read_compress (W4, compress kXR_read responses); a
 *       WRITE open gates on brix_write_compress (W5, decompress kXR_write
 *       payloads on ingest).
 *
 * WHY:  Inline compression must be strictly opt-in and invisible to stock peers.
 *       The negotiation rides the existing path?opaque carrier (stock servers
 *       ignore unknown CGI keys; stock clients never send them), gated behind the
 *       direction's directive (both off by default).  Fail-soft: an unknown or
 *       unbuilt codec degrades to plaintext rather than failing the open.
 *
 * HOW:  Extract the opaque, scan the '&'-separated CGI list for the
 *       "xrootd.compress=" key on a token boundary, look the value up by
 *       canonical name (then HTTP token, so "br" works) and require it built in.
 */
static uint8_t
open_negotiate_compress_codec(brix_ctx_t *ctx,
                              ngx_stream_brix_srv_conf_t *conf,
                              ngx_flag_t is_write)
{
	char                       opaque[BRIX_MAX_PATH + 1];
	const char                *p, *val, *end;
	size_t                     vlen;
	ngx_flag_t                 enabled;
	const brix_codec_desc_t *d;

	enabled = is_write ? conf->write_compress : conf->read_compress;
	if (!enabled || ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0)
	{
		return BRIX_CODEC_IDENTITY;
	}

	if (!open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
	                         opaque, sizeof(opaque)))
	{
		return BRIX_CODEC_IDENTITY;
	}

	p = strstr(opaque, "xrootd.compress=");
	if (p == NULL) {
		return BRIX_CODEC_IDENTITY;
	}
	/* Require a key boundary before the token (start, '&' or '?'). */
	if (p != opaque && p[-1] != '&' && p[-1] != '?') {
		return BRIX_CODEC_IDENTITY;
	}

	val = p + (sizeof("xrootd.compress=") - 1);
	end = val;
	while (*end != '\0' && *end != '&') {
		end++;
	}
	vlen = (size_t) (end - val);
	if (vlen == 0) {
		return BRIX_CODEC_IDENTITY;
	}

	d = brix_codec_by_name(val, vlen);
	if (d == NULL) {
		d = brix_codec_by_http_token(val, vlen);
	}
	if (d == NULL || !d->available || d->id == BRIX_CODEC_IDENTITY) {
		return BRIX_CODEC_IDENTITY;
	}
	return (uint8_t) d->id;
}

/*
 *
 * WHAT: Phase-57 W2 — pull a validated ZIP member name out of the kXR_open opaque
 *       "?xrdcl.unzip=<member>".  Returns 1 with out[] filled (NUL-terminated)
 *       for a usable member, 0 when no "xrdcl.unzip=" key is present (open the
 *       archive normally), or -1 when the key IS present but its value is invalid
 *       (empty / too long / traversal) — the caller rejects with kXR_ArgInvalid.
 * WHY:  ZIP member access serves one file inside an archive.  The member name is
 *       intra-archive, but a hostile name must never be trusted, so reject empty,
 *       absolute ("/..."), and any ".." path component here, before it reaches the
 *       central-directory lookup.
 * HOW:  Extract the opaque (same carrier as the compression negotiation), scan for
 *       the "xrdcl.unzip=" key on a token boundary (start / '&' / '?'), copy the
 *       value up to the next '&', then reject leading '/', a bare "..", a leading
 *       "../", any embedded "/../", or a trailing "/..".
 */
static int
open_extract_zip_member(brix_ctx_t *ctx, char *out, size_t outsz)
{
	char        opaque[BRIX_MAX_PATH + 1];
	const char *p, *val, *end;
	size_t      vlen;

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		return 0;
	}
	if (!open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen, opaque, sizeof(opaque))) {
		return 0;
	}

	p = strstr(opaque, "xrdcl.unzip=");
	if (p == NULL) {
		return 0;
	}
	if (p != opaque && p[-1] != '&' && p[-1] != '?') {
		return 0;   /* not on a key boundary */
	}

	/* From here the "xrdcl.unzip=" key IS present: a bad value is an explicit
	 * error (return -1, caller rejects with kXR_ArgInvalid), NOT a fall-through
	 * to opening the whole archive — so a traversal attempt is surfaced, not
	 * silently ignored. */
	val = p + (sizeof("xrdcl.unzip=") - 1);
	end = val;
	while (*end != '\0' && *end != '&') {
		end++;
	}
	vlen = (size_t) (end - val);
	if (vlen == 0 || vlen >= outsz) {
		return -1;
	}

	ngx_memcpy(out, val, vlen);
	out[vlen] = '\0';

	/* Intra-archive traversal / absolute-path guard. */
	if (out[0] == '/') {
		return -1;
	}
	if (ngx_strcmp(out, "..") == 0) {
		return -1;
	}
	if (vlen >= 3 && out[0] == '.' && out[1] == '.' && out[2] == '/') {
		return -1;   /* leading "../" */
	}
	if (strstr(out, "/../") != NULL) {
		return -1;
	}
	if (vlen >= 3 && ngx_strcmp(out + vlen - 3, "/..") == 0) {
		return -1;   /* trailing "/.." */
	}

	return 1;
}

/* SciTags echo timer (phase-34): periodically emit an "ongoing" firefly for a
 * long-lived marked connection.  ev->data is the brix_ctx_t; re-arms itself
 * until the connection is torn down (the timer is cancelled in on_disconnect). */
static void
brix_pmark_echo_timer(ngx_event_t *ev)
{
    brix_ctx_t *ctx = ev->data;

    if (ctx == NULL || ctx->destroyed || ctx->pmark.flow == NULL) {
        return;
    }
    brix_pmark_flow_echo(ctx->pmark.flow, ev->log);
    if (ctx->pmark.echo_ms > 0) {
        ngx_add_timer(ev, ctx->pmark.echo_ms);
    }
}

/*
 *
 * WHAT: Protocol-level entry point for kXR_open. Parses ClientOpenRequest from wire,
 *       validates permissions through security gates (manager mode redirect, authdb, VO ACL,
 *       token scope), resolves paths to canonical filesystem location based on read/write mode,
 *       detects TPC transfer context embedded as opaque parameters in the path string,
 *       and dispatches to either cached-read handler or brix_open_resolved_file().
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
 *      resolve, check authdb/VO ACL/token scope, mkpath dirs, delegate to brix_tpc_prepare_pull;
 *      if TPC source (read + tpc.key): register/consume key → return NGX_AGAIN on consume failure.
 *      Normal path: strip CGI query from path → validate depth → manager_mode redirect or CMS locate
 *      → static map prefix redirect → read resolve (cache-aware or realpath) → write resolver →
 *      authdb/VO ACL/token scope gates → reject directories → delegate to brix_open_resolved_file().
 */

ngx_int_t
brix_handle_open(brix_ctx_t *ctx, ngx_connection_t *c,
				   ngx_stream_brix_srv_conf_t *conf)
{
	xrdw_open_req_t    req;
	uint16_t           options;
	uint16_t           mode_bits;
	char               full_path[PATH_MAX];
	char               clean_path[PATH_MAX];  /* path with CGI query stripped */
	int                is_write;

	xrdw_open_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	options   = req.options;
	mode_bits = req.mode;

	/*
	 * open is the densest request in the read-side path because it bridges
	 * protocol semantics (flags, mkpath, retstat) with POSIX open(2) details
	 * including confined-path validation and fd allocation, and seeds per-handle
	 * bookkeeping (readable/writable flags, byte counters, timestamps) that all
	 * subsequent opcodes (read, pgread, readv, write, close) reuse.
	 */

	/* Determine whether this is a write-mode open (shared write-bit set). */
	is_write = brix_open_options_is_write(options);

	/*
	 * §7 XrdSsi: an open of a "/.ssi/<service>" resource is a unary RPC channel,
	 * not a file — intercept before path resolution/open. Clean early-return:
	 * non-SSI opens are byte-for-byte unchanged.
	 */
	if (conf->ssi_enable) {
		char        ssi_path[PATH_MAX];
		const char *svc;
		size_t      svclen;

		if (brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
		                        ssi_path, sizeof(ssi_path), 1)
		    && brix_ssi_match(conf, ssi_path, &svc, &svclen))
		{
			return brix_ssi_open(ctx, c, svc, svclen, options);
		}
	}

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
		char                 opaque[BRIX_MAX_PATH + 1];
		brix_tpc_params_t  tpc;

		if (ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0
		    && open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
		                           opaque, sizeof(opaque))
		    && brix_tpc_parse_opaque(opaque, &tpc) == 0)
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

					tpc_src_scope.data = (u_char *) tpc.src_path;
					tpc_src_scope.len = ngx_strlen(tpc.src_path);
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

				/* Format-aware authz (xrdacc engine or native authdb); the TPC
				 * pull creates the dest file (AOP_Create). */
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

				return brix_tpc_prepare_pull(ctx, c, conf, &tpc,
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
				               "brix: TPC source open key=%s dst=%s org=%s",
				               tpc.has_key ? tpc.key : "-",
				               tpc.has_dst ? tpc.dst : "-",
				               tpc.has_org ? tpc.org : "-");

				if (tpc.has_key && tpc.key[0] != '\0' && tpc.has_dst
				    && !tpc.has_org) {
					brix_tpc_key_register(tpc.key, conf->tpc_key_ttl_ms);
					ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
					               "brix: TPC source key=%s registered",
					               tpc.key);

				} else if (tpc.has_key && tpc.key[0] != '\0'
				           && tpc.has_org) {
					if (brix_tpc_key_consume(tpc.key)) {
						ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
						               "brix: TPC source key=%s consumed",
						               tpc.key);
					} else {
						BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
						                  ctx->recv.payload ? (char *) ctx->recv.payload : "-",
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
		brix_log_access(ctx, c, "OPEN",
						  ctx->recv.payload ? (char *) ctx->recv.payload : "-", "wr",
						  0, kXR_fsReadOnly, "read-only server", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
		return brix_send_error(ctx, c, kXR_fsReadOnly,
								 "this is a read-only server");
	}

	/* metadata_only without a manager_map: serve namespace only, no file I/O. */
	if (conf->caps.metadata_only && conf->manager_map == NULL) {
		brix_log_access(ctx, c, "OPEN",
						  ctx->recv.payload ? (char *) ctx->recv.payload : "-",
						  is_write ? "wr" : "rd",
						  0, kXR_Unsupported, "metadata-only server", 0);
		return brix_send_error(ctx, c, kXR_Unsupported,
								 "open not available on metadata-only server");
	}

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
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
	if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
							 clean_path, sizeof(clean_path), 1)) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", "-", is_write ? "wr" : "rd",
						  kXR_ArgInvalid, "invalid path payload");
	}

	/* Reject any ".." component (the reference does not normalize ".."); the
	 * open resolves through the kernel RESOLVE_BENEATH which would otherwise
	 * collapse an in-tree "..".  Same op id selection as the surrounding errors. */
	if (brix_reject_dotdot_path(ctx, c,
			is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
			"OPEN", clean_path)) {
		return ctx->write_rc;
	}

	if (brix_count_path_depth(clean_path) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
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
		    && brix_manager_tried_exhausted(ctx->recv.payload, ctx->recv.cur_dlen,
		                                      clean_path)) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", clean_path,
			                  "rd", kXR_NotFound,
			                  "file not found on any data server");
		}

		/* Collapse-redir cache: serve reads from cache to skip CMS. */
		if (!is_write && conf->caps.collapse_redir
		    && brix_redir_cache_lookup(clean_path, redir_host,
		                                 sizeof(redir_host), &redir_port)) {
			BRIX_RETURN_REDIR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
			                    clean_path, "redir-cache",
			                    redir_host, redir_port);
		}

		/* Open may redirect to a server whose CMS heartbeat just dropped (a
		 * transient blip under load blacklists it for 30 s though its data plane
		 * is still serving) — better than a false NotFound for a file that
		 * exists.  kXR_locate stays strict.  A truly dead target just makes the
		 * client's connect fail and the tried/triedrc retry converges to
		 * NotFound. */
		if (brix_srv_select_or_blacklisted(clean_path, is_write, redir_host,
		                      sizeof(redir_host), &redir_port)) {
			if (!is_write && conf->caps.collapse_redir) {
				brix_redir_cache_insert(clean_path, redir_host, redir_port,
				                          conf->caps.collapse_redir_ttl);
			}
			BRIX_RETURN_REDIR(ctx, c,
			                    is_write ? BRIX_OP_OPEN_WR
			                             : BRIX_OP_OPEN_RD,
			                    "OPEN", clean_path, "registry",
			                    redir_host, redir_port);
		}

		/* Registry miss — ask the CMS parent via kYR_locate. */
		if (conf->cms.ctx != NULL) {
			uint32_t  streamid;

			streamid = ngx_brix_cms_next_streamid(conf->cms.ctx);
			if (brix_pending_insert(streamid, ngx_pid, c->fd,
			                          c->number,
			                          ctx->recv.cur_streamid,
			                          conf->cms.locate_timeout) == NGX_OK)
			{
				ctx->cms_wait_streamid = streamid;
				ctx->state = XRD_ST_WAITING_CMS;
				ngx_add_timer(c->read, conf->cms.locate_timeout);
				if (ngx_brix_cms_send_locate(conf->cms.ctx, streamid,
				                               clean_path) == NGX_OK)
				{
					return NGX_AGAIN;
				}
				ngx_del_timer(c->read);
				ctx->state = XRD_ST_REQ_HEADER;
				brix_pending_remove(streamid, ngx_pid);
			}
			/* Fall through to static-map / local resolve / error. */
		}
	}

	/* Manager-mode mapping: redirect opens for configured prefixes. */
	if (conf->manager_map != NULL) {
		const brix_manager_map_t *m = brix_find_manager_map(clean_path,
																conf->manager_map);
		if (m != NULL) {
			BRIX_RETURN_REDIR(ctx, c,
							  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
							  "OPEN", clean_path, "redirect",
							  (const char *) m->host.data, m->port);
		}
	}

	/* Resolve the path.
	 * For read opens the file must already exist (realpath check).
	 * For write opens with kXR_mkpath the parent dirs may not exist yet,
	 * so use brix_resolve_path_noexist; otherwise use the write resolver
	 * which requires the parent to exist. */
	if (!is_write) {
		if (conf->cache) {
			return brix_open_cached_read(ctx, c, conf, clean_path,
			                               options, mode_bits);
		}

		/* Read opens: build the absolute path, then authorize BEFORE probing
		 * existence.  A denied principal must never distinguish kXR_NotFound
		 * (absent) from kXR_NotAuthorized (present-but-denied) — a namespace
		 * existence oracle — and must not be forwarded upstream on a miss, which
		 * would leak existence just the same.  The gate keys off (identity,
		 * logical path) and has no dependency on the probe result, so running it
		 * first is behavior-identical for every authorized principal (mirrors the
		 * statx.c / locate.c ordering). */
		brix_beneath_full_path(conf->common.root_canon, clean_path,
		                          full_path, sizeof(full_path));

		if (brix_auth_gate(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
							  clean_path, full_path, conf,
							  BRIX_AUTH_READ, 0) != NGX_OK) {
			return ctx->write_rc;
		}

		{
			int _exists, _is_dir;

			_exists = brix_open_read_probe(conf, c->log, clean_path,
			                                 full_path, &_is_dir);
			if (!_exists) {
				if (conf->upstream_host.len > 0) {
					brix_log_access(ctx, c, "OPEN", clean_path,
									  "upstream", 1, 0, NULL, 0);
					BRIX_OP_OK(ctx, BRIX_OP_OPEN_RD);
					return brix_upstream_start(ctx, c, conf);
				}
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
								  clean_path, "rd", kXR_NotFound,
								  "file not found");
			}
			if (_is_dir) {
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
								  clean_path, "rd", kXR_isDirectory,
								  "is a directory");
			}
		}

		/* Phase-57 W2: ZIP member access.  The archive existence check and READ
		 * auth above gate access to the member; serve the requested member of the
		 * archive instead of the whole file.  (Opt-in via brix_zip_access; the
		 * read-through cache path returned earlier, so this is the direct-serve
		 * case.) */
		if (conf->zip_access) {
			char zipmember[PATH_MAX];
			int  zr = open_extract_zip_member(ctx, zipmember,
			                                  sizeof(zipmember));
			if (zr < 0) {
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
				                  clean_path, "zip", kXR_ArgInvalid,
				                  "invalid zip member name");
			}
			if (zr > 0) {
				return brix_zip_open_member(ctx, c, conf, clean_path,
				                              full_path, zipmember, options);
			}
		}

		/* Phase 35: residency gate. A nearline file (on the backend, not on
		 * disk) is recalled and the client stalled with kXR_wait-and-retry.
		 * Runs AFTER auth so an unauthorized caller never learns residency. */
		if (conf->frm.enable && brix_stage_registry_singleton() != NULL) {
			brix_vfs_ctx_t      _rvc;
			brix_sd_residency_t _res;

			/* Residency comes from the backend's model via the VFS seam (sd_frm),
			 * so a tape:// export classifies nearline/offline with no FRM xattr. */
			brix_vfs_ctx_init(&_rvc, c->pool, c->log, BRIX_PROTO_ROOT,
			    conf->common.root_canon, NULL, conf->common.allow_write,
			    0 /* is_tls */, NULL, full_path);

			if (brix_vfs_residency(&_rvc, &_res, NULL) == NGX_OK) {
				if (_res == BRIX_SD_RES_OFFLINE
				    || _res == BRIX_SD_RES_LOST)
				{
					/* A failed/unretrievable recall — do not spin; surface an
					 * error so the client re-prepares or gives up. */
					BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
					                  clean_path, "rd", kXR_FSError,
					                  "file is offline (recall failed)");
				}
				if (_res == BRIX_SD_RES_NEARLINE) {
					brix_stage_request_view_t _v;
					char           _rq[BRIX_STAGE_REQID_LEN];
					ngx_memzero(&_v, sizeof(_v));
					_v.lfn        = full_path;
					_v.requester_dn = (ctx->login.dn[0] != '\0') ? ctx->login.dn : NULL;
					_v.tod_expire = (int64_t) ngx_time()
					              + (int64_t) (conf->frm.stage_ttl / 1000);
					(void) brix_stage_request_add(
					           brix_stage_registry_singleton(),
					           &_v, _rq, sizeof(_rq), c->log);
					/* recall driving (former frm_stage_kick) → engine step */

					/* When async recall is on, park the open with kXR_waitresp
					 * and wake it in place via kXR_attn(asynresp) on completion.
					 * Falls back to the kXR_wait poll model if async is off or
					 * the waiter table is full. */
					if (conf->frm.async_recall
					    && brix_stage_waiter_add(_rq, options,
					                      ctx->recv.cur_streamid, c->fd, c->number,
					                      ngx_pid, conf->frm.stage_ttl) == NGX_OK)
					{
						brix_log_access(ctx, c, "OPEN", clean_path,
						                  "staging-async", 1, 0, NULL, 0);
						(void) brix_send_waitresp(ctx, c);
						ctx->state = XRD_ST_WAITING_FRM;
						ngx_add_timer(c->read, conf->frm.stage_ttl);
						return NGX_AGAIN;
					}

					brix_log_access(ctx, c, "OPEN", clean_path, "staging",
					                  1, kXR_wait, NULL, 0);
					return brix_send_wait(ctx, c, conf->frm.stage_wait);
				}
			}
		}
	} else {
		brix_beneath_full_path(conf->common.root_canon, clean_path,
		                          full_path, sizeof(full_path));

		/* XrdAcc distinguishes creating a NEW file (needs Insert) from
		 * updating an existing one; kXR_new is the create intent. */
		if (brix_auth_gate_op(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
							  clean_path, full_path, conf,
							  BRIX_AUTH_UPDATE, 1,
							  (options & kXR_new) ? BRIX_AOP_CREATE
							                      : BRIX_AOP_UPDATE) != NGX_OK) {
			return ctx->write_rc;
		}

		/* Create the parent directory chain when the client set kXR_mkpath OR
		 * kXR_async — the EXACT condition the reference do_Open uses to add
		 * SFS_O_MKPTH (XrdXrootdXeq.cc:1544: `opts & (kXR_mkpath | kXR_async)`).
		 * xrdcp sends kXR_async (not mkpath) on every upload, so this is what
		 * makes uploads to a missing parent succeed; a create-open with NEITHER
		 * flag that names a missing parent must fail NotFound, matching stock
		 * (verified by raw-wire differential). Confined beneath the export root
		 * by brix_mkdir_recursive_policy. */
		if (options & (kXR_mkpath | kXR_async)) {
			char  parent[PATH_MAX];
			char *slash;
			ngx_cpystrn((u_char *) parent, (u_char *) full_path, sizeof(parent));
			slash = strrchr(parent, '/');
			if (slash && slash > parent) {
				*slash = '\0';
				/* mode 0755 for new directories; propagate group policy */
				brix_mkdir_recursive_policy(parent, 0755, c->log,
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
	if (ctx->pmark.flow == NULL && conf->common.pmark.enable) {
		char        opq[BRIX_MAX_PATH + 1];
		const char *cgi = NULL;
		if (ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0
		    && open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen, opq, sizeof(opq)))
		{
			cgi = opq;
		}
		ctx->pmark.flow = brix_pmark_flow_begin(&conf->common.pmark, c->pool, c,
			is_write,
			ctx->identity ? brix_identity_vo_csv_cstr(ctx->identity) : "",
			ctx->identity ? brix_identity_dn_cstr(ctx->identity) : "",
			clean_path, cgi, c->log);

		/* Arm the periodic "ongoing" firefly echo for this connection's flow
		 * (phase-34), if configured.  Cancelled in brix_on_disconnect. */
		if (ctx->pmark.flow != NULL && conf->common.pmark.echo > 0
		    && !ctx->pmark.echo_ev.timer_set)
		{
			ctx->pmark.echo_ms          = conf->common.pmark.echo;
			ctx->pmark.echo_ev.handler  = brix_pmark_echo_timer;
			ctx->pmark.echo_ev.data     = ctx;
			ctx->pmark.echo_ev.log      = c->log;
			ngx_add_timer(&ctx->pmark.echo_ev, ctx->pmark.echo_ms);
		}
	}

	/* Slow-tier composed-cache MISS (phase-64 SP2): the decorator's inline open
	 * would run the whole-file fill as a blocking wire transfer on the event
	 * loop (and self-connect deadlock when this worker also serves the source).
	 * Park the open in XRD_ST_AIO and fill on the async thread pool instead —
	 * the stream twin of the HTTP plane's http_cache_fill.c. A hit / slice /
	 * all-local stack has needs_offload == 0 and opens inline as before. */
	if (!is_write) {
		brix_sd_instance_t *gsd =
		    brix_vfs_backend_resolve(conf->common.root_canon, c->log);
		const char *gkey =
		    brix_vfs_export_relative_root(full_path, conf->common.root_canon);

		if (gsd != NULL && brix_sd_cache_fill_needs_offload(gsd, gkey)) {
			ngx_int_t grc = brix_cache_open_fill_offload(ctx, c, conf,
			                    clean_path, full_path, gsd, options, mode_bits);
			if (grc != NGX_DECLINED) {
				return grc;   /* parked (async) or a queued-error rc */
			}
			/* NGX_DECLINED: no thread pool — inline open below (may stall). */
		}
	}

	return brix_open_resolved_file(ctx, c, conf, full_path, options,
									 mode_bits, is_write,
									 open_negotiate_compress_codec(ctx, conf,
									                               is_write));
}
