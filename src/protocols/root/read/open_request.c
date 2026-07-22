#include "open.h"
#include "open_internal.h"
#include "protocols/ssi/ssi.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "net/manager/redir_cache.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_request_registry.h"
#include "fs/xfer/stage_waiter.h"
#include "fs/vfs/vfs.h"                   /* brix_vfs_residency (sd_frm seam) */
#include "fs/path/reserved_names.h"       /* brix_is_internal_name — hide sidecars */
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

/* open_extract_opaque(), the opaque CGI negotiation helpers
 * (open_negotiate_compress_codec / open_extract_zip_member, open_request_opaque.c),
 * the path-resolution phases (brix_open_read_resolve / brix_open_write_resolve,
 * open_request_resolve.c), and the open_tpc.c / open_manager.c phase entry points
 * are all declared in open_internal.h. */

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
 * Server-mode rejection for an open: a write to a read-only server (unless in
 * manager mode, which forwards writes), or any open on a metadata-only server
 * without a manager_map.  NGX_DECLINED to proceed; otherwise the response rc.
 */
static ngx_int_t
brix_open_mode_guard(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, const char *md)
{
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
						  md,
						  0, kXR_Unsupported, "metadata-only server", 0);
		return brix_send_error(ctx, c, kXR_Unsupported,
								 "open not available on metadata-only server");
	}

	return NGX_DECLINED;
}

/*
 * Pre-resolution guards + path extraction: server-mode rejection (via
 * brix_open_mode_guard), missing/invalid payload, ".." rejection, depth cap, and
 * the internal-name hide.  Fills clean_path (the CGI-stripped wire path).
 * NGX_DECLINED to proceed; otherwise the response rc.
 */
static ngx_int_t
brix_open_precheck(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, char *clean_path)
{
	int         op = is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD;
	const char *md = is_write ? "wr" : "rd";
	ngx_int_t   rc;

	rc = brix_open_mode_guard(ctx, c, conf, is_write, md);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		BRIX_RETURN_ERR(ctx, c,
						  op,
						  "OPEN", "-", md,
						  kXR_ArgMissing, "no path given");
	}

	/* D-2 byte-hygiene: reject an opaque carrying a control / non-ASCII /
	 * shell-metacharacter byte before any handler (TPC src/dst URL, delegated-
	 * token mode, compression, ZIP member) parses, logs, or forwards it. A
	 * well-formed opaque percent-encodes anything outside the unreserved/
	 * structural set, so this is a zero-false-positive gate at the parse edge. */
	{
		char          opq_raw[BRIX_MAX_PATH + 1];
		unsigned char bad_byte;

		if (open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen,
								 opq_raw, sizeof(opq_raw))) {
			if (brix_opaque_illegal_byte(opq_raw, &bad_byte)) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
							  "brix: rejecting kXR_open — illegal opaque byte 0x%02xd",
							  (int) bad_byte);
				BRIX_RETURN_ERR(ctx, c,
								  op,
								  "OPEN", "-", md,
								  kXR_ArgInvalid, "illegal byte in opaque");
			}

			/* D-2 strict half (opt-in): once the bytes are clean, enforce the
			 * schema — oss.asize must be an unsigned integer and every key must
			 * fall in a recognized namespace. Off by default (stock accepts
			 * both unchecked); on, a typed-wrong or unknown key is refused with
			 * kXR_ArgInvalid, named in the log, before any handler parses it. */
			if (conf->opaque_strict) {
				char badkey[64];
				int  verdict = brix_opaque_schema_check(opq_raw, badkey,
														sizeof(badkey));

				if (verdict != BRIX_OPAQUE_SCHEMA_OK) {
					ngx_log_error(NGX_LOG_INFO, c->log, 0,
								  "brix: rejecting kXR_open — opaque schema %s for key \"%s\"",
								  verdict == BRIX_OPAQUE_SCHEMA_BAD_TYPE
									  ? "type mismatch" : "unknown key",
								  badkey);
					BRIX_RETURN_ERR(ctx, c,
									  op,
									  "OPEN", "-", md,
									  kXR_ArgInvalid,
									  verdict == BRIX_OPAQUE_SCHEMA_BAD_TYPE
										  ? "opaque parameter type mismatch"
										  : "unknown opaque parameter");
				}
			}
		}
	}

	/* Strip XRootD CGI query string ("?oss.asize=N" etc.) from the path.
	 * xrdcp and other clients append these for metadata; they are not part
	 * of the filesystem path. */
	if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
							 clean_path, PATH_MAX, 1)) {
		BRIX_RETURN_ERR(ctx, c,
						  op,
						  "OPEN", "-", md,
						  kXR_ArgInvalid, "invalid path payload");
	}

	/* Reject any ".." component (the reference does not normalize ".."); the
	 * open resolves through the kernel RESOLVE_BENEATH which would otherwise
	 * collapse an in-tree "..".  Same op id selection as the surrounding errors. */
	if (brix_reject_dotdot_path(ctx, c,
			op,
			"OPEN", clean_path)) {
		return ctx->write_rc;
	}

	if (brix_count_path_depth(clean_path) != NGX_OK) {
		BRIX_RETURN_ERR(ctx, c,
						  op,
						  "OPEN", clean_path, md,
						  kXR_ArgInvalid, "path exceeds maximum depth");
	}

	/* Internal metadata/staging artifacts are invisible: a client may neither
	 * read one nor create one.  Answer as absent so an internal name is
	 * indistinguishable from a genuinely missing path. */
	if (brix_is_internal_name(clean_path)) {
		BRIX_RETURN_ERR(ctx, c,
						  op,
						  "OPEN", clean_path, md,
						  kXR_NotFound, "file not found");
	}

	return NGX_DECLINED;
}

/*
 * SciTags packet marking (phase-34): begin a flow on the FIRST local data open
 * of this connection and arm the periodic "ongoing" firefly echo.  Fail-open: a
 * NULL flow just means the connection is not marked.  Redirect/manager/cached
 * paths returned earlier and are intentionally not marked here.
 */
static void
brix_open_begin_pmark(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int is_write, const char *clean_path)
{
	char        opq[BRIX_MAX_PATH + 1];
	const char *cgi = NULL;

	if (ctx->pmark.flow != NULL || !conf->common.pmark.enable) {
		return;
	}

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

/*
 * Slow-tier composed-cache MISS (phase-64 SP2): the decorator's inline open would
 * run the whole-file fill as a blocking wire transfer on the event loop (and
 * self-connect deadlock when this worker also serves the source).  Park the open
 * in XRD_ST_AIO and fill on the async thread pool instead.  A hit / slice /
 * all-local stack has needs_offload == 0 and opens inline (NGX_DECLINED).
 */
static ngx_int_t
brix_open_try_cache_offload(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options, uint16_t mode_bits)
{
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
	return NGX_DECLINED;
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
	ngx_int_t          rc;

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

	/* TPC (third-party-copy) context — destination pull / source rendezvous —
	 * must act before normal path resolution. */
	rc = brix_open_handle_tpc(ctx, c, conf, is_write, options, mode_bits);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	/* Mode/metadata guards + path extraction/validation (fills clean_path). */
	rc = brix_open_precheck(ctx, c, conf, is_write, clean_path);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	/* Manager-mode redirect (dynamic CMS/registry + static manager_map). */
	rc = brix_open_manager_redirect(ctx, c, conf, is_write, clean_path);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	/* Resolve to the canonical filesystem target and run the auth gate (the sole
	 * checkpoint) before any existence probe.  Fills full_path. */
	if (!is_write) {
		rc = brix_open_read_resolve(ctx, c, conf, clean_path, full_path,
		                              options, mode_bits);
	} else {
		rc = brix_open_write_resolve(ctx, c, conf, clean_path, full_path,
		                               options);
	}
	if (rc != NGX_DECLINED) {
		return rc;
	}

	/* SciTags packet marking begins on the first local data open. */
	brix_open_begin_pmark(ctx, c, conf, is_write, clean_path);

	/* Slow-tier composed-cache MISS: offload the whole-file fill to the pool. */
	if (!is_write) {
		rc = brix_open_try_cache_offload(ctx, c, conf, clean_path, full_path,
		                                   options, mode_bits);
		if (rc != NGX_DECLINED) {
			return rc;
		}
	}

	brix_open_request_t oreq = {
		.resolved  = full_path,
		.options   = options,
		.mode_bits = mode_bits,
		.is_write  = is_write,
		.codec     = open_negotiate_compress_codec(ctx, conf, is_write),
	};
	return brix_open_resolved_file(ctx, c, conf, &oreq);
}
