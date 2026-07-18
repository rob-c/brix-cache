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

/* open_extract_opaque() + the open_tpc.c / open_manager.c phase entry points are
 * declared in open_internal.h. */

/*
 * Locate a CGI opaque key on a token boundary (start / '&' / '?') and return its
 * value span [*val, *val+*vlen).  Shared by the compression and ZIP-member
 * negotiations, which both scan the same path?opaque carrier.  Returns 1 when the
 * key is present on a boundary, 0 otherwise.
 */
static int
open_cgi_find_value(const char *opaque, const char *key,
    const char **val, size_t *vlen)
{
    const char *p = strstr(opaque, key);
    const char *v, *end;

    if (p == NULL) {
        return 0;
    }
    if (p != opaque && p[-1] != '&' && p[-1] != '?') {
        return 0;   /* not on a key boundary */
    }

    v = p + strlen(key);
    end = v;
    while (*end != '\0' && *end != '&') {
        end++;
    }
    *val = v;
    *vlen = (size_t) (end - v);
    return 1;
}

/* Layer 3 — read-open existence + directory probe.
 *
 * A driver-backed export (block-striped / object store) keeps its namespace in
 * the driver: the physical tree under conf->rootfd holds no data files, so a
 * POSIX confined stat would spuriously report ENOENT for a file that the driver
 * actually has. Probe the driver on the export-root-relative key when a driver
 * is bound; otherwise fall back to the confined fd-relative POSIX stat (the
 * unchanged default-export path). Returns 1 if the path exists (and sets
 * *is_dir accordingly), 0 if absent.
 *
 * WHY (phase-70) `ctx`/`pool`: on a REMOTE driver-backed export (root://
 * origin) the driver stat is not a local syscall — it opens the origin, which
 * demands authentication. Without forwarding the session's delegated credential
 * (bearer JWT / full proxy) this existence probe fails with "backend has NO
 * credential" and reports the file absent, turning a legitimate authorized read
 * into a spurious kXR_NotFound (the data open at brix_open_dispatch_open DOES
 * forward the credential, so writes — which skip this read probe — succeeded).
 * The probe binds the same deleg the data open uses and stats through
 * brix_sd_stat_maybe_cred so the origin sees the inbound user. A NULL ctx/pool
 * keeps the legacy service-credential behaviour (no passthrough configured). */
static int
brix_open_read_probe(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    ngx_connection_t *c, const char *clean_path, const char *full_path,
    int *is_dir)
{
    ngx_log_t          *log = c->log;
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

        /* Resolve the session's forwarded backend credential (deleg passthrough
         * bearer / full proxy, or a per-user credential-dir selection) onto a
         * transient VFS ctx and present it to the driver stat — the same
         * credential the data-plane open forwards (open_resolved_file.c) — so a
         * remote origin authorises this existence probe AS the inbound user. */
        brix_vfs_ctx_t   pvctx;
        brix_sd_ucred_t  ustore;
        brix_sd_cred_t   ucred;
        int              use_cred = 0;
        int              cerr = 0;

        ngx_memzero(&ucred, sizeof(ucred));
        brix_vfs_ctx_init(&pvctx, c->pool, log, BRIX_PROTO_ROOT,
            conf->common.root_canon, NULL, conf->common.allow_write,
            0 /* is_tls */, ctx != NULL ? ctx->identity : NULL, full_path);
        brix_vfs_ctx_bind_backend_cred(&pvctx,
            &conf->common.storage_credential_dir,
            conf->common.storage_credential_fallback);
        if (ctx != NULL) {
            brix_root_vfs_bind_deleg(ctx, conf, &pvctx);
        }
        if (brix_vfs_backend_cred(&pvctx, &ustore, &ucred, &use_cred, &cerr)
            != NGX_OK)
        {
            /* A deny-mode credential gate refused this principal — treat as a
             * miss (never distinguish kXR_NotFound from kXR_NotAuthorized; the
             * read auth gate above already authorised the logical path). */
            return 0;
        }

        if (brix_sd_stat_maybe_cred(sd, key, &sst,
                use_cred ? &ucred : NULL) != NGX_OK) {
            brix_sd_ucred_wipe(&ustore);   /* secret consumed; erase (A-4/T4) */
            return 0;
        }
        brix_sd_ucred_wipe(&ustore);       /* secret consumed; erase (A-4/T4) */
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
	const char                *val;
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

	if (!open_cgi_find_value(opaque, "xrootd.compress=", &val, &vlen)
	    || vlen == 0) {
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
/* Intra-archive traversal / absolute-path guard for a ZIP member name: reject a
 * leading '/', a bare "..", a leading "../", any embedded "/../", or a trailing
 * "/..".  Returns 1 (unsafe → caller rejects with kXR_ArgInvalid), else 0. */
static int
open_zip_member_path_unsafe(const char *out, size_t vlen)
{
	if (out[0] == '/') {
		return 1;
	}
	if (ngx_strcmp(out, "..") == 0) {
		return 1;
	}
	if (vlen >= 3 && out[0] == '.' && out[1] == '.' && out[2] == '/') {
		return 1;   /* leading "../" */
	}
	if (strstr(out, "/../") != NULL) {
		return 1;
	}
	if (vlen >= 3 && ngx_strcmp(out + vlen - 3, "/..") == 0) {
		return 1;   /* trailing "/.." */
	}
	return 0;
}

static int
open_extract_zip_member(brix_ctx_t *ctx, char *out, size_t outsz)
{
	char        opaque[BRIX_MAX_PATH + 1];
	const char *val;
	size_t      vlen;

	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
		return 0;
	}
	if (!open_extract_opaque(ctx->recv.payload, ctx->recv.cur_dlen, opaque, sizeof(opaque))) {
		return 0;
	}

	if (!open_cgi_find_value(opaque, "xrdcl.unzip=", &val, &vlen)) {
		return 0;   /* key absent — open the whole archive normally */
	}

	/* From here the "xrdcl.unzip=" key IS present: a bad value is an explicit
	 * error (return -1, caller rejects with kXR_ArgInvalid), NOT a fall-through
	 * to opening the whole archive — so a traversal attempt is surfaced, not
	 * silently ignored. */
	if (vlen == 0 || vlen >= outsz) {
		return -1;
	}

	ngx_memcpy(out, val, vlen);
	out[vlen] = '\0';

	if (open_zip_member_path_unsafe(out, vlen)) {
		return -1;
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
 * Phase 35 residency gate for a read open of a nearline/offline file (backend
 * model via the VFS seam, so a tape:// export classifies with no FRM xattr).
 * Runs AFTER auth so an unauthorized caller never learns residency.  NEARLINE
 * recalls and parks the client (kXR_wait, or kXR_waitresp under async_recall);
 * OFFLINE/LOST errors out; NGX_DECLINED when resident or FRM disabled.
 */
static ngx_int_t
brix_open_residency_gate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options)
{
	brix_vfs_ctx_t      _rvc;
	brix_sd_residency_t _res;

	if (!(conf->frm.enable && brix_stage_registry_singleton() != NULL)) {
		return NGX_DECLINED;
	}

	brix_vfs_ctx_init(&_rvc, c->pool, c->log, BRIX_PROTO_ROOT,
	    conf->common.root_canon, NULL, conf->common.allow_write,
	    0 /* is_tls */, NULL, full_path);

	if (brix_vfs_residency(&_rvc, &_res, NULL) != NGX_OK) {
		return NGX_DECLINED;
	}

	if (_res == BRIX_SD_RES_OFFLINE || _res == BRIX_SD_RES_LOST) {
		/* A failed/unretrievable recall — do not spin; surface an error so the
		 * client re-prepares or gives up. */
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

		/* When async recall is on, park the open with kXR_waitresp and wake it in
		 * place via kXR_attn(asynresp) on completion.  Falls back to the kXR_wait
		 * poll model if async is off or the waiter table is full. */
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

	return NGX_DECLINED;
}

/*
 * Read-open resolution: cache-aware read returns directly; otherwise build the
 * absolute path, run the auth gate BEFORE probing existence (no namespace
 * existence oracle), reject a missing/dir target (or forward upstream), serve a
 * ZIP member, and apply the residency gate.  Fills full_path.  NGX_DECLINED to
 * proceed to brix_open_resolved_file; otherwise the response rc.
 */
static ngx_int_t
brix_open_read_resolve(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options, uint16_t mode_bits)
{
	if (conf->cache) {
		return brix_open_cached_read(ctx, c, conf, clean_path,
		                               options, mode_bits);
	}

	/* Read opens: build the absolute path, then authorize BEFORE probing
	 * existence.  A denied principal must never distinguish kXR_NotFound from
	 * kXR_NotAuthorized (a namespace existence oracle) and must not be forwarded
	 * upstream on a miss.  The gate keys off (identity, logical path) with no
	 * dependency on the probe, so running it first is behavior-identical for
	 * every authorized principal (mirrors statx.c / locate.c ordering). */
	brix_beneath_full_path(conf->common.root_canon, clean_path,
	                          full_path, PATH_MAX);

	if (brix_auth_gate(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
						  clean_path, full_path, conf,
						  BRIX_AUTH_READ, 0) != NGX_OK) {
		return ctx->write_rc;
	}

	{
		int _exists, _is_dir;

		_exists = brix_open_read_probe(ctx, conf, c, clean_path,
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

	/* Phase-57 W2: ZIP member access.  The archive existence check and READ auth
	 * above gate access to the member; serve the requested member instead of the
	 * whole file.  (The read-through cache path returned earlier, so this is the
	 * direct-serve case.) */
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

	return brix_open_residency_gate(ctx, c, conf, clean_path, full_path,
	                                  options);
}

/*
 * Write-open resolution: build the absolute path, run the create/update auth
 * gate, and (kXR_mkpath | kXR_async) make the parent directory chain confined
 * beneath the export root.  Fills full_path.  NGX_DECLINED to proceed.
 */
static ngx_int_t
brix_open_write_resolve(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    char *full_path, uint16_t options)
{
	brix_beneath_full_path(conf->common.root_canon, clean_path,
	                          full_path, PATH_MAX);

	/* XrdAcc distinguishes creating a NEW file (needs Insert) from updating an
	 * existing one; kXR_new is the create intent. */
	if (brix_auth_gate_op(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
						  clean_path, full_path, conf,
						  BRIX_AUTH_UPDATE, 1,
						  (options & kXR_new) ? BRIX_AOP_CREATE
						                      : BRIX_AOP_UPDATE) != NGX_OK) {
		return ctx->write_rc;
	}

	/* Create the parent directory chain when the client set kXR_mkpath OR
	 * kXR_async — the EXACT condition the reference do_Open uses to add
	 * SFS_O_MKPTH.  xrdcp sends kXR_async on every upload, so this is what makes
	 * uploads to a missing parent succeed; a create-open with NEITHER flag that
	 * names a missing parent must fail NotFound, matching stock. */
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
