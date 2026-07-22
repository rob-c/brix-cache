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

        /* With a forwarded user cred, dispatch on the leaf instance so
         * brix_sd_stat_maybe_cred finds the leaf driver's stat_cred slot
         * (mirrors vfs_stat.c): the stage/cache decorators relay stat through
         * the PLAIN slot only, so probing the TOP instance with a resolved
         * user cred under fallback=deny hits the forwarder's
         * cred-would-be-dropped refusal (EACCES, no wire I/O) and a
         * stage-composed https/xroot origin spuriously reported every
         * existing file as absent → kXR_NotFound on read-open. Without a
         * cred the TOP instance must answer: a cache decorator's stat serves
         * warm hits from cinfo even when the origin object is gone. */
        if (brix_sd_stat_maybe_cred(use_cred ? brix_vfs_ns_leaf(sd) : sd,
                key, &sst, use_cred ? &ucred : NULL) != NGX_OK) {
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
ngx_int_t
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
ngx_int_t
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
