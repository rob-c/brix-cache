#include "config.h"
#include "../manager/redir_cache.h"
#include "../frm/waiter.h"
#include "../impersonate/lifecycle.h"
#include "../aio/uring.h"
#include "../compat/lifecycle_timing.h"

/* Human-readable name for an XROOTD_AUTH_* enum value (for the startup log). */
static const char *
xrootd_auth_mode_name(ngx_uint_t auth)
{
    switch (auth) {
    case XROOTD_AUTH_NONE:  return "none (anonymous)";
    case XROOTD_AUTH_GSI:   return "GSI/x509";
    case XROOTD_AUTH_TOKEN: return "bearer token";
    case XROOTD_AUTH_BOTH:  return "GSI or token";
    case XROOTD_AUTH_SSS:   return "shared-secret (sss)";
    case XROOTD_AUTH_UNIX:  return "unix (self-asserted)";
    case XROOTD_AUTH_KRB5:  return "Kerberos 5";
    case XROOTD_AUTH_HOST:  return "host allowlist";
    case XROOTD_AUTH_PWD:   return "password (pwd)";
    default:                return "unknown";
    }
}

/* Log a one-time NOTICE summary of the effective server config (auth, roots,
 * ports, enabled features). */
static void
xrootd_log_startup_summary(ngx_log_t *log, ngx_stream_xrootd_srv_conf_t *xcf)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "xrootd: root:// endpoint ready — export \"%V\" (%s), auth: %s",
        &xcf->common.root,
        xcf->common.allow_write ? "read-write" : "read-only",
        xrootd_auth_mode_name(xcf->auth));

    if (xcf->crl.len > 0) {
        if (xcf->crl_reload > 0) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd:   revocation: CRL \"%V\", reloaded every %T s",
                &xcf->crl, (time_t) xcf->crl_reload);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd:   revocation: CRL \"%V\", loaded once at startup "
                "(set xrootd_crl_reload for periodic refresh)",
                &xcf->crl);
        }
    }

    if (xcf->jwks_key_count > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   token validation: %d JWKS key(s) loaded",
            xcf->jwks_key_count);
    }

    if (xcf->manager_mode) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   mode: cluster manager — redirects clients to data "
            "servers (does not serve local files)");
    }
    if (xcf->proxy_enable) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   mode: proxy — forwards client traffic to a backend");
    }
    if (xcf->cache) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   mode: read-through cache in front of an origin");
    }

    /* Valid-but-noteworthy settings a first-time admin should see explicitly. */
    if (xcf->auth == XROOTD_AUTH_NONE) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   NOTE: no authentication required — this endpoint is "
            "OPEN to anonymous clients (set xrootd_auth to require "
            "credentials)");
    }
    if ((xcf->auth == XROOTD_AUTH_GSI || xcf->auth == XROOTD_AUTH_BOTH)
        && xcf->crl.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd:   NOTE: GSI auth is enabled but no CRL is configured — "
            "REVOKED certificates will be ACCEPTED (set xrootd_crl to a CRL "
            "file/dir, e.g. /etc/grid-security/certificates)");
    }
    if (xcf->common.allow_write) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd:   NOTE: write access is enabled — authorized clients can "
            "create, modify and delete files under the export root");
    }
}

/* Stream-module postconfiguration hook: validate config, build the runtime
 * objects (TLS/PKI/SHM/CMS), wire handlers, and log the startup summary.
 * Returns NGX_OK / NGX_ERROR. */
ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    xrootd_phase_timer_t           pt;

    /* Master-side config-build cost breakdown (one NOTICE line at the end). */
    xrootd_phase_timer_start(&pt);

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    /*
     * Attempt to load libvomsapi.so.1 via dlopen. If the library is not
     * present we continue; config validation below rejects xrootd_require_vo
     * directives when VOMS is unavailable.
     */
    (void) xrootd_voms_init(cf->log);

    /*
     * First pass over enabled servers initializes local runtime resources and
     * auth state after inherited values have been merged.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->common.enable) {
            continue;
        }

        if (xrootd_config_prepare_server(cf, xcf) != NGX_OK
            || xrootd_configure_gsi(cf, xcf) != NGX_OK
            || xrootd_configure_tls(cf, xcf) != NGX_OK
            || xrootd_configure_token_auth(cf, xcf) != NGX_OK
            || xrootd_configure_sss_auth(cf, xcf) != NGX_OK
            || xrootd_configure_krb5_auth(cf, xcf) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    xrootd_phase_mark(&pt, "prepare");   /* server prep + GSI/TLS/token/sss/krb5 */

    /*
     * Policy rules depend on finalized roots and on auth/VOMS availability, so
     * keep them after the auth setup pass.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->common.enable) {
            continue;
        }

        if (xrootd_config_finalize_policy(cf, xcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    xrootd_phase_mark(&pt, "policy");

    if (xrootd_configure_metrics(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    {
        /* Session registry is a single zone shared by all blocks; size it to
         * the largest xrootd_session_slots requested by any enabled server. */
        ngx_uint_t session_slots = 0;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (xcf->common.enable && xcf->session_slots > session_slots) {
                session_slots = xcf->session_slots;
            }
        }

        if (xrootd_configure_session_registry(cf, session_slots) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    {
        /*
         * The server registry is a single shared-memory zone.  Walk all enabled
         * server blocks to find the largest configured capacity so operators can
         * set xrootd_registry_slots once on whichever block they prefer.
         * All enabled blocks have registry_slots >= 128 after merge.
         */
        ngx_uint_t registry_slots = 0;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (xcf->common.enable && xcf->registry_slots > registry_slots) {
                registry_slots = xcf->registry_slots;
            }
        }

        if (xrootd_srv_configure_registry(cf, registry_slots ? registry_slots : 128) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Redirect-collapse cache: init if any server has collapse_redir on.
         * Capacity is the max xrootd_redir_cache_slots across enabled blocks. */
        {
            ngx_uint_t has_collapse = 0;
            ngx_uint_t redir_slots  = 0;
            for (i = 0; i < cmcf->servers.nelts; i++) {
                xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                           ngx_stream_xrootd_module);
                if (xcf->common.enable && xcf->collapse_redir) {
                    has_collapse = 1;
                    if (xcf->redir_cache_slots != NGX_CONF_UNSET_UINT
                        && xcf->redir_cache_slots > redir_slots)
                    {
                        redir_slots = xcf->redir_cache_slots;
                    }
                }
            }
            if (has_collapse) {
                if (xrootd_redir_cache_configure(cf, redir_slots) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (xrootd_pending_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_tpc_key_configure_registry(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_tpc_registry_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }
    xrootd_phase_mark(&pt, "registries");   /* metrics/dashboard/session/srv/tpc SHM */

    /*
     * Phase 35: bind the FRM durable stage queue + its SHM hot-index zone. A
     * single queue is shared by every frm-enabled server block (Phase 0). The
     * index zone-init callback reconciles file → index in the master before
     * fork; workers open their own fds in init_process.
     */
    {
        ngx_str_t   frm_path = ngx_null_string;
        ngx_uint_t  frm_max  = 64;
        ngx_uint_t  frm_peak = 0;
        ngx_uint_t  frm_per_source = 0;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                      ngx_stream_xrootd_module);
            if (xcf->common.enable && xcf->frm.enable
                && xcf->frm.queue_path.len)
            {
                /* phase-46 W2b: FRM is configured on this process — let the
                 * shared residency probe do its stat+getxattr (it short-circuits
                 * to ONLINE when this is never called). */
                frm_mark_configured((const char *) xcf->frm.control_dir.data);
                frm_path = xcf->frm.queue_path;
                frm_max  = xcf->frm.max_inflight;
                if (xcf->frm.max_inflight > frm_peak) {
                    frm_peak = xcf->frm.max_inflight;
                }
                if (xcf->frm.max_per_source > frm_per_source) {
                    frm_per_source = xcf->frm.max_per_source;
                }
            }
        }

        if (frm_path.len) {
            frm_queue_t *q = frm_queue_get(cf, &frm_path, frm_max,
                                           frm_per_source);
            if (q == NULL) {
                return NGX_ERROR;
            }
            /* Index capacity: several× max_inflight so terminal (ONLINE/FAILED)
             * records linger for QPrep polling before the reaper expires them. */
            if (frm_index_configure(cf, &frm_path, frm_peak * 4 + 64) != NGX_OK) {
                return NGX_ERROR;
            }
            /* Phase 3: async-recall waiter table (clients parked on kXR_waitresp).
             * Sized to a couple× the in-flight bound; harmless when async is off. */
            if (frm_waiter_configure(cf, frm_peak * 2 + 64) != NGX_OK) {
                return NGX_ERROR;
            }
            for (i = 0; i < cmcf->servers.nelts; i++) {
                xcf = ngx_stream_conf_get_module_srv_conf(
                          cscfp[i], ngx_stream_xrootd_module);
                if (xcf->common.enable && xcf->frm.enable) {
                    xcf->frm.queue = q;
                }
            }
        }
    }

    xrootd_phase_mark(&pt, "frm");

    if (xrootd_configure_thread_pools(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Phase 44: io_uring fail-fast.  `xrootd_io_uring on` is a hard requirement —
     * if it cannot be satisfied (not compiled in, or the runtime probe fails on
     * this host) refuse to start so the operator is not silently downgraded.
     * The runtime probe is consulted here (per-process, seccomp-accurate), not
     * at parse time.  `off`/`auto` always pass.
     */
    if (xrootd_uring_validate_conf(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#if (XROOTD_HAVE_LIBURING)
    /*
     * Phase 44 SB-W5b: register the cross-worker kill-switch SHM zone when any
     * enabled block wants io_uring (on/auto), and record whether the no-reload
     * admin endpoint was enabled.  Skipped entirely in a stub build.
     */
    {
        ngx_uint_t want_uring = 0, admin_on = 0;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                      ngx_stream_xrootd_module);
            if (!xcf->common.enable
                || xcf->io_uring == XROOTD_IO_URING_OFF)
            {
                continue;
            }
            want_uring = 1;
            if (xcf->io_uring_admin == 1) {
                admin_on = 1;
            }
        }

        if (want_uring) {
            if (xrootd_uring_killswitch_configure(cf) != NGX_OK) {
                return NGX_ERROR;
            }
            xrootd_uring_admin_set_enabled(admin_on);
        }
    }
#endif

    /*
     * Phase 40: validate the impersonation mode and, for `map`, derive the broker
     * confinement root from the first enabled data server's export root when the
     * admin did not set xrootd_impersonation_export explicitly.  No-op (returns
     * NGX_OK immediately) unless an xrootd_impersonation* directive was used.
     */
    {
        const char *derived_root = NULL;
        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                      ngx_stream_xrootd_module);
            if (xcf->common.enable && xcf->common.root_canon[0] != '\0') {
                derived_root = xcf->common.root_canon;
                break;
            }
        }
        if (xrootd_imp_validate(cf, derived_root) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /*
     * Everything above succeeded, so the configuration is valid. Print a
     * friendly per-endpoint summary (visible in `nginx -t` output and at
     * startup) so a first-time admin can confirm what each root:// block
     * actually serves and spot risky-but-valid settings immediately.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                  ngx_stream_xrootd_module);
        if (xcf->common.enable) {
            xrootd_log_startup_summary(cf->log, xcf);
        }
    }

    xrootd_phase_mark(&pt, "pools_uring");
    xrootd_phase_timer_log(&pt, cf->log, "xrootd postconfig");

    return NGX_OK;
}
