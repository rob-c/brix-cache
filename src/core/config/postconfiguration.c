#include "config.h"
#include "net/manager/redir_cache.h"
#include "fs/xfer/stage_waiter.h"
#include "auth/impersonate/lifecycle.h"
#include "core/aio/uring.h"
#include "core/compat/lifecycle_timing.h"

/* Human-readable name for an BRIX_AUTH_* enum value (for the startup log). */
static const char *
brix_auth_mode_name(ngx_uint_t auth)
{
    switch (auth) {
    case BRIX_AUTH_NONE:  return "none (anonymous)";
    case BRIX_AUTH_GSI:   return "GSI/x509";
    case BRIX_AUTH_TOKEN: return "bearer token";
    case BRIX_AUTH_BOTH:  return "GSI or token";
    case BRIX_AUTH_SSS:   return "shared-secret (sss)";
    case BRIX_AUTH_UNIX:  return "unix (self-asserted)";
    case BRIX_AUTH_KRB5:  return "Kerberos 5";
    case BRIX_AUTH_HOST:  return "host allowlist";
    case BRIX_AUTH_PWD:   return "password (pwd)";
    default:                return "unknown";
    }
}

/* Log a one-time NOTICE summary of the effective server config (auth, roots,
 * ports, enabled features). */
static void
brix_log_startup_summary(ngx_log_t *log, ngx_stream_brix_srv_conf_t *xcf)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "brix: root:// endpoint ready — export \"%V\" (%s), auth: %s",
        &xcf->common.root,
        xcf->common.allow_write ? "read-write" : "read-only",
        brix_auth_mode_name(xcf->auth));

    if (xcf->crl.len > 0) {
        if (xcf->crl_reload > 0) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix:   revocation: CRL \"%V\", reloaded every %T s",
                &xcf->crl, (time_t) xcf->crl_reload);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix:   revocation: CRL \"%V\", loaded once at startup "
                "(set brix_crl_reload for periodic refresh)",
                &xcf->crl);
        }
    }

    if (xcf->jwks_key_count > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   token validation: %d JWKS key(s) loaded",
            xcf->jwks_key_count);
    }

    if (xcf->manager_mode) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   mode: cluster manager — redirects clients to data "
            "servers (does not serve local files)");
    }
    if (xcf->proxy.enable) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   mode: proxy — forwards client traffic to a backend");
    }
    if (xcf->cache) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   mode: read-through cache in front of an origin");
    }

    /* Valid-but-noteworthy settings a first-time admin should see explicitly. */
    if (xcf->auth == BRIX_AUTH_NONE) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   NOTE: no authentication required — this endpoint is "
            "OPEN to anonymous clients (set brix_auth to require "
            "credentials)");
    }
    if ((xcf->auth == BRIX_AUTH_GSI || xcf->auth == BRIX_AUTH_BOTH)
        && xcf->crl.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix:   NOTE: GSI auth is enabled but no CRL is configured — "
            "REVOKED certificates will be ACCEPTED (set brix_crl to a CRL "
            "file/dir, e.g. /etc/grid-security/certificates)");
    }
    if (xcf->common.allow_write) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix:   NOTE: write access is enabled — authorized clients can "
            "create, modify and delete files under the export root");
    }
}

/* Per-server srv_conf accessor for the postconf walks below (shared shape:
 * every concern helper scans all server blocks and looks at enabled ones). */
static ngx_stream_brix_srv_conf_t *
postconf_srv_conf(ngx_stream_core_srv_conf_t **cscfp, ngx_uint_t i)
{
    return ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                               ngx_stream_brix_module);
}

/*
 * First pass over enabled servers initializes local runtime resources and
 * auth state after inherited values have been merged.
 */
static ngx_int_t
postconf_prepare_servers(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);

        if (!xcf->common.enable) {
            continue;
        }

        if (brix_config_prepare_server(cf, xcf) != NGX_OK
            || brix_configure_gsi(cf, xcf) != NGX_OK
            || brix_configure_tls(cf, xcf) != NGX_OK
            || brix_configure_token_auth(cf, xcf) != NGX_OK
            || brix_configure_sss_auth(cf, xcf) != NGX_OK
            || brix_configure_krb5_auth(cf, xcf) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * Policy rules depend on finalized roots and on auth/VOMS availability, so
 * keep them after the auth setup pass.
 */
static ngx_int_t
postconf_finalize_policies(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);

        if (!xcf->common.enable) {
            continue;
        }

        if (brix_config_finalize_policy(cf, xcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Session registry is a single zone shared by all blocks; size it to
 * the largest brix_session_slots requested by any enabled server. */
static ngx_int_t
postconf_session_registry(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    ngx_uint_t                   session_slots = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable && xcf->session_slots > session_slots) {
            session_slots = xcf->session_slots;
        }
    }

    return brix_configure_session_registry(cf, session_slots);
}

/*
 * The server registry is a single shared-memory zone.  Walk all enabled
 * server blocks to find the largest configured capacity so operators can
 * set brix_registry_slots once on whichever block they prefer.
 * All enabled blocks have registry_slots >= 128 after merge.
 */
static ngx_int_t
postconf_server_registry(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    ngx_uint_t                   registry_slots = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable && xcf->registry_slots > registry_slots) {
            registry_slots = xcf->registry_slots;
        }
    }

    return brix_srv_configure_registry(cf,
                                       registry_slots ? registry_slots : 128);
}

/* Redirect-collapse cache: init if any server has collapse_redir on.
 * Capacity is the max brix_redir_cache_slots across enabled blocks. */
static ngx_int_t
postconf_redir_cache(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    ngx_uint_t                   has_collapse = 0;
    ngx_uint_t                   redir_slots  = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable && xcf->caps.collapse_redir) {
            has_collapse = 1;
            if (xcf->redir_cache_slots != NGX_CONF_UNSET_UINT
                && xcf->redir_cache_slots > redir_slots)
            {
                redir_slots = xcf->redir_cache_slots;
            }
        }
    }

    if (!has_collapse) {
        return NGX_OK;
    }

    return brix_redir_cache_configure(cf, redir_slots);
}

/*
 * Phase 35: bind the FRM durable stage queue + its SHM hot-index zone. A
 * single queue is shared by every frm-enabled server block (Phase 0). The
 * index zone-init callback reconciles file → index in the master before
 * fork; workers open their own fds in init_process.
 */
static ngx_int_t
postconf_stage_waiter(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    ngx_uint_t                   frm_peak  = 0;
    int                          any_stage = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable && xcf->frm.enable) {
            any_stage = 1;
            if (xcf->frm.max_inflight > frm_peak) {
                frm_peak = xcf->frm.max_inflight;
            }
        }
    }

    /* Async-recall waiter SHM zone (clients parked on kXR_waitresp), sized to
     * a couple× the in-flight bound; harmless when async is off. The legacy
     * FRM durable queue + SHM index are retired — staging requests live in the
     * composable registry (opened per-worker in init_process). */
    if (any_stage
        && brix_stage_waiter_configure(cf, frm_peak * 2 + 64) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#if (BRIX_HAVE_LIBURING)
/*
 * Phase 44 SB-W5b: register the cross-worker kill-switch SHM zone when any
 * enabled block wants io_uring (on/auto), and record whether the no-reload
 * admin endpoint was enabled.  Skipped entirely in a stub build.
 */
static ngx_int_t
postconf_uring_killswitch(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    ngx_uint_t                   want_uring = 0, admin_on = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (!xcf->common.enable
            || xcf->io_uring == BRIX_IO_URING_OFF)
        {
            continue;
        }
        want_uring = 1;
        if (xcf->io_uring_admin == 1) {
            admin_on = 1;
        }
    }

    if (want_uring) {
        if (brix_uring_killswitch_configure(cf) != NGX_OK) {
            return NGX_ERROR;
        }
        brix_uring_admin_set_enabled(admin_on);
    }

    return NGX_OK;
}
#endif

/*
 * Phase 40: validate the impersonation mode and, for `map`, derive the broker
 * confinement root from the first enabled data server's export root when the
 * admin did not set brix_impersonation_export explicitly.  No-op (returns
 * NGX_OK immediately) unless an brix_impersonation* directive was used.
 */
static ngx_int_t
postconf_impersonation(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;
    const char                  *derived_root = NULL;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable && xcf->common.root_canon[0] != '\0') {
            derived_root = xcf->common.root_canon;
            break;
        }
    }

    return brix_imp_validate(cf, derived_root);
}

/*
 * Everything above succeeded, so the configuration is valid. Print a
 * friendly per-endpoint summary (visible in `nginx -t` output and at
 * startup) so a first-time admin can confirm what each root:// block
 * actually serves and spot risky-but-valid settings immediately.
 */
static void
postconf_log_summaries(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                   i;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = postconf_srv_conf(cscfp, i);
        if (xcf->common.enable) {
            brix_log_startup_summary(cf->log, xcf);
        }
    }
}

/* All single-shot SHM registry zones (session/server/redirect/pending/TPC).
 * Ordering is load-bearing: zone registration order determines SHM layout
 * across reloads, so this mirrors the historical inline sequence exactly. */
static ngx_int_t
postconf_shared_registries(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf,
    ngx_stream_core_srv_conf_t **cscfp)
{
    if (postconf_session_registry(cf, cmcf, cscfp) != NGX_OK
        || postconf_server_registry(cf, cmcf, cscfp) != NGX_OK
        || postconf_redir_cache(cf, cmcf, cscfp) != NGX_OK
        || brix_pending_configure(cf) != NGX_OK
        || brix_tpc_key_configure_registry(cf) != NGX_OK
        || brix_tpc_registry_configure(cf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Stream-module postconfiguration hook: validate config, build the runtime
 * objects (TLS/PKI/SHM/CMS), wire handlers, and log the startup summary.
 * Returns NGX_OK / NGX_ERROR. */
ngx_int_t
ngx_stream_brix_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    brix_phase_timer_t             pt;

    /* Master-side config-build cost breakdown (one NOTICE line at the end). */
    brix_phase_timer_start(&pt);

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    /*
     * Attempt to load libvomsapi.so.1 via dlopen. If the library is not
     * present we continue; config validation below rejects brix_require_vo
     * directives when VOMS is unavailable.
     */
    (void) brix_voms_init(cf->log);

    if (postconf_prepare_servers(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }
    brix_phase_mark(&pt, "prepare");   /* server prep + GSI/TLS/token/sss/krb5 */

    if (postconf_finalize_policies(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }
    brix_phase_mark(&pt, "policy");

    if (brix_configure_metrics(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (postconf_shared_registries(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }
    brix_phase_mark(&pt, "registries");   /* metrics/dashboard/session/srv/tpc SHM */

    if (postconf_stage_waiter(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_phase_mark(&pt, "frm");

    if (brix_configure_thread_pools(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Phase 44: io_uring fail-fast.  `brix_io_uring on` is a hard requirement —
     * if it cannot be satisfied (not compiled in, or the runtime probe fails on
     * this host) refuse to start so the operator is not silently downgraded.
     * The runtime probe is consulted here (per-process, seccomp-accurate), not
     * at parse time.  `off`/`auto` always pass.
     */
    if (brix_uring_validate_conf(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#if (BRIX_HAVE_LIBURING)
    if (postconf_uring_killswitch(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    if (postconf_impersonation(cf, cmcf, cscfp) != NGX_OK) {
        return NGX_ERROR;
    }

    postconf_log_summaries(cf, cmcf, cscfp);

    brix_phase_mark(&pt, "pools_uring");
    brix_phase_timer_log(&pt, cf->log, "xrootd postconfig");

    return NGX_OK;
}
