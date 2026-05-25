/* ------------------------------------------------------------------ */
/* Postconfiguration — Runtime Resource Initialization                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements nginx postconfiguration phase that initializes all runtime resources after parsing and merging is complete. Called once during nginx startup after server-level configurations have been allocated, merged from parent→child scope inheritance, and finalized with policy rules. Performs five sequential operations across all enabled servers: VOMS library loading (dlopen for libvomsapi.so.1 — graceful continuation if unavailable), auth subsystem configuration (GSI certificates/key, TLS context, token/JWT keys, SSS keytab), policy rule finalization (VO ACL rules, group inheritance rules, authDB rules), shared memory registry creation (session + handle tables), thread pool setup for AIO operations.
 *
 * WHY: Postconfiguration is critical because runtime resources require fully-merged configuration values — auth subsystems need to know the merged auth mode before loading certificates; policy rules depend on finalized roots and auth availability; shared memory zones must be created once across all workers with proper mutex initialization; thread pools must be sized based on operational requirements. Attempting these operations during parsing phase would fail because parent→child inheritance hasn't completed yet. */

/* ------------------------------------------------------------------ */
/* Section: VOMS Library Loading                                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_voms_init() attempts to load libvomsapi.so.1 via dlopen during postconfiguration — if the library is not present, continuation proceeds without error; config validation later in xrootd_config_finalize_policy() rejects xrootd_require_vo directives when VOMS is unavailable. This graceful degradation prevents nginx startup failures on systems lacking VOMS libraries while maintaining strict policy enforcement for deployments that require VOMS.
 *
 * WHY: VOMS (Virtual Organization Membership Service) is an optional dependency — not all XRootD deployments require VO ACL enforcement. Graceful loading allows operators to deploy without VOMS libraries while ensuring strict validation when xrootd_require_vo directives are present and VOMS is absent, preventing runtime authorization failures where policy rules reference unavailable library functions. */

/* ------------------------------------------------------------------ */
/* Section: Auth Subsystem Configuration                                */
/* ------------------------------------------------------------------ */
/*
 * WHAT: First pass over all enabled servers initializes auth subsystems in parallel order: GSI certificate/key loading (webdav_verify_proxy_cert validation), TLS context creation (xrootd_configure_tls for in-protocol upgrade), token/JWT key loading (xrootd_configure_token_auth with JWKS fetching), SSS shared secret configuration (xrootd_configure_sss_auth). Each subsystem returns NGX_OK/NGX_ERROR independently — any failure causes immediate postconfiguration abort preventing nginx startup.
 *
 * WHY: Auth subsystems must be configured before policy finalization because VO ACL rules and authDB access control depend on the authentication mode being established. GSI certificates enable certificate verification during login; TLS context enables in-protocol upgrade for roots:// clients; token keys enable JWT bearer validation during kXR_auth; SSS keytab enables shared secret authentication flow. Each subsystem must succeed before proceeding to ensure consistent security posture across all server blocks. */

/* ------------------------------------------------------------------ */
/* Section: Policy Rule Finalization                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Second pass over enabled servers finalizes policy rules after auth setup completes — xrootd_config_finalize_policy() validates VO ACL rules require VOMS library and cert directory, verifies authDB rules match configured auth mode, checks group inheritance rules have valid path normalization. Returns NGX_ERROR on any rule validation failure preventing nginx startup with inconsistent policy configuration.
 *
 * WHY: Policy finalization depends on auth/VOMS availability established in the first pass — VO ACL rules require libvomsapi.so.1 to be loaded and vomsdir/voms_cert_dir directories validated; authDB access control rules must match the configured authentication mode (GSI, token, or both); group inheritance rules need path normalization completed before enforcement during file operations. Sequencing ensures dependencies are satisfied before rule validation. */

/* ------------------------------------------------------------------ */
/* Section: Shared Memory Registry                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Creates session registry and handle table shared memory zones using xrootd_configure_session_registry() (two zones: xrootd_sessions for client metadata + xrootd_session_handles for published file handles), determines maximum registry_slots across all enabled server blocks for consistent capacity, configures pending signature verification state via xrootd_pending_configure(), initializes TPC key registry via xrootd_tpc_key_configure_registry(). All shared memory operations use mutex locks ensuring thread-safe cross-worker access.
 *
 * WHY: Shared memory enables cross-worker session persistence — without it sessions established by one worker would be invisible to subsequent requests arriving at different workers, causing authentication failures or duplicate session creation attempts. Registry slots sizing uses maximum across all server blocks ensuring sufficient capacity regardless of which worker handles a given request; pending sigver and TPC key registry enable cryptographic security mechanisms for authenticated sessions and native transfer protocols. */

/* ------------------------------------------------------------------ */
/* Section: Thread Pool Configuration                                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_configure_thread_pools() creates AIO thread pools for asynchronous read/write/pgread operations when NGX_THREADS is enabled — pools sized based on operational requirements ensuring sufficient concurrent I/O capacity without exhausting system resources. Thread pool allocation is conditional (NGX_THREADS compile flag) because synchronous fallback exists when threads are unavailable.
 *
 * WHY: Asynchronous I/O enables high-throughput reads and writes without blocking the nginx event loop — critical for large file transfers where pread(2)/pwrite(2) operations would otherwise stall the entire connection processing pipeline. Thread pool sizing balances throughput requirements against resource constraints ensuring sufficient concurrent capacity while preventing system overload from excessive thread allocation. */

/* ---- Function: ngx_stream_xrootd_postconfiguration() ----
 *
 * WHAT: Implements nginx postconfiguration phase initializing all runtime resources after parsing and merging is complete — five sequential operations across all enabled servers: (1) VOMS library loading via dlopen, (2) auth subsystem configuration (GSI/TLS/token/SSS), (3) policy rule finalization (VO ACL/group inheritance/authDB), (4) shared memory registry creation (session + handle tables + pending sigver + TPC key registry), (5) thread pool setup for AIO operations. Returns NGX_OK on success; NGX_ERROR on any operation failure preventing nginx startup.
 *
 * WHY: Postconfiguration is critical because runtime resources require fully-merged configuration values — auth subsystems need merged auth mode before loading certificates; policy rules depend on finalized roots and auth availability; shared memory zones must be created once across all workers with proper mutex initialization; thread pools must be sized based on operational requirements. Attempting these operations during parsing phase would fail because parent→child inheritance hasn't completed yet.
 *
 * HOW: Five-phase sequence → VOMS library loading (dlopen, graceful continuation if unavailable) → first pass over enabled servers initializing auth subsystems (GSI cert/key, TLS context, token keys, SSS keytab — abort on any failure) → second pass finalizing policy rules (VO ACL with VOMS validation, group inheritance, authDB rules) → shared memory registry creation (session + handle zones, max registry slots across all servers, pending sigver, TPC key registry) → thread pool configuration (conditional NGX_THREADS) → return NGX_OK; NGX_ERROR on failure. */

#include "config.h"

ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

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
            || xrootd_configure_sss_auth(cf, xcf) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

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

    if (xrootd_configure_metrics(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_configure_session_registry(cf) != NGX_OK) {
        return NGX_ERROR;
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
    }

    if (xrootd_pending_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_tpc_key_configure_registry(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_configure_thread_pools(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
