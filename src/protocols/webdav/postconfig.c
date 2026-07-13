/*
 * postconfig.c - content handler registration and HTTP SSL/thread setup.
 *
 * WHAT: Post-configuration lifecycle hook executed after nginx main configuration parsing — registers WebDAV content handler in NGX_HTTP_CONTENT_PHASE, enables GSI proxy certificate support on SSL contexts where proxy_certs=on, initializes SSL fd-cache index for connection reuse optimization, and allocates thread pool references for async file I/O operations (PUT/GET).
 *
 * WHY: nginx requires all modules to register their handlers during postconfiguration phase before accepting any traffic. WebDAV content handler must be registered in NGX_HTTP_CONTENT_PHASE so nginx can dispatch HTTP requests to ngx_http_brix_webdav_handler() after authentication completes. GSI/x509 proxy certificate authentication requires X509_V_FLAG_ALLOW_PROXY_CERTS flag on SSL context — without this flag, proxy certificates issued by CA intermediates are rejected as invalid (AGENTS.md INVARIANT: GSI auth uses proxy cert chains). Thread pool allocation enables async file I/O for blocking operations (PUT body write, GET range read) per AGENTS.md FAQ: "Async I/O? Event-loop only. No wait/sleep/read. Use ngx_thread_pool_run."
 *
 * HOW: Called once during nginx startup after all configuration directives parsed. First initializes SSL fd-cache index via webdav_auth_init_ssl_indices() for connection reuse optimization (already documented in fd_cache.c). Second, retrieves NGX_HTTP_CORE_MAIN_CONF and pushes ngx_http_brix_webdav_handler into content phase handler array — this is the entry point for all WebDAV HTTP requests after authentication routing. Third, iterates CMCF servers to find SSL contexts with proxy_certs=on flag, then sets X509_V_FLAG_ALLOW_PROXY_CERTS via SSL_CTX_get0_param + X509_VERIFY_PARAM_set_flags enabling GSI proxy cert chains. Fourth reinitializes fd-cache SSL index for connection tracking (per fd_cache.c). Finally iterates servers again under NGX_THREADS macro to locate thread pool via ngx_thread_pool_get() — uses wdcf->common.thread_pool_name if configured, otherwise defaults to "default" pool name defined in nginx.conf directive `thread_pool default threads=4 max_queue=65536`. Logs NOTICE-level message when pool not found (async I/O disabled) or successfully allocated.
 */

#include "webdav.h"
#include "protocols/shared/proto_exclusive.h"
#include "protocols/shared/protocol.h"
#include "core/http/ktls.h"
#include "tpc/common/registry.h"
#include "net/mirror/http_mirror.h"
#include "net/ratelimit/ratelimit.h"

/*
 * webdav_postconf_push_handler - append one phase handler to a phase array.
 *
 * WHAT: Push a single WebDAV request handler onto the handler array of a given
 * nginx HTTP phase, returning NGX_OK on success or NGX_ERROR if the array
 * allocation fails.
 *
 * WHY: The postconfiguration hook installs seven handlers across five phases;
 * each install is the identical push-then-null-check dance. Folding it into one
 * helper removes six repeated branches from the top-level function and keeps the
 * registration order visible as a flat, ordered list of calls at the call site.
 *
 * HOW: Calls ngx_array_push() on the target phase's handler array; on a NULL
 * return (out-of-memory) returns NGX_ERROR without touching the slot, otherwise
 * assigns the handler pointer and returns NGX_OK.
 */
static ngx_int_t
webdav_postconf_push_handler(ngx_http_core_main_conf_t *cmcf,
                             ngx_uint_t phase, ngx_http_handler_pt handler)
{
    ngx_http_handler_pt *h;

    h = ngx_array_push(&cmcf->phases[phase].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = handler;
    return NGX_OK;
}

/*
 * webdav_postconf_install_handlers - register all WebDAV phase handlers.
 *
 * WHAT: Install, in a fixed order, the access-phase auth/introspect/rate-limit
 * handlers, the log-phase bandwidth and mirror handlers, the precontent-phase
 * traffic-mirror handler, and the content-phase WebDAV method router; returns
 * NGX_ERROR if any array push fails.
 *
 * WHY: nginx dispatches requests through phase handlers in registration order,
 * so the exact sequence here is behavior-load-bearing (auth before rate-limit,
 * mirror takeover in precontent, method routing in content). Grouping the pushes
 * in one helper preserves that order as an auditable list while keeping the
 * top-level hook short.
 *
 * HOW: Calls webdav_postconf_push_handler() once per (phase, handler) pair in
 * the original order; the first failure short-circuits with NGX_ERROR via
 * early-return, otherwise returns NGX_OK.
 */
static ngx_int_t
webdav_postconf_install_handlers(ngx_http_core_main_conf_t *cmcf)
{
    /* Access phase: auth, CORS, write guards, and token-scope checks. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_ACCESS_PHASE,
                                     ngx_http_brix_webdav_access_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Phase 21 Step C: OIDC introspection runs as a second access-phase
     * handler (after the main auth handler), so its subrequest suspend/resume
     * re-entry replays only the introspection check — not the whole auth gate. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_ACCESS_PHASE,
                                     webdav_introspect_access_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Phase 25: advanced rate limiting runs as a third access-phase handler
     * (after auth, so the identity is populated) and chains a body filter for
     * bandwidth accounting. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_ACCESS_PHASE,
                                     brix_rl_http_access_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Bandwidth is charged in the log phase from the known response size. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_LOG_PHASE,
                                     brix_rl_http_log_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Phase 24: traffic mirror.  The precontent handler does both jobs: on the
     * main request it fires the background shadow subrequests, and on each
     * mirror subrequest it takes the request over and proxies it to the shadow.
     * Doing the takeover in the precontent phase avoids any dependence on
     * content-phase handler ordering. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_PRECONTENT_PHASE,
                                     brix_http_mirror_precontent_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Content phase: native WebDAV method routing for all implemented methods. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_CONTENT_PHASE,
                                     ngx_http_brix_webdav_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Log phase: stamp the primary's final status for the divergence compare. */
    if (webdav_postconf_push_handler(cmcf, NGX_HTTP_LOG_PHASE,
                                     brix_http_mirror_log_handler)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * webdav_postconf_setup_ssl_ctx - apply GSI-proxy and kTLS flags to one server.
 *
 * WHAT: For a single server block, enable X509_V_FLAG_ALLOW_PROXY_CERTS on its
 * SSL verify params when proxy_certs is on, and opt its TLS context into
 * kernel-TLS when brix_ktls is on; a no-op for servers without WebDAV config or
 * without an SSL context.
 *
 * WHY: GSI proxy-cert chains are rejected by OpenSSL unless the proxy-certs flag
 * is set (AGENTS.md INVARIANT), and kTLS offload must be armed per-server while
 * the ssl + brix_ktls directives live at server level. Isolating the per-server
 * body lets the caller iterate cleanly and keeps this security-load-bearing flag
 * manipulation in one auditable place.
 *
 * HOW: Reads the WebDAV loc-conf and SSL srv-conf from the server's context and
 * early-returns if either is absent. When proxy_certs is set it fetches the
 * verify params via SSL_CTX_get0_param() and sets the proxy-cert flag (logging
 * INFO); when common.ktls is set it calls brix_http_ktls_enable_ctx(). Registration
 * effects are identical whether or not this is split out.
 */
static void
webdav_postconf_setup_ssl_ctx(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_conf_ctx_t             *ctx = cscf->ctx;
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_http_ssl_srv_conf_t         *sslcf;
    X509_VERIFY_PARAM               *param;

    wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];
    if (wdcf == NULL) {
        return;
    }

    sslcf = ctx->srv_conf[ngx_http_ssl_module.ctx_index];
    if (sslcf == NULL || sslcf->ssl.ctx == NULL) {
        return;
    }

    if (wdcf->proxy_certs) {
        param = SSL_CTX_get0_param(sslcf->ssl.ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
            ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                          "brix_webdav: enabled X509_V_FLAG_ALLOW_PROXY_CERTS"
                          " on SSL context for server %V",
                          &cscf->server_name);
        }
    }

    /* kTLS: opt every https server's TLS context into kernel-TLS so HTTPS
     * GET sendfiles over kTLS and PUT decrypts in-kernel (unless brix_ktls
     * off on that server). The server-level webdav loc-conf carries the flag
     * (default on) for EVERY server — WebDAV and S3 alike, since brix_webdav/
     * brix_s3 typically sit in a location block while ssl + brix_ktls are
     * server-level. Transparent no-op for non-offloadable ciphers. */
    if (wdcf->common.ktls) {
        brix_http_ktls_enable_ctx(sslcf->ssl.ctx, cf->log,
                                  &cscf->server_name);
    }
}

/*
 * webdav_postconf_setup_thread_pool - resolve the async-I/O pool for one server.
 *
 * WHAT: For a WebDAV-enabled server block, look up the configured thread pool
 * (falling back to the "default" pool) and store it on the common conf, logging
 * a NOTICE for both the found and the not-found cases; a no-op for servers that
 * lack a WebDAV conf or have WebDAV disabled.
 *
 * WHY: Async file I/O for PUT/GET runs on an nginx thread pool resolved once at
 * config time. The pool name is per-server (explicit or "default"), so the
 * lookup must run per server block; keeping it in a helper mirrors the SSL-setup
 * split and keeps the loop body in the caller trivial.
 *
 * HOW: Reads the WebDAV loc-conf from the server context, early-returns if it is
 * absent or common.enable is unset, selects the configured pool name or the
 * shared "default", and calls ngx_thread_pool_get(); the returned pointer (or
 * NULL) is written to common.thread_pool with the matching NOTICE log.
 */
static void
webdav_postconf_setup_thread_pool(ngx_conf_t *cf,
                                  ngx_http_core_srv_conf_t *cscf)
{
    static ngx_str_t default_pool_name = ngx_string("default");

    ngx_http_conf_ctx_t             *ctx = cscf->ctx;
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_str_t                       *pool_name;

    wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];
    if (wdcf == NULL || !wdcf->common.enable) {
        return;
    }

    pool_name = (wdcf->common.thread_pool_name.len > 0)
                ? &wdcf->common.thread_pool_name
                : &default_pool_name;

    wdcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
    if (wdcf->common.thread_pool == NULL) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_webdav: thread pool \"%V\" not found - "
            "async file I/O disabled (add a thread_pool directive)",
            pool_name);
    } else {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_webdav: using thread pool \"%V\" for async file I/O",
            pool_name);
    }
}

/*
 * webdav_postconf_setup_servers - run per-server SSL and thread-pool setup.
 *
 * WHAT: Iterate every server block twice — first applying GSI-proxy/kTLS flags
 * to each SSL context, then resolving each WebDAV server's async-I/O thread pool.
 *
 * WHY: The original hook did both passes over cmcf->servers inline; preserving
 * two separate passes (rather than fusing them) keeps behavior identical — the
 * SSL flags are all set before any thread-pool lookup, matching the prior order
 * of side effects and log output.
 *
 * HOW: Fetches the servers array once, loops applying webdav_postconf_setup_ssl_ctx()
 * to each element, then loops again applying webdav_postconf_setup_thread_pool();
 * neither pass can fail, so no return value is needed.
 */
static void
webdav_postconf_setup_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_uint_t                 s;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        webdav_postconf_setup_ssl_ctx(cf, cscfp[s]);
    }

    for (s = 0; s < cmcf->servers.nelts; s++) {
        webdav_postconf_setup_thread_pool(cf, cscfp[s]);
    }
}

ngx_int_t
ngx_http_brix_webdav_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;

    if (webdav_auth_init_ssl_indices(cf->log) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (webdav_postconf_install_handlers(cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    webdav_postconf_setup_servers(cf, cmcf);

    if (brix_tpc_registry_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 2.1: populate the protocol-descriptor registry (after all merges) BEFORE
     * the exclusivity check, which now drives its protocol set off the registry. */
    brix_protocol_register_all();

    /* All module merges are done by the time any postconfiguration runs, so
     * every protocol's enable flag is final here: reject a config that mixes
     * brix protocols within one location or under one listen port. */
    if (brix_http_proto_exclusive_check(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
