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
 * webdav_postconf_load_client_capath - add a hashed CA dir to one server's
 * TLS client-verify trust store.
 *
 * WHAT: Load the brix_ssl_client_capath directory into the SSL_CTX certificate
 * store of one server block as an OpenSSL hashed-directory lookup; returns
 * NGX_OK, or NGX_ERROR (a fatal config error) when the path is not an
 * accessible directory or the store cannot be extended.
 *
 * WHY: Grid hosts ship their trust anchors as an OpenSSL hashed directory
 * (/etc/grid-security/certificates, the IGTF layout) and no bundle file, but
 * stock nginx's ssl_client_certificate/ssl_trusted_certificate are file-only —
 * so a fail-closed `ssl_verify_client on` front leg could not consume the dir
 * at all. A hashed lookup also resolves issuers at verify time, so CA-package
 * updates are picked up without a reload. Misconfiguration is fatal (not a
 * warning) because this directive IS the trust perimeter: a typo that silently
 * loaded nothing would reject every client with an unhelpful handshake error.
 *
 * HOW: 1) ngx_file_info() the path (conf tokens are NUL-terminated) and demand
 * an existing directory; 2) fetch the server's verify store with
 * SSL_CTX_get_cert_store(); 3) X509_STORE_load_locations(store, NULL, dir)
 * appends the hash-dir lookup (additive — certs from ssl_client_certificate
 * stay trusted); 4) log one INFO line naming the server and directory.
 */
static ngx_int_t
webdav_postconf_load_client_capath(ngx_conf_t *cf,
                                   ngx_http_core_srv_conf_t *cscf,
                                   ngx_http_ssl_srv_conf_t *sslcf,
                                   ngx_str_t *capath)
{
    ngx_file_info_t  fi;
    X509_STORE      *store;

    if (ngx_file_info(capath->data, &fi) != 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                      "brix_ssl_client_capath \"%V\" is not accessible",
                      capath);
        return NGX_ERROR;
    }

    if (!ngx_is_dir(&fi)) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_ssl_client_capath \"%V\" is not a directory "
                      "(for a bundle file use ssl_client_certificate)",
                      capath);
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(sslcf->ssl.ctx);
    if (store == NULL
        || X509_STORE_load_locations(store, NULL,
                                     (const char *) capath->data) != 1)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_ssl_client_capath \"%V\": cannot add hashed "
                      "CA-directory lookup to the TLS trust store", capath);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "brix_webdav: added hashed CA dir \"%V\" to the client-"
                  "verify trust store for server %V",
                  capath, &cscf->server_name);
    return NGX_OK;
}

/* The stock proxy module: its ctx_index locates the (private) proxy loc-conf
 * in each location's conf array; ngx_http_upstream_conf_t is that struct's
 * FIRST member, so a first-member cast reaches the public upstream conf. */
extern ngx_module_t  ngx_http_proxy_module;


/*
 * webdav_postconf_proxy_capath_apply - add one location's hashed CA dir to
 * its upstream (proxy_ssl) trust store.
 *
 * WHAT: For a single location conf array, when brix_proxy_ssl_capath is set,
 * add the directory as an OpenSSL hashed lookup to the location's upstream
 * SSL_CTX; NGX_OK when unset. Fatal (NGX_ERROR) when the location has no
 * https proxy_pass — the directive would otherwise silently protect nothing.
 *
 * WHY: second half of brix_proxy_ssl_capath (see module_directives.c): the
 * parse-time handler could only seed one <hash>.N file through the stock
 * proxy_ssl_trusted_certificate slot, because the upstream SSL_CTX does not
 * exist until the proxy module's merge. Here — after all merges — the ctx is
 * live, so the whole directory becomes a verify-time hashed lookup: every CA
 * in /etc/grid-security/certificates is trusted and IGTF package updates are
 * picked up without a reload.
 *
 * HOW: reads the webdav loc-conf for the capath, then casts the proxy
 * module's private loc-conf to its public first member
 * (ngx_http_upstream_conf_t) to reach upstream->ssl->ctx. The ssl object is
 * per-location here, not shared: injecting the trusted-certificate seed made
 * this location "SSL-configured", so the proxy merge gave it its own ctx.
 * X509_STORE_load_locations(store, NULL, dir) appends the hash-dir lookup
 * (additive — the seeded file stays trusted). Conf tokens and
 * ngx_conf_full_name results are NUL-terminated, so capath->data is a valid
 * C string.
 */
static ngx_int_t
webdav_postconf_proxy_capath_apply(ngx_conf_t *cf, void **loc_conf,
                                   ngx_str_t *name)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf;
    ngx_http_upstream_conf_t          *ucf;
    X509_STORE                        *store;

    wlcf = loc_conf[ngx_http_brix_webdav_module.ctx_index];
    if (wlcf == NULL || wlcf->proxy_ssl_capath.len == 0) {
        return NGX_OK;
    }

    ucf = loc_conf[ngx_http_proxy_module.ctx_index];

    if (ucf == NULL || ucf->ssl == NULL || ucf->ssl->ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_proxy_ssl_capath in location \"%V\" requires "
                      "\"proxy_pass https://...\" in the same location",
                      name);
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(ucf->ssl->ctx);
    if (store == NULL
        || X509_STORE_load_locations(store, NULL,
                        (const char *) wlcf->proxy_ssl_capath.data) != 1)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_proxy_ssl_capath \"%V\": cannot add hashed "
                      "CA-directory lookup to the upstream trust store",
                      &wlcf->proxy_ssl_capath);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "brix_webdav: added hashed CA dir \"%V\" to the upstream "
                  "(proxy_ssl) trust store for location %V",
                  &wlcf->proxy_ssl_capath, name);
    return NGX_OK;
}


/* Forward declaration: location and tree walkers are mutually recursive
 * (same finalised-structures walk as proto_exclusive.c — the raw
 * clcf->locations queue is unreliable after init_static_location_trees). */
static ngx_int_t webdav_postconf_proxy_capath_location(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf);


static ngx_int_t
webdav_postconf_proxy_capath_loc_array(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t **arr)
{
    ngx_uint_t  i;

    if (arr == NULL) {
        return NGX_OK;
    }
    for (i = 0; arr[i] != NULL; i++) {
        if (webdav_postconf_proxy_capath_location(cf, arr[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


static ngx_int_t
webdav_postconf_proxy_capath_tree(ngx_conf_t *cf,
    ngx_http_location_tree_node_t *node)
{
    if (node == NULL) {
        return NGX_OK;
    }

    if (node->exact != NULL
        && webdav_postconf_proxy_capath_location(cf, node->exact) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (node->inclusive != NULL
        && webdav_postconf_proxy_capath_location(cf, node->inclusive)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_postconf_proxy_capath_tree(cf, node->left) != NGX_OK
        || webdav_postconf_proxy_capath_tree(cf, node->tree) != NGX_OK
        || webdav_postconf_proxy_capath_tree(cf, node->right) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
webdav_postconf_proxy_capath_location(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf)
{
    if (webdav_postconf_proxy_capath_apply(cf, clcf->loc_conf, &clcf->name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_postconf_proxy_capath_tree(cf, clcf->static_locations)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    if (webdav_postconf_proxy_capath_loc_array(cf, clcf->regex_locations)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif
    return NGX_OK;
}


/*
 * webdav_postconf_setup_proxy_capath - walk every location of every server
 * and apply the brix_proxy_ssl_capath second half where the directive is set.
 * The directive is location-only (never merged), so the server-level conf
 * array cannot carry it; only the finalised location structures are walked.
 */
static ngx_int_t
webdav_postconf_setup_proxy_capath(ngx_conf_t *cf,
                                   ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_uint_t                 s;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (webdav_postconf_proxy_capath_tree(cf, clcf->static_locations)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

#if (NGX_PCRE)
        if (webdav_postconf_proxy_capath_loc_array(cf,
                clcf->regex_locations) != NGX_OK)
        {
            return NGX_ERROR;
        }
#endif

        if (webdav_postconf_proxy_capath_loc_array(cf,
                cscfp[s]->named_locations) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * webdav_postconf_setup_ssl_ctx - apply GSI-proxy and kTLS flags to one server.
 *
 * WHAT: For a single server block, enable X509_V_FLAG_ALLOW_PROXY_CERTS on its
 * SSL verify params when proxy_certs is on, add the brix_ssl_client_capath
 * hashed CA directory to its verify store when set (returning NGX_ERROR when
 * that directory is unusable — a fatal config error), and opt its TLS context
 * into kernel-TLS when brix_ktls is on; returns NGX_OK for servers without
 * WebDAV config or without an SSL context (no-op).
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
 * INFO); when ssl_client_capath is set it delegates to
 * webdav_postconf_load_client_capath() and propagates its failure; when
 * common.ktls is set it calls brix_http_ktls_enable_ctx(). Registration
 * effects are identical whether or not this is split out.
 */
static ngx_int_t
webdav_postconf_setup_ssl_ctx(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_conf_ctx_t             *ctx = cscf->ctx;
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_http_ssl_srv_conf_t         *sslcf;
    X509_VERIFY_PARAM               *param;

    wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];
    if (wdcf == NULL) {
        return NGX_OK;
    }

    sslcf = ctx->srv_conf[ngx_http_ssl_module.ctx_index];
    if (sslcf == NULL || sslcf->ssl.ctx == NULL) {
        return NGX_OK;
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

    if (wdcf->ssl_client_capath.len > 0
        && webdav_postconf_load_client_capath(cf, cscf, sslcf,
                                              &wdcf->ssl_client_capath)
           != NGX_OK)
    {
        return NGX_ERROR;
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

    return NGX_OK;
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
 * to each element (propagating NGX_ERROR — an unusable brix_ssl_client_capath
 * is a fatal config error), then loops again applying
 * webdav_postconf_setup_thread_pool(), which cannot fail.
 */
static ngx_int_t
webdav_postconf_setup_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_uint_t                 s;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        if (webdav_postconf_setup_ssl_ctx(cf, cscfp[s]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    for (s = 0; s < cmcf->servers.nelts; s++) {
        webdav_postconf_setup_thread_pool(cf, cscfp[s]);
    }

    return NGX_OK;
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

    if (webdav_postconf_setup_servers(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* brix_proxy_ssl_capath second half: the upstream SSL_CTX exists only
     * after the proxy module's merge, so the hashed-dir add runs here. */
    if (webdav_postconf_setup_proxy_capath(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

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
