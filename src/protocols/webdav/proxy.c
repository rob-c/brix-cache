/*
 * proxy.c - WebDAV upstream HTTP(S) proxy entry point.
 *
 * WHAT: Forwards WebDAV requests verbatim to a backend HTTP/HTTPS server (e.g., plain xrootd with davs:// disabled, or internal DAV service) using nginx's native upstream API. Terminates client-side HTTPS/WLCG token auth at nginx perimeter then relays operations to unauthenticated internal backend — enabling proxy mode deployment per README.md Mode 3 (WebDAV Perimeter Proxy). Implements three auth policies: anonymous (strip Authorization before forwarding for internal trust), forward (pass client's Authorization header unchanged for transparent relay), token (replace Authorization with static Bearer token for credential delegation).
 *
 * WHY: Proxy mode enables nginx-xrootd to act as HTTPS perimeter gateway terminating WLCG token authentication while forwarding plain HTTP operations to internal backend servers — eliminates need for SSL termination on every DAV server in the infrastructure. Three auth policies provide flexibility: anonymous policy strips client credentials (internal trust model), forward policy relays original Authorization header (transparent proxy), token policy uses static Bearer token for credential delegation when backend accepts a site-wide service account token. nginx's upstream API provides lazy connection management, buffering control, and per-request lifecycle hooks — this function configures those hooks via webdav_proxy_* callback functions registered in the ctx array.
 *
 * HOW: Entry point called after authentication gate completes (dispatch.c routes to proxy handler when brix_webdav_proxy=on). Creates nginx upstream object via ngx_http_upstream_create(), allocates per-request webdav_proxy_ctx_t from request pool and sets as module context via ngx_http_set_ctx(). Configures upstream lifecycle hooks: create_request/reinit_request for request generation, process_header for status line parsing, abort_request/finalize_request for cleanup. Copies pre-resolved upstream address (conf->upstream_resolved) into per-request resolved struct to avoid DNS lookup on each request. Sets ssl=1 flag if conf->upstream_ssl enabled under NGX_HTTP_SSL macro. Disables request body buffering via r->request_body_no_buffering=0 for streaming PUT/POST operations. Reads client request body asynchronously via ngx_http_read_client_request_body() with callback ngx_http_upstream_init() — returns NGX_DONE to signal async completion, or NGX_HTTP_SPECIAL_RESPONSE on error.
 */

#include "proxy_internal.h"
#include "core/http/http_body.h"

/*
 * WHAT: Configure nginx upstream object and lifecycle hooks for WebDAV proxy mode — sets up request forwarding infrastructure after authentication gate completes.
 *
 * WHY: nginx's upstream API provides lazy connection management, buffering control, and per-request lifecycle hooks essential for proxy deployment. This function is the entry point called by dispatch.c when brix_webdav_proxy=on in location config — it must configure all upstream callbacks before nginx can initiate backend connection and relay operations. Three auth policies (anonymous/forward/token) determine whether Authorization header is stripped, passed unchanged, or replaced with static Bearer token during request creation.
 *
 * HOW: First creates nginx upstream object via ngx_http_upstream_create() allocating r->upstream structure from request pool. Second allocates per-request webdav_proxy_ctx_t from pool and sets as module context via ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module) for downstream lifecycle hooks to access proxy state. Third configures upstream lifecycle callbacks: u->create_request = webdav_proxy_create_request (request body generation), u->reinit_request = webdav_proxy_reinit_request (connection reuse reinitialization), u->process_header = webdav_proxy_process_status_line (backend response parsing), u->abort_request = webdav_proxy_abort_request (error cleanup), u->finalize_request = webdav_proxy_finalize_request (completion cleanup). Fourth copies pre-resolved upstream address *conf->upstream_resolved into per-request resolved struct via ngx_palloc + memcpy to avoid DNS lookup on each request. Fifth sets ssl=1 flag under NGX_HTTP_SSL macro if conf->upstream_ssl enabled for backend HTTPS connection. Sixth disables body buffering via r->request_body_no_buffering=0 for streaming PUT/POST operations. Seventh reads client request body asynchronously via ngx_http_read_client_request_body(r, ngx_http_upstream_init) with callback initiating upstream connection — returns NGX_DONE to signal async completion or error response code on failure.
 */
ngx_int_t
webdav_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_upstream_t               *u;
    webdav_proxy_ctx_t                *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u = r->upstream;

    ctx = ngx_pcalloc(r->pool, sizeof(webdav_proxy_ctx_t));
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module);

    u->conf      = &conf->upstream_conf;
    u->buffering = conf->upstream_conf.buffering;

    u->create_request   = webdav_proxy_create_request;
    u->reinit_request   = webdav_proxy_reinit_request;
    u->process_header   = webdav_proxy_process_status_line;
    u->abort_request    = webdav_proxy_abort_request;
    u->finalize_request = webdav_proxy_finalize_request;

    /* Phase 23: when the dynamic SHM pool is enabled, select from it (runtime
     * add/remove/drain); otherwise use the Phase 21 config-pool backend array. */
    if (conf->proxy_pool_enabled) {
        brix_proxy_be_pick_t  *pick = ngx_palloc(r->pool, sizeof(*pick));
        brix_webdav_backend_t *be;
        struct sockaddr         *sa;

        if (pick == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (brix_proxy_pool_select(pick) != NGX_OK) {
            return NGX_HTTP_SERVICE_UNAVAILABLE;   /* no live backend */
        }

        be = ngx_pcalloc(r->pool, sizeof(*be));
        sa = ngx_palloc(r->pool, pick->socklen);
        if (be == NULL || sa == NULL) {
            brix_proxy_pool_dec_in_flight(pick->id);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(sa, &pick->sockaddr, pick->socklen);

        be->resolved.sockaddr = sa;
        be->resolved.socklen  = pick->socklen;
        be->resolved.naddrs   = 1;
        be->resolved.host.data = (u_char *) pick->host;
        be->resolved.host.len  = ngx_strlen(pick->host);
        be->resolved.port      = pick->port;
        be->host.data     = (u_char *) pick->host;
        be->host.len      = ngx_strlen(pick->host);
        be->url_base.data = (u_char *) pick->url_base;
        be->url_base.len  = ngx_strlen(pick->url_base);
        be->ssl           = pick->ssl;

        ctx->selected_backend = be;
        ctx->proxy_be_id      = pick->id;

        u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if (u->resolved == NULL) {
            brix_proxy_pool_dec_in_flight(pick->id);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        *u->resolved = be->resolved;
#if (NGX_HTTP_SSL)
        if (be->ssl) { r->upstream->ssl = 1; }
#endif

    } else {
        /* Round-robin select a healthy backend and copy its pre-resolved
         * address into the per-request resolved struct (avoids per-request
         * DNS). */
        brix_webdav_backend_t *be = webdav_proxy_pick_backend(r, conf);

        if (be == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->selected_backend = be;

        u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if (u->resolved == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        *u->resolved = be->resolved;

#if (NGX_HTTP_SSL)
        if (be->ssl) {
            r->upstream->ssl = 1;
        }
#endif
    }

    r->request_body_no_buffering = 0;
    return brix_http_read_body(r, ngx_http_upstream_init);
}

/*
 * Round-robin backend selection with passive health.  Skips a backend that has
 * accrued >= max_fails consecutive failures within the last fail_timeout; if
 * every backend is in its penalty window, falls through to backend[0] so the
 * request still has a chance rather than failing outright.  The round-robin
 * cursor and fail counters are per-worker.
 */
brix_webdav_backend_t *
webdav_proxy_pick_backend(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    brix_webdav_backend_t *be;
    ngx_uint_t               n, i, idx;
    ngx_msec_t               now;

    if (conf->upstream_backends == NULL
        || conf->upstream_backends->nelts == 0)
    {
        return NULL;
    }

    be  = conf->upstream_backends->elts;
    n   = conf->upstream_backends->nelts;
    now = ngx_current_msec;

    for (i = 0; i < n; i++) {
        idx = (ngx_uint_t) (ngx_atomic_fetch_add(&conf->upstream_rr, 1) % n);

        if (conf->upstream_max_fails > 0
            && be[idx].fail_count >= conf->upstream_max_fails
            && be[idx].fail_time != 0
            && (now - be[idx].fail_time) < conf->upstream_fail_timeout)
        {
            continue;   /* still in the penalty box */
        }
        return &be[idx];
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "brix_webdav_proxy: all %ui backends marked down; using backend[0]",
        n);
    return &be[0];
}
