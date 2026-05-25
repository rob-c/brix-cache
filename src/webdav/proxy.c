/*
 * proxy.c - WebDAV upstream HTTP(S) proxy entry point.
 *
 * WHAT: Forwards WebDAV requests verbatim to a backend HTTP/HTTPS server (e.g., plain xrootd with davs:// disabled, or internal DAV service) using nginx's native upstream API. Terminates client-side HTTPS/WLCG token auth at nginx perimeter then relays operations to unauthenticated internal backend — enabling proxy mode deployment per README.md Mode 3 (WebDAV Perimeter Proxy). Implements three auth policies: anonymous (strip Authorization before forwarding for internal trust), forward (pass client's Authorization header unchanged for transparent relay), token (replace Authorization with static Bearer token for credential delegation).
 *
 * WHY: Proxy mode enables nginx-xrootd to act as HTTPS perimeter gateway terminating WLCG token authentication while forwarding plain HTTP operations to internal backend servers — eliminates need for SSL termination on every DAV server in the infrastructure. Three auth policies provide flexibility: anonymous policy strips client credentials (internal trust model), forward policy relays original Authorization header (transparent proxy), token policy uses static Bearer token for credential delegation when backend accepts a site-wide service account token. nginx's upstream API provides lazy connection management, buffering control, and per-request lifecycle hooks — this function configures those hooks via webdav_proxy_* callback functions registered in the ctx array.
 *
 * HOW: Entry point called after authentication gate completes (dispatch.c routes to proxy handler when xrootd_webdav_proxy=on). Creates nginx upstream object via ngx_http_upstream_create(), allocates per-request webdav_proxy_ctx_t from request pool and sets as module context via ngx_http_set_ctx(). Configures upstream lifecycle hooks: create_request/reinit_request for request generation, process_header for status line parsing, abort_request/finalize_request for cleanup. Copies pre-resolved upstream address (conf->upstream_resolved) into per-request resolved struct to avoid DNS lookup on each request. Sets ssl=1 flag if conf->upstream_ssl enabled under NGX_HTTP_SSL macro. Disables request body buffering via r->request_body_no_buffering=0 for streaming PUT/POST operations. Reads client request body asynchronously via ngx_http_read_client_request_body() with callback ngx_http_upstream_init() — returns NGX_DONE to signal async completion, or NGX_HTTP_SPECIAL_RESPONSE on error.
 */

#include "proxy_internal.h"
#include "../compat/http_body.h"

/*
 * WHAT: Configure nginx upstream object and lifecycle hooks for WebDAV proxy mode — sets up request forwarding infrastructure after authentication gate completes.
 *
 * WHY: nginx's upstream API provides lazy connection management, buffering control, and per-request lifecycle hooks essential for proxy deployment. This function is the entry point called by dispatch.c when xrootd_webdav_proxy=on in location config — it must configure all upstream callbacks before nginx can initiate backend connection and relay operations. Three auth policies (anonymous/forward/token) determine whether Authorization header is stripped, passed unchanged, or replaced with static Bearer token during request creation.
 *
 * HOW: First creates nginx upstream object via ngx_http_upstream_create() allocating r->upstream structure from request pool. Second allocates per-request webdav_proxy_ctx_t from pool and sets as module context via ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module) for downstream lifecycle hooks to access proxy state. Third configures upstream lifecycle callbacks: u->create_request = webdav_proxy_create_request (request body generation), u->reinit_request = webdav_proxy_reinit_request (connection reuse reinitialization), u->process_header = webdav_proxy_process_status_line (backend response parsing), u->abort_request = webdav_proxy_abort_request (error cleanup), u->finalize_request = webdav_proxy_finalize_request (completion cleanup). Fourth copies pre-resolved upstream address *conf->upstream_resolved into per-request resolved struct via ngx_palloc + memcpy to avoid DNS lookup on each request. Fifth sets ssl=1 flag under NGX_HTTP_SSL macro if conf->upstream_ssl enabled for backend HTTPS connection. Sixth disables body buffering via r->request_body_no_buffering=0 for streaming PUT/POST operations. Seventh reads client request body asynchronously via ngx_http_read_client_request_body(r, ngx_http_upstream_init) with callback initiating upstream connection — returns NGX_DONE to signal async completion or error response code on failure.
 */
ngx_int_t
webdav_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_upstream_t               *u;
    webdav_proxy_ctx_t                *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u = r->upstream;

    ctx = ngx_pcalloc(r->pool, sizeof(webdav_proxy_ctx_t));
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);

    u->conf      = &conf->upstream_conf;
    u->buffering = conf->upstream_conf.buffering;

    u->create_request   = webdav_proxy_create_request;
    u->reinit_request   = webdav_proxy_reinit_request;
    u->process_header   = webdav_proxy_process_status_line;
    u->abort_request    = webdav_proxy_abort_request;
    u->finalize_request = webdav_proxy_finalize_request;

    /* Copy pre-resolved upstream address into the per-request resolved struct */
    u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    *u->resolved = *conf->upstream_resolved;

#if (NGX_HTTP_SSL)
    if (conf->upstream_ssl) {
        r->upstream->ssl = 1;
    }
#endif

    r->request_body_no_buffering = 0;
    return xrootd_http_read_body(r, ngx_http_upstream_init);
}
