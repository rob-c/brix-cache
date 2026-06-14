/*
 * xrdhttp_filter.c — XrdHttp response header (and body) output filter.
 *
 * Phase 21 Step A/B.  This is a *separate* HTTP_AUX_FILTER module rather than a
 * filter registered from the webdav module's own postconfiguration.  The
 * reason is nginx module ordering: postconfiguration hooks run in ngx_modules[]
 * array order, and ngx_http_header_filter_module installs the terminal header
 * filter with a *direct* assignment:
 *
 *     ngx_http_top_header_filter = ngx_http_header_filter;   // no save
 *
 * The webdav module sits *before* ngx_http_header_filter_module in the array,
 * so any filter the webdav module installs from preconfiguration OR
 * postconfiguration is clobbered by that direct assignment and never runs.
 * (An earlier in-tree comment and the Phase-21 design doc both misdiagnosed
 * this — the doc's "register in preconfiguration" fix does not work either.)
 *
 * An HTTP_AUX_FILTER add-on module is placed by auto/modules *after* the core
 * header/write filters, so its filter_init runs last and correctly chains on
 * top of ngx_http_header_filter: it saves the previous top into
 * ngx_http_next_header_filter and runs before the core filter serialises the
 * header block — which is exactly where XrdHttp headers must be injected.
 *
 * The filter is a safety net: xrdhttp_add_response_headers() is a no-op unless
 * the request's webdav context is flagged is_xrdhttp, and it carries its own
 * headers_injected guard, so it is fully idempotent with the direct call-site
 * injections that remain in get.c / multipart / redirect paths.  The filter
 * additionally covers paths that never reach a manual call (nginx-generated
 * error pages), so XrdHttp-aware clients always see X-Xrootd-Status.
 */
#include "webdav.h"
#include "xrdhttp.h"

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
xrdhttp_header_filter(ngx_http_request_t *r)
{
    (void) xrdhttp_add_response_headers(r, (ngx_int_t) r->headers_out.status);
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
xrdhttp_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    return xrdhttp_digest_body_filter(r, in, ngx_http_next_body_filter);
}

static ngx_int_t
xrdhttp_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = xrdhttp_header_filter;

    ngx_http_next_body_filter   = ngx_http_top_body_filter;
    ngx_http_top_body_filter    = xrdhttp_body_filter;

    return NGX_OK;
}

static ngx_http_module_t  ngx_http_xrootd_xrdhttp_filter_module_ctx = {
    NULL,                 /* preconfiguration  */
    xrdhttp_filter_init,  /* postconfiguration */
    NULL,                 /* create main configuration */
    NULL,                 /* init main configuration   */
    NULL,                 /* create server configuration */
    NULL,                 /* merge server configuration  */
    NULL,                 /* create location configuration */
    NULL                  /* merge location configuration  */
};

ngx_module_t  ngx_http_xrootd_xrdhttp_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_xrdhttp_filter_module_ctx,  /* module context */
    NULL,                                        /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};
