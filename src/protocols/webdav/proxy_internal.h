#ifndef BRIX_WEBDAV_PROXY_INTERNAL_H
#define BRIX_WEBDAV_PROXY_INTERNAL_H

/*
 * WHAT: Internal header for WebDAV upstream proxy mode — declares the per-request context struct (webdav_proxy_ctx_t) and six nginx upstream lifecycle callbacks that handle request creation, status line parsing, header forwarding, error abort, and completion cleanup. These functions are registered as u->create_request/u->reinit_request/u->process_header/u->abort_request/u->finalize_request hooks in proxy.c's webdav_proxy_handler().
 *
 * WHY: nginx upstream API requires lifecycle callbacks to manage the proxy request flow — create_request generates the backend HTTP request body, process_header parses status line and headers from backend response, abort_request cleans up on error, finalize_request handles completion. The per-request context struct (webdav_proxy_ctx_t) carries state across these callbacks via ngx_http_set_ctx(r, ctx, module). This header is internal (not webdav.h) because proxy mode only activates when brix_webdav_proxy=on in location config.
 *
 * HOW: Declares webdav_proxy_ctx_t with status field tracking backend HTTP response status; declares six callback prototypes matching nginx upstream API signatures — create_request/reinit_request return ngx_int_t for success/error, process_status_line/process_header return ngx_int_t, abort_request/finalize_request are void cleanup functions. */
#include "webdav.h"
#include "proxy_pool.h"   /* Phase 23: dynamic SHM backend pool */

/*
 * Phase 21 Step D — one resolved upstream backend.  A configured proxy URL
 * resolves to one or more of these (multiple comma/space-separated URLs, and
 * each URL may resolve to several addresses).  fail_count/fail_time implement
 * passive health: a backend with >= max_fails consecutive failures is skipped
 * for fail_timeout.  These counters are per-worker (COW after fork) — exact
 * cross-worker counting isn't required for best-effort health tracking.
 */
typedef struct {
    ngx_http_upstream_resolved_t  resolved;   /* single address (naddrs == 1) */
    ngx_str_t                     host;        /* Host: header value */
    ngx_str_t                     url_base;    /* scheme://host[:port] */
    ngx_flag_t                    ssl;         /* 1 if https backend */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                    *ssl_ctx;     /* per-backend TLS context */
#endif
    ngx_uint_t                    fail_count;  /* consecutive failures */
    ngx_msec_t                    fail_time;   /* ngx_current_msec of last fail */
} brix_webdav_backend_t;

typedef struct {
    ngx_http_status_t        status;
    brix_webdav_backend_t *selected_backend;  /* chosen for this request */
    uint32_t                 proxy_be_id;       /* Phase 23: dynamic-pool id (0 = none) */
} webdav_proxy_ctx_t;

/*
 * Round-robin select a healthy backend; returns NULL only when no backends are
 * configured.  When all are marked down it returns backend[0] (fail-through).
 */
brix_webdav_backend_t *webdav_proxy_pick_backend(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Parse the configured proxy URL list into conf->upstream_backends. */
ngx_int_t webdav_proxy_build_backends(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Phase 23 — configure proxy mode for the dynamic SHM pool (no static URL). */
ngx_int_t webdav_proxy_pool_setup(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev);

/*
 * u->create_request hook.  Builds the full HTTP/1.1 request (line + headers +
 * any buffered body) into u->request_bufs from r->pool.  Targets the per-request
 * selected_backend's host/url_base (falls back to conf single-backend fields).
 * Strips hop-by-hop headers (Connection/Host/Keep-Alive/Transfer-Encoding),
 * rewrites Destination: to the backend URL base, and applies the auth policy to
 * Authorization: (ANONYMOUS strips it, FORWARD passes the client's unchanged,
 * TOKEN replaces with the configured static Bearer).  NGX_OK / NGX_ERROR(alloc).
 */
ngx_int_t webdav_proxy_create_request(ngx_http_request_t *r);

/*
 * u->reinit_request hook (connection reuse / retry).  Zeroes ctx->status and
 * resets u->process_header to webdav_proxy_process_header.  NGX_OK, or
 * NGX_ERROR if the per-request ctx is missing.
 */
ngx_int_t webdav_proxy_reinit_request(ngx_http_request_t *r);

/*
 * Initial u->process_header hook: parses the backend status line into
 * ctx->status, populates u->headers_in.status_n/status_line (data copied into
 * r->pool), then re-points u->process_header at webdav_proxy_process_header and
 * tail-calls it so header parsing begins in the same invocation.  Returns
 * NGX_AGAIN (need more bytes), NGX_HTTP_UPSTREAM_INVALID_HEADER on a malformed
 * status line (becomes 502), or whatever process_header returns.
 */
ngx_int_t webdav_proxy_process_status_line(ngx_http_request_t *r);

/*
 * u->process_header hook (after the status line).  Parses each response header
 * into u->headers_in.headers and runs the matching upstream header handler from
 * umcf->headers_in_hash.  NGX_OK when headers complete, NGX_AGAIN for more data,
 * NGX_HTTP_UPSTREAM_INVALID_HEADER on a bad line, NGX_ERROR on alloc/handler
 * failure.  Note: writes a NUL after each parsed key/value in u->buffer.
 */
ngx_int_t webdav_proxy_process_header(ngx_http_request_t *r);

/* u->abort_request hook: debug-log only; no state to release. */
void webdav_proxy_abort_request(ngx_http_request_t *r);

/*
 * u->finalize_request hook (called on every completion path).  Despite the name
 * it does real work: releases the dynamic-pool in_flight reservation
 * (proxy_be_id) and updates the selected_backend's passive-health counters --
 * gateway-class rc (502/504/503) increments fail_count + stamps fail_time, a
 * 2xx/3xx/NGX_OK clears them.  No-op if ctx or selected_backend is NULL.
 */
void webdav_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

#endif /* BRIX_WEBDAV_PROXY_INTERNAL_H */
