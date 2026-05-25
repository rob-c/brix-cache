/*
 * WHAT: WebDAV upstream proxy response processing — three nginx upstream lifecycle callbacks parse backend HTTP response (status line, headers loop), one void callback aborts on error. These functions are registered as u->reinit_request/u->process_header hooks in proxy.c's webdav_proxy_handler() and handle the complete backend-to-client response relay pipeline.
 *
 * WHY: After creating the upstream request, nginx needs callbacks to parse the backend HTTP response — status line (HTTP/1.x 200 OK etc.), headers loop (Content-Length, Content-Type, Location for redirects), and completion cleanup. Proxy mode must faithfully relay backend responses to client so WebDAV COPY/MOVE/GET operations see correct status codes, redirect locations, and content metadata.
 *
 * HOW: reinit_request resets per-request ctx->status to zero and switches nginx upstream process_header callback from status-line parser to header-loop parser (webdav_proxy_process_status_line → webdav_proxy_process_header). process_status_line uses ngx_http_parse_status_line() to extract HTTP status code into ctx->status, copies status_line string into u->headers_in for nginx forwarding, then immediately delegates to process_header. process_header runs an infinite loop calling ngx_http_parse_header_line() pushing each header onto u->headers_in.headers list with hash/key/value/lowcase_key fields, running registered upstream header handlers via umcf->headers_in_hash lookup, logging debug headers, returning NGX_OK on NGX_HTTP_PARSE_HEADER_DONE or NGX_AGAIN if more data needed.
 */


#include "proxy_internal.h"

/* ---- Function: webdav_proxy_reinit_request() ----

 * WHAT: Resets per-request proxy context status to zero and switches nginx upstream process_header callback from status-line parser to header-loop parser. Returns NGX_OK on success or NGX_ERROR if ctx not found.

 * WHY: After request creation, the first response data arrives as a partial HTTP/1.x response starting with status line — nginx needs to parse that before headers. This function initializes the state machine by clearing status fields and registering the correct next callback (process_header) so the parser knows what stage it's in.

 * HOW: Get per-request ctx via ngx_http_get_module_ctx(r,module); if NULL return NGX_ERROR; memzero ctx->status to clear previous state; set r->upstream->process_header = webdav_proxy_process_header to switch callback chain. */

ngx_int_t
webdav_proxy_reinit_request(ngx_http_request_t *r)
{
    webdav_proxy_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) return NGX_ERROR;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

    r->upstream->process_header = webdav_proxy_process_header;
    return NGX_OK;
}

/* ---- Function: webdav_proxy_process_status_line() ----

 * WHAT: Parses the backend HTTP/1.x status line from upstream buffer — extracts status code and reason phrase into ctx->status via ngx_http_parse_status_line(), copies status_line string into u->headers_in for nginx forwarding, logs debug status, then immediately delegates to process_header. Returns NGX_AGAIN if more data needed, NGX_HTTP_UPSTREAM_INVALID_HEADER on parse error (502), or NGX_OK after delegating.

 * WHY: The first bytes of backend response form the HTTP/1.x status line — nginx needs this parsed before headers so it can set r->headers_out.status_n for client forwarding. This callback bridges between request creation and header parsing by extracting status code into ctx->status and u->state/u->headers_in.

 * HOW: Get ctx from per-request module context; call ngx_http_parse_status_line(r,&u->buffer,&ctx->status) — if NGX_AGAIN return, if NGX_ERROR log error and return invalid header (502); copy ctx->status.code into u->state->status and u->headers_in.status_n; allocate status_line string from ctx->status.start..end via ngx_pnalloc+ngx_memcpy; debug-log status; set process_header to webdav_proxy_process_header and immediately call it. */

ngx_int_t
webdav_proxy_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    webdav_proxy_ctx_t    *ctx;
    size_t                 len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) return NGX_ERROR;

    u  = r->upstream;
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) return NGX_AGAIN;

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav_proxy: upstream sent no valid HTTP/1.x header");
        /* Treat as 502 */
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len  = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) return NGX_ERROR;
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: upstream status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = webdav_proxy_process_header;
    return webdav_proxy_process_header(r);
}

/* ---- Function: webdav_proxy_process_header() ----

 * WHAT: Infinite loop parsing backend HTTP response headers — calls ngx_http_parse_header_line() extracting each header's name/value into u->headers_in.headers list, runs registered upstream header handlers via umcf->headers_in_hash lookup for known headers (Content-Length/Content-Type etc.), debug-logs each header, returns NGX_OK on header completion or NGX_AGAIN if more data needed.

 * WHY: After status line parsing, backend response contains multiple HTTP headers that nginx must relay to the client — Content-Length determines body size, Location triggers redirect, Content-Type sets response MIME type. The upstream module's headers_in_hash maps known header hashes to handler functions (e.g., ngx_http_upstream_process_content_length) that set u->headers_in fields.

 * HOW: Loop calling ngx_http_parse_header_line(r,&u->buffer,1); if NGX_OK push new header onto u->headers_in.headers list via ngx_list_push; set hash/key/value/lowcase_key from parser offsets; run registered handler via ngx_hash_find(umcf->headers_in_hash,h->hash,h->lowcase_key,h->key.len) if matched; debug-log header name+value; continue loop. If NGX_HTTP_PARSE_HEADER_DONE log completion and return NGX_OK. If NGX_AGAIN return (more data needed). If other error code log invalid header line and return NGX_HTTP_UPSTREAM_INVALID_HEADER. */

ngx_int_t
webdav_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_table_elt_t                 *h;
    ngx_http_upstream_t             *u;
    ngx_http_upstream_header_t      *hh;
    ngx_http_upstream_main_conf_t   *umcf;

    u    = r->upstream;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for (;;) {
        rc = ngx_http_parse_header_line(r, &u->buffer, 1);

        if (rc == NGX_OK) {
            h = ngx_list_push(&u->headers_in.headers);
            if (h == NULL) return NGX_ERROR;

            h->hash      = r->header_hash;
            h->key.len   = r->header_name_end - r->header_name_start;
            h->key.data  = r->header_name_start;
            h->key.data[h->key.len] = '\0';
            h->value.len  = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) return NGX_ERROR;
            ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xrootd_webdav_proxy upstream header: \"%V: %V\"",
                           &h->key, &h->value);
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xrootd_webdav_proxy: upstream headers done");
            return NGX_OK;
        }

        if (rc == NGX_AGAIN) return NGX_AGAIN;

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav_proxy: upstream sent invalid header line");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

/* ---- Function: webdav_proxy_abort_request() ----

 * WHAT: Void cleanup callback invoked when upstream request fails — logs debug message indicating abort. Returns nothing.

 * WHY: nginx upstream API requires an abort callback to clean up state when the backend connection fails or the client cancels. Proxy mode only needs a debug log since ctx carries minimal state (just status field) and is freed on finalize.

 * HOW: Single ngx_log_debug0 call logging event name. */

void
webdav_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: abort request");
}

/* ---- Function: webdav_proxy_finalize_request() ----

 * WHAT: Void cleanup callback invoked when upstream request completes (success or error) — logs debug message with final return code. Returns nothing.

 * WHY: nginx upstream API requires a finalize callback to clean up state after the backend connection finishes. Proxy mode only needs a debug log since ctx carries minimal state and is freed from r->pool on completion.

 * HOW: Single ngx_log_debug1 call logging event name + final rc code value. */

void
webdav_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: finalize request rc=%i", rc);
}
