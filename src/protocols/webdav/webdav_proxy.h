/*
 * webdav/webdav_proxy.h
 *
 * WebDAV reverse-proxy mode: the content-phase upstream handler and the
 * upstream-backend config parsing/build helpers (single-URL back-compat parser,
 * multi-backend builder, and the brix_webdav_proxy_upstream directive setter).
 * Split out of webdav.h so the proxy surface is grouped by concern and
 * individually reviewable.  Includes webdav.h for the shared request/config
 * types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_PROXY_H
#define NGX_HTTP_BRIX_WEBDAV_PROXY_H

#include "webdav.h"

/* Upstream HTTP(S) proxy */
/* Content-phase handler (proxy mode): create the nginx upstream, pick a backend
 * (dynamic SHM pool or static round-robin array), set ssl per backend, and start
 * the request via brix_http_read_body.  Returns NGX_DONE on the async upstream
 * path; an NGX_HTTP_* status (500 OOM, 503 no live backend) on setup failure. */
ngx_int_t webdav_proxy_handler(ngx_http_request_t *r);
/* Backward-compat single-URL config parser; thin wrapper over
 * webdav_proxy_build_backends.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf);
/* Postconfig: build conf->upstream_backends (cf->pool) from upstream_urls (or the
 * legacy single upstream_url), apply upstream_conf timeout/buffer defaults, wire
 * the TLS ctx, and point the legacy upstream_* aliases at backend[0].  NGX_ERROR
 * (fails nginx -t) when no usable backend; NGX_OK otherwise. */
ngx_int_t webdav_proxy_build_backends(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf);
/* Directive setter: brix_webdav_proxy_upstream <url> [<url> ...]; */
char *webdav_conf_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* NGX_HTTP_BRIX_WEBDAV_PROXY_H */
