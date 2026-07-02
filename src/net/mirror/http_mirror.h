/*
 * http_mirror.h — Phase 24 HTTP/WebDAV traffic mirror.
 *
 * Off by default.  When `xrootd_mirror_url http[s]://host:port` is configured on
 * a WebDAV location, a qualifying READ request (GET/HEAD/PROPFIND/OPTIONS, per
 * xrootd_mirror_methods) spawns one fire-and-forget background subrequest per
 * shadow target.  The primary request is served to the client normally and is
 * never delayed; the shadow response body is discarded and its status compared
 * to the primary to detect divergence.
 *
 * Two phase handlers implement this:
 *   - xrootd_http_mirror_precontent_handler (NGX_HTTP_PRECONTENT_PHASE) does
 *     both jobs: on the MAIN request it fires the background subrequests, and
 *     on each mirror SUBREQUEST it takes the request over and proxies it to the
 *     shadow target with credentials stripped.  Running the takeover before the
 *     content phase avoids any dependence on content-phase handler ordering.
 *   - xrootd_http_mirror_log_handler (NGX_HTTP_LOG_PHASE) records the primary's
 *     final status for the divergence comparison.
 * Both are registered from src/webdav/postconfig.c.
 */
#ifndef XROOTD_MIRROR_HTTP_MIRROR_H
#define XROOTD_MIRROR_HTTP_MIRROR_H

#include "webdav/webdav.h"

/* PRECONTENT_PHASE handler with two roles keyed on r vs r->main:
 *   - MAIN request: if mirroring is enabled, the method/write/loop/sample gates
 *     pass, and it has not already fired (ctx->mirror_fired), fire one background
 *     subrequest per shadow target.  For body methods (PUT) it first buffers the
 *     client body (returns NGX_DONE to suspend the main request, fires from the
 *     body handler); otherwise it fires inline and returns NGX_DECLINED so the
 *     main request proceeds to its content handler — the client is never delayed.
 *   - mirror SUBREQUEST (ctx->is_mirror): takes the request over and proxies it
 *     to the shadow with credentials stripped.
 * Returns NGX_DECLINED to pass control on (the common case), NGX_DONE while the
 * body is being read, the proxy rc on a shadow subreq, or an HTTP error status.
 * May allocate and attach the webdav req ctx on r->pool. */
ngx_int_t xrootd_http_mirror_precontent_handler(ngx_http_request_t *r);

/* LOG_PHASE handler: on the MAIN request only, if a mirror was fired, stamp the
 * primary's final HTTP status into ctx->primary_status for divergence
 * comparison.  Always returns NGX_OK; no-op for subrequests. */
ngx_int_t xrootd_http_mirror_log_handler(ngx_http_request_t *r);

/* Built at WebDAV merge time when the mirror has at least one target:
 * configures mirror_upstream_conf (timeouts, bufs, hide-headers hash, TLS). */
ngx_int_t xrootd_http_mirror_setup(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev);

/* Directive setters (registered in src/webdav/module.c). */

/* `xrootd_mirror_url <http[s]://host[:port][/path]>` setter: parses and resolves
 * the URL at config time and APPENDS a shadow target (host, port, ssl flag,
 * resolved sockaddr, Host-header value, url_base) to conf->mirror.targets.
 * Called once per directive occurrence, so multiple targets accumulate up to
 * XROOTD_MIRROR_MAX_TARGETS.  Returns NGX_CONF_OK, or NGX_CONF_ERROR on a bad
 * scheme, unresolvable host, the target cap, or allocation failure. */
char *xrootd_http_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* `xrootd_mirror_methods <METHOD>...` setter: OR-parses the listed HTTP/WebDAV
 * method names into conf->mirror.method_mask, REPLACING any prior value (not
 * additive).  Write methods still require xrootd_mirror_writes to actually
 * mirror.  Returns NGX_CONF_OK, or NGX_CONF_ERROR on an unrecognized method. */
char *xrootd_http_mirror_set_methods(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* XROOTD_MIRROR_HTTP_MIRROR_H */
