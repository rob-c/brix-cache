#pragma once

/*
 * proxy.h — public API for the XRootD transparent proxy module.
 *
 * When xrootd_proxy is enabled for a server block, every post-login opcode is
 * forwarded to the configured upstream XRootD server.  The proxy:
 *
 *   1. Authenticates the client normally (token, GSI, sss, or anonymous).
 *   2. Lazily connects to the upstream on the first non-session opcode and
 *      completes a standard XRootD bootstrap (handshake + protocol + login).
 *   3. Translates client-assigned file handles to upstream-assigned ones for
 *      open/read/write/close opcodes.
 *   4. Relays upstream responses verbatim (or with fhandle rewriting) back to
 *      the client, preserving the client's streamid.
 *   5. Collects per-request metrics and emits a JSON audit record at close.
 *
 * The upstream connection is unauthenticated (anonymous login) in Phase 1;
 * auth bridging (GSI delegation, token forwarding) is a Phase 4 concern.
 */

#include "../ngx_xrootd_module.h"

/* Opaque: full definition in proxy_internal.h */
typedef struct xrootd_proxy_ctx_s xrootd_proxy_ctx_t;

/*
 * xrootd_proxy_dispatch — intercept and forward an opcode to the upstream.
 *
 * Called from handshake/dispatch.c immediately after session opcodes are
 * handled but before the local read/write dispatchers, whenever
 * conf->proxy_enable is set and ctx->logged_in is true.
 *
 * Returns NGX_OK / NGX_ERROR / NGX_DONE (never XROOTD_DISPATCH_CONTINUE).
 */
ngx_int_t xrootd_proxy_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_conf_set_proxy_upstream — nginx directive handler for
 * "xrootd_proxy_upstream host[:port]".  Parses the value and appends to
 * proxy_upstreams; also sets proxy_host / proxy_port for backward compat.
 * May appear multiple times to register multiple backends (round-robin).
 */
char *xrootd_conf_set_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * xrootd_conf_set_proxy_auth — nginx directive handler for
 * "xrootd_proxy_auth anonymous|forward|sss".
 */
char *xrootd_conf_set_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * xrootd_conf_set_proxy_path_rewrite — nginx directive handler for
 * "xrootd_proxy_path_rewrite /strip-prefix /add-prefix".
 */
char *xrootd_conf_set_proxy_path_rewrite(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * xrootd_proxy_cleanup — release upstream connection and all proxy resources.
 * Safe to call even if proxy was never fully connected.
 * Called from xrootd_on_disconnect().
 */
void xrootd_proxy_cleanup(xrootd_proxy_ctx_t *proxy);
