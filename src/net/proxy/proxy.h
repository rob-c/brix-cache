#ifndef BRIX_PROXY_PROXY_H
#define BRIX_PROXY_PROXY_H

/*
 * proxy.h — public API for the XRootD transparent proxy module.
 *
 * When brix_proxy is enabled for a server block, every post-login opcode is
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

#include "core/ngx_brix_module.h"

/* Opaque: full definition in proxy_internal.h */
typedef struct brix_proxy_ctx_s brix_proxy_ctx_t;

/*
 * brix_proxy_dispatch — intercept and forward an opcode to the upstream.
 *
 * Called from handshake/dispatch.c immediately after session opcodes are
 * handled but before the local read/write dispatchers, whenever
 * conf->proxy.enable is set and ctx->login.logged_in is true.
 *
 * Returns NGX_OK / NGX_ERROR / NGX_DONE (never BRIX_DISPATCH_CONTINUE).
 */
ngx_int_t brix_proxy_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_proxy_dispatch_to — brix_proxy_dispatch with an explicit target.
 *
 * Phase-115 W2.1 (`brix_cms_response proxy`): a manager that has just selected
 * a data server for the in-flight request creates the session's proxy pinned
 * to host:port instead of the configured upstream list, then forwards exactly
 * as brix_proxy_dispatch does (the request is saved and replayed once the
 * upstream bootstrap completes).  host == NULL selects the configured upstream.
 * A session that already carries a proxy keeps it: the pin is decided once, on
 * the first selection, and every later opcode rides the same upstream (see
 * handshake/dispatch.c — the forwarding gate also opens for ctx->proxy != NULL).
 */
ngx_int_t brix_proxy_dispatch_to(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *host, uint16_t port);

/*
 * brix_proxy_session_may_reselect — is this session's pin currently movable?
 *
 * True only when the upstream is bootstrapped and quiescent (XRD_PX_IDLE, no
 * file handle open).  handshake/dispatch.c uses it to decide whether a
 * SELECTION-pinned session (ctx->proxy != NULL while conf->proxy.enable is
 * off) should fall through to the manager for this opcode instead of being
 * short-circuited onto its current upstream: without that fall-through the
 * manager never runs again and the pin, decided on the first selection, is
 * permanent.  A statically configured proxy (conf->proxy.enable) is never
 * asked — it has no manager to fall through to.
 */
int brix_proxy_session_may_reselect(const brix_proxy_ctx_t *proxy);

/*
 * brix_conf_set_proxy_upstream — nginx directive handler for
 * "brix_proxy_upstream host[:port]".  Parses the value and appends to
 * proxy_upstreams; also sets proxy_host / proxy_port for backward compat.
 * May appear multiple times to register multiple backends (round-robin).
 */
char *brix_conf_set_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * brix_conf_set_proxy_auth — nginx directive handler for
 * "brix_proxy_auth anonymous|forward|sss".
 */
char *brix_conf_set_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * brix_conf_set_proxy_login_user — nginx directive handler for
 * "brix_proxy_login_user anonymous|passthrough|fixed:<name>".
 */
char *brix_conf_set_proxy_login_user(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * brix_conf_set_proxy_sss_identity — nginx directive handler for
 * "brix_tap_proxy_sss_identity keytab|client" (release-2.0 F9).
 */
char *brix_conf_set_proxy_sss_identity(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * brix_conf_set_proxy_path_rewrite — nginx directive handler for
 * "brix_tap_proxy_path_rewrite /strip-prefix /add-prefix".
 */
char *brix_conf_set_proxy_path_rewrite(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * brix_proxy_cleanup — release upstream connection and all proxy resources.
 * Safe to call even if proxy was never fully connected.
 * Called from brix_on_disconnect().
 */
void brix_proxy_cleanup(brix_proxy_ctx_t *proxy);

#endif /* BRIX_PROXY_PROXY_H */
