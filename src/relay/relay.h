#ifndef NGX_XROOTD_RELAY_H
#define NGX_XROOTD_RELAY_H

/*
 * relay.h — transparent pass-through relay for the stream xrootd listener.
 *
 * WHAT: when xrootd_transparent_proxy host:port is configured, every connection
 *   on the port is relayed verbatim to an upstream official XRootD server — the
 *   client's auth handshake (anonymous / token / x509 / GSI) travels end-to-end,
 *   so the relay holds no credential. In parallel a non-consuming tap decodes the
 *   cleartext XRootD frames it forwards and emits them to a JSON audit log.
 *
 * WHY: operators want to monitor the protocol metadata (opcodes, paths, handles)
 *   crossing into a backend storage server without terminating auth or altering
 *   the byte stream. A passive tap over a verbatim relay does exactly that, for
 *   whatever travels in cleartext (classic root:// auth-without-bulk-encryption).
 *
 * HOW: a small bidirectional buffered TCP relay (modeled on src/handoff/handoff.c)
 *   plus a per-direction xrootd_tap_stream that is fed each freshly-recv'd chunk.
 *   No XRootD framing is terminated; the relay just pumps bytes and observes.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/* Directive handler: xrootd_transparent_proxy host:port (SRV_CONF|TAKE1).
 * Resolves the target into conf->relay_addr at config time. */
char *xrootd_conf_set_transparent_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Begin a transparent relay: the connection becomes a raw, tapped byte relay to
 * the configured upstream XRootD server. Engages before any XRootD frame is read.
 * Returns NGX_OK when the relay owns the connection (the caller returns without
 * finalizing), or NGX_ERROR on a setup failure. */
ngx_int_t xrootd_relay_start(ngx_stream_session_t *s, ngx_connection_t *c,
    void *srv_conf);

#endif /* NGX_XROOTD_RELAY_H */
