#ifndef NGX_BRIX_HANDOFF_H
#define NGX_BRIX_HANDOFF_H

/*
 * handoff.h — single-port protocol handoff for the stream xrootd listener.
 *
 * WHAT: when a connection on a root:// stream port opens with a non-XRootD first
 *   byte (the XRootD client hello always begins with a zero streamid word, so any
 *   HTTP method letter or TLS ClientHello 0x16 is unambiguously not XRootD) and
 *   brix_http_handoff is configured, the connection is transparently spliced to
 *   a local HTTP/WebDAV listener instead of being closed.
 *
 * WHY: stock xrootd MULTIPLEXES HTTP (XrdHttp) on its data port, so a stock
 *   XrdHttp redirector redirects an HTTP client to a data server's *data* port.
 *   nginx serves WebDAV on a SEPARATE http{} port, so without this an nginx data
 *   node behind a stock redirector is unreachable over WebDAV.  Detecting the
 *   protocol on the data port and forwarding HTTP to the node's own WebDAV
 *   listener makes one registered port serve both protocols, closing that gap.
 *
 * HOW: brix_http_handoff_start() dials conf->http_handoff_addr, replays the
 *   already-read prefix bytes, then runs a small bidirectional buffered TCP relay
 *   (no XRootD framing) until either side closes or the relay idles out.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/* Directive handler: brix_http_handoff host:port (NGX_STREAM_SRV_CONF|TAKE1).
 * Resolves the target into conf->http_handoff_addr at config time. */
char *brix_conf_set_http_handoff(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Begin a handoff: the connection becomes a raw relay to the configured local
 * HTTP/WebDAV listener.  `prefix`/`prefix_len` are the bytes already consumed
 * from the client while detecting the protocol (replayed to the upstream first).
 * Returns NGX_OK when the relay has taken ownership of the connection (the caller
 * must return without finalizing the session), or NGX_ERROR on a setup failure
 * (the caller falls back to closing the connection). */
ngx_int_t brix_http_handoff_start(ngx_stream_session_t *s,
    ngx_connection_t *c, void *srv_conf, u_char *prefix, size_t prefix_len);

#endif /* NGX_BRIX_HANDOFF_H */
