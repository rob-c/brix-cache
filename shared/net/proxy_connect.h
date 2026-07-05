/* proxy_connect.h — HTTP CONNECT tunnel handshake over a connected socket
 * (pure C, no ngx, no alloc).
 *
 * WHAT: given a socket already connected to a proxy, negotiate a CONNECT tunnel
 *       to host:port so any TCP protocol (root://, TLS, http) can then run over
 *       the fd transparently.
 * WHY:  the hand-rolled brix clients (root://, roots://, WebDAV) connect via
 *       sock.c's brix_tcp_connect; routing them through an env proxy means one
 *       CONNECT handshake at connect time. Kept separate from sock.c so it is
 *       testable against a real proxy without linking client/lib.
 * HOW:  send "CONNECT host:port HTTP/1.1", read headers to the blank line, and
 *       require a 200 status. poll-based timeouts; works on blocking or
 *       non-blocking fds.
 */
#ifndef BRIX_PROXY_CONNECT_H
#define BRIX_PROXY_CONNECT_H

#include <stddef.h>

/* Negotiate a CONNECT tunnel to `host:port` over `fd` (already connected to the
 * proxy). Returns 0 on a 200 response; -1 on error, with a short message in
 * `err` (if non-NULL). */
int brix_proxy_connect_tunnel(int fd, const char *host, int port, int timeout_ms,
                              char *err, size_t errlen);

#endif /* BRIX_PROXY_CONNECT_H */
