/*
 * tls_internal.h - private split contract for tls.c and tls_io.c.
 * Not a public API: include only from lib/net/.
 *
 * tls.c owns session setup (handshake, SSL_CTX, teardown, introspection) and
 * tls_io.c owns byte transfer.  Both need the same two primitives, so they live
 * in tls.c and are declared here rather than duplicated: one error-formatting
 * path means an OpenSSL failure reads the same whoever reported it, and one
 * poll wrapper means the WANT_READ/WANT_WRITE retry discipline cannot drift
 * between the handshake and the transfer loops.
 */
#ifndef XRDC_TLS_INTERNAL_H
#define XRDC_TLS_INTERNAL_H

#include "brix.h"

/* Drain OpenSSL's error queue into *st as "<what>: <reason>". */
void brix_tls_err(brix_status *st, int kxr, const char *what);

/* poll one fd for `events`; >0 ready, 0 timeout, <0 error (EINTR retried). */
int brix_tls_wait_io(int fd, short events, int timeout_ms);

#endif /* XRDC_TLS_INTERNAL_H */
