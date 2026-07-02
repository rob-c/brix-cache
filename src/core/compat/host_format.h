/*
 * host_format.h — bracket IPv6 literal hosts for host:port wire/header strings.
 *
 * XRootD redirect/locate wire strings, HTTP Host: headers, and rebuilt root://
 * URLs all carry a host[:port].  A bare IPv6 literal contains colons (e.g.
 * "2001:db8::1"), so it MUST be bracketed ("[2001:db8::1]") or a client parsing
 * host:port mis-reads the address.  The module stores the canonical *bare*
 * address everywhere (ngx_sock_ntop(...,0), c->addr_text, and ngx_parse_url all
 * yield bare IPv6); these helpers bracket *on emit*.  IPv4 addresses, hostnames,
 * and already-bracketed strings pass through unchanged (none contain a bare ':').
 *
 * Centralises the bracket format already proven at src/read/locate.c (the
 * AF_INET6 locate branch emits "S%c[%s]:%d") so every emit site shares one
 * implementation.  Pure C (no nginx types) so it is trivially unit-testable.
 */

#ifndef XROOTD_HOST_FORMAT_H
#define XROOTD_HOST_FORMAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Return 1 if `host` is a bare IPv6 literal that needs bracketing: non-NULL,
 * non-empty, not already '['-prefixed, and contains ':'.  A hostname never
 * contains ':' and an IPv4 dotted-quad never contains ':', so the colon test is
 * a sufficient discriminator for a host-only string (it also catches zone-id
 * link-local forms like "fe80::1%eth0" that inet_pton would reject).
 */
int xrootd_host_is_ipv6_literal(const char *host);

/*
 * Write "[host]" for an IPv6 literal, else "host", into out[sz] (NUL-terminated).
 * For the kXR_redirect body, where the port is carried in a separate field.
 * Returns bytes written (excluding the NUL), or 0 on NULL/overflow (out is left
 * as a valid empty string when sz > 0).
 */
size_t xrootd_format_host(const char *host, char *out, size_t sz);

/*
 * Write "[host]:port" for an IPv6 literal, else "host:port", into out[sz]
 * (NUL-terminated).  Returns bytes written (excluding the NUL), or 0 on
 * NULL/overflow.
 */
size_t xrootd_format_host_port(const char *host, uint16_t port,
                               char *out, size_t sz);

#endif /* XROOTD_HOST_FORMAT_H */
