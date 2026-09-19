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

#ifndef BRIX_HOST_FORMAT_H
#define BRIX_HOST_FORMAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Return 1 if `host` is a bare IPv6 literal that needs bracketing: non-NULL,
 * non-empty, not already '['-prefixed, and contains ':'.  A hostname never
 * contains ':' and an IPv4 dotted-quad never contains ':', so the colon test is
 * a sufficient discriminator for a host-only string (it also catches zone-id
 * link-local forms like "fe80::1%eth0" that inet_pton would reject).
 */
int brix_host_is_ipv6_literal(const char *host);

/*
 * Fold an IPv4-mapped IPv6 literal ("::ffff:10.0.0.1") down to the IPv4 address
 * it names ("10.0.0.1"), into out[sz] (NUL-terminated).  Every other host — a
 * hostname, a dotted quad, a genuine IPv6 literal — is copied through byte for
 * byte, so a caller may run it over any host unconditionally.  Expects the bare
 * form the module stores (ngx_parse_url and tpc parse.c both strip the brackets
 * off "[::1]"); a still-bracketed string is not an address to inet_pton and so
 * passes through.  Returns 1 when out holds a host, 0 on NULL/overflow (out is
 * left a valid empty string when sz > 0).
 *
 * The two spellings name the same machine but are NOT the same bytes to anything
 * that compares addresses rather than resolving them — an X.509 iPAddress SAN
 * for an IPv4 host is the 4-byte form, and OpenSSL's IP match is a memcmp of
 * equal lengths.  A peer named by the mapped form therefore matches no IPv4 SAN
 * that exists.  Folding first is what lets such a name be checked at all.
 */
int brix_host_unmap_v4(const char *host, char *out, size_t sz);

/*
 * Write "[host]" for an IPv6 literal, else "host", into out[sz] (NUL-terminated).
 * For the kXR_redirect body, where the port is carried in a separate field.
 * Returns bytes written (excluding the NUL), or 0 on NULL/overflow (out is left
 * as a valid empty string when sz > 0).
 */
size_t brix_format_host(const char *host, char *out, size_t sz);

/*
 * Write "[host]:port" for an IPv6 literal, else "host:port", into out[sz]
 * (NUL-terminated).  Returns bytes written (excluding the NUL), or 0 on
 * NULL/overflow.
 */
size_t brix_format_host_port(const char *host, uint16_t port,
                               char *out, size_t sz);

#endif /* BRIX_HOST_FORMAT_H */
