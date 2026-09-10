/*
 * resolve.h — the client's ONE name-resolution seam (phase-116).
 *
 * WHAT: brix_resolve() turns host:port into an ordered list of socket
 *       addresses; brix_resolve_ntop() / brix_resolve_port() render one back
 *       to numeric text.  Every client program — libbrix, the diag tools, the
 *       standalone fault proxy and (through brixcvmfs_curl_pin.c) libcurl —
 *       resolves here and nowhere else.
 * WHY:  getaddrinfo() used to be scattered over eight files, each with its
 *       own hints, its own failure mapping and no memory of the last answer.
 *       One path means one place that honours the process family hint
 *       (netpref.c demotion), one place that tells a transient resolver
 *       failure (EAI_AGAIN) from a permanent one, one bounded answer cache
 *       (what libcurl's private cache gave the cvmfs path before it was
 *       pinned), and one symbol for tools/ci/check_dns_seam.py to pin:
 *       getaddrinfo() appears in resolve.c and nowhere else under client/.
 * HOW:  libc getaddrinfo() under a small mutex-guarded cache.  The client is
 *       synchronous and has no event loop, so a blocking lookup is the right
 *       tool — phase-116 forbids the scatter, not the call.  libc reads
 *       /etc/resolv.conf itself (glibc re-reads it when its mtime changes),
 *       so the client follows the same runtime file as the server.  No
 *       libbrix dependency: the fault proxy compiles this file standalone.
 */
#ifndef BRIX_CLIENT_NET_RESOLVE_H
#define BRIX_CLIENT_NET_RESOLVE_H

#include <stddef.h>
#include <sys/socket.h>

/* candidates returned per lookup (glibc rarely hands back more than 8) */
#define BRIX_RESOLVE_MAX        16
/* longest numeric text brix_resolve_ntop() writes, NUL included */
#define BRIX_RESOLVE_NTOP_LEN   64
/* seconds a positive answer is reused; $XRDC_RESOLVE_CACHE_S overrides */
#define BRIX_RESOLVE_CACHE_S    60

/* hint flags — a subset of AI_*, so callers need no <netdb.h> */
#define BRIX_RESOLVE_ADDRCONFIG 0x1u  /* only families this host has configured */
#define BRIX_RESOLVE_PASSIVE    0x2u  /* a bind address: host NULL = wildcard */
#define BRIX_RESOLVE_NUMERIC    0x4u  /* literal only: never ask DNS */

typedef struct {
    struct sockaddr_storage ss;
    socklen_t               len;
    int                     family;    /* AF_INET / AF_INET6 */
    int                     socktype;
    int                     protocol;
} brix_resolve_addr;

typedef struct {
    int         transient;  /* 1 = EAI_AGAIN: a retry may succeed */
    const char *text;       /* gai_strerror() of the failure (static storage) */
} brix_resolve_err;

/* Resolve host:port into up to `max` candidates, in resolver order.
 * family: AF_UNSPEC / AF_INET / AF_INET6 (connect paths pass
 * brix_netpref_family()); socktype SOCK_STREAM / SOCK_DGRAM.
 * Returns the candidate count (>= 1); 0 when the name has no address (`err`
 * filled when non-NULL); -1 on a bad argument.  Positive answers are cached
 * for BRIX_RESOLVE_CACHE_S seconds per (host, port, family, socktype, flags);
 * literals (BRIX_RESOLVE_NUMERIC) and failures are never cached. */
int brix_resolve(const char *host, int port, int family, int socktype,
                 unsigned flags, brix_resolve_addr *out, int max,
                 brix_resolve_err *err);

/* Numeric text of `sa` ("::1", "10.0.0.1") into buf; "" when the family is
 * not IP or buf is too small.  Returns buf.  Never consults DNS. */
const char *brix_resolve_ntop(const struct sockaddr *sa, socklen_t len,
                              char *buf, size_t buflen);

/* Host-order port of an IP `sa`; -1 for any other family. */
int brix_resolve_port(const struct sockaddr *sa, socklen_t len);

#endif /* BRIX_CLIENT_NET_RESOLVE_H */
