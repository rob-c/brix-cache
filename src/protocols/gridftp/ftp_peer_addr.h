/*
 * ftp_peer_addr.h — canonical GridFTP transport-peer address comparison.
 *
 * WHAT: normalizes IPv4, IPv6, and IPv4-mapped IPv6 socket addresses and
 * compares their host identity while deliberately ignoring transport ports.
 *
 * WHY: passive GridFTP data sockets inherit the authenticated control
 * session's filesystem authority.  A clear data socket therefore has to come
 * from the same transport peer; accepting the first connector lets a racing
 * host steal a download or inject an upload.  One predicate shared by MODE S
 * and MODE E prevents representation differences from splitting that boundary.
 *
 * HOW: each supported sockaddr is copied into a fixed canonical form.  Mapped
 * IPv6 addresses become their four-byte IPv4 address; native IPv6 retains its
 * scope identifier so equal link-local bytes on different interfaces do not
 * alias.  Unknown families, short structures, and NULL inputs fail closed.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    int      family;
    uint8_t  bytes[16];
    uint32_t scope_id;
} brix_ftp_peer_addr_t;


/* ---- Canonicalize one transport-peer address ----
 *
 * WHAT: Writes a port-independent canonical address to `out` and returns 1;
 * returns 0 for malformed, unsupported, or absent input.
 *
 * WHY: IPv4 and IPv4-mapped IPv6 are two wire representations of the same
 * host and must make the same security decision, while truncated sockaddrs
 * must never be interpreted from uninitialized bytes.
 *
 * HOW: 1. Validate pointers and the family-specific structure length.
 *      2. Copy IPv4 bytes directly or fold a mapped IPv6 address to IPv4.
 *      3. Preserve all native IPv6 bytes and its scope identifier.
 */
static inline int
brix_ftp_peer_addr_canonical(const struct sockaddr *address,
    socklen_t address_len, brix_ftp_peer_addr_t *out)
{
    const struct sockaddr_in  *address4;
    const struct sockaddr_in6 *address6;

    if (address == NULL || out == NULL
        || address_len < (socklen_t) sizeof(struct sockaddr))
    {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    if (address->sa_family == AF_INET) {
        if (address_len < (socklen_t) sizeof(*address4)) {
            return 0;
        }
        address4 = (const struct sockaddr_in *) address;
        out->family = AF_INET;
        memcpy(out->bytes, &address4->sin_addr, sizeof(address4->sin_addr));
        return 1;
    }

    if (address->sa_family != AF_INET6
        || address_len < (socklen_t) sizeof(*address6))
    {
        return 0;
    }

    address6 = (const struct sockaddr_in6 *) address;
    if (IN6_IS_ADDR_V4MAPPED(&address6->sin6_addr)) {
        out->family = AF_INET;
        memcpy(out->bytes, &address6->sin6_addr.s6_addr[12],
               sizeof(struct in_addr));
        return 1;
    }

    out->family = AF_INET6;
    memcpy(out->bytes, &address6->sin6_addr, sizeof(address6->sin6_addr));
    out->scope_id = address6->sin6_scope_id;
    return 1;
}


/* ---- Compare two transport peers without their ephemeral ports ----
 *
 * WHAT: Returns 1 only when both inputs are valid supported socket addresses
 * naming the same canonical host; otherwise returns 0.
 *
 * WHY: a passive data connection uses a new port by design, so port equality
 * would reject every legitimate transfer, while raw family/byte comparison
 * would let mapped-address spelling create inconsistent admission decisions.
 *
 * HOW: 1. Canonicalize both inputs with the fail-closed helper above.
 *      2. Require the same canonical family and IPv6 scope.
 *      3. Compare exactly four IPv4 bytes or sixteen IPv6 bytes.
 */
static inline int
brix_ftp_peer_addr_equal(const struct sockaddr *left, socklen_t left_len,
    const struct sockaddr *right, socklen_t right_len)
{
    brix_ftp_peer_addr_t left_address;
    brix_ftp_peer_addr_t right_address;
    size_t               byte_count;

    if (!brix_ftp_peer_addr_canonical(left, left_len, &left_address)
        || !brix_ftp_peer_addr_canonical(right, right_len, &right_address))
    {
        return 0;
    }
    if (left_address.family != right_address.family
        || left_address.scope_id != right_address.scope_id)
    {
        return 0;
    }

    byte_count = left_address.family == AF_INET
                 ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    return memcmp(left_address.bytes, right_address.bytes, byte_count) == 0;
}
