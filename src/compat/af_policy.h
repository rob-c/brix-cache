#ifndef NGX_XROOTD_COMPAT_AF_POLICY_H
#define NGX_XROOTD_COMPAT_AF_POLICY_H

/*
 * af_policy.h — outbound address-family policy for cache/proxy origin connects.
 *
 * WHAT: a 3-value policy (auto/inet/inet6) plus a string parser. The enum values
 *   ARE the AF_* constants, so a policy assigns straight into a getaddrinfo
 *   hints.ai_family with no mapping table.
 * WHY: a dual-stack/IPv6 cache node must be able to reach an IPv4-only or
 *   IPv6-only origin. Constraining the family of the OUTBOUND resolve is the whole
 *   mechanism — the listen side stays dual-stack via nginx `listen`.
 * HOW: header-only, pure, no nginx deps, so it is shared by the directive handler,
 *   the resolver, and a standalone unit test.
 */

#include <sys/socket.h>   /* AF_UNSPEC / AF_INET / AF_INET6 */
#include <stddef.h>
#include <string.h>

typedef enum {
    XROOTD_AF_AUTO  = AF_UNSPEC,   /* try every family (legacy default) */
    XROOTD_AF_INET  = AF_INET,     /* IPv4-only origin */
    XROOTD_AF_INET6 = AF_INET6     /* IPv6-only origin */
} xrootd_af_policy_t;

/* Parse "auto" | "inet" | "inet6" → policy value; -1 on any other token. */
static inline int
xrootd_af_policy_parse(const char *s, size_t len)
{
    if (len == 4 && memcmp(s, "auto", 4) == 0)  { return XROOTD_AF_AUTO; }
    if (len == 4 && memcmp(s, "inet", 4) == 0)  { return XROOTD_AF_INET; }
    if (len == 5 && memcmp(s, "inet6", 5) == 0) { return XROOTD_AF_INET6; }
    return -1;
}

#endif /* NGX_XROOTD_COMPAT_AF_POLICY_H */
