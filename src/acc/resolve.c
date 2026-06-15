/*
 * resolve.c — reverse-DNS peer resolution for XrdAcc host rules.
 *
 * WHAT: xrootd_acc_resolve_peer() reverse-resolves a peer socket address to a
 *   hostname via getnameinfo(NI_NAMEREQD) so authdb `h <host>` (exact) and
 *   `h .domain` (suffix) records can match.  Writes the FQDN into `buf` and
 *   returns it on success; returns NULL on failure so the caller can fall back
 *   to the numeric peer IP.
 *
 * WHY: XrdAcc (XrdAccAccess::Resolve) matches host/domain records against the
 *   client's resolved hostname, not its IP.  Without a reverse lookup those
 *   records never fire.  Resolution is opt-in (xrootd_acc_resolve_hosts) and
 *   cached once per connection by the caller, which bounds the blocking-DNS
 *   cost and the DoS surface — the same cost-control XrdAcc gets by resolving
 *   only when a host looks like a raw IP literal and the authdb has host rules.
 *
 * HOW: a single getnameinfo() with NI_NAMEREQD — no numeric fallback, because
 *   we want NULL (not the IP) when there is no PTR record, so the caller can
 *   distinguish "unresolved" from "resolved to a name".  This file owns the
 *   only <netdb.h> dependency; callers pass a plain stack buffer.
 */

#include "acc.h"
#include <netdb.h>
#include <sys/socket.h>

const char *
xrootd_acc_resolve_peer(struct sockaddr *sa, socklen_t salen,
                        char *buf, size_t buflen)
{
    if (sa == NULL || buf == NULL || buflen == 0) {
        return NULL;
    }

    if (getnameinfo(sa, salen, buf, (socklen_t) buflen, NULL, 0,
                    NI_NAMEREQD) != 0) {
        return NULL;
    }

    return buf;
}
