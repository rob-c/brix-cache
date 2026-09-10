/*
 * resolve.c — reverse-DNS the peer for `h <host>` / `h .domain` rule matching
 * (XrdAccAccess::Resolve).
 *
 * WHAT: A never-blocking probe of the phase-116 reverse-DNS cache for the
 *       peer's FQDN.  NGX_OK fills `buf` with the name; NGX_DECLINED means the
 *       address has no PTR record (or is not an IP address at all) so the
 *       caller keeps the numeric peer; NGX_AGAIN means the answer is not known
 *       yet — a background fill has been started so the next probe can answer.
 * WHY:  Every caller sits on the event loop (XrdAcc host rules, protbind host
 *       templates, `host` authentication), where the old getnameinfo() stalled
 *       the whole worker — the Phase 51 circuit breaker only bounded how often.
 *       Phase 116 moved the lookup off the loop: the stream accept path
 *       (connection/peer_name.c) and the HTTP PREACCESS phase
 *       (core/http/http_peer_name.c) wait for the answer before any rule runs,
 *       so by the time a decision is made this probe is a cache hit.  The
 *       AGAIN arm stays for callers reached without a wait (a hot reload that
 *       enabled the policy mid-session, an eviction between accept and the
 *       decision): they fall back to the numeric peer, and the fallback is
 *       counted so an operator can see it happening.
 * HOW:  brix_dns_reverse_cached() → on NGX_AGAIN, brix_dns_reverse_prefetch()
 *       under the server's DNS policy + BRIX_RESIL_METRIC_INC.  No state of
 *       its own: the cache in src/net/dns owns TTLs, negative answers and the
 *       in-flight markers, and it answers NGX_DECLINED for a non-IP peer.
 */
#include "acc.h"
#include "net/dns/dns.h"
#include "observability/metrics/metrics.h"          /* ngx_brix_metrics_t */
#include "observability/metrics/metrics_macros.h"   /* BRIX_RESIL_METRIC_INC */

#include <sys/socket.h>

ngx_int_t
brix_acc_resolve_peer(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t salen, char *buf, size_t buflen)
{
    ngx_int_t  rc;

    if (sa == NULL || buf == NULL || buflen == 0) {
        return NGX_DECLINED;
    }

    rc = brix_dns_reverse_cached(sa, salen, buf, buflen);
    if (rc == NGX_AGAIN) {
        brix_dns_reverse_prefetch(policy, sa, salen);
        BRIX_RESIL_METRIC_INC(acc_dns_pending_fallback_total);
    }
    return rc;
}
