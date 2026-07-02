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
#include "observability/metrics/metrics.h"          /* ngx_xrootd_metrics_t */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (E6): breaker counter */
#include <netdb.h>
#include <sys/socket.h>
#include <time.h>

/*
 * Phase 51 (E3): circuit-breaker around the blocking reverse-DNS lookup so a slow
 * or down resolver cannot block the event loop on every new connection's first
 * resolve.  After N consecutive slow lookups the breaker opens for a cooldown,
 * during which we fail fast to NULL (caller falls back to the numeric IP — host
 * rules simply don't fire, the conservative degraded behaviour).  Per-worker,
 * event-loop only → lock-free.
 */
#define ACC_DNS_SLOW_MS        2000
#define ACC_DNS_TRIP_COUNT     5
#define ACC_DNS_COOLDOWN_SECS  10

static struct {
    int     consecutive_slow;
    time_t  open_until;
} acc_dns_breaker;

static int64_t
acc_dns_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

const char *
xrootd_acc_resolve_peer(struct sockaddr *sa, socklen_t salen,
                        char *buf, size_t buflen)
{
    time_t   now;
    int64_t  t0, elapsed;
    int      rc;

    if (sa == NULL || buf == NULL || buflen == 0) {
        return NULL;
    }

    now = time(NULL);
    if (acc_dns_breaker.open_until > now) {
        return NULL;            /* breaker open — skip the (slow) resolver */
    }

    t0 = acc_dns_monotonic_ms();
    rc = getnameinfo(sa, salen, buf, (socklen_t) buflen, NULL, 0, NI_NAMEREQD);
    elapsed = acc_dns_monotonic_ms() - t0;

    if (elapsed >= ACC_DNS_SLOW_MS) {
        if (++acc_dns_breaker.consecutive_slow >= ACC_DNS_TRIP_COUNT) {
            acc_dns_breaker.open_until = now + ACC_DNS_COOLDOWN_SECS;
            acc_dns_breaker.consecutive_slow = 0;
            XROOTD_RESIL_METRIC_INC(acc_dns_breaker_open_total);
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "xrootd_acc: reverse DNS slow (%L ms) — opening "
                          "circuit breaker for %ds (host rules fall back to IP)",
                          (long long) elapsed, ACC_DNS_COOLDOWN_SECS);
        }
    } else {
        acc_dns_breaker.consecutive_slow = 0;
    }

    if (rc != 0) {
        return NULL;
    }

    return buf;
}
