/* failover.h — CVMFS replica + proxy failover policy engine (pure C, no ngx).
 *
 * WHAT: a pure state machine that ranks and selects (proxy, host) routes,
 *       blacklists failing endpoints with a timed reset, tracks per-endpoint
 *       connect-RTT (EWMA), and yields exponential backoff — the reusable heart
 *       of CVMFS crappy-network survival.
 * WHY:  both the standalone FUSE client (choosing the next URL to fetch) and the
 *       nginx server (ranking origins for sd_http) need the SAME policy; only the
 *       mechanism differs (blocking connect vs event-loop timers), so the policy
 *       lives here and the mechanism stays on each side.
 * HOW:  CVMFS distinguishes forward proxies (load-balance groups tried in order,
 *       "DIRECT" = no proxy) from hosts (Stratum-1 replicas). select() returns the
 *       best live proxy (lowest group, then lowest EWMA) and best live host; a
 *       return of -1 means every endpoint is blacklisted — the caller drops to
 *       offline/cache-only mode. All time is caller-supplied monotonic seconds so
 *       the engine is deterministic and testable. No allocation.
 */
#ifndef BRIX_CVMFS_FAILOVER_H
#define BRIX_CVMFS_FAILOVER_H

#include <stddef.h>

#define CVMFS_FO_MAX_PROXIES 16
#define CVMFS_FO_MAX_HOSTS   16

typedef struct {
    char   url[256];
    int    group;               /* proxies only: load-balance group index */
    long   blacklisted_until;   /* monotonic secs; 0 = live */
    double ewma_rtt_us;         /* 0 = no sample yet */
    unsigned fail_count;
} cvmfs_fo_endpoint_t;

typedef struct {
    cvmfs_fo_endpoint_t proxies[CVMFS_FO_MAX_PROXIES]; size_t n_proxies;
    cvmfs_fo_endpoint_t hosts[CVMFS_FO_MAX_HOSTS];     size_t n_hosts;
    long                reset_interval_s;   /* blacklist CAP (max backoff) */
    long                base_blacklist_s;   /* first-failure probation (snap-back) */
    double              ewma_alpha;         /* RTT smoothing (0..1) */
} cvmfs_failover_t;

/* Selected route: indices into the proxy/host arrays (-1 = none available). */
typedef struct {
    int proxy;   /* index into fo->proxies, or -1 */
    int host;    /* index into fo->hosts,   or -1 */
} cvmfs_fo_route_t;

/* Initialise with a blacklist reset interval (seconds). */
void cvmfs_failover_init(cvmfs_failover_t *fo, long reset_interval_s);

/* Append a proxy ("DIRECT" allowed) in load-balance `group`. 0 on success. */
int cvmfs_failover_add_proxy(cvmfs_failover_t *fo, const char *url, int group);

/* Append a Stratum host. 0 on success. */
int cvmfs_failover_add_host(cvmfs_failover_t *fo, const char *url);

/* Reorder the host list by `order` (0-based indices, `n` entries) so the
 * geo-closest server becomes index 0 (sticky-preferred). Ignores out-of-range /
 * duplicate indices; a partial/empty order leaves the list unchanged. */
void cvmfs_failover_reorder_hosts(cvmfs_failover_t *fo, const int *order, size_t n);

/* Parse a CVMFS Geo-API response (1-based indices in proximity order, separated
 * by commas/newlines/space, e.g. "2,1,3") into 0-based `order`. Returns the count
 * written (<= max), or 0 on malformed input. */
size_t cvmfs_geo_parse_order(const char *resp, size_t len, int *order, size_t max);

/* Choose the best live (proxy, host) at monotonic time `now`. Returns 0 with a
 * route, or -1 if no live proxy or no live host remains (→ offline mode). A
 * host-only fetch (no proxies configured) yields route.proxy == -1 and rc 0. */
int cvmfs_failover_select(cvmfs_failover_t *fo, long now, cvmfs_fo_route_t *out);

/* Record the outcome of a fetch over `route`. On failure the used endpoint is
 * blacklisted until now + reset_interval_s; on success its fail_count clears and
 * (when rtt_us > 0) its EWMA updates. */
void cvmfs_failover_record(cvmfs_failover_t *fo, const cvmfs_fo_route_t *route,
                           int ok, long rtt_us, long now);

/* Exponential backoff in milliseconds for a 0-based retry `attempt`, capped. */
long cvmfs_failover_backoff_ms(unsigned attempt);

/* 1 if every proxy AND every host is blacklisted at `now` (offline). */
int cvmfs_failover_all_down(const cvmfs_failover_t *fo, long now);

#endif /* BRIX_CVMFS_FAILOVER_H */
