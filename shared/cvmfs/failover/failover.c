/* failover.c — CVMFS replica + proxy failover policy engine. See failover.h. */
#include "cvmfs/failover/failover.h"

#include <string.h>

#define CVMFS_FO_BACKOFF_BASE_MS 200L
#define CVMFS_FO_BACKOFF_CAP_MS  30000L

void cvmfs_failover_init(cvmfs_failover_t *fo, long reset_interval_s) {
    memset(fo, 0, sizeof(*fo));
    fo->reset_interval_s = reset_interval_s > 0 ? reset_interval_s : 30;
    fo->base_blacklist_s = 2;      /* short first-failure probation (snap-back) */
    fo->ewma_alpha = 0.25;
}

static int add_endpoint(cvmfs_fo_endpoint_t *arr, size_t *n, size_t cap,
                        const char *url, int group) {
    size_t len = strlen(url);
    if (*n >= cap || len >= sizeof(arr[0].url)) return -1;
    cvmfs_fo_endpoint_t *e = &arr[*n];
    memset(e, 0, sizeof(*e));
    memcpy(e->url, url, len + 1);                     /* bound proven above */
    e->group = group;
    (*n)++;
    return 0;
}

int cvmfs_failover_add_proxy(cvmfs_failover_t *fo, const char *url, int group) {
    return add_endpoint(fo->proxies, &fo->n_proxies, CVMFS_FO_MAX_PROXIES, url, group);
}

int cvmfs_failover_add_host(cvmfs_failover_t *fo, const char *url) {
    return add_endpoint(fo->hosts, &fo->n_hosts, CVMFS_FO_MAX_HOSTS, url, 0);
}

void cvmfs_failover_reorder_hosts(cvmfs_failover_t *fo, const int *order, size_t n) {
    if (n == 0 || n > fo->n_hosts) return;
    cvmfs_fo_endpoint_t tmp[CVMFS_FO_MAX_HOSTS];
    char seen[CVMFS_FO_MAX_HOSTS] = {0};
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        int idx = order[i];
        if (idx < 0 || (size_t) idx >= fo->n_hosts || seen[idx]) return; /* invalid → no-op */
        seen[idx] = 1;
        tmp[k++] = fo->hosts[idx];
    }
    if (k != fo->n_hosts) return;                        /* must be a full permutation */
    memcpy(fo->hosts, tmp, k * sizeof(tmp[0]));
}

size_t cvmfs_geo_parse_order(const char *resp, size_t len, int *order, size_t max) {
    size_t k = 0, i = 0;
    while (i < len && k < max) {
        while (i < len && (resp[i] < '0' || resp[i] > '9')) i++;   /* skip separators */
        if (i >= len) break;
        int v = 0, any = 0;
        while (i < len && resp[i] >= '0' && resp[i] <= '9') { v = v * 10 + (resp[i] - '0'); i++; any = 1; }
        if (any && v >= 1) order[k++] = v - 1;                     /* 1-based → 0-based */
    }
    return k;
}

static int is_live(const cvmfs_fo_endpoint_t *e, long now) {
    return e->blacklisted_until <= now;
}

/* STICKY selection: the lowest-index live endpoint (hosts are in geo/preference
 * order, so index 0 = closest). For proxies the lowest live index within the
 * lowest live group. We never drift off the closest for a marginally-faster peer;
 * the closest is used again the instant its (short) blacklist lapses. */
static int first_live_host(const cvmfs_fo_endpoint_t *arr, size_t n, long now) {
    for (size_t i = 0; i < n; i++) if (is_live(&arr[i], now)) return (int) i;
    return -1;
}

static int first_live_proxy(const cvmfs_fo_endpoint_t *arr, size_t n, long now) {
    int best = -1;
    for (size_t i = 0; i < n; i++) {
        if (!is_live(&arr[i], now)) continue;
        if (best < 0 || arr[i].group < arr[best].group) best = (int) i;  /* lowest group, then lowest index */
    }
    return best;
}

int cvmfs_failover_select(cvmfs_failover_t *fo, long now, cvmfs_fo_route_t *out) {
    out->proxy = fo->n_proxies == 0 ? -1 : first_live_proxy(fo->proxies, fo->n_proxies, now);
    out->host  = first_live_host(fo->hosts, fo->n_hosts, now);

    if (out->host < 0) return -1;                        /* no live replica */
    if (fo->n_proxies > 0 && out->proxy < 0) return -1;  /* all proxies dead */
    return 0;
}

static void mark(cvmfs_fo_endpoint_t *e, int ok, long rtt_us, long now,
                 long base_s, long cap_s, double alpha) {
    if (ok) {
        e->fail_count = 0;
        e->blacklisted_until = 0;
        if (rtt_us > 0) {
            e->ewma_rtt_us = e->ewma_rtt_us == 0.0
                ? (double) rtt_us
                : alpha * (double) rtt_us + (1.0 - alpha) * e->ewma_rtt_us;
        }
    } else {
        /* SNAP-BACK: short first probation, doubling on each consecutive failure,
         * capped — assume a transient network blip, escalate only if it persists. */
        e->fail_count++;
        long dur = base_s > 0 ? base_s : 1;
        for (unsigned i = 1; i < e->fail_count && dur < cap_s; i++) dur *= 2;
        if (dur > cap_s) dur = cap_s;
        e->blacklisted_until = now + dur;
    }
}

void cvmfs_failover_record(cvmfs_failover_t *fo, const cvmfs_fo_route_t *route,
                           int ok, long rtt_us, long now) {
    if (route->proxy >= 0 && (size_t) route->proxy < fo->n_proxies) {
        cvmfs_fo_endpoint_t *p = &fo->proxies[route->proxy];
        /* A "DIRECT" pseudo-proxy is not an endpoint — there is nothing to blame
         * or blacklist on a failure (the fault belongs to the host). Blacklisting
         * it starves select() of any live proxy and reports offline while healthy
         * replicas remain, killing host failover entirely. Successes still clear
         * its counters (harmless, keeps state tidy). */
        if (ok || strcmp(p->url, "DIRECT") != 0)
            mark(p, ok, rtt_us, now,
                 fo->base_blacklist_s, fo->reset_interval_s, fo->ewma_alpha);
    }
    if (route->host >= 0 && (size_t) route->host < fo->n_hosts)
        mark(&fo->hosts[route->host], ok, rtt_us, now,
             fo->base_blacklist_s, fo->reset_interval_s, fo->ewma_alpha);
}

long cvmfs_failover_backoff_ms(unsigned attempt) {
    long ms = CVMFS_FO_BACKOFF_BASE_MS;
    for (unsigned i = 0; i < attempt && ms < CVMFS_FO_BACKOFF_CAP_MS; i++)
        ms *= 2;
    return ms > CVMFS_FO_BACKOFF_CAP_MS ? CVMFS_FO_BACKOFF_CAP_MS : ms;
}

int cvmfs_failover_all_down(const cvmfs_failover_t *fo, long now) {
    for (size_t i = 0; i < fo->n_proxies; i++)
        if (is_live(&fo->proxies[i], now)) return 0;
    for (size_t i = 0; i < fo->n_hosts; i++)
        if (is_live(&fo->hosts[i], now)) return 0;
    return 1;
}
