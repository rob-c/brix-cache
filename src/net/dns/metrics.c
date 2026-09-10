/*
 * metrics.c — Prometheus view of the runtime-DNS driver (phase-116).
 *
 * WHAT: brix_dns_metrics_emit(): a `brix_dns_targets{state}` gauge (one row
 *       per registry state), the summed `brix_dns_resolutions_total` and
 *       `brix_dns_failures_total` target counters, the per-query
 *       `brix_dns_lookups_total{result}` counter (ok / nxdomain / timeout /
 *       error — completed queries only, never cache hits) and the forward
 *       (`brix_dns_cache_*`) and reverse (`brix_dns_reverse_cache_*`) cache
 *       entries gauge + hits / misses / negative-hits counters, and the
 *       thread-pool bridge's `brix_dns_bridge_requests_total` /
 *       `brix_dns_bridge_timeouts_total`.
 * WHY:  A target stuck in "failed" or "resolving" is the one signal an
 *       operator needs when a brix_cms_manager / brix_upstream / mirror name
 *       never came up; the lookup counter separates "the nameserver says no"
 *       from "the nameserver is unreachable"; the cache counters prove one
 *       query per TTL window.  The error text itself lives on the dashboard
 *       panel (api_snapshot_dns.c) and in the error log, never in a label
 *       (I-8: both label sets are closed enumerations).
 * HOW:  Reads the per-worker registry (targets.c) and caches — the worker
 *       answering /metrics reports its own view; every worker runs the same
 *       schedule so the views agree to within one refresh interval.  The
 *       lookup counters are ngx_atomic_t because brix_dns_resolve_sync()
 *       completes libc lookups on thread-pool threads (per-process runtime
 *       state, the origin_probe precedent — not a new global policy).
 */
#include "net/dns/dns.h"
#include "observability/metrics/metrics_internal.h"


static ngx_atomic_t  dns_lookups[BRIX_DNS_RESULT_COUNT];

static const char *const dns_result_names[BRIX_DNS_RESULT_COUNT] = {
    "ok", "nxdomain", "timeout", "error",
};


void
brix_dns_lookup_note(ngx_uint_t result)
{
    if (result < BRIX_DNS_RESULT_COUNT) {
        (void) ngx_atomic_fetch_add(&dns_lookups[result], 1);
    }
}


void
brix_dns_lookups_count(ngx_uint_t counts[BRIX_DNS_RESULT_COUNT])
{
    ngx_uint_t  i;

    for (i = 0; i < BRIX_DNS_RESULT_COUNT; i++) {
        counts[i] = (ngx_uint_t) dns_lookups[i];
    }
}


const char *
brix_dns_result_name(ngx_uint_t result)
{
    return result < BRIX_DNS_RESULT_COUNT ? dns_result_names[result]
                                          : "error";
}


static void
dns_metrics_emit_targets(metrics_writer_t *mw)
{
    ngx_uint_t               counts[BRIX_DNS_STATE_COUNT];
    ngx_uint_t               i, n, resolutions = 0, failures = 0;
    const brix_dns_target_t *t;

    brix_dns_targets_count(counts);
    n = brix_dns_targets_n();
    for (i = 0; i < n; i++) {
        t = brix_dns_target_at(i);
        resolutions += t->resolutions;
        failures += t->failures;
    }

    mw_printf(mw, "# HELP brix_dns_targets Runtime-DNS targets registered "
                  "from the configuration, by state (this worker's view).\n"
                  "# TYPE brix_dns_targets gauge\n");
    for (i = 0; i < BRIX_DNS_STATE_COUNT; i++) {
        mw_printf(mw, "brix_dns_targets{state=\"%s\"} %lu\n",
                  brix_dns_state_name(i), (unsigned long) counts[i]);
    }
    mw_printf(mw, "# HELP brix_dns_resolutions_total Successful runtime "
                  "resolutions of registered targets (this worker).\n"
                  "# TYPE brix_dns_resolutions_total counter\n"
                  "brix_dns_resolutions_total %lu\n"
                  "# HELP brix_dns_failures_total Failed runtime resolution "
                  "attempts of registered targets (this worker).\n"
                  "# TYPE brix_dns_failures_total counter\n"
                  "brix_dns_failures_total %lu\n",
              (unsigned long) resolutions, (unsigned long) failures);
}


static void
dns_metrics_emit_lookups(metrics_writer_t *mw)
{
    ngx_uint_t  counts[BRIX_DNS_RESULT_COUNT];
    ngx_uint_t  i;

    brix_dns_lookups_count(counts);
    mw_printf(mw, "# HELP brix_dns_lookups_total Completed runtime DNS "
                  "queries by outcome (this worker; cache hits excluded).\n"
                  "# TYPE brix_dns_lookups_total counter\n");
    for (i = 0; i < BRIX_DNS_RESULT_COUNT; i++) {
        mw_printf(mw, "brix_dns_lookups_total{result=\"%s\"} %lu\n",
                  brix_dns_result_name(i), (unsigned long) counts[i]);
    }
}


/* brix_dns_bridge_* — the thread-pool -> event-loop bridge (resolve_bridge.c).
 * A blocking caller (TPC pin, cache-origin/gsiftp connect, cvmfs probe, OCSP)
 * either crosses the bridge and resolves under the worker's own `brix_resolver`
 * policy, or falls back to libc with a different resolv.conf, a different search
 * list and no shared cache.  requests counts the crossings, timeouts the ones
 * that gave up waiting for the loop; requests staying at 0 while thread-pool
 * sites are busy is the signal that every one of them silently took libc.  Both
 * are label-free per-worker counters (I-8, I-DNS-4). */
static void
dns_metrics_emit_bridge(metrics_writer_t *mw)
{
    ngx_uint_t  requests = 0, timeouts = 0;

    brix_dns_bridge_stats(&requests, &timeouts);
    mw_printf(mw, "# HELP brix_dns_bridge_requests_total Blocking resolutions "
                  "handed to the event loop by a thread-pool caller (this "
                  "worker).\n"
                  "# TYPE brix_dns_bridge_requests_total counter\n"
                  "brix_dns_bridge_requests_total %lu\n",
              (unsigned long) requests);
    mw_printf(mw, "# HELP brix_dns_bridge_timeouts_total Bridge crossings that "
                  "timed out waiting for the event loop and fell back to "
                  "libc.\n"
                  "# TYPE brix_dns_bridge_timeouts_total counter\n"
                  "brix_dns_bridge_timeouts_total %lu\n",
              (unsigned long) timeouts);
}


/* one cache's four series under a family prefix ("brix_dns_cache",
 * "brix_dns_reverse_cache") */
static void
dns_metrics_emit_cache(metrics_writer_t *mw, const char *prefix,
    const char *what, ngx_uint_t entries, ngx_uint_t hits, ngx_uint_t misses,
    ngx_uint_t negative_hits)
{
    mw_printf(mw, "# HELP %s_entries Live entries in the per-worker %s "
                  "cache.\n# TYPE %s_entries gauge\n%s_entries %lu\n",
              prefix, what, prefix, prefix, (unsigned long) entries);
    mw_printf(mw, "# HELP %s_hits_total Positive %s cache hits.\n"
                  "# TYPE %s_hits_total counter\n%s_hits_total %lu\n",
              prefix, what, prefix, prefix, (unsigned long) hits);
    mw_printf(mw, "# HELP %s_misses_total %s cache misses (a query "
                  "followed).\n# TYPE %s_misses_total counter\n"
                  "%s_misses_total %lu\n",
              prefix, what, prefix, prefix, (unsigned long) misses);
    mw_printf(mw, "# HELP %s_negative_hits_total Negative %s cache hits "
                  "(no query sent).\n# TYPE %s_negative_hits_total counter\n"
                  "%s_negative_hits_total %lu\n",
              prefix, what, prefix, prefix, (unsigned long) negative_hits);
}


void
brix_dns_metrics_emit(metrics_writer_t *mw)
{
    ngx_uint_t  entries, hits, misses, negative_hits;

    dns_metrics_emit_targets(mw);
    dns_metrics_emit_lookups(mw);
    dns_metrics_emit_bridge(mw);
    brix_dns_cache_stats(&entries, &hits, &misses, &negative_hits);
    dns_metrics_emit_cache(mw, "brix_dns_cache", "forward-DNS", entries,
                           hits, misses, negative_hits);
    brix_dns_rcache_stats(&entries, &hits, &misses, &negative_hits);
    dns_metrics_emit_cache(mw, "brix_dns_reverse_cache", "reverse-DNS",
                           entries, hits, misses, negative_hits);
}
