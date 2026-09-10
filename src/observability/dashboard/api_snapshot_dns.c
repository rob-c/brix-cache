/*
 * api_snapshot_dns.c - the "dns" panel of the dashboard snapshot (phase-116).
 *
 * WHAT: dashboard_fill_dns() — one row per runtime-DNS target (directive,
 *       host, port, state, last error, next retry, counters) plus the
 *       per-state summary, read from the worker-local registry (net/dns).
 * WHY:  "why is this node not in the cluster" is answered here in one look:
 *       a brix_cms_manager / brix_upstream / mirror name that never resolved
 *       shows its state and the resolver's error text; the Prometheus gauge
 *       (net/dns/metrics.c) deliberately carries no error text.
 * HOW:  Mirrors the other dashboard_fill_* panels: populate keys on a
 *       caller-supplied object, tolerate jansson OOM (NULL children are
 *       dropped by json_object_set_new / json_array_append_new).  Hostnames
 *       come from the operator's own configuration, so they are not redacted.
 */
#include "dashboard_api_internal.h"
#include "net/dns/dns.h"


static json_t *
dashboard_dns_target_row(const brix_dns_target_t *t)
{
    json_t      *o = json_object();
    ngx_msec_t   now = ngx_current_msec;

    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "directive", json_string(t->directive));
    json_object_set_new(o, "host", json_string((const char *) t->host.data));
    json_object_set_new(o, "port", json_integer((json_int_t) t->port));
    json_object_set_new(o, "state", json_string(brix_dns_state_name(t->state)));
    json_object_set_new(o, "literal", t->literal ? json_true() : json_false());
    json_object_set_new(o, "addresses", json_integer((json_int_t) t->naddrs));
    json_object_set_new(o, "last_error", json_string(t->last_error));
    json_object_set_new(o, "next_retry_ms",
        json_integer(t->next_retry > now ? (json_int_t) (t->next_retry - now) : 0));
    json_object_set_new(o, "resolutions", json_integer((json_int_t) t->resolutions));
    json_object_set_new(o, "failures", json_integer((json_int_t) t->failures));
    json_object_set_new(o, "zone",
        json_string(t->dns && t->dns->status_zone.data
                    ? (const char *) t->dns->status_zone.data : ""));
    return o;
}


void
dashboard_fill_dns(json_t *target)
{
    ngx_uint_t  counts[BRIX_DNS_STATE_COUNT];
    ngx_uint_t  i, n = brix_dns_targets_n();
    json_t     *rows = json_array();

    brix_dns_targets_count(counts);
    json_object_set_new(target, "targets_total", json_integer((json_int_t) n));
    for (i = 0; i < BRIX_DNS_STATE_COUNT; i++) {
        json_object_set_new(target, brix_dns_state_name(i),
                            json_integer((json_int_t) counts[i]));
    }
    if (rows == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {
        json_array_append_new(rows, dashboard_dns_target_row(brix_dns_target_at(i)));
    }
    json_object_set_new(target, "targets", rows);
}
