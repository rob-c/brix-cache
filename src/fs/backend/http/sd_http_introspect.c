/*
 * sd_http_introspect.c — T19/T20 selection + health introspection API.
 *
 * Read-mostly accessors over the HTTP-origin driver's endpoint set: rank
 * programming (set_ranks), endpoint enumeration, last-answering-origin +
 * failover display state, and the health snapshot the cvmfs geo/selection
 * logging consults.  Split out of sd_http.c; the public entry points are
 * declared in sd_http.h and the shared state layout comes from
 * sd_http_internal.h.  sd_http_instance_is stays file-private.
 */

#include "sd_http_internal.h"

#include <string.h>
#include <stdio.h>

/* ---- T19/T20 selection + introspection API -------------------------------- */

/* Push selection ranks (rank 0 = most preferred; order = endpoint order).
 * Written on the event loop, read by fill threads — relaxed atomics. */
void
sd_http_set_ranks(brix_sd_instance_t *inst, const int *ranks, int n)
{
    sd_http_inst_state *is;
    int                 i;

    if (!sd_http_instance_is(inst)) {
        return;
    }
    is = inst->state;
    for (i = 0; i < is->n_eps && i < n; i++) {
        atomic_store_explicit(&is->eps[i].rank, ranks[i],
                              memory_order_relaxed);
    }
}

/* Endpoint inventory for the RTT prober (copies, no ngx types). */
int
sd_http_endpoint_list(brix_sd_instance_t *inst, char hosts[][256],
    int *ports, int max)
{
    sd_http_inst_state *is;
    int                 i, n;

    if (!sd_http_instance_is(inst)) {
        return 0;
    }
    is = inst->state;
    n = (is->n_eps < max) ? is->n_eps : max;
    for (i = 0; i < n; i++) {
        memcpy(hosts[i], is->eps[i].host, sizeof(is->eps[i].host));
        ports[i] = is->eps[i].port;
    }
    return n;
}

/* Endpoint count (0 for a non-http instance). */
int
sd_http_n_endpoints(brix_sd_instance_t *inst)
{
    return sd_http_instance_is(inst)
         ? ((sd_http_inst_state *) inst->state)->n_eps : 0;
}

/* "host:port" of the endpoint that answered the most recent read (display
 * only; racy-by-design). 0 with buf filled, or -1 (non-http / none yet). */
int
sd_http_last_origin(brix_sd_instance_t *inst, char *buf, size_t cap)
{
    sd_http_inst_state *is;

    if (!sd_http_instance_is(inst)) {
        return -1;
    }
    is = inst->state;
    if (is->last_origin[0] == '\0') {
        return -1;
    }
    snprintf(buf, cap, "%s", is->last_origin);
    return 0;
}

/* 1 iff the endpoint that answered the most recent read was a failover (not
 * the first-tried). Pairs with sd_http_last_origin; racy-by-design. */
int
sd_http_last_was_failover(brix_sd_instance_t *inst)
{
    return sd_http_instance_is(inst)
         ? ((sd_http_inst_state *) inst->state)->last_failover : 0;
}

/* Health snapshot for /healthz: copies up to `max` (host, port, fail_score)
 * triplets. Returns the count (0 for a non-http instance). */
int
sd_http_health_snapshot(brix_sd_instance_t *inst, char hosts[][256],
    int *ports, int *scores, int max)
{
    sd_http_inst_state *is;
    int                 i, n;

    if (!sd_http_instance_is(inst)) {
        return 0;
    }
    is = inst->state;
    n = (is->n_eps < max) ? is->n_eps : max;
    for (i = 0; i < n; i++) {
        memcpy(hosts[i], is->eps[i].host, sizeof(is->eps[i].host));
        ports[i]  = is->eps[i].port;
        scores[i] = is->eps[i].fail_score;
    }
    return n;
}
