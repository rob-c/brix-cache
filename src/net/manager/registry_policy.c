/*
 * registry_policy.c — §2.2/§2.3/§2.9 registry-level cluster policy state.
 *
 * WHAT: The set-once selection-policy globals (cms.sched component weights,
 * the SUPCount floor) with their config-time setters, the per-node load-
 * vector writer the LOAD heartbeat feeds, the floor test the manager request
 * paths gate on, and the supervisor finder the ManTree-style login offload
 * uses.
 *
 * WHY: Split from registry.c (file-size ceiling) — registry.c keeps the zone
 * lifecycle and the register/update/unregister choke points; this file owns
 * the policy additions layered on top of them.
 *
 * HOW: Same locking discipline as every sibling: set-once globals are written
 * only at config time (before fork); per-entry writers and scans take
 * brix_srv_mutex.
 */
#include "registry_internal.h"

brix_srv_sched_t  brix_srv_sched;        /* §2.3: all-zero = engine off */

ngx_uint_t    brix_srv_delay_servers;    /* §2.2: SUPCount floor, 0 = off */


/* §2.3 — install the component weights + fuzz/maxload (config time, before
 * fork).  Weights are clamped to 0-100 like the legacy load weight; a NULL
 * sched clears the engine back to legacy scoring. */
void
brix_srv_set_sched(const brix_srv_sched_t *sched)
{
    ngx_uint_t *field, i;

    if (sched == NULL) {
        ngx_memzero(&brix_srv_sched, sizeof(brix_srv_sched));
        return;
    }
    brix_srv_sched = *sched;
    field = (ngx_uint_t *) &brix_srv_sched;
    for (i = 0; i < sizeof(brix_srv_sched) / sizeof(ngx_uint_t); i++) {
        if (field[i] > 100) {
            field[i] = 100;
        }
    }
}


/* §2.2 — SUPCount floor setter (config time, before fork). */
void
brix_srv_set_delay_servers(ngx_uint_t n)
{
    brix_srv_delay_servers = n;
}


void
brix_srv_set_load_weight(ngx_uint_t weight)
{
    brix_srv_load_weight = weight > 100 ? 100 : weight;
}


void
brix_srv_set_affinity(ngx_uint_t on)
{
    brix_srv_affinity = on ? 1 : 0;
}


/* brix_srv_set_load_vector — §2.3: record the five raw heartbeat theLoad
 * bytes so weighted selection can blend per component (contract in
 * registry.h).  Each byte is clamped to 100 at the store choke point. */
void
brix_srv_set_load_vector(const char *host, uint16_t port,
    const uint8_t load5[5])
{
    brix_srv_entry_t *e;
    ngx_uint_t          i;

    if (srv_table() == NULL || load5 == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    if (e != NULL) {
        for (i = 0; i < 5; i++) {
            e->load5[i] = load5[i] > 100 ? 100 : load5[i];
        }
    }
    ngx_shmtx_unlock(&brix_srv_mutex);
}

/* brix_srv_count_servers — §2.2: occupied data-serving slots.  Managers
 * ("M"), supervisors ("R") and peers ("P") are cluster control/overflow
 * capacity, not data servers, so they do not count toward the floor. */
ngx_uint_t
brix_srv_count_servers(void)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i, n = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use && (e->role[0] == 'S'
                          || (e->role[0] == 'P' && e->role[1] == 'S')))
        {
            n++;
        }
    }
    ngx_shmtx_unlock(&brix_srv_mutex);
    return n;
}

/* brix_srv_below_floor — §2.2: is the SUPCount floor configured and unmet? */
int
brix_srv_below_floor(void)
{
    return brix_srv_delay_servers > 0
           && brix_srv_count_servers() < brix_srv_delay_servers;
}

/*
 * brix_srv_find_supervisor — §2.9: pick the least-utilised live supervisor.
 *
 * WHAT: Scans in-use, non-blacklisted "R"-role entries and returns the one
 *       with the lowest util_pct (first-seen wins ties).  1 = found.
 * WHY:  A manager at its brix_cms_server_max_direct cap redirects a new
 *       server login to a supervisor (kYR_try at login) — tree formation
 *       needs a target, and the coolest supervisor spreads the subtree load.
 * HOW:  Same locked scan shape as the other selectors, filtered to role "R".
 */
int
brix_srv_find_supervisor(char *host_out, size_t host_size,
    uint16_t *port_out)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 best = -1;
    uint32_t            best_util = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->role[0] != 'R') {
            continue;
        }
        if (e->blacklisted_until != 0
            && e->blacklisted_until > ngx_current_msec)
        {
            continue;
        }
        if (best == -1 || e->util_pct < best_util) {
            best = (int) i;
            best_util = e->util_pct;
        }
    }

    if (best >= 0) {
        e = &tbl->slots[best];
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return best >= 0;
}

/* brix_srv_is_registered — §2.9: is host:port currently in the registry?
 * A reconnecting known member is exempt from the max_direct offload — a
 * heartbeat blip must not bounce an established server into the tree. */
int
brix_srv_is_registered(const char *host, uint16_t port)
{
    brix_srv_entry_t *e;
    int                 found;

    if (srv_table() == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    found = (e != NULL);
    ngx_shmtx_unlock(&brix_srv_mutex);
    return found;
}
