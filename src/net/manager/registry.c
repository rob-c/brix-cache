/*
 * registry.c - (kept) routing + shared helpers
 * Phase-38 split of registry.c; behavior-identical.
 */
#include "registry_internal.h"

ngx_shm_zone_t *brix_srv_shm_zone;
ngx_shmtx_t   brix_srv_mutex;

ngx_uint_t    brix_srv_registry_nslots = BRIX_SRV_REGISTRY_SLOTS;

ngx_msec_t    brix_srv_stale_after_ms;

ngx_uint_t    brix_srv_load_weight;

ngx_uint_t    brix_srv_affinity;


void
brix_srv_set_stale_after(ngx_msec_t ms)
{
    brix_srv_stale_after_ms = ms;
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


brix_srv_table_t *
srv_table(void)
{
    if (brix_srv_shm_zone == NULL
        || brix_srv_shm_zone->data == NULL
        || brix_srv_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_srv_table_t *) brix_srv_shm_zone->data;
}



/* WHAT
 * Shared-memory zone initialiser callback. Called by nginx when the shared-
 * memory zone is mapped (first time) or reattached (subsequent workers).

 * WHY
 * Ensures the registry table is zero-filled and the spinlock is created on
 * first boot; on restart (data != NULL) just recreates the lock against the
 * existing table structure.

 * HOW
 * Delegates fresh-alloc / reload / re-attach to brix_shm_table_alloc(), which
 * allocates the table FROM the slab pool so nginx's slab-pool header survives at
 * shm.addr (ngx_unlock_mutexes() force-unlocks that header on every child death;
 * laying our own struct over it would SIGSEGV the master). The helper zero-fills
 * the table and creates the worker-local mutex from tbl->lock (the table's first
 * member). On a brand-new allocation we set the capacity; on reuse we must not,
 * to preserve the live table state.
 */
ngx_int_t
brix_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_srv_table_t *tbl;
    ngx_flag_t          fresh;
    size_t              table_bytes;

    table_bytes = sizeof(brix_srv_table_t)
                + (size_t) brix_srv_registry_nslots
                  * sizeof(brix_srv_entry_t);

    tbl = brix_shm_table_alloc(shm_zone, data, table_bytes,
                                 &brix_srv_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        tbl->capacity = brix_srv_registry_nslots;
    }

    return NGX_OK;
}



/* WHAT
 * Allocates the shared-memory zone for the server registry and sets its size
 * based on the configured slot count.

 * WHY
 * Called during nginx configuration parsing (brix_registry_slots directive).
 * Must happen before any traffic so that workers can find the zone at startup.

 * HOW
 * Sets brix_srv_registry_nslots to the requested value, computes zone size
 * via brix_shm_zone_size(table_bytes) — the table is allocated FROM the slab
 * pool, so the zone must hold the table plus slab overhead — adds the zone via
 * ngx_shared_memory_add(), sets init callback and (void *)1 sentinel data.
 */
ngx_int_t
brix_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("brix_srv_registry");
    size_t     zone_size;

    brix_srv_registry_nslots = slots;
    zone_size = brix_shm_zone_size(
                    sizeof(brix_srv_table_t)
                  + (size_t) slots * sizeof(brix_srv_entry_t));
    brix_srv_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                  zone_size,
                                                  &ngx_stream_brix_module);
    if (brix_srv_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_shm_zone_warn_on_resize(cf, brix_srv_shm_zone,
                                   "brix_registry_slots");

    brix_srv_shm_zone->init = brix_srv_shm_init_zone;
    brix_srv_shm_zone->data = (void *) 1;

    return NGX_OK;
}



/* WHAT
 * Registers or updates a data server entry in the shared-memory registry.
 * Called by CMS server handler when a data server logs in or heartbeats.

 * WHY
 * The redirector needs to know which servers exist, what paths they serve,
 * and their current load metrics so that kXR_locate / kXR_open can pick the
 * best server for each request.

 * HOW
 * Locks mutex → scans all slots: if host+port match found, update paths/free/
 * util/last_seen fields. If no match and a free slot exists, allocate it with
 * host/port/paths/free/util/last_seen/in_use=1. If registry is full, log warn
 * and increment registry_full_total Prometheus counter.
 */
void
brix_srv_register(const char *host, uint16_t port,
    const char *paths, uint32_t free_mb, uint32_t util_pct)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i, free_slot;
    int                 found;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    /*
     * W1c — reject any host string that is not a clean hostname / IP literal
     * before it can enter the registry.  This is the single store choke point,
     * so it also protects every redirect-emit path (brix_srv_select /
     * brix_srv_locate_all) from control-byte or scheme injection into the
     * "S<r|w>host:port" string a client parses.  Registry hosts are normally
     * the peer IP from ngx_sock_ntop, so a rejection here means a poisoned or
     * malformed registration attempt.
     */
    if (host == NULL || !brix_net_host_chars_valid(host, ngx_strlen(host))) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "brix: rejected registration with invalid host string");
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    free_slot = tbl->capacity;
    found = 0;

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (free_slot == tbl->capacity) {
                free_slot = i;
            }
            continue;
        }
        if (e->port == port && ngx_strcmp(e->host, host) == 0) {
            /* Update existing entry; clear any prior blacklist on reconnect. */
            ngx_cpystrn((u_char *) e->paths,
                        (u_char *) (paths ? paths : ""),
                        sizeof(e->paths));
            e->free_mb          = free_mb;
            e->util_pct         = util_pct;
            e->last_seen        = ngx_current_msec;
            e->blacklisted_until = 0;
            e->error_count      = 0;
            found = 1;
            break;
        }
    }

    if (!found && free_slot < tbl->capacity) {
        e = &tbl->slots[free_slot];
        ngx_cpystrn((u_char *) e->host, (u_char *) host, sizeof(e->host));
        e->port = port;
        ngx_cpystrn((u_char *) e->paths,
                    (u_char *) (paths ? paths : ""),
                    sizeof(e->paths));
        e->free_mb   = free_mb;
        e->util_pct  = util_pct;
        e->last_seen = ngx_current_msec;
        e->in_use    = 1;
    } else if (!found) {
        /* Registry is full: log a warning and increment the Prometheus counter. */
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "brix: server registry full (%ui slots); "
                      "dropping registration for %s:%ui "
                      "(increase brix_registry_slots)",
                      tbl->capacity, host, (ngx_uint_t) port);
        {
            ngx_brix_metrics_t *m = brix_metrics_shared();
            if (m != NULL) {
                ngx_atomic_fetch_add(&m->registry_full_total, 1);
            }
        }
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}



/* WHAT
 * Refreshes free-space and utilisation metrics for an already-registered server.
 * Called on each CMS heartbeat from the data server.

 * WHY
 * Selection policy depends on current load: reads pick least-loaded servers,
 * writes pick most-free-space. Metrics must stay fresh for accurate routing.

 * HOW
 * Locks mutex → scans slots for host+port match → updates free_mb, util_pct,
 * last_seen fields only (no path changes). Unlocks and returns.
 */
void
brix_srv_update_load(const char *host, uint16_t port,
    uint32_t free_mb, uint32_t util_pct)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            e->free_mb   = free_mb;
            e->util_pct  = util_pct;
            e->last_seen = ngx_current_msec;
            break;
        }
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}



/* WHAT
 * Removes a data server entry from the registry by host+port match.
 * Called when a data server disconnects or is removed from the cluster.

 * WHY
 * Prevents stale entries from being selected by locate/open operations. A
 * disconnected server should not receive client traffic.

 * HOW
 * Locks mutex → scans slots for host+port match → zero-fills the entry (all
 * fields cleared, in_use=0). Unlocks and returns.
 */
void
brix_srv_unregister(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}

/*
 * srv_find_locked — locate the in-use entry for host:port.  Caller MUST hold
 * brix_srv_mutex; returns NULL when the node is not registered (or the zone
 * is absent), so every Phase-89 W9 attribute writer degrades to a no-op for
 * an unknown node instead of creating one.
 */
static brix_srv_entry_t *
srv_find_locked(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL || host == NULL) {
        return NULL;
    }

    for (i = 0; i < tbl->capacity; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].port == port
            && ngx_strcmp(tbl->slots[i].host, host) == 0)
        {
            return &tbl->slots[i];
        }
    }

    return NULL;
}

/*
 * brix_srv_reset — kYR_status(reset): forget the node's cached metrics and
 * fault state but keep the registration + paths (contract in registry.h).
 * The stale metrics window this opens closes on the node's next load/avail
 * heartbeat; clearing the blacklist too mirrors stock cmsd, where reset is
 * the node saying "my state machine restarted, judge me fresh".
 */
int
brix_srv_reset(const char *host, uint16_t port)
{
    brix_srv_entry_t *e;
    int                 found = 0;

    if (srv_table() == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    if (e != NULL) {
        e->free_mb            = 0;
        e->util_pct           = 0;
        e->error_count        = 0;
        e->blacklisted_until  = 0;
        e->hc_fail_count      = 0;
        e->hc_in_progress     = 0;
        e->load_pct           = 0;
        e->last_seen          = ngx_current_msec;
        found = 1;
    }
    ngx_shmtx_unlock(&brix_srv_mutex);

    return found;
}

/* brix_srv_set_vnid — record the login-advertised virtual network id
 * (contract in registry.h; NULL and "" both clear). */
void
brix_srv_set_vnid(const char *host, uint16_t port, const char *vnid)
{
    brix_srv_entry_t *e;

    if (srv_table() == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    if (e != NULL) {
        ngx_cpystrn((u_char *) e->vnid,
                    (u_char *) (vnid ? vnid : ""), sizeof(e->vnid));
    }
    ngx_shmtx_unlock(&brix_srv_mutex);
}

/* brix_srv_set_stage — record staging availability from the kYR_status
 * stage/nostage bits (contract in registry.h). */
void
brix_srv_set_stage(const char *host, uint16_t port, ngx_uint_t stage)
{
    brix_srv_entry_t *e;

    if (srv_table() == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    if (e != NULL) {
        e->stage = stage ? 1 : 0;
    }
    ngx_shmtx_unlock(&brix_srv_mutex);
}

/* brix_srv_set_machine_load — record the heartbeat machine-load percentage
 * (contract in registry.h). */
void
brix_srv_set_machine_load(const char *host, uint16_t port, uint32_t load_pct)
{
    brix_srv_entry_t *e;

    if (srv_table() == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
    e = srv_find_locked(host, port);
    if (e != NULL) {
        e->load_pct = load_pct > 100 ? 100 : load_pct;
    }
    ngx_shmtx_unlock(&brix_srv_mutex);
}
