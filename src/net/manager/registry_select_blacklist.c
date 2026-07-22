/*
 * registry_select_blacklist.c - extracted concern
 * Phase-38 split of registry.c; further split from registry_select.c.
 * Blacklist / drain / undrain admin mutations + path-cover query.
 * Behavior-identical.
 */
#include "registry_internal.h"


/* WHAT
 * Marks a registered server as temporarily unavailable for selection.
 * Called from brix_cms_srv_close() when a data server's CMS connection
 * drops.  The server entry stays in the registry so its paths and metrics are
 * preserved for the reconnect; brix_srv_select() and brix_srv_locate_all()
 * both skip entries whose blacklisted_until is in the future.
 *
 * WHY
 * A clean reconnect within the window re-registers and clears the flag,
 * making the server immediately available again.  A permanently dead server
 * stays blacklisted until the window expires, at which point its stale metrics
 * become visible — operators detect this via brix_cluster_server_last_seen_seconds.
 *
 * HOW
 * Locks mutex → scans for host+port match → increments error_count →
 * sets blacklisted_until = ngx_current_msec + duration_ms.  Unlocks.
 */
void
brix_srv_blacklist(const char *host, uint16_t port, ngx_msec_t duration_ms)
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
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        e->error_count++;
        e->blacklisted_until = ngx_current_msec + duration_ms;
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}


/*
 * Phase 23 — clear a drain/blacklist set on a server (admin "undrain").
 * Resets blacklisted_until, error_count, and any health-check failure state so
 * brix_srv_select() routes to it again immediately.  Returns 1 if a matching
 * in-use entry was found, 0 otherwise.
 */
int
brix_srv_undrain(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 found = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        e->blacklisted_until = 0;
        e->error_count       = 0;
        e->hc_fail_count     = 0;
        found = 1;
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return found;
}


/* Phase-89 W3 — public wrapper over the longest-prefix matcher (registry.h). */
int
brix_srv_paths_cover(const char *paths, const char *path)
{
    if (paths == NULL || path == NULL) {
        return 0;
    }
    return srv_path_matches(paths, path);
}


/* Phase-89 W3 — is host:port inside an active blacklist window? (registry.h). */
int
brix_srv_is_blacklisted(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 drained = 0;

    tbl = srv_table();
    if (tbl == NULL || host == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        drained = (e->blacklisted_until != 0
                   && ngx_current_msec < e->blacklisted_until);
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return drained;
}
