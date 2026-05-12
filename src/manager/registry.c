#include "registry.h"
#include <ngx_shmtx.h>
#include <string.h>

ngx_shm_zone_t *xrootd_srv_shm_zone;

static ngx_shmtx_t   xrootd_srv_mutex;
static ngx_uint_t    xrootd_srv_registry_nslots = XROOTD_SRV_REGISTRY_SLOTS;

static xrootd_srv_table_t *
srv_table(void)
{
    if (xrootd_srv_shm_zone == NULL
        || xrootd_srv_shm_zone->data == NULL
        || xrootd_srv_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_srv_table_t *) xrootd_srv_shm_zone->data;
}

ngx_int_t
xrootd_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_srv_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (xrootd_srv_table_t *) data;
        if (ngx_shmtx_create(&xrootd_srv_mutex, &tbl->lock, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (xrootd_srv_table_t *) shm_zone->shm.addr;
    tbl->capacity = xrootd_srv_registry_nslots;
    ngx_memzero(tbl->slots,
                tbl->capacity * sizeof(xrootd_srv_entry_t));

    if (ngx_shmtx_create(&xrootd_srv_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

ngx_int_t
xrootd_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("xrootd_srv_registry");
    size_t     zone_size;

    xrootd_srv_registry_nslots = slots;
    zone_size = sizeof(xrootd_srv_table_t)
              + (size_t) slots * sizeof(xrootd_srv_entry_t)
              + ngx_pagesize;
    xrootd_srv_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                  zone_size,
                                                  &ngx_stream_xrootd_module);
    if (xrootd_srv_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_srv_shm_zone->init = xrootd_srv_shm_init_zone;
    xrootd_srv_shm_zone->data = (void *) 1;

    return NGX_OK;
}

/* Return 1 if path starts with any colon-delimited token in paths. */
static int
srv_path_matches(const char *paths, const char *path)
{
    const char *p, *end;
    size_t      tok_len, path_len;

    path_len = strlen(path);
    p = paths;

    while (*p) {
        end = strchr(p, ':');
        if (end == NULL) {
            end = p + strlen(p);
        }
        tok_len = (size_t)(end - p);

        if (tok_len > 0
            && path_len >= tok_len
            && ngx_strncmp(path, p, tok_len) == 0
            && (p[tok_len - 1] == '/'
                || path[tok_len] == '/' || path[tok_len] == '\0'))
        {
            return 1;
        }

        p = *end ? end + 1 : end;
    }
    return 0;
}

void
xrootd_srv_register(const char *host, uint16_t port,
    const char *paths, uint32_t free_mb, uint32_t util_pct)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i, free_slot;
    int                 found;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

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
            /* Update existing entry. */
            ngx_cpystrn((u_char *) e->paths,
                        (u_char *) (paths ? paths : ""),
                        sizeof(e->paths));
            e->free_mb   = free_mb;
            e->util_pct  = util_pct;
            e->last_seen = ngx_current_msec;
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
                      "xrootd: server registry full (%ui slots); "
                      "dropping registration for %s:%ui "
                      "(increase xrootd_registry_slots)",
                      tbl->capacity, host, (ngx_uint_t) port);
        {
            ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
            if (m != NULL) {
                ngx_atomic_fetch_add(&m->registry_full_total, 1);
            }
        }
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

void
xrootd_srv_update_load(const char *host, uint16_t port,
    uint32_t free_mb, uint32_t util_pct)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

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

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

void
xrootd_srv_unregister(const char *host, uint16_t port)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

int
xrootd_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    int                 best;
    uint32_t            best_val;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    best     = -1;
    best_val = for_write ? 0 : (uint32_t) -1;

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (!srv_path_matches(e->paths, path)) {
            continue;
        }
        if (for_write) {
            if (best == -1 || e->free_mb > best_val) {
                best     = (int) i;
                best_val = e->free_mb;
            }
        } else {
            if (best == -1 || e->util_pct < best_val) {
                best     = (int) i;
                best_val = e->util_pct;
            }
        }
    }

    if (best >= 0) {
        e = &tbl->slots[best];
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return best >= 0;
}

void
xrootd_srv_unregister_path(const char *host, uint16_t port, const char *path)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    const char         *p, *end;
    char               *dst;
    size_t              tok_len, path_len;
    int                 first;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    path_len = strlen(path);

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }

        /* In-place removal: walk tokens, copying those that don't match. */
        p     = e->paths;
        dst   = e->paths;
        first = 1;

        while (*p) {
            end = strchr(p, ':');
            if (end == NULL) {
                end = p + strlen(p);
            }
            tok_len = (size_t)(end - p);

            if (tok_len == path_len && ngx_strncmp(p, path, tok_len) == 0) {
                /* Drop this token. */
            } else {
                if (!first) {
                    *dst++ = ':';
                }
                /* dst <= p always — safe overlap direction for memcpy. */
                ngx_memcpy(dst, p, tok_len);
                dst  += tok_len;
                first  = 0;
            }

            p = *end ? end + 1 : end;
        }
        *dst = '\0';
        break;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}


void
xrootd_srv_aggregate_space(uint32_t *total_free_mb, uint32_t *avg_util_pct)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    uint32_t            sum_free;
    uint64_t            sum_util;
    ngx_uint_t          count;

    *total_free_mb = 0;
    *avg_util_pct  = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    sum_free = 0;
    sum_util = 0;
    count    = 0;

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        sum_free += e->free_mb;
        sum_util += e->util_pct;
        count++;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);

    *total_free_mb = sum_free;
    *avg_util_pct  = count > 0 ? (uint32_t) (sum_util / count) : 0;
}
