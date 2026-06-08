/*
 * redir_cache.c — shared-memory redirect-collapse cache.
 *
 * WHAT: Fixed-size (512-slot) ring-buffer cache in nginx shared memory.
 *   Key: canonical path string (up to 255 bytes).
 *   Value: DS host string + port + expiry timestamp (ngx_current_msec + ttl).
 *   Lookup: linear scan; expired entries are treated as misses.
 *   Insert: ring-buffer eviction — overwrites the slot at next_slot % SLOTS.
 *
 * WHY: When kXR_collapseRedir is advertised, clients expect that repeated
 *   identical open/locate requests skip the CMS round-trip.  The cache stores
 *   the resolved DS address from a prior successful redirect so the event-loop
 *   handler can answer from memory without blocking on CMS.
 *
 * HOW: One nginx shared-memory zone ("xrootd_redir_cache") holds the header
 *   (lock + next_slot counter) and the 512 entry array.  A single spinlock
 *   serialises all reads and writes — hold time is a small linear scan of at
 *   most 512 compact entries (~400 bytes each), which is well under 1 µs on
 *   any modern CPU.  ngx_current_msec (updated by the nginx timer) provides
 *   millisecond-resolution expiry without syscalls.
 */

#include "redir_cache.h"
#include <ngx_shmtx.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char        path[256];    /* NUL-terminated canonical path (key) */
    char        host[128];    /* NUL-terminated DS hostname          */
    uint16_t    port;         /* DS XRootD port                      */
    uint8_t     in_use;       /* 1 = slot occupied                   */
    uint8_t     _pad[5];      /* alignment padding                   */
    ngx_msec_t  expires;      /* ngx_current_msec at expiry          */
} xrootd_redir_cache_entry_t;

typedef struct {
    ngx_shmtx_sh_t             lock;      /* must be first */
    ngx_atomic_t               next_slot; /* ring-buffer write cursor */
    xrootd_redir_cache_entry_t entries[XROOTD_REDIR_CACHE_SLOTS];
} xrootd_redir_cache_t;

/* ------------------------------------------------------------------ */
/* Module-level state                                                   */
/* ------------------------------------------------------------------ */

static ngx_shm_zone_t *xrootd_redir_shm_zone;
static ngx_shmtx_t    xrootd_redir_mutex;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static xrootd_redir_cache_t *
redir_cache(void)
{
    if (xrootd_redir_shm_zone == NULL
        || xrootd_redir_shm_zone->data == NULL
        || xrootd_redir_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_redir_cache_t *) xrootd_redir_shm_zone->data;
}

static ngx_int_t
redir_cache_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_redir_cache_t *c;

    if (data) {
        shm_zone->data = data;
        c = (xrootd_redir_cache_t *) data;
        return ngx_shmtx_create(&xrootd_redir_mutex, &c->lock, NULL);
    }

    c = (xrootd_redir_cache_t *) shm_zone->shm.addr;
    ngx_memzero(c, sizeof(*c));

    if (ngx_shmtx_create(&xrootd_redir_mutex, &c->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = c;
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_redir_cache_configure(ngx_conf_t *cf)
{
    ngx_str_t  name = ngx_string("xrootd_redir_cache");
    size_t     size;

    size = sizeof(xrootd_redir_cache_t) + ngx_pagesize;

    xrootd_redir_shm_zone = ngx_shared_memory_add(cf, &name, size,
                                                    &ngx_stream_xrootd_module);
    if (xrootd_redir_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_redir_shm_zone->init = redir_cache_shm_init;
    xrootd_redir_shm_zone->data = (void *) 1;

    return NGX_OK;
}

int
xrootd_redir_cache_lookup(const char *path,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    xrootd_redir_cache_t      *c;
    xrootd_redir_cache_entry_t *e;
    ngx_uint_t                  i;
    int                         found;
    ngx_msec_t                  now;

    c = redir_cache();
    if (c == NULL) {
        return 0;
    }

    now   = ngx_current_msec;
    found = 0;

    ngx_shmtx_lock(&xrootd_redir_mutex);

    for (i = 0; i < XROOTD_REDIR_CACHE_SLOTS; i++) {
        e = &c->entries[i];
        if (!e->in_use || e->expires <= now) {
            continue;
        }
        if (ngx_strcmp(e->path, path) == 0) {
            ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
            *port_out = e->port;
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_redir_mutex);
    return found;
}

void
xrootd_redir_cache_insert(const char *path,
    const char *host, uint16_t port, ngx_msec_t ttl_ms)
{
    xrootd_redir_cache_t      *c;
    xrootd_redir_cache_entry_t *e;
    ngx_uint_t                  i, slot;
    ngx_msec_t                  now;

    c = redir_cache();
    if (c == NULL || ttl_ms == 0) {
        return;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&xrootd_redir_mutex);

    /* Update existing entry for this path if present. */
    for (i = 0; i < XROOTD_REDIR_CACHE_SLOTS; i++) {
        e = &c->entries[i];
        if (e->in_use && ngx_strcmp(e->path, path) == 0) {
            ngx_cpystrn((u_char *) e->host, (u_char *) host, sizeof(e->host));
            e->port    = port;
            e->expires = now + ttl_ms;
            ngx_shmtx_unlock(&xrootd_redir_mutex);
            return;
        }
    }

    /* New entry — claim next ring-buffer slot. */
    slot = (ngx_uint_t) ngx_atomic_fetch_add(&c->next_slot, 1)
           % XROOTD_REDIR_CACHE_SLOTS;
    e = &c->entries[slot];

    ngx_cpystrn((u_char *) e->path, (u_char *) path, sizeof(e->path));
    ngx_cpystrn((u_char *) e->host, (u_char *) host, sizeof(e->host));
    e->port    = port;
    e->expires = now + ttl_ms;
    e->in_use  = 1;

    ngx_shmtx_unlock(&xrootd_redir_mutex);
}
