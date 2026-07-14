/*
 * redir_cache.c — shared-memory redirect-collapse cache.
 *
 * WHAT: Fixed-size open-addressing hash cache in nginx shared memory.
 *   Key: canonical path string (up to 255 bytes).
 *   Value: DS host string + port + expiry timestamp (ngx_current_msec + ttl).
 *   Lookup: FNV-1a hash → bounded linear probe; expired entries are misses.
 *   Insert: same hash window — update in place, else reuse a free/expired slot,
 *     else evict the soonest-to-expire entry in the window.
 *
 * WHY: When kXR_collapseRedir is advertised, clients expect that repeated
 *   identical open/locate requests skip the CMS round-trip.  The cache stores
 *   the resolved DS address from a prior successful redirect so the event-loop
 *   handler can answer from memory without blocking on CMS.  On a busy manager
 *   every open/locate consults this cache under a single spinlock, so the
 *   previous O(capacity) full-table scan (~512 × ~400-byte entries, L3-missing)
 *   was a contention hot spot — hashing bounds the locked work to a small fixed
 *   probe window regardless of table size.
 *
 * HOW: One nginx shared-memory zone ("brix_redir_cache") holds the header
 *   (lock + capacity) and the entry array.  A single spinlock serialises reads
 *   and writes, but each operation now touches at most BRIX_REDIR_PROBE_MAX
 *   consecutive slots starting at hash(path) % capacity — O(1) under the lock.
 *   An entry always lives within that probe window of its hash bucket or it is
 *   not cached; lookup and insert probe the same window, so they stay
 *   consistent.  ngx_current_msec (updated by the nginx timer) provides
 *   millisecond-resolution expiry without syscalls.
 */

#include "redir_cache.h"
#include "core/compat/shm_slots.h"
#include <ngx_shmtx.h>
#include <string.h>


typedef struct {
    char        path[256];    /* NUL-terminated canonical path (key) */
    char        host[128];    /* NUL-terminated DS hostname          */
    uint16_t    port;         /* DS XRootD port                      */
    uint8_t     in_use;       /* 1 = slot occupied                   */
    uint8_t     _pad[5];      /* alignment padding                   */
    ngx_msec_t  expires;      /* ngx_current_msec at expiry          */
} brix_redir_cache_entry_t;

typedef struct {
    ngx_shmtx_sh_t             lock;      /* must be first */
    ngx_atomic_t               next_slot; /* vestigial (kept for SHM layout) */
    ngx_uint_t                 capacity;  /* runtime slot count (>= 1) */
    brix_redir_cache_entry_t entries[]; /* [capacity] — flexible array */
} brix_redir_cache_t;

/* Maximum slots probed per lookup/insert, starting at hash(path) % capacity.
 * Bounds the locked work to O(1) regardless of configured table size. */
#define BRIX_REDIR_PROBE_MAX 32


static ngx_shm_zone_t *brix_redir_shm_zone;
static ngx_shmtx_t    brix_redir_mutex;

/* Runtime slot count (brix_redir_cache_slots); defaults to the compile-time
 * capacity.  Set once during configuration before workers fork. */
static ngx_uint_t     brix_redir_cache_nslots = BRIX_REDIR_CACHE_SLOTS;


static brix_redir_cache_t *
redir_cache(void)
{
    if (brix_redir_shm_zone == NULL
        || brix_redir_shm_zone->data == NULL
        || brix_redir_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_redir_cache_t *) brix_redir_shm_zone->data;
}

/* FNV-1a 32-bit hash of a NUL-terminated path, used to pick the probe window. */
static uint32_t
redir_hash(const char *path)
{
    uint32_t h = 2166136261u;

    while (*path) {
        h ^= (unsigned char) *path++;
        h *= 16777619u;
    }

    return h;
}

static ngx_int_t
redir_cache_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_redir_cache_t *c;
    ngx_flag_t            fresh;
    size_t                table_bytes;

    /*
     * Allocate the table FROM the slab pool so nginx's slab-pool header (and the
     * mutex ngx_unlock_mutexes() force-unlocks on every child death) survives at
     * shm.addr.  The helper handles fresh alloc, reload (data != NULL), and
     * re-attach, zeroes the table, creates the process-local mutex from the
     * table's leading ngx_shmtx_sh_t lock, and publishes it via shm_zone->data.
     */
    table_bytes = sizeof(brix_redir_cache_t)
                  + (size_t) brix_redir_cache_nslots
                    * sizeof(brix_redir_cache_entry_t);

    c = brix_shm_table_alloc(shm_zone, data, table_bytes,
                               &brix_redir_mutex, &fresh);
    if (c == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        c->capacity = brix_redir_cache_nslots;
    }

    return NGX_OK;
}


ngx_int_t
brix_redir_cache_configure(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  name = ngx_string("brix_redir_cache");
    size_t     size;

    if (slots == 0) {
        slots = BRIX_REDIR_CACHE_SLOTS;
    }
    brix_redir_cache_nslots = slots;

    size = brix_shm_zone_size(sizeof(brix_redir_cache_t)
                                + (size_t) slots
                                  * sizeof(brix_redir_cache_entry_t));

    brix_redir_shm_zone = ngx_shared_memory_add(cf, &name, size,
                                                    &ngx_stream_brix_module);
    if (brix_redir_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_redir_shm_zone->init = redir_cache_shm_init;
    brix_redir_shm_zone->data = (void *) 1;

    return NGX_OK;
}

int
brix_redir_cache_lookup(const char *path,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    brix_redir_cache_t      *c;
    brix_redir_cache_entry_t *e;
    ngx_uint_t                  probe, nprobe, start;
    int                         found;
    ngx_msec_t                  now;

    c = redir_cache();
    if (c == NULL) {
        return 0;
    }

    now    = ngx_current_msec;
    found  = 0;
    start  = (ngx_uint_t) redir_hash(path) % c->capacity;
    nprobe = (c->capacity < BRIX_REDIR_PROBE_MAX)
             ? c->capacity : BRIX_REDIR_PROBE_MAX;

    ngx_shmtx_lock(&brix_redir_mutex);

    for (probe = 0; probe < nprobe; probe++) {
        e = &c->entries[(start + probe) % c->capacity];
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

    ngx_shmtx_unlock(&brix_redir_mutex);
    return found;
}

void
brix_redir_cache_insert(const char *path,
    const char *host, uint16_t port, ngx_msec_t ttl_ms)
{
    brix_redir_cache_t       *c;
    brix_redir_cache_entry_t *e, *free_slot, *lru_slot, *victim;
    ngx_uint_t                  probe, nprobe, start;
    ngx_msec_t                  now, lru_exp;

    c = redir_cache();
    if (c == NULL || ttl_ms == 0) {
        return;
    }

    now    = ngx_current_msec;
    /* phase79-fp: c NULL-checked above; analyzer loses the guard on c through this path */
    start  = (ngx_uint_t) redir_hash(path) % c->capacity;
    nprobe = (c->capacity < BRIX_REDIR_PROBE_MAX)
             ? c->capacity : BRIX_REDIR_PROBE_MAX;

    ngx_shmtx_lock(&brix_redir_mutex);

    /*
     * Single pass over the probe window: if the path is already cached (live),
     * update it in place; otherwise remember the best eviction target — the
     * first free/expired slot if any, else the live entry closest to expiry.
     * Scanning the whole window before evicting prevents inserting a duplicate
     * of a path that already lives further along the window.
     */
    free_slot = NULL;
    lru_slot  = NULL;
    lru_exp   = 0;

    for (probe = 0; probe < nprobe; probe++) {
        /* phase79-fp: c NULL-checked at entry; analyzer drops the guard across ngx_shmtx_lock */
        e = &c->entries[(start + probe) % c->capacity];

        if (e->in_use && e->expires > now) {
            if (ngx_strcmp(e->path, path) == 0) {
                ngx_cpystrn((u_char *) e->host, (u_char *) host,
                            sizeof(e->host));
                e->port    = port;
                e->expires = now + ttl_ms;
                ngx_shmtx_unlock(&brix_redir_mutex);
                return;
            }
            if (lru_slot == NULL || e->expires < lru_exp) {
                lru_slot = e;
                lru_exp  = e->expires;
            }
        } else if (free_slot == NULL) {
            free_slot = e;          /* free or expired — best reuse target */
        }
    }

    victim = (free_slot != NULL) ? free_slot : lru_slot;
    if (victim == NULL) {
        ngx_shmtx_unlock(&brix_redir_mutex);   /* nprobe >= 1; defensive */
        return;
    }

    ngx_cpystrn((u_char *) victim->path, (u_char *) path, sizeof(victim->path));
    ngx_cpystrn((u_char *) victim->host, (u_char *) host, sizeof(victim->host));
    victim->port    = port;
    victim->expires = now + ttl_ms;
    victim->in_use  = 1;

    ngx_shmtx_unlock(&brix_redir_mutex);
}
