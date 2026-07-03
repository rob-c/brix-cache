/*
 * proxy_pool.c — Phase 23 dynamic WebDAV proxy backend pool (see proxy_pool.h).
 *
 * One shared-memory zone, mirroring the manager registry pattern: a spinlock at
 * the front, a flexible array of fixed-capacity slots.  All mutating operations
 * (add/remove/drain/undrain/select) hold the spinlock for an O(n) pass with no
 * I/O inside the critical section; the per-entry in_flight counter is updated
 * atomically without the lock.
 */
#include "core/ngx_brix_module.h"
#include "proxy_pool.h"
#include "core/compat/host_format.h"  /* brix_format_host[_port] — IPv6 bracketing */
#include "core/compat/shm_slots.h"    /* slab-safe SHM table alloc (preserves slab header) */

static ngx_shm_zone_t *brix_proxy_pool_zone;
static ngx_shmtx_t     brix_proxy_pool_mutex;

extern ngx_module_t ngx_http_brix_webdav_module;

/*
 * Return the live backend table, or NULL if the SHM zone is not ready.
 * (void *) 1 is the pre-init placeholder that brix_proxy_pool_configure stores
 * in ->data before the zone's init callback runs; treat it (and NULL) as "not
 * ready" so callers degrade gracefully instead of dereferencing it.
 */
static brix_proxy_be_table_t *
pool_table(void)
{
    if (brix_proxy_pool_zone == NULL
        || brix_proxy_pool_zone->data == NULL
        || brix_proxy_pool_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_proxy_be_table_t *) brix_proxy_pool_zone->data;
}

/*
 * SHM zone init callback (run by nginx on startup and reload).
 * The table is allocated FROM the slab pool (via brix_shm_table_alloc) so the
 * ngx_slab_pool_t header at shm.addr survives — nginx's ngx_unlock_mutexes()
 * force-unlocks that header's mutex on every child death, so a zone that laid its
 * own struct over shm.addr would crash the master.  On reload/re-attach the helper
 * returns the existing table (backends configured at runtime survive a config
 * reload) and re-creates the worker-local mutex handle over the in-SHM lock; only
 * a brand-new allocation (*fresh) gets its capacity/next_id initialised.
 */
static ngx_int_t
brix_proxy_pool_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t               fresh;
    brix_proxy_be_table_t *tbl;

    tbl = brix_shm_table_alloc(shm_zone, data,
              sizeof(brix_proxy_be_table_t)
              + (size_t) BRIX_PROXY_POOL_SLOTS
                * sizeof(brix_proxy_be_entry_t),
              &brix_proxy_pool_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }
    if (fresh) {
        tbl->capacity = BRIX_PROXY_POOL_SLOTS;
        tbl->next_id  = 1;
    }
    return NGX_OK;
}

/*
 * Declare the shared-memory zone at config time (called once from postconfig per
 * worker tree).  Idempotent: the single zone is shared by every location that
 * enables the dynamic pool.  Size = the table bytes (header + fixed slot array)
 * grown by brix_shm_zone_size() to cover the slab allocator's own bookkeeping,
 * since the table is slab-allocated rather than overlaid on shm.addr.  The
 * (void *) 1 sentinel marks the zone as "declared but not yet initialised" until
 * init_zone runs.
 */
ngx_int_t
brix_proxy_pool_configure(ngx_conf_t *cf)
{
    ngx_str_t  name = ngx_string("brix_proxy_pool");
    size_t     size;

    if (brix_proxy_pool_zone != NULL) {
        return NGX_OK;                   /* idempotent: shared across locations */
    }

    size = brix_shm_zone_size(
               sizeof(brix_proxy_be_table_t)
               + (size_t) BRIX_PROXY_POOL_SLOTS
                 * sizeof(brix_proxy_be_entry_t));

    brix_proxy_pool_zone = ngx_shared_memory_add(cf, &name, size,
                                                   &ngx_http_brix_webdav_module);
    if (brix_proxy_pool_zone == NULL) {
        return NGX_ERROR;
    }
    brix_proxy_pool_zone->init = brix_proxy_pool_init_zone;
    brix_proxy_pool_zone->data = (void *) 1;
    return NGX_OK;
}

/*
 * Resolve a configured "http(s)://host[:port][/uri]" backend URL into a ready-to-
 * use entry: parse the scheme (sets ssl + default port), DNS/parse the authority
 * into a sockaddr, and precompute the two display strings stored per backend —
 * `host` ("host" or "host:port" for the Host: header) and `url_base`
 * ("scheme://host[:port]" for rewriting the request line / Destination).  Only
 * the first resolved address is used.  Returns NGX_ERROR on a bad scheme, parse
 * failure, or an address too large for the fixed sockaddr field.
 */
static ngx_int_t
proxy_pool_resolve(const char *url, ngx_pool_t *pool, ngx_log_t *log,
    brix_proxy_be_entry_t *out)
{
    ngx_url_t   u;
    ngx_str_t   us;
    in_port_t   default_port;
    size_t      scheme_len, n;
    ngx_uint_t  ssl;

    us.data = (u_char *) url;
    us.len  = ngx_strlen(url);

    if (us.len > 8 && ngx_strncasecmp(us.data, (u_char *) "https://", 8) == 0) {
        ssl = 1; scheme_len = 8; default_port = 443;
    } else if (us.len > 7
               && ngx_strncasecmp(us.data, (u_char *) "http://", 7) == 0) {
        ssl = 0; scheme_len = 7; default_port = 80;
    } else {
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(u));
    u.url.data     = us.data + scheme_len;
    u.url.len      = us.len  - scheme_len;
    u.uri_part     = 1;
    u.default_port = default_port;

    if (ngx_parse_url(pool, &u) != NGX_OK || u.naddrs == 0) {
        if (u.err) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_proxy_pool: \"%s\" in url \"%s\"", u.err, url);
        }
        return NGX_ERROR;
    }
    if (u.socklen > sizeof(out->sockaddr)) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));
    ngx_memcpy(&out->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    out->socklen = u.addrs[0].socklen;
    out->port    = u.port;
    out->ssl     = ssl;

    /* host[:port] for the Host: header — omit the port when it is the scheme
     * default so the Host header matches what a normal client would send.
     * ngx_parse_url strips the brackets off "[::1]", so u.host arrives as a bare
     * IPv6 literal and must be re-bracketed on emit ("[::1]" not "::1"). */
    {
        char hostz[256];
        n = ngx_min(u.host.len, sizeof(hostz) - 1);
        ngx_memcpy(hostz, u.host.data, n);
        hostz[n] = '\0';
        if (u.port == default_port) {
            brix_format_host(hostz, out->host, sizeof(out->host));
        } else {
            brix_format_host_port(hostz, (uint16_t) u.port,
                                    out->host, sizeof(out->host));
        }
    }
    /* scheme://host[:port] for the request line / Destination rewrite. */
    ngx_snprintf((u_char *) out->url_base, sizeof(out->url_base), "%*s%s%Z",
                 scheme_len, url, out->host);
    return NGX_OK;
}

/*
 * Add a backend to the pool at runtime (admin REST API).
 * Returns NGX_DECLINED if the pool is not enabled/ready, NGX_ERROR on resolve
 * failure or when the pool is full, NGX_OK with *id_out set on success.
 * DNS resolution is done BEFORE taking the lock so no blocking I/O happens in the
 * critical section; the locked region is a pure O(n) free-slot scan + slot fill.
 */
ngx_int_t
brix_proxy_pool_add(const char *url, ngx_uint_t weight, ngx_pool_t *pool,
    ngx_log_t *log, uint32_t *id_out)
{
    brix_proxy_be_table_t *tbl;
    brix_proxy_be_entry_t  resolved;
    brix_proxy_be_entry_t *e;
    ngx_uint_t               i, free_slot;
    ngx_int_t                rc = NGX_ERROR;

    tbl = pool_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }
    /* Resolve outside the lock (getaddrinfo may block). */
    if (proxy_pool_resolve(url, pool, log, &resolved) != NGX_OK) {
        return NGX_ERROR;
    }
    if (weight == 0) {
        weight = 1;
    }

    ngx_shmtx_lock(&brix_proxy_pool_mutex);

    /* Find the first unused slot (free_slot == capacity means the table is full). */
    free_slot = tbl->capacity;
    for (i = 0; i < tbl->capacity; i++) {
        if (!tbl->slots[i].in_use && free_slot == tbl->capacity) {
            free_slot = i;
        }
    }
    if (free_slot < tbl->capacity) {
        e = &tbl->slots[free_slot];
        ngx_memcpy(&e->sockaddr, &resolved.sockaddr, sizeof(e->sockaddr));
        e->socklen = resolved.socklen;
        e->port    = resolved.port;
        e->ssl     = resolved.ssl;
        ngx_memcpy(e->host, resolved.host, sizeof(e->host));
        ngx_memcpy(e->url_base, resolved.url_base, sizeof(e->url_base));
        e->weight    = weight;
        e->state     = BRIX_PROXY_BE_ACTIVE;
        e->added_at  = ngx_current_msec;
        e->drained_at = 0;
        e->in_flight = 0;
        e->id        = tbl->next_id++;   /* ids are monotonic, never reused */
        e->in_use    = 1;
        if (id_out) { *id_out = e->id; }
        rc = NGX_OK;
    }

    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
    return rc;
}

/*
 * Shared implementation for remove/drain/undrain: find the slot with this id and
 * either zero it (remove_it) or set its state (drain stamps drained_at so callers
 * can age out idle draining backends).  Returns 1 if a matching backend was
 * found, 0 otherwise.  Holds the lock for the whole O(n) scan.
 */
static int
proxy_pool_set_state(uint32_t id, int remove_it, brix_proxy_be_state_e state)
{
    brix_proxy_be_table_t *tbl;
    ngx_uint_t               i;
    int                      found = 0;

    tbl = pool_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_proxy_pool_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        brix_proxy_be_entry_t *e = &tbl->slots[i];
        if (!e->in_use || e->id != id) {
            continue;
        }
        if (remove_it) {
            ngx_memzero(e, sizeof(*e));
        } else {
            e->state = state;
            e->drained_at = (state == BRIX_PROXY_BE_DRAINING)
                            ? ngx_current_msec : 0;
        }
        found = 1;
        break;
    }
    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
    return found;
}

/* Remove a backend entirely (frees its slot). Returns 1 if found. */
int
brix_proxy_pool_remove(uint32_t id)
{
    return proxy_pool_set_state(id, 1, BRIX_PROXY_BE_ACTIVE);
}

/* Mark a backend draining: it stops receiving new picks (select skips non-ACTIVE)
 * but existing in-flight requests are allowed to finish. Returns 1 if found. */
int
brix_proxy_pool_drain(uint32_t id)
{
    return proxy_pool_set_state(id, 0, BRIX_PROXY_BE_DRAINING);
}

/* Return a drained backend to ACTIVE so it is eligible for selection again. */
int
brix_proxy_pool_undrain(uint32_t id)
{
    return proxy_pool_set_state(id, 0, BRIX_PROXY_BE_ACTIVE);
}

/* Current in-flight request count for a backend, or -1 if the id is unknown
 * (used by the admin API to confirm a draining backend has quiesced). */
long
brix_proxy_pool_in_flight(uint32_t id)
{
    brix_proxy_be_table_t *tbl;
    ngx_uint_t               i;
    long                     result = -1;

    tbl = pool_table();
    if (tbl == NULL) {
        return -1;
    }
    ngx_shmtx_lock(&brix_proxy_pool_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].id == id) {
            result = (long) tbl->slots[i].in_flight;
            break;
        }
    }
    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
    return result;
}

/*
 * Pick one ACTIVE backend by weighted round-robin and copy it into *out.
 * Algorithm: sum the weights of all eligible backends; advance the shared
 * rr_index by one and take it modulo the total to get a position in the weighted
 * ring; then walk the slots subtracting each weight until the position lands
 * inside a backend's weight band — that backend is chosen.  Heavier weights span
 * a wider band, so are chosen proportionally more often.  Increments the chosen
 * backend's in_flight (caller must pair with dec_in_flight).
 * Returns NGX_DECLINED when the pool is unavailable or no backend is ACTIVE.
 */
ngx_int_t
brix_proxy_pool_select(brix_proxy_be_pick_t *out)
{
    brix_proxy_be_table_t *tbl;
    brix_proxy_be_entry_t *e, *chosen = NULL;
    ngx_uint_t               i, total = 0, pick;

    tbl = pool_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&brix_proxy_pool_mutex);

    /* Pass 1: total weight of selectable (in_use + ACTIVE) backends. */
    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use && e->state == BRIX_PROXY_BE_ACTIVE) {
            total += (e->weight ? e->weight : 1);
        }
    }
    if (total == 0) {
        ngx_shmtx_unlock(&brix_proxy_pool_mutex);
        return NGX_DECLINED;   /* no active backend */
    }

    /* Position in the weighted ring; rr_index advances atomically across workers. */
    pick = (ngx_uint_t) (ngx_atomic_fetch_add(&tbl->rr_index, 1) % total);
    /* Pass 2: walk weight bands until `pick` falls within one. */
    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->state != BRIX_PROXY_BE_ACTIVE) {
            continue;
        }
        {
            ngx_uint_t w = e->weight ? e->weight : 1;
            if (pick < w) { chosen = e; break; }
            pick -= w;
        }
    }
    if (chosen == NULL) {
        ngx_shmtx_unlock(&brix_proxy_pool_mutex);
        return NGX_DECLINED;
    }

    ngx_memcpy(&out->sockaddr, &chosen->sockaddr, sizeof(out->sockaddr));
    out->socklen = chosen->socklen;
    out->port    = chosen->port;
    out->ssl     = chosen->ssl;
    out->id      = chosen->id;
    ngx_memcpy(out->host, chosen->host, sizeof(out->host));
    ngx_memcpy(out->url_base, chosen->url_base, sizeof(out->url_base));
    /* Charge one in-flight request to the chosen backend (released by
     * dec_in_flight when the proxied request completes). */
    (void) ngx_atomic_fetch_add(&chosen->in_flight, 1);

    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
    return NGX_OK;
}

/*
 * Release one in-flight reference taken by brix_proxy_pool_select, identified
 * by backend id.  Guards against underflow (count already 0) and silently does
 * nothing if the backend was removed meanwhile.
 */
void
brix_proxy_pool_dec_in_flight(uint32_t id)
{
    brix_proxy_be_table_t *tbl;
    ngx_uint_t               i;

    tbl = pool_table();
    if (tbl == NULL) {
        return;
    }
    ngx_shmtx_lock(&brix_proxy_pool_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        brix_proxy_be_entry_t *e = &tbl->slots[i];
        if (e->in_use && e->id == id) {
            if (e->in_flight > 0) {
                (void) ngx_atomic_fetch_add(&e->in_flight, -1);
            }
            break;
        }
    }
    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
}

/*
 * Copy up to `max` in-use backends into the caller's `out` array (read model for
 * the admin/dashboard view).  Returns the number written.  Takes a consistent
 * point-in-time snapshot under the lock; the host string and counters are copied
 * by value so the caller can release/format without holding the lock.
 */
ngx_uint_t
brix_proxy_pool_snapshot(brix_proxy_be_snapshot_t *out, ngx_uint_t max)
{
    brix_proxy_be_table_t *tbl;
    ngx_uint_t               i, n = 0;

    tbl = pool_table();
    if (tbl == NULL) {
        return 0;
    }
    ngx_shmtx_lock(&brix_proxy_pool_mutex);
    for (i = 0; i < tbl->capacity && n < max; i++) {
        brix_proxy_be_entry_t *e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        out[n].id        = e->id;
        ngx_memcpy(out[n].host, e->host, sizeof(out[n].host));
        out[n].port      = e->port;
        out[n].ssl       = e->ssl;
        out[n].weight    = e->weight;
        out[n].state     = e->state;
        out[n].added_at  = e->added_at;
        out[n].in_flight = (uint32_t) e->in_flight;
        n++;
    }
    ngx_shmtx_unlock(&brix_proxy_pool_mutex);
    return n;
}
