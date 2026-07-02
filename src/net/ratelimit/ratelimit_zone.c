/*
 * ratelimit_zone.c — Phase 25 rate-limit SHM zone: init, rbtree, LRU eviction.
 *
 * Each `xrootd_rate_limit_zone zone=NAME:SIZE` directive declares one nginx
 * shared-memory slab zone holding an rbtree of xrootd_rl_node_t plus an LRU
 * queue.  Structure and lifecycle mirror ngx_http_limit_req_module: nodes are
 * slab-allocated on demand, linked into both the rbtree (keyed by a 32-bit hash
 * of the principal key string) and a most-recent-at-head LRU queue; when the
 * slab fills, the oldest queue entries are evicted before retrying.
 *
 * A single shared tag is used for every rate-limit zone so the same NAME
 * declared in both an http{} and a stream{} block resolves to ONE shared zone
 * (cross-plane principal accounting).
 */
#include "ratelimit.h"
#include "observability/metrics/metrics_macros.h"
#include "core/compat/alloc_guard.h"

#define XROOTD_RL_MAX_ZONES   16
#define XROOTD_RL_MIN_SIZE    (64 * 1024)

/* Unique tag shared by all rate-limit zones (see file header). */
static ngx_uint_t        xrootd_rl_zone_tag;
static xrootd_rl_zone_t *xrootd_rl_zones[XROOTD_RL_MAX_ZONES];
static ngx_uint_t        xrootd_rl_nzones;

#define XROOTD_RL_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_xrootd_metrics_t *_m = xrootd_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


/* FNV-1a 32-bit (matches the codebase's kv.c hashing convention) */
uint32_t
xrootd_rl_hash(const char *key, size_t len)
{
    const uint8_t *p = (const uint8_t *) key;
    uint32_t       h = 2166136261u;     /* FNV offset basis (32-bit) */
    size_t         i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;                  /* FNV prime (32-bit) */
    }
    return h;
}


/* rbtree insert (hash key, ties broken by key_str bytes) */
/*
 * Custom rbtree insert callback (passed to ngx_rbtree_init).  The tree is
 * ordered by node->key (the 32-bit FNV hash), but distinct principal strings
 * can collide on that hash, so equal-hash nodes are sub-ordered by a byte
 * comparison of their full key_str.  This keeps every node uniquely findable;
 * xrootd_rl_lookup_locked() walks the tree with the identical key-then-bytes
 * comparison, so the two MUST stay in lock-step.
 */
static void
xrootd_rl_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    xrootd_rl_node_t   *rln, *rlnt;

    /* Descend to the insertion slot: branch on hash first, on raw key bytes
     * second when hashes are equal (collision tie-break). */
    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            rln  = (xrootd_rl_node_t *) node;
            rlnt = (xrootd_rl_node_t *) temp;
            p = (ngx_memn2cmp(rln->key_str, rlnt->key_str, rln->len, rlnt->len)
                 < 0) ? &temp->left : &temp->right;
        }
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left   = sentinel;
    node->right  = sentinel;
    ngx_rbt_red(node);
}


/* zone init callback */
/*
 * nginx shared-memory init callback, invoked once per worker generation after
 * the slab is mapped.  Handles three entry paths, in priority order:
 *   1. `data != NULL`  — config reload: a previous-generation zone exists; just
 *      adopt its already-populated sh/shpool so live buckets survive the reload.
 *   2. shm.exists      — the slab was inherited (e.g. binary upgrade); the
 *      shctx already lives at shpool->data, so re-point to it without re-init.
 *   3. fresh           — first creation: carve the shctx out of the slab,
 *      init the rbtree + LRU queue, and stash a human-readable log prefix.
 */
void
xrootd_rl_zone_reset_gauges(xrootd_rl_shctx_t *sh)
{
    ngx_queue_t      *q;
    xrootd_rl_node_t *rln;

    if (sh == NULL) {
        return;
    }
    for (q = ngx_queue_head(&sh->queue);
         q != ngx_queue_sentinel(&sh->queue);
         q = ngx_queue_next(q))
    {
        rln = ngx_queue_data(q, xrootd_rl_node_t, queue);
        rln->in_flight  = 0;               /* leaked concurrency reservation */
        rln->open_files = 0;               /* leaked per-user open handle    */
    }
}


static ngx_int_t
xrootd_rl_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_rl_zone_t *ozone = data;            /* previous (reload) */
    xrootd_rl_zone_t *zone  = shm_zone->data;
    ngx_slab_pool_t  *shpool;

    if (ozone != NULL) {
        /* Reload: inherit the already-initialised shared structure. The
         * time-windowed rate/bandwidth buckets survive, but the in-use gauges
         * (in_flight, open_files) are zeroed: they self-heal only via a matched
         * decrement, so a worker SIGKILLed mid-request (e.g. at reload's
         * worker_shutdown_timeout) would otherwise leak its increment forever,
         * accumulating across reboots until the cap wedges the key. Resetting
         * here bounds any crash-leak to a single generation. */
        zone->sh     = ozone->sh;
        zone->shpool = ozone->shpool;
        xrootd_rl_zone_reset_gauges(zone->sh);
        return NGX_OK;
    }

    /* The slab pool header sits at the very start of the mapped segment. */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    zone->shpool = shpool;

    if (shm_zone->shm.exists) {
        zone->sh = shpool->data;
        return NGX_OK;
    }

    zone->sh = ngx_slab_alloc(shpool, sizeof(xrootd_rl_shctx_t));
    if (zone->sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data = zone->sh;

    /* Wire the empty rbtree to our collision-aware insert callback, and the
     * LRU queue used for O(1) eviction when the slab fills. */
    ngx_rbtree_init(&zone->sh->rbtree, &zone->sh->sentinel,
                    xrootd_rl_rbtree_insert_value);
    ngx_queue_init(&zone->sh->queue);

    /* Slab-allocated suffix appended to nginx slab OOM diagnostics so a full
     * zone is attributable by name.  Size = template (incl. the two quotes and
     * trailing NUL counted by strlen) + the variable zone name length. */
    shpool->log_ctx = ngx_slab_alloc(shpool, ngx_strlen(" in rate-limit zone"
                                     " \"\"") + zone->name.len);
    if (shpool->log_ctx != NULL) {
        ngx_sprintf(shpool->log_ctx, " in rate-limit zone \"%V\"%Z",
                    &zone->name);
    }
    return NGX_OK;
}


/* public: declare / resolve a zone */
ngx_int_t
xrootd_rl_zone_add(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    xrootd_rl_zone_t **out)
{
    xrootd_rl_zone_t *zone;
    ngx_shm_zone_t   *shm_zone;

    /* Already declared (possibly in the other plane)? Reuse the handle. */
    zone = xrootd_rl_zone_get(name);
    if (zone != NULL) {
        if (out) { *out = zone; }
        return NGX_OK;
    }

    if (xrootd_rl_nzones >= XROOTD_RL_MAX_ZONES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many xrootd_rate_limit_zone zones (max %d)",
                           XROOTD_RL_MAX_ZONES);
        return NGX_ERROR;
    }
    if (size < XROOTD_RL_MIN_SIZE) {
        size = XROOTD_RL_MIN_SIZE;
    }

    XROOTD_PCALLOC_OR_RETURN(zone, cf->pool, sizeof(*zone), NGX_ERROR);
    zone->name = *name;
    zone->size = size;

    /* Register/look up the SHM segment under the single shared rate-limit tag,
     * so the same NAME in http{} and stream{} maps to one segment.  If nginx
     * returns an existing segment that already has data, a sibling declaration
     * won the race — discard the zone we just pcalloc'd and adopt theirs; only
     * the first declarant installs the init callback. */
    shm_zone = ngx_shared_memory_add(cf, name, size, &xrootd_rl_zone_tag);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }
    if (shm_zone->data != NULL) {
        /* Another tag-sharing declaration created it first — adopt it. */
        zone = shm_zone->data;
    } else {
        shm_zone->init = xrootd_rl_init_zone;
        shm_zone->data = zone;
    }
    zone->shm_zone = shm_zone;

    xrootd_rl_zones[xrootd_rl_nzones++] = zone;
    if (out) { *out = zone; }
    return NGX_OK;
}

xrootd_rl_zone_t *
xrootd_rl_zone_get(ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; i < xrootd_rl_nzones; i++) {
        if (xrootd_rl_zones[i]->name.len == name->len
            && ngx_strncmp(xrootd_rl_zones[i]->name.data, name->data,
                           name->len) == 0)
        {
            return xrootd_rl_zones[i];
        }
    }
    return NULL;
}

ngx_uint_t
xrootd_rl_zones_all(xrootd_rl_zone_t **out, ngx_uint_t max)
{
    ngx_uint_t i, n = 0;

    for (i = 0; i < xrootd_rl_nzones && n < max; i++) {
        out[n++] = xrootd_rl_zones[i];
    }
    return n;
}


/* node lookup / allocate (caller holds shpool->mutex) */
/* Find the node for key_str, or NULL.  Refreshes its LRU position. */
xrootd_rl_node_t *
xrootd_rl_lookup_locked(xrootd_rl_zone_t *zone, uint32_t hash,
    const char *key_str, size_t len)
{
    ngx_rbtree_node_t *node     = zone->sh->rbtree.root;
    ngx_rbtree_node_t *sentinel = zone->sh->rbtree.sentinel;
    xrootd_rl_node_t  *rln;
    ngx_int_t          rc;

    /* Mirror of xrootd_rl_rbtree_insert_value's ordering: branch on hash, and
     * on a byte compare of key_str only when hashes collide.  Diverging from
     * the insert comparator here would silently lose nodes in the tree. */
    while (node != sentinel) {
        if (hash < node->key) { node = node->left;  continue; }
        if (hash > node->key) { node = node->right; continue; }

        rln = (xrootd_rl_node_t *) node;
        rc  = ngx_memn2cmp((u_char *) key_str, rln->key_str, len, rln->len);
        if (rc == 0) {
            /* Found: bump to LRU head so it is the last to be evicted.  This is
             * the function's side effect — a "lookup" also marks recently-used,
             * which is why callers must already hold the mutex. */
            ngx_queue_remove(&rln->queue);
            ngx_queue_insert_head(&zone->sh->queue, &rln->queue);
            return rln;
        }
        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

/* Evict the single oldest (LRU tail) node.  Returns 1 if one was freed. */
static int
xrootd_rl_evict_oldest_locked(xrootd_rl_zone_t *zone)
{
    ngx_queue_t      *q;
    xrootd_rl_node_t *rln;

    if (ngx_queue_empty(&zone->sh->queue)) {
        return 0;
    }
    /* Tail of the LRU queue = least-recently used node.  Unlink it from BOTH
     * structures (queue + rbtree) before freeing, or the tree would dangle. */
    q   = ngx_queue_last(&zone->sh->queue);
    rln = ngx_queue_data(q, xrootd_rl_node_t, queue);

    ngx_queue_remove(q);
    ngx_rbtree_delete(&zone->sh->rbtree, &rln->node);
    ngx_slab_free_locked(zone->shpool, rln);
    XROOTD_RL_METRIC_INC(rl_eviction_total);
    return 1;
}

/* Create a node for key_str at LRU head.  NULL on exhaustion (after evicting
 * up to a few oldest entries).  Caller holds the mutex. */
xrootd_rl_node_t *
xrootd_rl_create_locked(xrootd_rl_zone_t *zone, uint32_t hash,
    const char *key_str, size_t len)
{
    xrootd_rl_node_t *rln;
    /* Exact node size: fixed header up to the flexible key_str member plus the
     * key bytes (key_str[1] in the struct is not double-counted via offsetof). */
    size_t            sz = offsetof(xrootd_rl_node_t, key_str) + len;
    int               tries;

    /* Try to allocate; on slab exhaustion evict the LRU tail and retry, up to
     * 8 times.  Bounding the retries prevents an unbounded eviction storm if
     * the requested size can never fit (e.g. fragmentation), and lets us fail
     * gracefully (fail-open at the call site) rather than spin. */
    rln = ngx_slab_alloc_locked(zone->shpool, sz);
    for (tries = 0; rln == NULL && tries < 8; tries++) {
        if (!xrootd_rl_evict_oldest_locked(zone)) {
            break;                 /* queue empty — nothing left to reclaim */
        }
        rln = ngx_slab_alloc_locked(zone->shpool, sz);
    }
    if (rln == NULL) {
        XROOTD_RL_METRIC_INC(rl_zone_full_errors);
        return NULL;
    }

    /* Zero only the fixed header (counters/excess/timestamps); the trailing
     * key_str is initialised explicitly by the memcpy below. */
    ngx_memzero(rln, offsetof(xrootd_rl_node_t, key_str));
    rln->node.key = hash;
    rln->len      = (u_short) len;
    ngx_memcpy(rln->key_str, key_str, len);

    /* Link into the rbtree (for lookup) and at the LRU head (newest). */
    ngx_rbtree_insert(&zone->sh->rbtree, &rln->node);
    ngx_queue_insert_head(&zone->sh->queue, &rln->queue);
    return rln;
}
