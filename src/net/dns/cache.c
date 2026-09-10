/*
 * cache.c — per-worker DNS answer cache (phase-116 W4).
 *
 * WHAT: A bounded positive + negative cache keyed by (lowercased name, address
 *       family policy).  Positive entries hold up to BRIX_DNS_MAX_ADDRS port-
 *       less addresses and an expiry; negative entries hold an expiry only.
 *       Least-recently-used entries are evicted once the cap is reached.
 * WHY:  The re-resolve paths (health checks, TPC pins, proxy pool adds) can
 *       ask for the same name many times per second; without a cache every
 *       ask is a resolver round-trip or a thread-pool hop.  The negative
 *       cache stops a dead name from hammering the nameserver at retry pace.
 * HOW:  ngx_rbtree keyed by ngx_crc32_short(name) with a string compare on
 *       collision, plus an ngx_queue_t in LRU order — the ngx_resolver layout,
 *       without its per-name waiting lists.  Per-process singleton allocated
 *       lazily with ngx_alloc (never from a request pool); a fork inherits an
 *       empty cache because entries are created only at runtime.  A plain
 *       pthread mutex guards every entry point: the event loop and the
 *       thread-pool callers of brix_dns_resolve_sync() share one cache, and
 *       nothing under the lock blocks or re-enters (ngx_time() is a cached
 *       read, allocation is ngx_alloc).  Not an SHM mutex — this cache is
 *       process-private (invariant 10 concerns shared memory only).
 */
#include "net/dns/dns.h"

#include <pthread.h>

typedef struct {
    ngx_rbtree_node_t  node;       /* key = crc32 of the lowercased name */
    ngx_queue_t        queue;      /* LRU */
    u_char            *name;
    size_t             len;
    brix_af_policy_t   af;
    time_t             expires;
    unsigned           negative:1;
    unsigned           pending:1;  /* fill in flight: a miss that is not re-started */
    ngx_uint_t         naddrs;
    brix_dns_addr_t    addrs[BRIX_DNS_MAX_ADDRS];
} dns_cache_entry_t;

typedef struct {
    ngx_rbtree_t        tree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         lru;
    ngx_uint_t          entries;
    ngx_uint_t          max;
    ngx_uint_t          hits;
    ngx_uint_t          misses;
    ngx_uint_t          negative_hits;
    unsigned            ready:1;
} dns_cache_t;

/* per-process singleton (origin_probe precedent: runtime-only state) */
static dns_cache_t      dns_cache;
static pthread_mutex_t  dns_cache_mu = PTHREAD_MUTEX_INITIALIZER;


static void
dns_cache_ready(void)
{
    if (dns_cache.ready) {
        return;
    }
    ngx_rbtree_init(&dns_cache.tree, &dns_cache.sentinel,
                    ngx_rbtree_insert_value);
    ngx_queue_init(&dns_cache.lru);
    if (dns_cache.max == 0) {
        dns_cache.max = BRIX_DNS_CACHE_MAX_DEFAULT;
    }
    dns_cache.ready = 1;
}


void
brix_dns_cache_set_max(ngx_uint_t max)
{
    if (max > 0) {
        pthread_mutex_lock(&dns_cache_mu);
        dns_cache.max = max;
        pthread_mutex_unlock(&dns_cache_mu);
    }
}


/* lowercase copy for a case-insensitive key; returns the crc */
static uint32_t
dns_cache_key(const ngx_str_t *name, u_char *lower, size_t *len)
{
    size_t  i, n = ngx_min(name->len, BRIX_RESOLV_DOMAIN_LEN - 1);

    for (i = 0; i < n; i++) {
        lower[i] = ngx_tolower(name->data[i]);
    }
    if (n > 0 && lower[n - 1] == '.') {
        n--;                              /* "host." == "host" */
    }
    *len = n;
    return ngx_crc32_short(lower, n);
}


static dns_cache_entry_t *
dns_cache_find(uint32_t key, const u_char *lower, size_t len,
    brix_af_policy_t af)
{
    ngx_rbtree_node_t  *node = dns_cache.tree.root;
    ngx_rbtree_node_t  *sentinel = dns_cache.tree.sentinel;

    while (node != sentinel) {
        dns_cache_entry_t *e;

        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }
        e = (dns_cache_entry_t *) node;
        if (e->len == len && e->af == af
            && ngx_memcmp(e->name, lower, len) == 0)
        {
            return e;
        }
        /* same crc, different name: the tree is not a multimap, so walk
         * the right subtree the way ngx_resolver does for its hash */
        node = node->right;
    }
    return NULL;
}


static void
dns_cache_remove(dns_cache_entry_t *e)
{
    ngx_rbtree_delete(&dns_cache.tree, &e->node);
    ngx_queue_remove(&e->queue);
    dns_cache.entries--;
    ngx_free(e->name);
    ngx_free(e);
}


static ngx_int_t
dns_cache_lookup_locked(brix_dns_req_t *req)
{
    u_char             lower[BRIX_RESOLV_DOMAIN_LEN];
    size_t             len;
    uint32_t           key;
    dns_cache_entry_t *e;
    ngx_uint_t         i;

    dns_cache_ready();
    key = dns_cache_key(&req->name, lower, &len);
    e = dns_cache_find(key, lower, len, req->af);
    if (e == NULL) {
        dns_cache.misses++;
        return NGX_DECLINED;
    }
    if (e->expires <= ngx_time()) {
        dns_cache_remove(e);
        dns_cache.misses++;
        return NGX_DECLINED;
    }
    if (e->pending) {
        dns_cache.misses++;                /* the async driver resolves as usual */
        return NGX_DECLINED;
    }

    /* touch: move to the LRU head */
    ngx_queue_remove(&e->queue);
    ngx_queue_insert_head(&dns_cache.lru, &e->queue);

    req->cached = 1;
    req->ttl = e->expires - ngx_time();
    if (e->negative) {
        dns_cache.negative_hits++;
        req->negative = 1;
        req->naddrs = 0;
        req->rc = NGX_ERROR;
        req->error = "name not found (negative cache)";
        return NGX_OK;
    }
    dns_cache.hits++;
    req->naddrs = e->naddrs;
    for (i = 0; i < e->naddrs; i++) {
        req->addrs[i] = e->addrs[i];
        ngx_inet_set_port((struct sockaddr *) &req->addrs[i].ss, req->port);
    }
    req->rc = NGX_OK;
    req->error = NULL;
    return NGX_OK;
}


ngx_int_t
brix_dns_cache_lookup(brix_dns_req_t *req)
{
    ngx_int_t  rc;

    pthread_mutex_lock(&dns_cache_mu);
    rc = dns_cache_lookup_locked(req);
    pthread_mutex_unlock(&dns_cache_mu);
    return rc;
}


static void
dns_cache_evict_lru(void)
{
    ngx_queue_t  *q;

    while (dns_cache.entries >= dns_cache.max
           && !ngx_queue_empty(&dns_cache.lru))
    {
        q = ngx_queue_last(&dns_cache.lru);
        dns_cache_remove(ngx_queue_data(q, dns_cache_entry_t, queue));
    }
}


static void
dns_cache_store_locked(const brix_dns_req_t *req)
{
    u_char             lower[BRIX_RESOLV_DOMAIN_LEN];
    size_t             len;
    uint32_t           key;
    dns_cache_entry_t *e;
    ngx_uint_t         i;

    dns_cache_ready();
    key = dns_cache_key(&req->name, lower, &len);
    e = dns_cache_find(key, lower, len, req->af);
    if (e != NULL) {
        dns_cache_remove(e);
    }
    dns_cache_evict_lru();

    e = ngx_calloc(sizeof(dns_cache_entry_t), req->log);
    if (e == NULL) {
        return;
    }
    e->name = ngx_alloc(len + 1, req->log);
    if (e->name == NULL) {
        ngx_free(e);
        return;
    }
    ngx_memcpy(e->name, lower, len);
    e->name[len] = '\0';
    e->len = len;
    e->af = req->af;
    e->expires = ngx_time() + req->ttl;
    e->negative = (req->rc != NGX_OK);
    e->naddrs = e->negative ? 0 : req->naddrs;
    for (i = 0; i < e->naddrs; i++) {
        e->addrs[i] = req->addrs[i];
        ngx_inet_set_port((struct sockaddr *) &e->addrs[i].ss, 0);
    }
    e->node.key = key;
    ngx_rbtree_insert(&dns_cache.tree, &e->node);
    ngx_queue_insert_head(&dns_cache.lru, &e->queue);
    dns_cache.entries++;
}


void
brix_dns_cache_store(const brix_dns_req_t *req)
{
    if (req->ttl <= 0 || req->literal) {
        return;
    }
    pthread_mutex_lock(&dns_cache_mu);
    dns_cache_store_locked(req);
    pthread_mutex_unlock(&dns_cache_mu);
}


/* WHAT: insert an in-flight marker for (name, af) unless a live entry exists.
 * WHY:  brix_dns_lookup_cached() must not start one background fill per probe
 *       while the first is still running; the marker makes the second probe
 *       an "in flight" answer instead.  brix_dns_cache_store() replaces it.
 * HOW:  a pending entry with a short expiry; an expired marker (fill lost) is
 *       simply re-armed. */
unsigned
brix_dns_cache_mark_pending(const ngx_str_t *name, brix_af_policy_t af,
    time_t hold)
{
    u_char             lower[BRIX_RESOLV_DOMAIN_LEN];
    size_t             len;
    uint32_t           key;
    dns_cache_entry_t *e;
    unsigned           marked = 0;

    pthread_mutex_lock(&dns_cache_mu);
    dns_cache_ready();
    key = dns_cache_key(name, lower, &len);
    e = dns_cache_find(key, lower, len, af);
    if (e != NULL && e->expires > ngx_time()) {
        pthread_mutex_unlock(&dns_cache_mu);
        return 0;
    }
    if (e != NULL) {
        dns_cache_remove(e);
    }
    dns_cache_evict_lru();
    e = ngx_calloc(sizeof(dns_cache_entry_t), ngx_cycle->log);
    if (e != NULL) {
        e->name = ngx_alloc(len + 1, ngx_cycle->log);
        if (e->name == NULL) {
            ngx_free(e);
            e = NULL;
        }
    }
    if (e != NULL) {
        ngx_memcpy(e->name, lower, len);
        e->name[len] = '\0';
        e->len = len;
        e->af = af;
        e->expires = ngx_time() + (hold > 0 ? hold : BRIX_DNS_PENDING_HOLD);
        e->pending = 1;
        e->node.key = key;
        ngx_rbtree_insert(&dns_cache.tree, &e->node);
        ngx_queue_insert_head(&dns_cache.lru, &e->queue);
        dns_cache.entries++;
        marked = 1;
    }
    pthread_mutex_unlock(&dns_cache_mu);
    return marked;
}


void
brix_dns_cache_stats(ngx_uint_t *entries, ngx_uint_t *hits,
    ngx_uint_t *misses, ngx_uint_t *negative_hits)
{
    pthread_mutex_lock(&dns_cache_mu);
    *entries = dns_cache.entries;
    *hits = dns_cache.hits;
    *misses = dns_cache.misses;
    *negative_hits = dns_cache.negative_hits;
    pthread_mutex_unlock(&dns_cache_mu);
}
