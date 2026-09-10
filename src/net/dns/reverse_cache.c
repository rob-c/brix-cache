/*
 * reverse_cache.c — per-worker reverse (PTR) answer cache (phase-116 W7).
 *
 * WHAT: A bounded cache keyed by the raw peer address (family + address
 *       bytes, port ignored) holding one FQDN, a negative marker, or an
 *       "in flight" marker with an expiry.  The reverse consumers — XrdAcc
 *       `h` rules, protbind hostname templates, `host` auth, the TPC origin
 *       id — ask this cache on the event loop and never wait for it there.
 * WHY:  Reverse lookups used to happen inline on the event loop (a blocking
 *       PTR query per connection) — a slow resolver stalled every
 *       connection in the worker.  Keying by address lets one background fill
 *       serve every connection from that peer for the record's TTL, and the
 *       in-flight marker keeps a burst of connections from starting a fill
 *       each (I-DNS-1).
 * HOW:  ngx_rbtree keyed by ngx_crc32_short over the address bytes with a
 *       memcmp on collision, plus an LRU queue — the forward cache's layout
 *       (cache.c).  Per-process singleton guarded by a plain pthread mutex:
 *       the event loop probes and stores, the TPC pull thread stores through
 *       brix_dns_reverse_sync().  Nothing under the lock blocks or re-enters.
 */
#include "net/dns/dns.h"

#include <pthread.h>

typedef struct {
    ngx_rbtree_node_t  node;       /* key = crc32 of the address bytes */
    ngx_queue_t        queue;      /* LRU */
    u_char             addr[16];   /* IPv4 in the first 4 bytes */
    size_t             alen;       /* 4 or 16 */
    sa_family_t        family;
    time_t             expires;
    unsigned           negative:1;
    unsigned           pending:1;
    char               name[BRIX_DNS_REVERSE_NAME_LEN];
} dns_rcache_entry_t;

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
} dns_rcache_t;

/* per-process singleton (origin_probe precedent: runtime-only state) */
static dns_rcache_t     dns_rcache;
static pthread_mutex_t  dns_rcache_mu = PTHREAD_MUTEX_INITIALIZER;


static void
dns_rcache_ready(void)
{
    if (dns_rcache.ready) {
        return;
    }
    ngx_rbtree_init(&dns_rcache.tree, &dns_rcache.sentinel,
                    ngx_rbtree_insert_value);
    ngx_queue_init(&dns_rcache.lru);
    if (dns_rcache.max == 0) {
        dns_rcache.max = BRIX_DNS_CACHE_MAX_DEFAULT;
    }
    dns_rcache.ready = 1;
}


/* [brix_dns_cache_max] bounds this cache too: its key space is the PEER's
 * address, so an unbounded reverse cache is a remote memory-growth lever. */
void
brix_dns_reverse_cache_set_max(ngx_uint_t max)
{
    if (max > 0) {
        pthread_mutex_lock(&dns_rcache_mu);
        dns_rcache.max = max;
        pthread_mutex_unlock(&dns_rcache_mu);
    }
}


/* The address bytes that identify a peer; 0 for an unsupported family. */
static size_t
dns_rcache_key(const struct sockaddr *sa, socklen_t len, u_char *addr,
    uint32_t *key)
{
    size_t  alen = 0;

    if (sa == NULL) {
        return 0;
    }
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        ngx_memcpy(addr, &((const struct sockaddr_in *) sa)->sin_addr, 4);
        alen = 4;
    }
#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        ngx_memcpy(addr, &((const struct sockaddr_in6 *) sa)->sin6_addr, 16);
        alen = 16;
    }
#endif
    if (alen > 0) {
        *key = ngx_crc32_short(addr, alen);
    }
    return alen;
}


static dns_rcache_entry_t *
dns_rcache_find(uint32_t key, const u_char *addr, size_t alen,
    sa_family_t family)
{
    ngx_rbtree_node_t  *node = dns_rcache.tree.root;
    ngx_rbtree_node_t  *sentinel = dns_rcache.tree.sentinel;

    while (node != sentinel) {
        dns_rcache_entry_t *e;

        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }
        e = (dns_rcache_entry_t *) node;
        if (e->alen == alen && e->family == family
            && ngx_memcmp(e->addr, addr, alen) == 0)
        {
            return e;
        }
        node = node->right;               /* crc collision: keep walking */
    }
    return NULL;
}


static void
dns_rcache_remove(dns_rcache_entry_t *e)
{
    ngx_rbtree_delete(&dns_rcache.tree, &e->node);
    ngx_queue_remove(&e->queue);
    dns_rcache.entries--;
    ngx_free(e);
}


static void
dns_rcache_evict_lru(void)
{
    ngx_queue_t  *q;

    while (dns_rcache.entries >= dns_rcache.max
           && !ngx_queue_empty(&dns_rcache.lru))
    {
        q = ngx_queue_last(&dns_rcache.lru);
        dns_rcache_remove(ngx_queue_data(q, dns_rcache_entry_t, queue));
    }
}


/* Insert a fresh entry for the key (any existing one already removed). */
static dns_rcache_entry_t *
dns_rcache_insert(uint32_t key, const u_char *addr, size_t alen,
    sa_family_t family, time_t expires)
{
    dns_rcache_entry_t  *e;

    dns_rcache_evict_lru();
    e = ngx_calloc(sizeof(dns_rcache_entry_t), ngx_cycle->log);
    if (e == NULL) {
        return NULL;
    }
    ngx_memcpy(e->addr, addr, alen);
    e->alen = alen;
    e->family = family;
    e->expires = expires;
    e->node.key = key;
    ngx_rbtree_insert(&dns_rcache.tree, &e->node);
    ngx_queue_insert_head(&dns_rcache.lru, &e->queue);
    dns_rcache.entries++;
    return e;
}


ngx_int_t
brix_dns_rcache_lookup(const struct sockaddr *sa, socklen_t len, char *buf,
    size_t buflen)
{
    u_char               addr[16];
    uint32_t             key = 0;
    size_t               alen;
    dns_rcache_entry_t  *e;
    ngx_int_t            rc;

    alen = dns_rcache_key(sa, len, addr, &key);
    if (alen == 0) {
        return NGX_DECLINED;                  /* no PTR for a non-IP peer */
    }
    pthread_mutex_lock(&dns_rcache_mu);
    dns_rcache_ready();
    e = dns_rcache_find(key, addr, alen, sa->sa_family);
    if (e != NULL && e->expires <= ngx_time()) {
        dns_rcache_remove(e);
        e = NULL;
    }
    if (e == NULL) {
        dns_rcache.misses++;
        rc = NGX_AGAIN;
    } else if (e->pending) {
        rc = NGX_AGAIN;
    } else if (e->negative) {
        dns_rcache.negative_hits++;
        rc = NGX_DECLINED;
    } else {
        dns_rcache.hits++;
        ngx_queue_remove(&e->queue);
        ngx_queue_insert_head(&dns_rcache.lru, &e->queue);
        if (buf != NULL && buflen > 0) {
            ngx_cpystrn((u_char *) buf, (u_char *) e->name, buflen);
        }
        rc = NGX_OK;
    }
    pthread_mutex_unlock(&dns_rcache_mu);
    return rc;
}


unsigned
brix_dns_rcache_mark_pending(const struct sockaddr *sa, socklen_t len,
    time_t hold)
{
    u_char               addr[16];
    uint32_t             key = 0;
    size_t               alen;
    dns_rcache_entry_t  *e;
    unsigned             marked = 0;

    alen = dns_rcache_key(sa, len, addr, &key);
    if (alen == 0) {
        return 0;
    }
    pthread_mutex_lock(&dns_rcache_mu);
    dns_rcache_ready();
    e = dns_rcache_find(key, addr, alen, sa->sa_family);
    if (e != NULL && e->expires > ngx_time()) {
        pthread_mutex_unlock(&dns_rcache_mu);
        return 0;                             /* known, or already in flight */
    }
    if (e != NULL) {
        dns_rcache_remove(e);
    }
    e = dns_rcache_insert(key, addr, alen, sa->sa_family,
                          ngx_time() + (hold > 0 ? hold
                                                 : BRIX_DNS_PENDING_HOLD));
    if (e != NULL) {
        e->pending = 1;
        marked = 1;
    }
    pthread_mutex_unlock(&dns_rcache_mu);
    return marked;
}


void
brix_dns_rcache_store(const struct sockaddr *sa, socklen_t len,
    const char *name, time_t ttl)
{
    u_char               addr[16];
    uint32_t             key = 0;
    size_t               alen;
    dns_rcache_entry_t  *e;

    alen = dns_rcache_key(sa, len, addr, &key);
    if (alen == 0 || ttl <= 0) {
        return;
    }
    pthread_mutex_lock(&dns_rcache_mu);
    dns_rcache_ready();
    e = dns_rcache_find(key, addr, alen, sa->sa_family);
    if (e != NULL) {
        dns_rcache_remove(e);
    }
    e = dns_rcache_insert(key, addr, alen, sa->sa_family, ngx_time() + ttl);
    if (e != NULL) {
        if (name == NULL || name[0] == '\0') {
            e->negative = 1;
        } else {
            ngx_cpystrn((u_char *) e->name, (u_char *) name, sizeof(e->name));
        }
    }
    pthread_mutex_unlock(&dns_rcache_mu);
}


void
brix_dns_rcache_stats(ngx_uint_t *entries, ngx_uint_t *hits,
    ngx_uint_t *misses, ngx_uint_t *negative_hits)
{
    pthread_mutex_lock(&dns_rcache_mu);
    *entries = dns_rcache.entries;
    *hits = dns_rcache.hits;
    *misses = dns_rcache.misses;
    *negative_hits = dns_rcache.negative_hits;
    pthread_mutex_unlock(&dns_rcache_mu);
}
