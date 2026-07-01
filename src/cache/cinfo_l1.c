/*
 * cinfo_l1.c - the per-worker write-through cinfo cache (section 6.4). See header.
 *
 * A malloc-owned hash table (FNV-1a, chaining) over an intrusive MRU-at-head LRU
 * list. get/put/drop are O(1) amortised; put past the bound evicts the LRU tail.
 * No nginx pool so it is safe on the cache fill worker thread.
 */
#include "cinfo_l1.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Default entry bound when the policy leaves l1_entries 0 (section 2.3). */
#define CINFO_L1_DEFAULT_ENTRIES 4096

typedef struct cinfo_l1_entry_s {
    char                     *key;        /* strdup'd object key (lookup)        */
    xrootd_cache_cinfo_t      hdr;        /* the cached header record            */
    struct cinfo_l1_entry_s  *hnext;      /* hash-bucket chain                   */
    struct cinfo_l1_entry_s  *lru_prev;   /* LRU list (head = MRU, tail = LRU)   */
    struct cinfo_l1_entry_s  *lru_next;
} cinfo_l1_entry_t;

typedef struct {
    cinfo_l1_entry_t **buckets;
    size_t             nbuckets;          /* power of two */
    size_t             mask;              /* nbuckets - 1 */
    cinfo_l1_entry_t  *lru_head;
    cinfo_l1_entry_t  *lru_tail;
    size_t             count;
    size_t             max;
    ngx_log_t         *log;
} cinfo_l1_impl_t;

/* ---- pure helpers --------------------------------------------------------- */

/* Smallest power of two >= n (>= 1). */
static size_t
cinfo_l1_pow2_ceil(size_t n)
{
    size_t p = 1;

    while (p < n) {
        p <<= 1;
    }
    return p;
}

/* FNV-1a over a NUL-terminated key. */
static uint64_t
cinfo_l1_hash(const char *key)
{
    uint64_t h = 1469598103934665603ULL;   /* FNV offset basis */
    const unsigned char *p = (const unsigned char *) key;

    while (*p != '\0') {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;             /* FNV prime */
    }
    return h;
}

/* ---- intrusive LRU list --------------------------------------------------- */

static void
cinfo_l1_lru_unlink(cinfo_l1_impl_t *t, cinfo_l1_entry_t *e)
{
    if (e->lru_prev != NULL) {
        e->lru_prev->lru_next = e->lru_next;
    } else {
        t->lru_head = e->lru_next;
    }
    if (e->lru_next != NULL) {
        e->lru_next->lru_prev = e->lru_prev;
    } else {
        t->lru_tail = e->lru_prev;
    }
    e->lru_prev = NULL;
    e->lru_next = NULL;
}

static void
cinfo_l1_lru_push_front(cinfo_l1_impl_t *t, cinfo_l1_entry_t *e)
{
    e->lru_prev = NULL;
    e->lru_next = t->lru_head;
    if (t->lru_head != NULL) {
        t->lru_head->lru_prev = e;
    }
    t->lru_head = e;
    if (t->lru_tail == NULL) {
        t->lru_tail = e;
    }
}

/* Promote `e` to MRU. */
static void
cinfo_l1_touch(cinfo_l1_impl_t *t, cinfo_l1_entry_t *e)
{
    if (t->lru_head == e) {
        return;
    }
    cinfo_l1_lru_unlink(t, e);
    cinfo_l1_lru_push_front(t, e);
}

/* ---- hash bucket ops ------------------------------------------------------ */

static cinfo_l1_entry_t *
cinfo_l1_find(cinfo_l1_impl_t *t, const char *key, size_t bucket)
{
    cinfo_l1_entry_t *e;

    for (e = t->buckets[bucket]; e != NULL; e = e->hnext) {
        if (strcmp(e->key, key) == 0) {
            return e;
        }
    }
    return NULL;
}

/* Remove `e` from its hash chain (LRU unlink + free are the caller's job). */
static void
cinfo_l1_bucket_remove(cinfo_l1_impl_t *t, cinfo_l1_entry_t *e, size_t bucket)
{
    cinfo_l1_entry_t **pp = &t->buckets[bucket];

    while (*pp != NULL) {
        if (*pp == e) {
            *pp = e->hnext;
            return;
        }
        pp = &(*pp)->hnext;
    }
}

static void
cinfo_l1_evict_tail(cinfo_l1_impl_t *t)
{
    cinfo_l1_entry_t *victim = t->lru_tail;
    size_t            bucket;

    if (victim == NULL) {
        return;
    }
    bucket = (size_t) (cinfo_l1_hash(victim->key) & t->mask);
    cinfo_l1_bucket_remove(t, victim, bucket);
    cinfo_l1_lru_unlink(t, victim);
    free(victim->key);
    free(victim);
    t->count--;
}

/* ---- public API ----------------------------------------------------------- */

xrootd_cinfo_l1_t *
xrootd_cinfo_l1_create(size_t max_entries, ngx_log_t *log)
{
    xrootd_cinfo_l1_t *l1;
    cinfo_l1_impl_t   *t;

    if (max_entries == 0) {
        max_entries = CINFO_L1_DEFAULT_ENTRIES;
    }
    l1 = calloc(1, sizeof(*l1));
    t  = calloc(1, sizeof(*t));
    if (l1 == NULL || t == NULL) {
        free(l1);
        free(t);
        errno = ENOMEM;
        return NULL;
    }
    t->max      = max_entries;
    t->nbuckets = cinfo_l1_pow2_ceil(max_entries);
    t->mask     = t->nbuckets - 1;
    t->log      = log;
    t->buckets  = calloc(t->nbuckets, sizeof(*t->buckets));
    if (t->buckets == NULL) {
        free(t);
        free(l1);
        errno = ENOMEM;
        return NULL;
    }
    l1->opaque = t;
    return l1;
}

void
xrootd_cinfo_l1_destroy(xrootd_cinfo_l1_t *l1)
{
    cinfo_l1_impl_t  *t;
    cinfo_l1_entry_t *e;

    if (l1 == NULL || l1->opaque == NULL) {
        free(l1);
        return;
    }
    t = l1->opaque;
    e = t->lru_head;
    while (e != NULL) {
        cinfo_l1_entry_t *next = e->lru_next;

        free(e->key);
        free(e);
        e = next;
    }
    free(t->buckets);
    free(t);
    free(l1);
}

ngx_int_t
xrootd_cinfo_l1_get(xrootd_cinfo_l1_t *l1, const char *key,
    xrootd_cache_cinfo_t *out)
{
    cinfo_l1_impl_t  *t;
    cinfo_l1_entry_t *e;
    size_t            bucket;

    if (l1 == NULL || l1->opaque == NULL || key == NULL || out == NULL) {
        return NGX_DECLINED;
    }
    t = l1->opaque;
    bucket = (size_t) (cinfo_l1_hash(key) & t->mask);
    e = cinfo_l1_find(t, key, bucket);
    if (e == NULL) {
        return NGX_DECLINED;
    }
    *out = e->hdr;
    cinfo_l1_touch(t, e);
    return NGX_OK;
}

void
xrootd_cinfo_l1_put(xrootd_cinfo_l1_t *l1, const char *key,
    const xrootd_cache_cinfo_t *hdr)
{
    cinfo_l1_impl_t  *t;
    cinfo_l1_entry_t *e;
    size_t            bucket;

    if (l1 == NULL || l1->opaque == NULL || key == NULL || hdr == NULL) {
        return;
    }
    t = l1->opaque;
    bucket = (size_t) (cinfo_l1_hash(key) & t->mask);

    e = cinfo_l1_find(t, key, bucket);
    if (e != NULL) {
        e->hdr = *hdr;                 /* write-through update */
        cinfo_l1_touch(t, e);
        return;
    }

    e = calloc(1, sizeof(*e));
    if (e == NULL) {
        return;                        /* L1 is best-effort - a miss just refetches */
    }
    e->key = strdup(key);
    if (e->key == NULL) {
        free(e);
        return;
    }
    e->hdr = *hdr;
    e->hnext = t->buckets[bucket];
    t->buckets[bucket] = e;
    cinfo_l1_lru_push_front(t, e);
    t->count++;

    if (t->count > t->max) {
        cinfo_l1_evict_tail(t);
    }
}

void
xrootd_cinfo_l1_drop(xrootd_cinfo_l1_t *l1, const char *key)
{
    cinfo_l1_impl_t  *t;
    cinfo_l1_entry_t *e;
    size_t            bucket;

    if (l1 == NULL || l1->opaque == NULL || key == NULL) {
        return;
    }
    t = l1->opaque;
    bucket = (size_t) (cinfo_l1_hash(key) & t->mask);
    e = cinfo_l1_find(t, key, bucket);
    if (e == NULL) {
        return;
    }
    cinfo_l1_bucket_remove(t, e, bucket);
    cinfo_l1_lru_unlink(t, e);
    free(e->key);
    free(e);
    t->count--;
}
