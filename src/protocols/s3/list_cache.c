/*
 * list_cache.c — per-worker LRU cache of sorted ListObjects results (W6c).
 * See list_cache.h for the design, consistency model, and rationale.
 */

#include "list_cache.h"

#include <string.h>

#define S3_LIST_CACHE_SLOTS  16

typedef struct {
    char     *key;        /* ngx_alloc'd, NUL-terminated */
    unsigned  is_prefix;
} s3_lc_entry_t;

typedef struct {
    int            used;
    uint64_t       seq;          /* LRU recency (higher = more recent) */
    char          *root;         /* identity: (root, prefix, delimiter) */
    char          *prefix;
    char          *delimiter;
    time_t         dir_mtime;    /* bucket-root mtime when stored */
    ngx_msec_t     stored_at;    /* ngx_current_msec at store time */
    s3_lc_entry_t *entries;
    int            n;
} s3_lc_slot_t;

/* Per-worker (process-local) state — never shared across workers. */
static s3_lc_slot_t  s3_lc_slots[S3_LIST_CACHE_SLOTS];
static uint64_t      s3_lc_seq;

static char *
s3_lc_strdup(const char *s)
{
    size_t  n = strlen(s) + 1;
    char   *p = ngx_alloc(n, ngx_cycle->log);
    if (p != NULL) {
        ngx_memcpy(p, s, n);
    }
    return p;
}

/* Release a slot's heap and mark it free. */
static void
s3_lc_slot_clear(s3_lc_slot_t *s)
{
    int i;

    if (s->entries != NULL) {
        for (i = 0; i < s->n; i++) {
            ngx_free(s->entries[i].key);
        }
        ngx_free(s->entries);
    }
    ngx_free(s->root);
    ngx_free(s->prefix);
    ngx_free(s->delimiter);
    ngx_memzero(s, sizeof(*s));
}

static int
s3_lc_matches(const s3_lc_slot_t *s, const char *root, const char *prefix,
    const char *delimiter)
{
    return s->used
           && strcmp(s->root, root) == 0
           && strcmp(s->prefix, prefix) == 0
           && strcmp(s->delimiter, delimiter) == 0;
}

int
s3_list_cache_get(ngx_http_request_t *r, const char *root,
    const char *prefix, const char *delimiter, time_t dir_mtime,
    ngx_msec_t ttl_ms, s3_entry_t **out_items, int *out_n)
{
    s3_lc_slot_t *s = NULL;
    s3_entry_t   *items;
    int           i;

    for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
        if (s3_lc_matches(&s3_lc_slots[i], root, prefix, delimiter)) {
            s = &s3_lc_slots[i];
            break;
        }
    }
    if (s == NULL) {
        return 0;                                   /* not cached */
    }

    /* Invalidate on a top-level mutation or TTL expiry. */
    if (s->dir_mtime != dir_mtime
        || (ngx_msec_t) (ngx_current_msec - s->stored_at) >= ttl_ms)
    {
        s3_lc_slot_clear(s);
        return 0;
    }

    /* Hit: materialise an s3_entry_t array in the request pool, duplicating the
     * keys (stat fields left zero for the lazy per-page s3_entry_fill_stat). */
    items = ngx_pcalloc(r->pool, sizeof(s3_entry_t) * (size_t) s->n);
    if (items == NULL) {
        return 0;                                   /* fall back to a walk */
    }
    for (i = 0; i < s->n; i++) {
        size_t klen = strlen(s->entries[i].key);
        char  *kp   = ngx_pnalloc(r->pool, klen + 1);
        if (kp == NULL) {
            return 0;
        }
        ngx_memcpy(kp, s->entries[i].key, klen + 1);
        items[i].key       = kp;
        items[i].is_prefix = s->entries[i].is_prefix;
    }

    s->seq = ++s3_lc_seq;                            /* mark most-recently-used */
    *out_items = items;
    *out_n     = s->n;
    return 1;
}

void
s3_list_cache_put(ngx_log_t *log, const char *root, const char *prefix,
    const char *delimiter, time_t dir_mtime, const s3_entry_t *items, int n)
{
    s3_lc_slot_t *victim = NULL;
    s3_lc_entry_t *copy;
    uint64_t       min_seq = (uint64_t) -1;
    int            i;

    if (n > S3_LIST_CACHE_MAX_ENTRIES) {
        static int warned = 0;
        if (!warned) {
            warned = 1;
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "s3 list-cache: %d entries exceeds cap %d; "
                          "this listing is not cached", n,
                          S3_LIST_CACHE_MAX_ENTRIES);
        }
        return;
    }

    /* Reuse a matching slot, else a free slot, else evict the LRU. */
    for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
        if (s3_lc_matches(&s3_lc_slots[i], root, prefix, delimiter)) {
            victim = &s3_lc_slots[i];
            break;
        }
        if (!s3_lc_slots[i].used) {
            victim = &s3_lc_slots[i];                /* prefer a free slot */
        } else if (victim == NULL || !victim->used) {
            /* keep the best free candidate; otherwise track LRU below */
        }
    }
    if (victim == NULL || victim->used) {
        for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
            if (s3_lc_slots[i].used && s3_lc_slots[i].seq < min_seq) {
                min_seq = s3_lc_slots[i].seq;
                victim  = &s3_lc_slots[i];
            }
        }
    }
    if (victim == NULL) {
        return;
    }

    copy = ngx_alloc(sizeof(s3_lc_entry_t) * (size_t) n, log);
    if (copy == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {
        copy[i].key       = s3_lc_strdup(items[i].key);
        copy[i].is_prefix = items[i].is_prefix;
        if (copy[i].key == NULL) {                   /* OOM: unwind + bail */
            while (--i >= 0) {
                ngx_free(copy[i].key);
            }
            ngx_free(copy);
            return;
        }
    }

    s3_lc_slot_clear(victim);                         /* free any prior content */
    victim->root      = s3_lc_strdup(root);
    victim->prefix    = s3_lc_strdup(prefix);
    victim->delimiter = s3_lc_strdup(delimiter);
    if (victim->root == NULL || victim->prefix == NULL
        || victim->delimiter == NULL)
    {
        for (i = 0; i < n; i++) {
            ngx_free(copy[i].key);
        }
        ngx_free(copy);
        s3_lc_slot_clear(victim);
        return;
    }
    victim->dir_mtime = dir_mtime;
    victim->stored_at = ngx_current_msec;
    victim->entries   = copy;
    victim->n         = n;
    victim->seq       = ++s3_lc_seq;
    victim->used      = 1;
}
