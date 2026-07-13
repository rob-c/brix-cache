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

/* Cache identity: a listing is keyed by (root, prefix, delimiter). Grouped
 * so file-local helpers pass one value instead of three parallel strings. */
typedef struct {
    const char *root;
    const char *prefix;
    const char *delimiter;
} s3_lc_id_t;

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
s3_lc_matches(const s3_lc_slot_t *s, const s3_lc_id_t *id)
{
    return s->used
           && strcmp(s->root, id->root) == 0
           && strcmp(s->prefix, id->prefix) == 0
           && strcmp(s->delimiter, id->delimiter) == 0;
}

int
s3_list_cache_get(ngx_http_request_t *r, const char *root,
    const char *prefix, const char *delimiter, time_t dir_mtime,
    ngx_msec_t ttl_ms, s3_entry_t **out_items, int *out_n)
{
    s3_lc_id_t    id = { root, prefix, delimiter };
    s3_lc_slot_t *s  = NULL;
    s3_entry_t   *items;
    int           i;

    for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
        if (s3_lc_matches(&s3_lc_slots[i], &id)) {
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

/*
 * WHAT: Decide whether an n-entry listing is cacheable, warning once if not.
 * WHY:  A listing larger than the cap would evict the whole per-worker cache
 *       for a single oversized directory; we skip it and log the reason once.
 * HOW:  Compare against S3_LIST_CACHE_MAX_ENTRIES; emit an INFO log the first
 *       time only (static latch) and report non-cacheable via the return.
 */
static int
s3_lc_within_cap(ngx_log_t *log, int n)
{
    static int  warned = 0;

    if (n <= S3_LIST_CACHE_MAX_ENTRIES) {
        return 1;
    }
    if (!warned) {
        warned = 1;
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "s3 list-cache: %d entries exceeds cap %d; "
                      "this listing is not cached", n,
                      S3_LIST_CACHE_MAX_ENTRIES);
    }
    return 0;
}

/*
 * WHAT: Pick the slot to (re)use for (root, prefix, delimiter).
 * WHY:  Storing must reuse a matching slot in place, otherwise fill a free
 *       slot, otherwise evict the least-recently-used one — this is the sole
 *       eviction policy and must not change.
 * HOW:  One pass prefers an identity match (early return) and otherwise
 *       remembers a free slot; if none is free, a second pass selects the
 *       minimum-seq used slot. Returns NULL only for an empty slot array.
 */
static s3_lc_slot_t *
s3_lc_select_victim(const s3_lc_id_t *id)
{
    s3_lc_slot_t *victim  = NULL;
    uint64_t      min_seq = (uint64_t) -1;
    int           i;

    for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
        if (s3_lc_matches(&s3_lc_slots[i], id)) {
            return &s3_lc_slots[i];
        }
        if (!s3_lc_slots[i].used) {
            victim = &s3_lc_slots[i];                /* prefer a free slot */
        }
    }
    if (victim != NULL && !victim->used) {
        return victim;
    }

    victim = NULL;
    for (i = 0; i < S3_LIST_CACHE_SLOTS; i++) {
        if (s3_lc_slots[i].used && s3_lc_slots[i].seq < min_seq) {
            min_seq = s3_lc_slots[i].seq;
            victim  = &s3_lc_slots[i];
        }
    }
    return victim;
}

/*
 * WHAT: Deep-copy [items, n) into a fresh heap array of s3_lc_entry_t.
 * WHY:  Cached entries outlive the caller's request pool, so keys are strdup'd
 *       into ngx_alloc'd storage owned by the slot.
 * HOW:  Allocate the array, strdup each key; on any OOM, unwind the keys copied
 *       so far, free the array, and return NULL — leaving no partial state.
 */
static s3_lc_entry_t *
s3_lc_copy_entries(ngx_log_t *log, const s3_entry_t *items, int n)
{
    s3_lc_entry_t *copy;
    int            i;

    copy = ngx_alloc(sizeof(s3_lc_entry_t) * (size_t) n, log);
    if (copy == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        copy[i].key       = s3_lc_strdup(items[i].key);
        copy[i].is_prefix = items[i].is_prefix;
        if (copy[i].key == NULL) {                   /* OOM: unwind + bail */
            while (--i >= 0) {
                ngx_free(copy[i].key);
            }
            ngx_free(copy);
            return NULL;
        }
    }
    return copy;
}

/*
 * WHAT: Populate an emptied victim slot with the copied listing + identity.
 * WHY:  The slot is only marked used once all three identity strings are
 *       strdup'd; a partial strdup must not leave a half-built live slot.
 * HOW:  Copy identity strings; on any OOM free the entry array, clear the slot
 *       and return 0. On success wire up metadata and mark used, returning 1.
 */
static int
s3_lc_slot_store(s3_lc_slot_t *victim, const s3_lc_id_t *id, time_t dir_mtime,
    s3_lc_entry_t *copy, int n)
{
    victim->root      = s3_lc_strdup(id->root);
    victim->prefix    = s3_lc_strdup(id->prefix);
    victim->delimiter = s3_lc_strdup(id->delimiter);
    if (victim->root == NULL || victim->prefix == NULL
        || victim->delimiter == NULL)
    {
        int i;
        for (i = 0; i < n; i++) {
            ngx_free(copy[i].key);
        }
        ngx_free(copy);
        s3_lc_slot_clear(victim);
        return 0;
    }
    victim->dir_mtime = dir_mtime;
    victim->stored_at = ngx_current_msec;
    victim->entries   = copy;
    victim->n         = n;
    victim->seq       = ++s3_lc_seq;
    victim->used      = 1;
    return 1;
}

void
s3_list_cache_put(ngx_log_t *log, const char *root, const char *prefix,
    const char *delimiter, time_t dir_mtime, const s3_entry_t *items, int n)
{
    s3_lc_id_t     id = { root, prefix, delimiter };
    s3_lc_slot_t  *victim;
    s3_lc_entry_t *copy;

    if (!s3_lc_within_cap(log, n)) {
        return;
    }

    /* Reuse a matching slot, else a free slot, else evict the LRU. */
    victim = s3_lc_select_victim(&id);
    if (victim == NULL) {
        return;
    }

    copy = s3_lc_copy_entries(log, items, n);
    if (copy == NULL) {
        return;
    }

    s3_lc_slot_clear(victim);                         /* free any prior content */
    (void) s3_lc_slot_store(victim, &id, dir_mtime, copy, n);
}
