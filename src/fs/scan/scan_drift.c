/*
 * scan_drift.c — namespace↔catalog reconciliation set (see scan_drift.h).
 *
 * Open-addressing hash map (linear probe, power-of-two capacity, grow at 70%
 * load). Pure and ngx-free: it mallocs its own table (an engine-time structure,
 * not a hot path) and is unit-tested by scan_unittest.c.
 */
#include "scan_drift.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    char    *key;      /* NULL ⇒ empty slot */
    int64_t  size;
    int      seen;     /* set by match() */
} drift_slot;

struct brix_scan_driftset_s {
    drift_slot *tab;
    size_t      cap;   /* power of two */
    size_t      n;     /* live entries */
};

static size_t
drift_hash(const char *s)
{
    size_t h = 5381;
    for (; *s != '\0'; s++) {
        h = ((h << 5) + h) ^ (unsigned char) *s;   /* djb2-xor */
    }
    return h;
}

static size_t
drift_roundup_pow2(size_t v)
{
    size_t p = 16;
    while (p < v) {
        p <<= 1;
    }
    return p;
}

brix_scan_driftset_t *
brix_scan_driftset_create(size_t expected)
{
    brix_scan_driftset_t *s = calloc(1, sizeof(*s));

    if (s == NULL) {
        return NULL;
    }
    s->cap = drift_roundup_pow2(expected * 2 + 1);
    s->tab = calloc(s->cap, sizeof(*s->tab));
    if (s->tab == NULL) {
        free(s);
        return NULL;
    }
    return s;
}

void
brix_scan_driftset_free(brix_scan_driftset_t *s)
{
    size_t i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < s->cap; i++) {
        free(s->tab[i].key);
    }
    free(s->tab);
    free(s);
}

/* Locate the slot for `key`: either the slot holding it, or the first empty slot
 * on its probe chain. Returns the index. */
static size_t
drift_probe(const drift_slot *tab, size_t cap, const char *key)
{
    size_t i = drift_hash(key) & (cap - 1);

    while (tab[i].key != NULL && strcmp(tab[i].key, key) != 0) {
        i = (i + 1) & (cap - 1);
    }
    return i;
}

static int
drift_grow(brix_scan_driftset_t *s)
{
    size_t      newcap = s->cap << 1;
    drift_slot *newtab = calloc(newcap, sizeof(*newtab));
    size_t      i;

    if (newtab == NULL) {
        return -1;
    }
    for (i = 0; i < s->cap; i++) {
        if (s->tab[i].key != NULL) {
            size_t j = drift_probe(newtab, newcap, s->tab[i].key);
            newtab[j] = s->tab[i];   /* move the key pointer + size + seen */
        }
    }
    free(s->tab);
    s->tab = newtab;
    s->cap = newcap;
    return 0;
}

int
brix_scan_driftset_add(brix_scan_driftset_t *s, const char *key, int64_t size)
{
    size_t i;

    if ((s->n + 1) * 10 >= s->cap * 7) {   /* > 70% load ⇒ grow */
        if (drift_grow(s) != 0) {
            return -1;
        }
    }
    i = drift_probe(s->tab, s->cap, key);
    if (s->tab[i].key != NULL) {
        s->tab[i].size = size;             /* update existing */
        return 0;
    }
    s->tab[i].key = strdup(key);
    if (s->tab[i].key == NULL) {
        return -1;
    }
    s->tab[i].size = size;
    s->tab[i].seen = 0;
    s->n++;
    return 0;
}

brix_scan_drift_class_t
brix_scan_driftset_match(brix_scan_driftset_t *s, const char *key,
                           int64_t ns_size, int64_t *cat_size)
{
    size_t i = drift_probe(s->tab, s->cap, key);

    if (s->tab[i].key == NULL) {
        return BRIX_DRIFT_NAMESPACE_ONLY;
    }
    s->tab[i].seen = 1;
    if (cat_size != NULL) {
        *cat_size = s->tab[i].size;
    }
    return (s->tab[i].size == ns_size) ? BRIX_DRIFT_IN_BOTH
                                       : BRIX_DRIFT_SIZE_MISMATCH;
}

void
brix_scan_driftset_orphans(brix_scan_driftset_t *s,
                             brix_scan_orphan_cb cb, void *ctx)
{
    size_t i;

    for (i = 0; i < s->cap; i++) {
        if (s->tab[i].key != NULL && !s->tab[i].seen) {
            cb(ctx, s->tab[i].key, s->tab[i].size);
        }
    }
}
