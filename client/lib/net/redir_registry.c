/*
 * redir_registry.c — redirect-collapse registry (§7.11). See redir_registry.h.
 *
 * A bounded array of (url -> target) pairs. record() collapses the new target
 * through the table so stored mappings are always url->FINAL; lookup() still
 * follows the chain hop-capped as a belt-and-suspenders against a mapping added
 * before a later one shortened it. Cycles can never be stored (record refuses a
 * mapping whose collapsed target is the url itself), and both record and lookup
 * bound their hop counts, so no operation can spin.
 */
#include "net/redir_registry.h"

#include <stdlib.h>
#include <string.h>

#define VREDIR_CAP      256      /* endpoints a single copy touches: small */
#define VREDIR_MAX_HOPS 32       /* chain-follow bound (cycle/deep-chain guard) */

typedef struct {
    char    *url;
    char    *target;
    unsigned seq;                /* LRU stamp: higher = more recently used */
} vredir_entry_t;

static vredir_entry_t  vredir_tbl[VREDIR_CAP];
static unsigned        vredir_n;
static unsigned        vredir_clock;

/* Find the slot for `url`, or NULL. */
static vredir_entry_t *
vredir_find(const char *url)
{
    unsigned i;

    for (i = 0; i < vredir_n; i++) {
        if (strcmp(vredir_tbl[i].url, url) == 0) {
            return &vredir_tbl[i];
        }
    }
    return NULL;
}

/* Follow url through the chain (hop-capped), returning the final target string
 * or NULL if `url` maps nowhere. */
static const char *
vredir_resolve(const char *url)
{
    const char *cur = url;
    const char *last = NULL;
    int         hops;

    for (hops = 0; hops < VREDIR_MAX_HOPS; hops++) {
        vredir_entry_t *e = vredir_find(cur);

        if (e == NULL) {
            break;
        }
        last = e->target;
        cur  = e->target;
    }
    return last;
}

const char *
brix_vredir_lookup(const char *url)
{
    if (url == NULL || url[0] == '\0') {
        return NULL;
    }
    return vredir_resolve(url);
}

/* Evict the least-recently-used entry to make room. */
static void
vredir_evict_lru(void)
{
    unsigned i, victim = 0;

    for (i = 1; i < vredir_n; i++) {
        if (vredir_tbl[i].seq < vredir_tbl[victim].seq) {
            victim = i;
        }
    }
    free(vredir_tbl[victim].url);
    free(vredir_tbl[victim].target);
    vredir_tbl[victim] = vredir_tbl[--vredir_n];
}

void
brix_vredir_record(const char *url, const char *target)
{
    const char     *final;
    vredir_entry_t *e;
    char           *ku, *kt;

    if (url == NULL || target == NULL || url[0] == '\0' || target[0] == '\0') {
        return;
    }
    /* Collapse the target through any existing chain, then refuse a mapping that
     * would point url at itself (direct or via the chain) — that is the cycle. */
    final = vredir_resolve(target);
    if (final == NULL) {
        final = target;
    }
    if (strcmp(final, url) == 0) {
        return;
    }

    e = vredir_find(url);
    if (e != NULL) {                        /* update in place */
        char *nt = strdup(final);
        if (nt == NULL) {
            return;
        }
        free(e->target);
        e->target = nt;
        e->seq    = ++vredir_clock;
        return;
    }

    if (vredir_n == VREDIR_CAP) {
        vredir_evict_lru();
    }
    ku = strdup(url);
    kt = strdup(final);
    if (ku == NULL || kt == NULL) {
        free(ku);
        free(kt);
        return;
    }
    vredir_tbl[vredir_n].url    = ku;
    vredir_tbl[vredir_n].target = kt;
    vredir_tbl[vredir_n].seq    = ++vredir_clock;
    vredir_n++;
}

void
brix_vredir_clear(void)
{
    unsigned i;

    for (i = 0; i < vredir_n; i++) {
        free(vredir_tbl[i].url);
        free(vredir_tbl[i].target);
    }
    vredir_n = 0;
    vredir_clock = 0;
}

unsigned
brix_vredir_count(void)
{
    return vredir_n;
}
