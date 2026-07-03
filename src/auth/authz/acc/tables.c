/*
 * tables.c — identity-table lookups + table lifetime (XrdAccAccess_Tables).
 *
 * WHAT: brix_acc_named_find() resolves a name (user/group/host/org/role/
 *   netgroup/template) to its capability list by exact match;
 *   brix_acc_domain_find() resolves a host to a domain capability list by
 *   SUFFIX match (a `.cern.ch` record matches any host ending in `.cern.ch`).
 *   brix_acc_tables_free() releases an entire table generation.
 *
 * WHY: faithful ports of XrdOucHash::Find (exact) and XrdAccCapName::Find
 *   (suffix).  The category tables are modelled as singly-linked name lists
 *   rather than hashes — authdb files are small and authorization results are
 *   memoized by the existing auth cache, so O(rules) lookup is immaterial and
 *   keeps the build + atomic refresh swap trivial (one pool per generation).
 *
 * HOW: linear scan with ngx_strcmp for exact lookups; for domains, compare the
 *   record name against the tail of the host name of equal length.
 */

#include "acc.h"

brix_acc_cap_t *
brix_acc_named_find(brix_acc_named_t *list, const char *name)
{
    if (name == NULL) {
        return NULL;
    }
    for (; list != NULL; list = list->next) {
        if (ngx_strcmp(list->name, name) == 0) {
            return list->caps;
        }
    }
    return NULL;
}

brix_acc_cap_t *
brix_acc_domain_find(brix_acc_named_t *dlist, const char *host)
{
    int  hlen;

    if (host == NULL) {
        return NULL;
    }
    hlen = (int) ngx_strlen(host);

    /* A domain record (e.g. ".cern.ch") matches when it is a suffix of the
     * host of equal length (XrdAccCapName::Find). */
    for (; dlist != NULL; dlist = dlist->next) {
        if (dlist->nlen <= hlen
            && ngx_strcmp(dlist->name, host + (hlen - dlist->nlen)) == 0)
        {
            return dlist->caps;
        }
    }
    return NULL;
}

void
brix_acc_tables_free(brix_acc_tables_t *tabs)
{
    /* Every node (lists, names, caps, paths) was allocated from tabs->pool,
     * which itself was allocated from that pool's first block, so destroying
     * the pool reclaims the whole generation in one step. */
    if (tabs != NULL && tabs->pool != NULL) {
        ngx_destroy_pool(tabs->pool);
    }
}
