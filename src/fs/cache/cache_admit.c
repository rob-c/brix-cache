/*
 * cache_admit.c — the shared admission filter. See cache_admit.h. Lifted from
 * the write-through decision engine so read-caching and write-through share one
 * matcher (deny>allow precedence, whitelist, size cap, include-regex bypass).
 */

#include "cache_admit.h"

#include <string.h>

/* path starts with prefix (plain string compare, not regex). */
static int
admit_prefix_match(const char *path, const ngx_str_t *p)
{
    if (p->len == 0 || path == NULL) {
        return 0;
    }
    if (strlen(path) < p->len) {
        return 0;
    }
    return ngx_strncmp((u_char *) path, p->data, p->len) == 0;
}

static int
admit_any_prefix(const char *path, ngx_array_t *a)
{
    xrootd_wt_prefix_entry_t *e;
    ngx_uint_t                i;

    if (a == NULL || a->nelts == 0) {
        return 0;
    }
    e = a->elts;
    for (i = 0; i < a->nelts; i++) {
        if (admit_prefix_match(path, &e[i].prefix)) {
            return 1;
        }
    }
    return 0;
}

xrootd_cache_admit_e
xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg, const char *path,
    off_t size, int is_new)
{
    if (cfg == NULL || path == NULL) {
        return XROOTD_CACHE_DECLINE;            /* fail-closed */
    }

    /* Size cap: an existing file over the limit DECLINEs unless an include regex
     * matches; a not-yet-existing file (is_new) has no size to test. */
    if (cfg->size_limit > 0 && !is_new && size > cfg->size_limit) {
        if (cfg->include_regex == NULL
            || regexec(cfg->include_regex, path, 0, NULL, 0) != 0)
        {
            return XROOTD_CACHE_DECLINE;
        }
    }

    /* Deny prefixes take precedence (blacklist). */
    if (admit_any_prefix(path, cfg->deny_prefixes)) {
        return XROOTD_CACHE_DECLINE;
    }

    /* A configured allow list is a whitelist: a non-match DECLINEs. */
    if (cfg->allow_prefixes != NULL && cfg->allow_prefixes->nelts > 0
        && !admit_any_prefix(path, cfg->allow_prefixes))
    {
        return XROOTD_CACHE_DECLINE;
    }

    return XROOTD_CACHE_ADMIT;
}
