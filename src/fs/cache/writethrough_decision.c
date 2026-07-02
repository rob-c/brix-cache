#include "writethrough.h"
#include "cache_admit.h"   /* shared admission filter (read+write parity) */

#include <string.h>
#include <sys/stat.h>

/*
 * writethrough_decision.c — the default write-through policy engine. At kXR_open
 * time it decides DENY / ALLOW_SYNC / ALLOW_ASYNC for a path (the result is cached
 * on the handle to drive close-time flush). Mirrors XrdPfc's blacklist/allow
 * decisions, priority order: size filter → deny prefixes (precedence) → allow
 * prefixes (whitelist) → default ALLOW_SYNC. A custom xrootd_wt_decision_fn can
 * replace it via config.
 */

/* xrootd_wt_default_decide — the policy decision at kXR_open write intent (from
 * read/open.c): DENY on NULL config/path; otherwise the shared admission filter
 * (size cap skipped for a not-yet-existing kXR_new file or a path that does not
 * stat as a regular file, bypassed by an include-regex match; deny prefixes take
 * precedence, then the allow whitelist). An ADMIT becomes ALLOW_ASYNC. */
xrootd_wt_decision_t xrootd_wt_default_decide(const char *path, uint16_t options,
                                               void *user_data)
{
    xrootd_wt_decision_cfg_t *cfg;
    xrootd_cache_admit_cfg_t  a;
    off_t                     size = 0;
    int                       is_new;

    if (user_data == NULL || path == NULL) {
        return XROOTD_WT_DECISION_DENY;          /* fail-closed */
    }
    cfg = (xrootd_wt_decision_cfg_t *) user_data;

    /* Resolve the size for the cap: a kXR_new create has no size yet; an existing
     * regular file contributes its st_size; anything else skips the cap. stat()
     * is a local syscall, not a network round-trip. */
    is_new = (options & kXR_new) != 0;
    if (!is_new && cfg->max_write_through_bytes > 0) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            size = st.st_size;
        } else {
            is_new = 1;                          /* not a regular existing file */
        }
    }

    a.deny_prefixes  = cfg->deny_prefixes;
    a.allow_prefixes = cfg->allow_prefixes;
    a.size_limit     = cfg->max_write_through_bytes;
    a.include_regex  = cfg->include_regex_set ? &cfg->include_regex : NULL;

    if (xrootd_cache_admit(&a, path, size, is_new) == XROOTD_CACHE_DECLINE) {
        return XROOTD_WT_DECISION_DENY;
    }
    return XROOTD_WT_DECISION_ALLOW_ASYNC;
}

/* xrootd_wt_config_init_prefixes — populate a cf->pool-lived prefix array (created
 * on first use, capacity 4) from a config directive's prefix list; the strings
 * persist across merges. Logs the configured count. */
ngx_int_t xrootd_wt_config_init_prefixes(ngx_conf_t *cf,
                                          ngx_array_t *prefix_list,
                                          ngx_array_t **out_array,
                                          const char *directive_name)
{
    ngx_uint_t i;

    if (prefix_list == NULL) {
        return NGX_OK;
    }

    if (*out_array == NULL) {
        *out_array = ngx_array_create(cf->pool, 4, sizeof(xrootd_wt_prefix_entry_t));
        if (*out_array == NULL) {
            return NGX_ERROR;
        }
    }

    for (i = 0; i < prefix_list->nelts; i++) {
        ngx_str_t *src = prefix_list->elts;
        xrootd_wt_prefix_entry_t *entry = ngx_array_push(*out_array);
        if (entry == NULL) {
            return NGX_ERROR;
        }
        entry->prefix = src[i];
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "wt: configured %ui prefix entries for %s",
                       (*out_array)->nelts, directive_name);
    return NGX_OK;
}

xrootd_wt_decision_t
xrootd_cache_should_writethrough(const xrootd_vfs_ctx_t *ctx,
    off_t offset, size_t length)
{
    xrootd_wt_decision_cfg_t *cfg;
    const char               *path;
    void                     *user_data;

    (void) offset;
    (void) length;

    if (ctx == NULL || !ctx->cache_writethrough
        || ctx->cache_writethrough_cfg == NULL)
    {
        return XROOTD_WT_DECISION_DENY;
    }

    if (ctx->resolved.resolved.data == NULL) {
        return XROOTD_WT_DECISION_DENY;
    }

    cfg = ctx->cache_writethrough_cfg;
    if (cfg->fn == NULL) {
        return XROOTD_WT_DECISION_DENY;
    }

    path = (const char *) ctx->resolved.resolved.data;
    user_data = cfg->user_data != NULL ? cfg->user_data : cfg;

    return cfg->fn(path, 0, user_data);
}
