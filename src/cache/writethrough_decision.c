#include "writethrough_decision.h"

#include <string.h>
#include <sys/stat.h>

/* ---- Write-through default policy engine (prefix-based) — kXR_open time decision ----
 *
 * WHAT: Default write-through policy engine that evaluates whether a file should be propagated back to origin XRootD server.
 *       Called once at kXR_open time, result cached on handle determines close-time flush behavior (DENY/ALLOW_SYNC/ALLOW_ASYNC). */

/*---- Policy engine mechanism ----
 *
 * WHAT: Mirrors XrdPfcBlacklistDecision.cc's approach of checking a path database against configured deny/allow lists.
 *       Decision logic follows priority order: size filter → deny prefixes → allow prefixes → default ALLOW_SYNC. */

/*---- Policy engine invariant (priority ordering) ----
 *
 * WHY: Deny prefixes take precedence over allow prefixes, ensuring blacklist semantics where explicit exclusions override whitelists. */

/*---- Default policy engine flow ----
 *
 * HOW: 1) Size check — if file > max_write_through_bytes AND no include regex match → DENY; 
 *      2) Deny prefix check — any deny_prefix matches → DENY (deny takes precedence);
 *      3) Allow prefix check — allow list configured AND none match → DENY (whitelist mode);
 *      4) Default — ALLOW_SYNC (mirrors XrdPfcAllowDecision, sync preferred for local origins). */

/*---- Policy engine extensibility ----
 *
 * WHY: External plugins can provide custom xrootd_wt_decision_fn implementation and register via config callback.
 *      This default engine is suitable for most deployments without requiring external plugin setup. */

/* ---- Internal helpers — prefix matching utility functions ----
 *
 * WHAT: Two helper functions for checking if a path matches a single prefix or any prefix in an array.
 *       xrootd_wt_path_matches_prefix() = O(n) comparison where n = prefix length; acceptable for typical path prefixes (/data/, /atlas/). */

/*---- Prefix matching helper function ----
 *
 * WHAT: Simple prefix comparison — checks if path starts with prefix string using ngx_strncmp(). Returns 0 (false) on NULL/empty inputs. */

/*---- Array prefix matching helper function ----
 *
 * WHAT: Iterates through array of prefixes calling xrootd_wt_path_matches_prefix() for each entry. Returns 1 (true) if any match found. */

/* ---- Decision function (called at kXR_open time) — policy evaluation ----
 *
 * WHAT: Main decision function called from src/read/open.c when kXR_open options indicate write intent. Evaluates size, prefixes, and defaults to determine WT policy. */

/*---- Decision function precondition check ----
 *
 * WHY: Returns DENY if user_data (config) or path is NULL — conservative default prevents unauthorized writes without proper configuration. */

/*---- Size-based admission filter (mirrors cache_max_file_size) ----
 *
 * WHAT: Files larger than max_write_through_bytes are denied unless they match an include regex (configured via xrootd_cache_include_regex). */

/*---- Size check invariant (existing vs new file handling) ----
 *
 * WHY: If file doesn't exist yet (kXR_new open), skip size check and allow creation — this prevents blocking new file creation. */

/*---- Prefix-based admission control ----
 *
 * WHAT: Deny prefixes take precedence (blacklist semantics); allow list configured AND path doesn't match → deny (whitelist mode). */

/*---- Default policy — allow with async flush ----
 *
 * WHY: Mirrors XrdPfcAllowDecision. Sync mode is preferred for local filesystem origins; async for proxy mode. */

/* ---- Configuration helper functions — prefix array initialization ----
 *
 * WHAT: Helper function to initialize and populate prefix arrays from nginx configuration directives. Allocates memory from cf->pool for persistence. */

/*---- Config init helper flow ----
 *
 * HOW: 1) Allocate array if NULL (ngx_array_create with 4 entries); 2) Copy each prefix string into entry from prefix_list;
 *      3) Log configured count via ngx_conf_log_error(NGX_LOG_NOTICE). Prefix strings allocated from cf->pool persist across merges. */

/*---- Config init helper invariant ----
 *
 * WHY: Prefix strings allocated from cf->pool so they persist across merges and don't need to be freed manually — prevents resource leaks. */

/* ---- Internal helpers ---- */

static inline int xrootd_wt_path_matches_prefix(const char *path, const ngx_str_t *prefix)
{
    /* Simple prefix comparison: path starts with prefix string.
     * This is O(n) where n = prefix length — acceptable for typical
     * path prefixes (/data/, /atlas/, etc.). */
    if (prefix->len == 0 || path == NULL) {
        return 0;
    }
    if ((size_t)(path[0] ? strlen(path) : 0) < prefix->len) {
        return 0;
    }
    return ngx_strncmp((u_char *) path, prefix->data, prefix->len) == 0;
}

static inline int xrootd_wt_path_matches_any_prefix(const char *path, ngx_array_t *prefixes)
{
    if (prefixes == NULL || prefixes->nelts == 0) {
        return 0;
    }
    xrootd_wt_prefix_entry_t *entries = prefixes->elts;
    for (ngx_uint_t i = 0; i < prefixes->nelts; ++i) {
        if (xrootd_wt_path_matches_prefix(path, &entries[i].prefix)) {
            return 1;
        }
    }
    return 0;
}

/* ---- Decision function (called at kXR_open time) ---- */

xrootd_wt_decision_t xrootd_wt_default_decide(const char *path, uint16_t options,
                                               void *user_data)
{
    if (user_data == NULL || path == NULL) {
        /* No config or invalid path — deny to be safe. */
        return XROOTD_WT_DECISION_DENY;
    }

    xrootd_wt_decision_cfg_t *cfg = (xrootd_wt_decision_cfg_t *) user_data;

    /* Check 1: Size-based admission filter (mirrors cache_max_file_size).
     * Files larger than the limit are denied unless they match an include
     * regex (configured via xrootd_cache_include_regex — we reuse it here). */
    if (cfg->max_write_through_bytes > 0) {
        off_t file_size;

        /* Try to get file size via stat() — this is a local syscall, not a
         * network round-trip. If the file doesn't exist yet (kXR_new open),
         * skip the size check and allow creation. */
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            file_size = st.st_size;
        } else {
            /* File doesn't exist yet or not a regular file — allow creation. */
            goto check_prefixes;
        }

        if ((off_t)(options & kXR_new) == 0 && file_size > cfg->max_write_through_bytes) {
            /* Large existing file without include regex match → deny. */
            if (!cfg->include_regex_set || regexec(&cfg->include_regex, path, 0, NULL, 0) != 0) {
                return XROOTD_WT_DECISION_DENY;
            }
        }
    }

check_prefixes:
    /* Check 2: Deny prefixes take precedence (blacklist semantics). */
    if (xrootd_wt_path_matches_any_prefix(path, cfg->deny_prefixes)) {
        return XROOTD_WT_DECISION_DENY;
    }

    /* Check 3: If allow list is configured and path doesn't match → deny.
     * This implements an explicit whitelist mode when allow_prefixes is set. */
    if (cfg->allow_prefixes != NULL && cfg->allow_prefixes->nelts > 0) {
        if (!xrootd_wt_path_matches_any_prefix(path, cfg->allow_prefixes)) {
            return XROOTD_WT_DECISION_DENY;
        }
    }

    /* Check 4: Default — allow with async flush (mirrors XrdPfcAllowDecision).
     * Sync mode is preferred for local filesystem origins; async for proxy mode. */
    return XROOTD_WT_DECISION_ALLOW_ASYNC;
}

/* ---- Configuration helper functions ---- */

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
