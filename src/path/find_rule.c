#include "../ngx_xrootd_module.h"

#include <string.h>

/*
 * WHAT: Longest-prefix rule matching — find the most specific policy rule for a resolved path.
 * WHY: Policy rules (VO, group, manager-map) are configured as prefixes that may overlap (e.g., `/data` and `/data/atlas`).
 *      The longest prefix match ensures the most specific rule wins when multiple prefixes cover the same path.
 *      This is critical for VO membership checks where broader groups inherit from narrower ones. INVARIANT:
 *      all paths passed here must be canonical (normalized via normalize.c) before matching.
 * HOW: Static helper xrootd_path_prefix_match validates prefix containment (must match up to prefix_len AND either end-of-string or next slash).
 *      Three public functions iterate their respective rule arrays using this helper, tracking best_len to select longest-matching rule.
 *      Returns NULL if no match found or input is invalid.
 */

/* ---- static helper: xrootd_path_prefix_match() ----
 * WHAT: Check whether path starts with prefix and the next byte after prefix is either end-of-string or a slash.
 * WHY: Prefix containment must be boundary-aware — `/data/atlas` matches `/data` but `/data-atlas` should NOT match.
 *      The boundary check (path[prefix_len] == '\0' || path[prefix_len] == '/') prevents false-positive prefix overlap.
 * HOW: strncmp comparison up to prefix_len; return 1 if match AND next byte is '\0' or '/'; return 0 otherwise. NULL guards prevent crashes. */

static ngx_flag_t
xrootd_path_prefix_match(const char *prefix, const char *path)
{
    size_t prefix_len;

    if (prefix == NULL || path == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

/* ---- public API: xrootd_find_vo_rule() ----
 * WHAT: Find the VO (Virtual Organization) rule with longest prefix match for a resolved filesystem path.
 * WHY: VO rules define access permissions per organization (ATLAS, CMS, etc.). Longest-prefix ensures that
 *      `/data/atlas/run3` matches the more specific `/data/atlas/run3` rule over the generic `/data/atlas` rule.
 * HOW: Iterate vo_rule_t array via xrootd_path_prefix_match; track best_len; return longest-matching rule or NULL. */

const xrootd_vo_rule_t *
xrootd_find_vo_rule(const char *resolved_path, ngx_array_t *rules)
{
    const xrootd_vo_rule_t *best = NULL;
    xrootd_vo_rule_t       *rule;
    size_t                  best_len = 0;
    ngx_uint_t              i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!xrootd_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

/* ---- public API: xrootd_find_group_rule() ----
 * WHAT: Find the group policy rule with longest prefix match for a resolved filesystem path.
 * WHY: Group rules enable parent-group inheritance — child groups inherit permissions from their parent group's path prefix.
 *      Longest-prefix ensures that `/data/cms/group1` matches more specific group1 rules over generic cms-level rules.
 * HOW: Identical pattern to xrootd_find_vo_rule — iterate group_rule_t array via xrootd_path_prefix_match; track best_len; return longest-matching rule or NULL. */

const xrootd_group_rule_t *
xrootd_find_group_rule(const char *resolved_path, ngx_array_t *rules)
{
    const xrootd_group_rule_t *best = NULL;
    xrootd_group_rule_t       *rule;
    size_t                     best_len = 0;
    ngx_uint_t                 i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!xrootd_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

/* ---- public API: xrootd_find_manager_map() ----
 * WHAT: Find the manager-map entry with longest prefix match for a request path.
 * WHY: Manager maps route specific paths to cluster management servers or special handling endpoints.
 *      Longest-prefix ensures `/data/manager/special` matches the most specific routing rule over generic `/data/manager` rules.
 * HOW: Identical pattern — iterate manager_map_t array via xrootd_path_prefix_match; track best_len (uses entry[i].prefix.len); return longest-matching entry or NULL. */

const xrootd_manager_map_t *
xrootd_find_manager_map(const char *reqpath, ngx_array_t *map)
{
    const xrootd_manager_map_t *best = NULL;
    xrootd_manager_map_t       *entry;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (reqpath == NULL || map == NULL) {
        return NULL;
    }

    entry = map->elts;
    for (i = 0; i < map->nelts; i++) {
        size_t prefix_len = entry[i].prefix.len;

        if (!xrootd_path_prefix_match((const char *) entry[i].prefix.data,
                                      reqpath))
        {
            continue;
        }

        if (prefix_len >= best_len) {
            best = &entry[i];
            best_len = prefix_len;
        }
    }

    return best;
}
