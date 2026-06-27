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

/* xrootd_path_prefix_match — boundary-aware prefix test: path starts with prefix
 * (prefix_len bytes) AND the next byte is '\0' or '/', so `/data` matches
 * `/data/atlas` but not `/data-atlas`. The caller passes prefix_len (it knows the
 * rule length), avoiding a redundant strlen per request in the match loop. */

static ngx_flag_t
xrootd_path_prefix_match(const char *prefix, size_t prefix_len, const char *path)
{
    if (prefix == NULL || path == NULL) {
        return 0;
    }

    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    /*
     * The match must land on a path-component boundary so "/foo" does not match
     * "/foobar". A prefix that itself ends in '/' is already at a separator — the
     * root prefix "/" (which cannot be stripped) and any explicit "/dir/" prefix
     * therefore match everything beneath them. Without this, a manager_map / VO /
     * authdb rule on "/" matched only the literal "/" and not "/file" (e.g. a
     * static-map redirector failed to redirect a stat of "/blob.bin").
     */
    if (prefix_len > 0 && prefix[prefix_len - 1] == '/') {
        return 1;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

/* xrootd_find_vo_rule — longest-prefix-match the VO (Virtual Organization) rule for
 * a resolved path (a more specific `/data/atlas/run3` rule wins over `/data/atlas`):
 * scan the vo_rule_t array via xrootd_path_prefix_match tracking best_len. NULL if
 * none match. */

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

        if (!xrootd_path_prefix_match(rule[i].resolved, rule_len,
                                      resolved_path))
        {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

/* xrootd_find_group_rule — longest-prefix-match the group policy rule for a resolved
 * path (enabling parent-group inheritance: a `/data/cms/group1` rule wins over a
 * generic cms-level one); same scan as xrootd_find_vo_rule over group_rule_t. */

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

        if (!xrootd_path_prefix_match(rule[i].resolved, rule_len,
                                      resolved_path))
        {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

/* xrootd_find_manager_map — longest-prefix-match the manager-map entry routing a
 * request path to a cluster management server / special endpoint; same scan over
 * manager_map_t (using entry[i].prefix.len). */

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
                                      prefix_len, reqpath))
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
