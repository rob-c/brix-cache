#include "../ngx_xrootd_module.h"

#include <string.h>

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
