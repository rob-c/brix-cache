#include "core/ngx_brix_module.h"

#include <stddef.h>
#include <string.h>

/*
 * WHAT: Longest-prefix rule matching — find the most specific policy rule for a resolved path.
 * WHY: Policy rules (VO, group, manager-map) are configured as prefixes that may overlap (e.g., `/data` and `/data/atlas`).
 *      The longest prefix match ensures the most specific rule wins when multiple prefixes cover the same path.
 *      This is critical for VO membership checks where broader groups inherit from narrower ones. INVARIANT:
 *      all paths passed here must be canonical (normalized via normalize.c) before matching.
 * HOW: Static helper brix_path_prefix_match validates prefix containment (must match up to prefix_len AND either end-of-string or next slash).
 *      brix_find_longest_rule holds the shared longest-prefix scan (parameterized by element size + offset of the resolved-prefix field),
 *      with brix_find_vo_rule / brix_find_group_rule as thin per-type wrappers; brix_find_manager_map runs the same scan inline because
 *      its prefix is an ngx_str_t (length known, no strlen). Returns NULL if no match found or input is invalid.
 */

/* brix_path_prefix_match — boundary-aware prefix test: path starts with prefix
 * (prefix_len bytes) AND the next byte is '\0' or '/', so `/data` matches
 * `/data/atlas` but not `/data-atlas`. The caller passes prefix_len (it knows the
 * rule length), avoiding a redundant strlen per request in the match loop. */

static ngx_flag_t
brix_path_prefix_match(const char *prefix, size_t prefix_len, const char *path)
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

/* ---- brix_find_longest_rule — generic longest-prefix rule scan ----
 *
 * WHAT: Scans an ngx_array_t of fixed-size rule elements, each holding a
 * NUL-terminated resolved-path prefix at byte offset `resolved_off`, and
 * returns a pointer to the element whose prefix is the longest
 * boundary-aware match for `resolved_path` (ties: last matching element
 * wins, via >=). Returns NULL when input is NULL or nothing matches.
 *
 * WHY: brix_find_vo_rule and brix_find_group_rule were byte-identical scans
 * differing only in the element type; one core parameterized by element size
 * and the offset of the `resolved` char array keeps the longest-prefix
 * semantics (and the tie-break) defined once.
 *
 * HOW: 1. NULL-guard path and array; 2. walk the elements as a byte array in
 * steps of `elt_size`; 3. strlen the prefix at `resolved_off`, filter through
 * brix_path_prefix_match; 4. track best/best_len with >= so a later
 * equal-length rule wins, exactly as the original loops did.
 */
static const void *
brix_find_longest_rule(const char *resolved_path, const ngx_array_t *rules,
                         size_t elt_size, size_t resolved_off)
{
    const u_char *elts;
    const void   *best = NULL;
    size_t        best_len = 0;
    ngx_uint_t    i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    elts = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        const char *prefix = (const char *) (elts + i * elt_size
                                             + resolved_off);
        size_t      rule_len = strlen(prefix);

        if (!brix_path_prefix_match(prefix, rule_len, resolved_path)) {
            continue;
        }

        if (rule_len >= best_len) {
            best = elts + i * elt_size;
            best_len = rule_len;
        }
    }

    return best;
}

/* brix_find_vo_rule — longest-prefix-match the VO (Virtual Organization) rule for
 * a resolved path (a more specific `/data/atlas/run3` rule wins over `/data/atlas`):
 * thin wrapper over brix_find_longest_rule for the vo_rule_t layout. NULL if
 * none match. */

const brix_vo_rule_t *
brix_find_vo_rule(const char *resolved_path, ngx_array_t *rules)
{
    return brix_find_longest_rule(resolved_path, rules,
                                    sizeof(brix_vo_rule_t),
                                    offsetof(brix_vo_rule_t, resolved));
}

/* brix_find_group_rule — longest-prefix-match the group policy rule for a resolved
 * path (enabling parent-group inheritance: a `/data/cms/group1` rule wins over a
 * generic cms-level one); thin wrapper over brix_find_longest_rule for the
 * group_rule_t layout. */

const brix_group_rule_t *
brix_find_group_rule(const char *resolved_path, ngx_array_t *rules)
{
    return brix_find_longest_rule(resolved_path, rules,
                                    sizeof(brix_group_rule_t),
                                    offsetof(brix_group_rule_t, resolved));
}

/* brix_find_manager_map — longest-prefix-match the manager-map entry routing a
 * request path to a cluster management server / special endpoint; same scan over
 * manager_map_t (using entry[i].prefix.len). */

const brix_manager_map_t *
brix_find_manager_map(const char *reqpath, ngx_array_t *map)
{
    const brix_manager_map_t *best = NULL;
    brix_manager_map_t       *entry;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (reqpath == NULL || map == NULL) {
        return NULL;
    }

    entry = map->elts;
    for (i = 0; i < map->nelts; i++) {
        size_t prefix_len = entry[i].prefix.len;

        if (!brix_path_prefix_match((const char *) entry[i].prefix.data,
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
