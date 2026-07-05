/* copy_filter.c — pure transfer-policy predicates for xrdcp.
 * WHAT: --exclude/--include pattern matching + --sync-check up-to-date test.
 * WHY:  the same policy must apply identically in the single, batch, and
 *       recursive copy paths (lib + app), so it lives here once, pure and
 *       unit-testable.
 * HOW:  fnmatch(3) with flags 0 against the copy-root-relative path AND its
 *       basename (so `--exclude '*.log'` works at any depth). Exclude wins
 *       over include; a non-empty include list is a whitelist for files. */
#include "copy_internal.h"
#include <fnmatch.h>

static const char *
rel_basename(const char *rel)
{
    const char *b = strrchr(rel, '/');
    return (b != NULL) ? b + 1 : rel;
}

int
brix_copy_filter_match(const brix_copy_opts *o, const char *rel)
{
    size_t i;

    if (o == NULL || rel == NULL) {
        return 1;
    }
    for (i = 0; i < o->n_excludes; i++) {
        if (fnmatch(o->excludes[i], rel, 0) == 0
            || fnmatch(o->excludes[i], rel_basename(rel), 0) == 0) {
            return 0;
        }
    }
    if (o->n_includes > 0) {
        for (i = 0; i < o->n_includes; i++) {
            if (fnmatch(o->includes[i], rel, 0) == 0
                || fnmatch(o->includes[i], rel_basename(rel), 0) == 0) {
                return 1;
            }
        }
        return 0;
    }
    return 1;
}

int
brix_sync_should_skip(int cmp, long long ssz, long long smt,
                      long long dsz, long long dmt)
{
    if (ssz != dsz) {
        return 0;
    }
    if (cmp == XRDC_SYNC_MTIME && smt > dmt) {
        return 0;   /* source is newer than the destination — copy */
    }
    return 1;       /* SIZE (and the size half of CKSUM) — up to date */
}
