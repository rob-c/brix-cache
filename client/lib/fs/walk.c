/* walk.c — generic pre-order remote tree walk over brix_dirlist.
 * WHAT: visit every entry under `path` (files and directories), parent first.
 * WHY:  xrdcksum tree, sync --delete and future tools all need one bounded,
 *       overflow-checked walker instead of four ad-hoc recursions.
 * HOW:  brix_dirlist(want_stat=1) per directory; recursion capped at
 *       BRIX_WALK_MAXDEPTH; path joins are length-checked. */
#include "brix.h"
#include "brix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIX_WALK_MAXDEPTH 64

static int
walk_is_dot(const char *n)
{
    return n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0'));
}

static int
walk_join(const char *dir, const char *name, char *out, size_t outsz)
{
    size_t dl = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%s", dir, sep, name) >= outsz)
           ? -1 : 0;
}

static int
tree_walk_depth(brix_conn *c, const char *path, int depth,
                brix_walk_fn fn, void *u, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int          rc = 0;

    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n && rc == 0; i++) {
        char full[XRDC_PATH_MAX];
        if (walk_is_dot(ents[i].name)) {
            continue;
        }
        if (walk_join(path, ents[i].name, full, sizeof(full)) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "walk: path too long under %s", path);
            rc = -1;
            break;
        }
        rc = fn(full, &ents[i], depth, u);
        if (rc == 0 && ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            if (depth + 1 >= BRIX_WALK_MAXDEPTH) {
                brix_status_set(st, XRDC_EUSAGE, 0, "walk: depth cap at %s", full);
                rc = -1;
            } else {
                rc = tree_walk_depth(c, full, depth + 1, fn, u, st);
            }
        }
    }
    free(ents);
    return rc;
}

int
brix_tree_walk(brix_conn *c, const char *path, brix_walk_fn fn, void *u,
               brix_status *st)
{
    return tree_walk_depth(c, path, 0, fn, u, st);
}
