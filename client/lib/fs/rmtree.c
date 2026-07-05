/* rmtree.c — post-order recursive remote delete (rm -r for root://).
 * WHAT: delete every file, then every directory bottom-up, under `path`,
 *       then `path` itself.
 * WHY:  the wire has no bulk delete; xrdfs rm -r and xrdcp --delete both
 *       need one careful implementation (depth-capped, overflow-checked,
 *       refuses the export root).
 * HOW:  brix_dirlist(want_stat=1); recurse into dirs first, brix_rm files,
 *       brix_rmdir self last. BRIX_RMTREE_DRYRUN reports without deleting. */
#include "brix.h"
#include "brix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIX_RMTREE_MAXDEPTH 64

static int
rmtree_depth(brix_conn *c, const char *path, int depth, unsigned flags,
             brix_rmtree_report report, void *u, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int          rc = 0;

    if (depth >= BRIX_RMTREE_MAXDEPTH) {
        brix_status_set(st, XRDC_EUSAGE, 0, "rmtree: depth cap at %s", path);
        return -1;
    }
    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n && rc == 0; i++) {
        char full[XRDC_PATH_MAX];
        size_t dl = strlen(path);
        const char *sep = (dl > 0 && path[dl - 1] == '/') ? "" : "/";
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(full, sizeof(full), "%s%s%s", path, sep,
                              ents[i].name) >= sizeof(full)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "rmtree: path too long under %s", path);
            rc = -1;
            break;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            rc = rmtree_depth(c, full, depth + 1, flags, report, u, st);
        } else {
            if (report != NULL && report(full, 0, u) != 0) { rc = -1; break; }
            if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rm(c, full, st) != 0) {
                rc = -1;
            }
        }
    }
    free(ents);
    if (rc != 0) {
        return rc;
    }
    if (report != NULL && report(path, 1, u) != 0) {
        return -1;
    }
    if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rmdir(c, path, st) != 0) {
        return -1;
    }
    return 0;
}

int
brix_rmtree(brix_conn *c, const char *path, unsigned flags,
            brix_rmtree_report report, void *u, brix_status *st)
{
    if (path == NULL || path[0] == '\0' || strcmp(path, "/") == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: refusing to delete the export root");
        return -1;
    }
    return rmtree_depth(c, path, 0, flags, report, u, st);
}
