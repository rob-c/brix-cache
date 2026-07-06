/* rmtree.c — post-order recursive remote delete (rm -r for root://).
 * WHAT: delete every file, then every directory bottom-up, under `path`,
 *       then `path` itself.
 * WHY:  the wire has no bulk delete; xrdfs rm -r and xrdcp --delete both
 *       need one careful implementation (depth-capped, overflow-checked,
 *       refuses the export root).
 * HOW:  brix_dirlist(want_stat=1); recurse into dirs first, brix_rm files,
 *       brix_rmdir self last. BRIX_RMTREE_DRYRUN reports without deleting.
 *       Before descending a dirlist entry flagged kXR_isDir, call brix_lstat
 *       to detect directory symlinks: if the entry is a symlink (kXR_other),
 *       brix_rm the LINK instead of descending into the target's subtree. */
#include "brix.h"
#include "brix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIX_RMTREE_MAXDEPTH 64

/*
 * rmtree_join — join dir + name into out[outsz] with exactly one separator.
 *
 * WHAT: produce "dir/name" (or "dir" + name when dir already ends with '/').
 * WHY:  the same path-join pattern appears in walk.c; centralise it as a
 *       static helper to avoid silent snprintf truncation.
 * HOW:  snprintf returns ≥ outsz on truncation; treat that as an error (-1).
 */
static int
rmtree_join(const char *dir, const char *name, char *out, size_t outsz)
{
    size_t      dl  = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%s", dir, sep, name) >= outsz)
           ? -1 : 0;
}

/*
 * rmtree_depth — post-order recursive delete of `path` subtree.
 *
 * WHAT: dirlist `path`; for each entry: recurse into real dirs, probe symlinks
 *       with lstat and rm the link, rm plain files.  Then rmdir `path` itself.
 * WHY:  dirlist stat does not distinguish a real directory from a dir-symlink
 *       (both carry kXR_isDir); descending a symlink would delete the target's
 *       contents, not the link.  brix_lstat (kXR_statNoFollow) resolves this:
 *       a symlink returns kXR_other, not kXR_isDir.
 * HOW:  for entries with kXR_isDir: brix_lstat first; if kXR_other → brix_rm
 *       the link; if still kXR_isDir → descend; if lstat fails → abort (-1).
 *       On report-callback abort: set st with XRDC_EUSAGE and return -1. */
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
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if (rmtree_join(path, ents[i].name, full, sizeof(full)) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "rmtree: path too long under %s", path);
            rc = -1;
            break;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            /* The dirlist kXR_isDir bit is set for both real directories and
             * directory symlinks.  Probe with lstat (kXR_statNoFollow) to
             * distinguish them before deciding whether to descend. */
            brix_statinfo lsi;
            if (brix_lstat(c, full, &lsi, st) != 0) {
                /* Conservative: if the probe fails we cannot safely determine
                 * the entry type — abort rather than guess. */
                rc = -1;
                break;
            }
            if (lsi.flags & kXR_other) {
                /* kXR_other means "not a regular file or dir" — i.e. a symlink.
                 * Remove the LINK itself; do not descend into the target. */
                if (report != NULL && report(full, 0, u) != 0) {
                    brix_status_set(st, XRDC_EUSAGE, 0,
                                    "rmtree: aborted by report callback at %s", full);
                    rc = -1;
                    break;
                }
                if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rm(c, full, st) != 0) {
                    rc = -1;
                }
            } else {
                /* Real directory: recurse post-order. */
                rc = rmtree_depth(c, full, depth + 1, flags, report, u, st);
            }
        } else {
            if (report != NULL && report(full, 0, u) != 0) {
                brix_status_set(st, XRDC_EUSAGE, 0,
                                "rmtree: aborted by report callback at %s", full);
                rc = -1;
                break;
            }
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
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: aborted by report callback at %s", path);
        return -1;
    }
    if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rmdir(c, path, st) != 0) {
        return -1;
    }
    return 0;
}

/*
 * brix_rmtree — post-order recursive delete of a remote tree.
 *
 * WHAT: guard the export root and all-slash paths, then recurse.
 * WHY:  "/" and "//" both resolve to the export root on the server; rejecting
 *       any path made solely of '/' characters prevents accidental fleet-wide
 *       deletes from paths that collapse to root.
 * HOW:  scan for at least one non-'/' byte; NULL / empty are also refused. */
int
brix_rmtree(brix_conn *c, const char *path, unsigned flags,
            brix_rmtree_report report, void *u, brix_status *st)
{
    const char *p;

    if (path == NULL || path[0] == '\0') {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: refusing to delete the export root");
        return -1;
    }
    /* Reject paths that consist entirely of '/' characters ("/" "//" etc). */
    for (p = path; *p == '/'; p++) { }
    if (*p == '\0') {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: refusing to delete the export root");
        return -1;
    }
    return rmtree_depth(c, path, 0, flags, report, u, st);
}
