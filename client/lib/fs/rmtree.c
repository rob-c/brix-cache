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

/* Forward declaration: rmtree_depth and rmtree_handle_dir_entry are mutually
 * recursive (descend into a real directory re-enters rmtree_depth). */
static int
rmtree_depth(brix_conn *c, const char *path, int depth, unsigned flags,
             brix_rmtree_report report, void *u, brix_status *st);

/*
 * rmtree_join — join dir + name into out[outsz] with exactly one separator.
 *
 * WHAT: produce "dir/name" (or "dir" + name when dir already ends with '/');
 *       return 0 on success, -1 if the result would be truncated.
 * WHY:  the same path-join pattern appears in walk.c; centralise it as a
 *       static helper to avoid silent snprintf truncation.
 * HOW:  snprintf returns >= outsz on truncation; treat that as an error (-1).
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
 * rmtree_is_dot — test whether a dirlist entry name is "." or "..".
 *
 * WHAT: return 1 for the self ("." ) and parent ("..") entries, 0 otherwise.
 * WHY:  a post-order walk must skip the two directory-relative entries or it
 *       would recurse into itself / its parent; factoring the compound test
 *       out keeps the traversal loop readable.
 * HOW:  match a leading '.' followed by end-of-string, or a second '.'
 *       followed by end-of-string.
 */
static int
rmtree_is_dot(const char *name)
{
    return name[0] == '.'
           && (name[1] == '\0'
               || (name[1] == '.' && name[2] == '\0'));
}

/*
 * rmtree_remove_leaf — report then delete a single file or symlink.
 *
 * WHAT: invoke the report callback (is_dir=0) and, unless dry-run, brix_rm the
 *       path; return 0 on success, -1 on callback abort or removal failure.
 * WHY:  the identical report -> dry-run gate -> brix_rm sequence is needed for
 *       both plain files and for symlinks (whose LINK is removed rather than
 *       descended); sharing it keeps the two callers byte-for-byte identical.
 * HOW:  1. if a report callback is set and it returns non-zero, record an
 *          XRDC_EUSAGE abort status and return -1.
 *       2. unless BRIX_RMTREE_DRYRUN is set, brix_rm the path; propagate its
 *          failure as -1.
 */
static int
rmtree_remove_leaf(brix_conn *c, const char *full, unsigned flags,
                   brix_rmtree_report report, void *u, brix_status *st)
{
    if (report != NULL && report(full, 0, u) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: aborted by report callback at %s", full);
        return -1;
    }
    if (!(flags & BRIX_RMTREE_DRYRUN) && brix_rm(c, full, st) != 0) {
        return -1;
    }
    return 0;
}

/*
 * rmtree_handle_dir_entry — resolve a kXR_isDir entry into descend-or-unlink.
 *
 * WHAT: lstat `full`; if it is a symlink (kXR_other) remove the link, else
 *       recurse into it as a real directory; return 0 on success, -1 on error.
 * WHY:  the dirlist kXR_isDir bit is set for both real directories and
 *       directory symlinks; descending a symlink would delete the target's
 *       contents, not the link.  brix_lstat (kXR_statNoFollow) resolves this:
 *       a symlink returns kXR_other, not kXR_isDir.
 * HOW:  1. brix_lstat the path; on failure return -1 (conservative — we cannot
 *          safely determine the entry type, so abort rather than guess).
 *       2. if the result carries kXR_other it is a symlink — remove the LINK
 *          via rmtree_remove_leaf and do not descend.
 *       3. otherwise it is a real directory — recurse post-order at depth+1.
 */
static int
rmtree_handle_dir_entry(brix_conn *c, const char *full, int depth,
                        unsigned flags, brix_rmtree_report report, void *u,
                        brix_status *st)
{
    brix_statinfo lsi;

    if (brix_lstat(c, full, &lsi, st) != 0) {
        return -1;
    }
    if (lsi.flags & kXR_other) {
        return rmtree_remove_leaf(c, full, flags, report, u, st);
    }
    return rmtree_depth(c, full, depth + 1, flags, report, u, st);
}

/*
 * rmtree_one_entry — process a single dirlist entry of the current directory.
 *
 * WHAT: skip "."/"..", build the child path, then descend directories or
 *       remove files/symlinks; return 0 on success (including skipped dots),
 *       -1 on any error (path too long, lstat/removal failure, callback abort).
 * WHY:  isolates the per-entry decision (dir-vs-leaf, symlink probing) so the
 *       traversal loop stays a flat iterate-until-error sequence.
 * HOW:  1. return 0 immediately for the "." and ".." entries.
 *       2. join the parent path and entry name; on truncation record an
 *          XRDC_EUSAGE status and return -1.
 *       3. if the entry has stat info flagged kXR_isDir, hand it to
 *          rmtree_handle_dir_entry (symlink probe / descend); otherwise treat
 *          it as a plain file and remove it via rmtree_remove_leaf.
 */
static int
rmtree_one_entry(brix_conn *c, const char *path, const brix_dirent *ent,
                 int depth, unsigned flags, brix_rmtree_report report, void *u,
                 brix_status *st)
{
    char full[XRDC_PATH_MAX];

    if (rmtree_is_dot(ent->name)) {
        return 0;
    }
    if (rmtree_join(path, ent->name, full, sizeof(full)) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "rmtree: path too long under %s", path);
        return -1;
    }
    if (ent->have_stat && (ent->st.flags & kXR_isDir)) {
        return rmtree_handle_dir_entry(c, full, depth, flags, report, u, st);
    }
    return rmtree_remove_leaf(c, full, flags, report, u, st);
}

/*
 * rmtree_depth — post-order recursive delete of `path` subtree.
 *
 * WHAT: dirlist `path`, remove every child (files/symlinks directly, real
 *       directories by recursion), then rmdir `path` itself; return 0 on
 *       success, -1 on depth cap, dirlist failure, or any child/self error.
 * WHY:  the server has no bulk delete, so the tree must be walked bottom-up;
 *       the depth cap bounds recursion and per-entry symlink probing (see
 *       rmtree_handle_dir_entry) prevents descending a directory symlink.
 * HOW:  1. refuse when depth reaches BRIX_RMTREE_MAXDEPTH (XRDC_EUSAGE).
 *       2. brix_dirlist(want_stat=1); on failure propagate -1.
 *       3. process each entry via rmtree_one_entry, stopping at the first error.
 *       4. free the entry array, then (if no error) report and rmdir `path`
 *          itself, honouring BRIX_RMTREE_DRYRUN and callback abort.
 */
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
        rc = rmtree_one_entry(c, path, &ents[i], depth, flags, report, u, st);
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
