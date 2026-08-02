/*
 * copy_recursive_ul.c - recursive upload walk + copy_recursive driver.
 * Phase-38 split of copy_recursive.c; behavior-identical.
 */
#include "copy_internal.h"

/* 1 = the upload of local FILE lc (stat SB) to remote rc may be skipped
 * because the remote destination is up to date under --sync; 0 = copy.
 *
 * WHY: a failed remote stat (missing file, error) or a directory in the way
 * falls through to the copy — never skip on an undeterminable compare.  Runs
 * before the dry-run print so -r --sync --dry-run only lists files that
 * would actually be transferred. */
static int
ul_sync_skip(const copy_walk_ctx *w, const char *rc, const char *lc,
             const struct stat *sb)
{
    brix_statinfo si;
    brix_status   sst;

    if (!w->o->sync) {
        return 0;
    }
    brix_status_clear(&sst);
    return brix_stat(w->c, rc, &si, &sst) == 0 && !(si.flags & kXR_isDir)
           && brix_sync_should_skip(w->o->sync_cmp,
                                    (long long) sb->st_size,
                                    (long long) sb->st_mtime,
                                    (long long) si.size,
                                    (long long) si.mtime)
           && (w->o->sync_cmp != XRDC_SYNC_CKSUM
               || sync_cksum_match(w->c, rc, lc, w->o));
}


/* Transfer one local regular FILE lc (stat SB) to the remote path rc
 * (upload walk).
 *
 * HOW: filter → sync-skip → dry-run guard → copy_one_l2r → --remove-source.
 * Returns 0 (copied or skipped) or -1 (fatal, w->st set by copy_one_l2r). */
static int
tree_ul_file(const copy_walk_ctx *w, const char *relc,
             const char *lc, const char *rc, const struct stat *sb)
{
    if (!brix_copy_filter_match(w->o, relc)) {
        return 0;
    }
    if (ul_sync_skip(w, rc, lc, sb)) {
        return 0;   /* up-to-date — skip */
    }
    if (w->o->dry_run) {
        printf("[dry-run] copy %s -> %s\n", lc, rc);
        return 0;
    }
    if (copy_one_l2r(w->c, lc, rc, w->o, w->st) != 0) {
        return -1;
    }
    if (w->o->remove_source && !w->o->dry_run) {
        (void) unlink(lc);
    }
    return 0;
}


/* Handle one local directory entry NAME of the upload walk.
 *
 * HOW: skip dots; build the copy-root-relative path (relc) plus the local
 * and remote child paths; lstat (not stat) so symlinks are detected, not
 * followed — a link to a parent directory would otherwise drive unbounded
 * recursion; symlinks are skipped (loop-safe; mirrors official -r default).
 * Directories recurse via copy_tree_upload (then best-effort rmdir under
 * --remove-source); regular files go through tree_ul_file.  Returns 0 to
 * continue the walk, -1 fatal (w->st set). */
static int
tree_ul_entry(const copy_walk_ctx *w, const char *name)
{
    char        relc[XRDC_PATH_MAX];
    char        lc[XRDC_PATH_MAX], rc[XRDC_PATH_MAX];
    struct stat sb;

    if (dirent_is_dot(name)) {
        return 0;
    }
    /* Build the path of this entry relative to the copy root so that
     * brix_copy_filter_match can match at both full-rel and basename. */
    if (rel_join(w->rel, name, relc, sizeof(relc)) != 0
        || path_join(w->lpath, name, lc, sizeof(lc)) != 0
        || path_join(w->rpath, name, rc, sizeof(rc)) != 0) {
        brix_status_set(w->st, XRDC_EUSAGE, 0,
                        "recursive copy: path too long under %s", w->lpath);
        return -1;
    }
    if (lstat(lc, &sb) != 0) {
        return 0;   /* vanished between readdir and stat — skip */
    }
    if (S_ISLNK(sb.st_mode)) {
        return 0;   /* skip symlinks (loop-safe; mirrors official -r default) */
    }
    if (S_ISDIR(sb.st_mode)) {
        copy_walk_ctx cw = { w->c, rc, lc, relc, w->o, w->st };
        if (copy_tree_upload(&cw) != 0) {
            return -1;
        }
        if (w->o->remove_source && !w->o->dry_run) {
            (void) rmdir(lc);
        }
        return 0;
    }
    if (S_ISREG(sb.st_mode)) {
        return tree_ul_file(w, relc, lc, rc, &sb);
    }
    return 0;   /* sockets/fifos/devices — not copied */
}


/* Recurse a local tree (lpath) into a remote tree (rpath) under conn c.
 *
 * WHAT: uploads every regular file under lpath to the mirrored remote path,
 *       applying --exclude/--include filters and honoring --dry-run and --sync
 *       (size/mtime/cksum up-to-date skip per o->sync_cmp).
 * WHY:  same rel-threading rationale as copy_tree_download — filter patterns
 *       must see the full relative path so they behave consistently at depth.
 * HOW:  skip brix_mkdir in dry-run mode; delegate each readdir entry to
 *       tree_ul_entry (filter → sync-skip → dry-run → copy_one_l2r).  Sync
 *       runs before dry-run so -r --sync --dry-run only lists files that
 *       would actually be transferred. */
int
copy_tree_upload(const copy_walk_ctx *w)
{
    DIR           *d;
    struct dirent *de;
    brix_status    mst;

    brix_status_clear(&mst);
    if (!w->o->dry_run) {
        (void) brix_mkdir(w->c, w->rpath, 0755, 1 /*parents*/, &mst);  /* may already exist */
    }
    d = opendir(w->lpath);
    if (d == NULL) {
        brix_status_set(w->st, XRDC_ESOCK, errno, "opendir %s: %s",
                        w->lpath, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        if (tree_ul_entry(w, de->d_name) != 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    /* Mirror-delete pass: remove remote entries that the local tree no longer
     * has.  Runs only when --sync --delete is active; lists the remote
     * directory here (post-upload) so the remote snapshot is fresh. */
    if (w->o->sync_delete) {
        mirror_delete_remote(w->c, w->rpath, w->lpath, w->rel, w->o);
    }
    return 0;
}


/* Build the recursive copy's destination root from the source path, using
 * rsync-style trailing-slash semantics:
 *
 *   src WITHOUT a trailing slash ("dir")  -> NEST the tree under the source's
 *       last path component: <dst>/<basename(dir)>/...  This matches stock
 *       `xrdcp -r <dir> <dst>` and avoids silently merging two differently-named
 *       source trees into one flattened destination.
 *   src WITH a trailing slash ("dir/")    -> FLAT mirror: copy the CONTENTS of
 *       the source straight into <dst>/... (no extra basename level), exactly as
 *       `rsync dir/ dst/` does.
 *
 * A degenerate basename ('.', '/', or empty — e.g. the whole-export `//.`/`//`
 * forms) has no meaningful name to nest under, so the destination is likewise
 * used verbatim.  Returns 0 on success, -1 if the composed path would overflow. */
int
recursive_dest_root(const char *dstdir, const char *srcpath,
                    char *out, size_t outsz)
{
    size_t      len = strlen(srcpath);
    const char *base;
    size_t      blen, dl, i;
    const char *sep;

    /* Trailing slash on the source => flat mirror (copy contents into <dst>). */
    if (len > 0 && srcpath[len - 1] == '/') {
        return ((size_t) snprintf(out, outsz, "%s", dstdir) >= outsz) ? -1 : 0;
    }

    base = srcpath;
    for (i = len; i > 0; i--) {
        if (srcpath[i - 1] == '/') { base = srcpath + i; break; }
    }
    blen = (size_t) (srcpath + len - base);

    if (blen == 0 || (blen == 1 && base[0] == '.')) {       /* nothing to nest */
        return ((size_t) snprintf(out, outsz, "%s", dstdir) >= outsz) ? -1 : 0;
    }
    dl  = strlen(dstdir);
    sep = (dl > 0 && dstdir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%.*s", dstdir, sep,
                              (int) blen, base) >= outsz) ? -1 : 0;
}


/* Recursive copy entry: connect once, walk the source tree. Direction-aware. */
int
copy_recursive(const copy_recurse_req *rq, brix_status *st)
{
    const brix_url       *su = rq->su;
    const brix_copy_opts *o  = rq->o;
    brix_conn             c;
    int                   rc;
    char                  destroot[XRDC_PATH_MAX];

    /* Nest under the source basename (stock parity); see recursive_dest_root. */
    if (recursive_dest_root(rq->du->path, su->path, destroot,
                            sizeof(destroot)) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy: destination path too long");
        return -1;
    }

    if (rq->download) {
        copy_walk_ctx w = { &c, su->path, destroot, "", o, st };
        if (brix_connect(&c, su, rq->co, st) != 0) { return -1; }
        rc = copy_tree_download(&w);
        /* Best-effort: remove the source root dir when the whole tree succeeded.
         * The walker already removed each file and subdir, so the root will only
         * succeed when nothing was filtered; failure is silently ignored. */
        if (rc == 0 && o->remove_source && !o->dry_run) {
            brix_status rst;
            brix_status_clear(&rst);
            (void) brix_rmdir(&c, su->path, &rst);
        }
    } else {
        copy_walk_ctx w = { &c, destroot, su->path, "", o, st };
        if (brix_connect(&c, rq->du, rq->co, st) != 0) { return -1; }
        rc = copy_tree_upload(&w);
        /* Best-effort: remove the local source root after a fully-successful
         * upload walk (only succeeds if the directory is now empty). */
        if (rc == 0 && o->remove_source && !o->dry_run) {
            (void) rmdir(su->path);
        }
    }
    brix_close(&c);
    return rc;
}
