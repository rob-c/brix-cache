/*
 * copy_recursive.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/* Create LPATH and every missing parent directory (local `mkdir -p`).
 *
 * WHY: the recursive download nests the copied tree under the destination
 * (recursive_dest_root → e.g. <dst>/<basename>), so the very first directory
 * created can be two levels below an existing parent (<dst> itself may not yet
 * exist).  A single mkdir() would fail with ENOENT on that missing parent; the
 * remote upload side already creates parents (brix_mkdir parents=1), so the
 * local side must match.  Idempotent: an existing component is not an error
 * (deeper failures such as a non-directory in the path still surface ENOTDIR).
 * Returns 0 on success, -1 with errno set on the first uncreatable component. */
static int
local_mkdirs(const char *lpath, mode_t mode)
{
    char   buf[XRDC_PATH_MAX];
    size_t n = strlen(lpath);
    size_t i;

    if (n == 0 || n >= sizeof(buf)) {
        errno = (n == 0) ? EINVAL : ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, lpath, n + 1);
    for (i = 1; i < n; i++) {                    /* each intermediate component */
        if (buf[i] != '/') {
            continue;
        }
        buf[i] = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) {
            return -1;
        }
        buf[i] = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST) {  /* the leaf */
        return -1;
    }
    return 0;
}


/* 1 = NAME is "." or ".." (the self/parent entries every directory walk must
 * skip); 0 otherwise.  Shared by every tree walker and mirror pass below so
 * the dot test is written exactly once. */
static int
dirent_is_dot(const char *name)
{
    return name[0] == '.'
           && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}


/* Compose the copy-root-relative path of a child entry: "<rel>/<name>", with
 * no leading '/' when rel is "" (the top level).  Every walker threads this
 * form into brix_copy_filter_match so patterns behave identically at any
 * depth.  Returns 0 on success, -1 when the result would not fit. */
static int
rel_join(const char *rel, const char *name, char *out, size_t outsz)
{
    return ((size_t) snprintf(out, outsz, "%s%s%s",
                              rel, rel[0] ? "/" : "", name) >= outsz) ? -1 : 0;
}


/* Compose "<dir>/<name>" into out.  Returns 0 on success, -1 when the result
 * would not fit (callers report their own context-specific message). */
static int
path_join(const char *dir, const char *name, char *out, size_t outsz)
{
    return ((size_t) snprintf(out, outsz, "%s/%s", dir, name) >= outsz)
           ? -1 : 0;
}


/* 1 = the remote file (rpath, over the walker's open conn) and the local file
 * (lpath) have the same digest under o->sync_cksum_algo; 0 = differ or
 * undeterminable.
 *
 * WHAT: the XRDC_SYNC_CKSUM content check for the recursive walkers.
 * WHY:  brix_sync_should_skip is only the size gate for CKSUM mode; the byte
 *       comparison happens here.  Any failure (bad algo, query error, open or
 *       read error) returns 0 so the walker COPIES — an undeterminable
 *       comparison must never skip (silent skip on error is data loss).
 * HOW:  server digest via kXR_Qcksum on the already-open conn (no reconnect
 *       per file), local digest via brix_cksum_fd; case-insensitive hex compare. */
static int
sync_cksum_match(brix_conn *c, const char *rpath, const char *lpath,
                 const brix_copy_opts *o)
{
    const char     *algo = o->sync_cksum_algo ? o->sync_cksum_algo : "adler32";
    brix_cksum_algo a;
    brix_status     st;
    char            rhex[132], lhex[132];
    int             fd, rc;

    brix_status_clear(&st);
    if (brix_cksum_algo_parse(algo, &a) != 0) {
        return 0;
    }
    if (brix_query_cksum(c, rpath, algo, rhex, sizeof(rhex), &st) != 0) {
        return 0;
    }
    fd = open(lpath, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    rc = brix_cksum_fd(fd, a, lhex, sizeof(lhex), &st);
    close(fd);
    if (rc != 0) {
        return 0;
    }
    return strcasecmp(rhex, lhex) == 0;
}


/* Recursively remove a local tree (mirror-delete helper).
 *
 * WHAT: post-order deletion of a local path without following symlinks.
 * WHY:  called by mirror_delete_local to prune extra local paths that have no
 *       corresponding remote entry.  lstat (not stat) is used throughout so a
 *       symlink inside the destination tree can never escape the root and delete
 *       unrelated data.
 * HOW:  lstat to classify; dirs → opendir + recurse each child + rmdir; files
 *       → unlink.  Returns 0 on success, -1 with errno set on first failure. */
static int
local_rmtree(const char *path)
{
    struct stat sb;

    if (lstat(path, &sb) != 0) {
        return -1;
    }
    if (S_ISDIR(sb.st_mode)) {
        DIR           *d = opendir(path);
        struct dirent *de;
        if (d == NULL) { return -1; }
        while ((de = readdir(d)) != NULL) {
            char child[XRDC_PATH_MAX];
            if (dirent_is_dot(de->d_name)) {
                continue;
            }
            if (path_join(path, de->d_name, child, sizeof(child)) != 0) {
                closedir(d);
                errno = ENAMETOOLONG;
                return -1;
            }
            if (local_rmtree(child) != 0) { closedir(d); return -1; }
        }
        closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}


/* 1 = NAME appears in the remote listing ents[0..nents); 0 otherwise.
 * The tombstone presence probe for the download-direction mirror pass. */
static int
name_in_ents(const brix_dirent *ents, size_t nents, const char *name)
{
    size_t i;

    for (i = 0; i < nents; i++) {
        if (strcmp(ents[i].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}


/* Delete one extra LOCAL path for the mirror pass (or print it in dry-run).
 *
 * WHY: shared tombstone-removal tail of mirror_delete_local.  lstat first:
 * for regular files (and symlinks) use unlink directly rather than the full
 * recursive rmtree; local_rmtree is only needed for directories.  lstat
 * avoids following a symlink that might point outside the tree. */
static void
mirror_local_remove(const char *lchild, const brix_copy_opts *o)
{
    struct stat csb;

    if (o->dry_run) {
        printf("[dry-run] delete %s\n", lchild);
        return;
    }
    if (lstat(lchild, &csb) == 0 && S_ISDIR(csb.st_mode)) {
        if (local_rmtree(lchild) != 0) {
            fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                    lchild, strerror(errno));
        }
    } else if (unlink(lchild) != 0) {
        fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                lchild, strerror(errno));
    }
}


/* Prune local entries under lpath that are absent from the remote listing.
 *
 * WHAT: the download-direction mirror pass for xrdcp -r --sync --delete.
 * WHY:  after the download loop the ents[] array holds every name the remote
 *       directory contains; a local child absent from that set is an extra
 *       that must be removed to keep the local tree a faithful mirror of the
 *       remote.  Excluded paths are outside the sync scope and must never be
 *       deleted (the filter gate enforces this).
 * HOW:  opendir(lpath); for each local entry, scan ents[] by name; if absent
 *       AND brix_copy_filter_match passes → mirror_local_remove (dry-run
 *       print, or delete via local_rmtree for dirs / unlink for files). */
static void
mirror_delete_local(const char *lpath, const brix_dirent *ents, size_t nents,
                    const char *rel, const brix_copy_opts *o)
{
    DIR           *d;
    struct dirent *de;

    d = opendir(lpath);
    if (d == NULL) {
        fprintf(stderr, "xrdcp: --delete: opendir %s: %s\n", lpath, strerror(errno));
        return;
    }
    while ((de = readdir(d)) != NULL) {
        char relc[XRDC_PATH_MAX];
        char lchild[XRDC_PATH_MAX];

        if (dirent_is_dot(de->d_name)) {
            continue;
        }
        /* Keep the local entry if the remote listing still has this name. */
        if (name_in_ents(ents, nents, de->d_name)) {
            continue;
        }
        /* Build relative and absolute paths for the filter check and deletion. */
        if (rel_join(rel, de->d_name, relc, sizeof(relc)) != 0
            || path_join(lpath, de->d_name, lchild, sizeof(lchild)) != 0) {
            fprintf(stderr, "xrdcp: --delete: path too long under %s\n", lpath);
            continue;
        }
        /* Excluded entries are outside the sync scope — never delete them. */
        if (!brix_copy_filter_match(o, relc)) {
            continue;
        }
        mirror_local_remove(lchild, o);
    }
    closedir(d);
}


/* Resolve whether the remote entry E (absolute path rchild) is a directory.
 *
 * WHY: if dirlist provided no stat info (have_stat=0), do a defensive stat to
 * resolve the type before deletion.  Without this, a stat-less directory
 * would be treated as a file, causing brix_rm to fail confusingly.  If the
 * defensive stat also fails, warn and return -1 (caller skips the entry)
 * rather than guessing.  Returns 0 with *is_dir set on success. */
static int
remote_entry_is_dir(brix_conn *c, const brix_dirent *e, const char *rchild,
                    int *is_dir)
{
    brix_statinfo si;
    brix_status   sst;

    if (e->have_stat) {
        *is_dir = (e->st.flags & kXR_isDir) ? 1 : 0;
        return 0;
    }
    brix_status_clear(&sst);
    if (brix_stat(c, rchild, &si, &sst) == 0) {
        *is_dir = (si.flags & kXR_isDir) ? 1 : 0;
        return 0;
    }
    fprintf(stderr, "xrdcp: --delete: cannot stat %s, skipping\n", rchild);
    return -1;
}


/* Delete one extra REMOTE path for the mirror pass (or print it in dry-run).
 *
 * WHY: shared tombstone-removal tail of mirror_delete_remote.  For dry-run,
 * only print; do not call brix_rmtree with BRIX_RMTREE_DRYRUN because that
 * would walk the remote tree (I/O), bloating the dry-run output.  Instead,
 * the call itself is guarded so dry-run performs no remote I/O. */
static void
mirror_remote_remove(brix_conn *c, const char *rchild, int is_dir,
                     const brix_copy_opts *o)
{
    brix_status st;

    if (o->dry_run) {
        printf("[dry-run] delete %s\n", rchild);
        return;
    }
    brix_status_clear(&st);
    if (is_dir) {
        if (brix_rmtree(c, rchild, 0, NULL, NULL, &st) != 0) {
            fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                    rchild, st.msg);
        }
    } else if (brix_rm(c, rchild, &st) != 0) {
        fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                rchild, st.msg);
    }
}


/* Prune remote entries under rpath that have no local counterpart in lpath.
 *
 * WHAT: the upload-direction mirror pass for xrdcp -r --sync --delete.
 * WHY:  after the upload loop the local tree is authoritative; a remote entry
 *       with no local counterpart must be removed so the remote mirrors the
 *       local.  Excluded paths are outside the sync scope and must never be
 *       deleted.
 * HOW:  brix_dirlist(rpath) for the remote snapshot; for each remote entry,
 *       lstat the local counterpart; if absent AND filter passes →
 *       mirror_remote_remove (dry-run print, or brix_rmtree for dirs /
 *       brix_rm for files, type resolved by remote_entry_is_dir).
 * GUARD: this pass treats the LOCAL tree as authoritative, so it MUST NOT run
 *       alongside --remove-source (which deletes each local source after upload):
 *       the sources would already be gone here and every uploaded remote copy
 *       would be purged.  xrdcp rejects that flag combination at parse time
 *       (see the --delete/--remove-source guard in main), so this function is
 *       only ever reached with the local tree intact. */
static void
mirror_delete_remote(brix_conn *c, const char *rpath, const char *lpath,
                     const char *rel, const brix_copy_opts *o)
{
    brix_dirent *ents = NULL;
    brix_status  st;
    size_t       n = 0, i;

    brix_status_clear(&st);
    if (brix_dirlist(c, rpath, 1, &ents, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: --delete: dirlist %s: %s\n", rpath, st.msg);
        return;
    }
    for (i = 0; i < n; i++) {
        char        relc[XRDC_PATH_MAX];
        char        rchild[XRDC_PATH_MAX];
        char        lchild[XRDC_PATH_MAX];
        struct stat sb;
        int         is_dir;

        if (dirent_is_dot(ents[i].name)) {
            continue;
        }
        if (rel_join(rel, ents[i].name, relc, sizeof(relc)) != 0
            || path_join(rpath, ents[i].name, rchild, sizeof(rchild)) != 0
            || path_join(lpath, ents[i].name, lchild, sizeof(lchild)) != 0) {
            fprintf(stderr, "xrdcp: --delete: path too long under %s\n", rpath);
            continue;
        }
        /* Keep the remote entry if the local counterpart exists. */
        if (lstat(lchild, &sb) == 0) {
            continue;
        }
        /* Excluded entries are outside the sync scope — never delete them. */
        if (!brix_copy_filter_match(o, relc)) {
            continue;
        }
        if (remote_entry_is_dir(c, &ents[i], rchild, &is_dir) != 0) {
            continue;
        }
        mirror_remote_remove(c, rchild, is_dir, o);
    }
    free(ents);
}


/* 1 = the download of remote entry E (rc) may be skipped because the local
 * destination (lc) is up to date under --sync; 0 = copy.
 *
 * WHY: only when the remote side has trustworthy dirlist stat data (no
 * kXR_other — a symlink's listed size is the link-target-path length, not
 * the served bytes) AND the local side stats as a regular file; any
 * undeterminable side falls through to the copy (data-loss rule).  Runs
 * before the dry-run print so -r --sync --dry-run only lists files that
 * would actually be transferred. */
static int
dl_sync_skip(const copy_walk_ctx *w, const brix_dirent *e,
             const char *rc, const char *lc)
{
    struct stat sb;

    if (!w->o->sync || !e->have_stat || (e->st.flags & kXR_other)) {
        return 0;
    }
    return stat(lc, &sb) == 0 && S_ISREG(sb.st_mode)
           && brix_sync_should_skip(w->o->sync_cmp,
                                    (long long) e->st.size,
                                    (long long) e->st.mtime,
                                    (long long) sb.st_size,
                                    (long long) sb.st_mtime)
           && (w->o->sync_cmp != XRDC_SYNC_CKSUM
               || sync_cksum_match(w->c, rc, lc, w->o));
}


/* Transfer one remote FILE entry E to the local path lc (download walk).
 *
 * HOW: filter → sync-skip → dry-run guard → copy_one_r2l → --remove-source.
 * For a symlink (kXR_other) the dirlist size is the lstat size — the LENGTH
 * OF THE LINK TARGET PATH, not the bytes the server serves when it follows
 * the link on open.  Trusting it truncates the copy (a link to a 10-byte
 * file named "two.txt" would copy 7 bytes), so read to EOF (expected = -1)
 * for those; regular files keep their real size, whose short-read guard
 * still catches truncation.  Returns 0 (copied or skipped) or -1 (fatal,
 * w->st set by copy_one_r2l). */
static int
tree_dl_file(const copy_walk_ctx *w, const brix_dirent *e,
             const char *relc, const char *rc, const char *lc)
{
    int64_t expected = (e->have_stat && !(e->st.flags & kXR_other))
                       ? e->st.size : -1;

    if (!brix_copy_filter_match(w->o, relc)) {
        return 0;
    }
    if (dl_sync_skip(w, e, rc, lc)) {
        return 0;   /* up-to-date — skip */
    }
    if (w->o->dry_run) {
        printf("[dry-run] copy %s -> %s\n", rc, lc);
        return 0;
    }
    if (copy_one_r2l(w->c, rc, lc, expected, w->st) != 0) {
        return -1;
    }
    if (w->o->remove_source && !w->o->dry_run) {
        brix_status rst;
        brix_status_clear(&rst);
        (void) brix_rm(w->c, rc, &rst);
    }
    return 0;
}


/* Handle one remote directory entry E of the download walk.
 *
 * HOW: skip dots; build the copy-root-relative path (relc) plus the remote
 * and local child paths; directories recurse via copy_tree_download (then
 * best-effort rmdir under --remove-source), everything else goes through
 * tree_dl_file.  Returns 0 to continue the walk, -1 fatal (w->st set). */
static int
tree_dl_entry(const copy_walk_ctx *w, const brix_dirent *e)
{
    char relc[XRDC_PATH_MAX];
    char rc[XRDC_PATH_MAX], lc[XRDC_PATH_MAX];

    if (dirent_is_dot(e->name)) {
        return 0;
    }
    /* Build the path of this entry relative to the copy root so that
     * brix_copy_filter_match can match at both full-rel and basename. */
    if (rel_join(w->rel, e->name, relc, sizeof(relc)) != 0) {
        brix_status_set(w->st, XRDC_EUSAGE, 0,
                        "recursive copy: rel path too long under %s", w->rpath);
        return -1;
    }
    if (path_join(w->rpath, e->name, rc, sizeof(rc)) != 0
        || path_join(w->lpath, e->name, lc, sizeof(lc)) != 0) {
        brix_status_set(w->st, XRDC_EUSAGE, 0,
                        "recursive copy: path too long under %s", w->rpath);
        return -1;
    }
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        copy_walk_ctx cw = { w->c, rc, lc, relc, w->o, w->st };
        if (copy_tree_download(&cw) != 0) {
            return -1;
        }
        if (w->o->remove_source && !w->o->dry_run) {
            brix_status rst;
            brix_status_clear(&rst);
            (void) brix_rmdir(w->c, rc, &rst);
        }
        return 0;
    }
    return tree_dl_file(w, e, relc, rc, lc);
}


/* Recurse a remote tree (rpath) under conn c into local lpath.
 *
 * WHAT: downloads every regular file under rpath into the mirrored local path,
 *       applying --exclude/--include filters and honoring --dry-run and --sync
 *       (size/mtime/cksum up-to-date skip per o->sync_cmp).
 * WHY:  threading `rel` (path relative to the copy root, "" at the top level)
 *       through every recursive call lets brix_copy_filter_match compare
 *       both the full relative path and its basename, so pattern semantics are
 *       consistent at any depth.
 * HOW:  skip mkdir in dry-run mode; list the remote directory; delegate each
 *       entry to tree_dl_entry (filter → sync-skip → dry-run → copy_one_r2l).
 *       The sync-skip runs before the dry-run print so that `-r --sync
 *       --dry-run` only lists files that would actually be copied. */
int
copy_tree_download(const copy_walk_ctx *w)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;

    if (!w->o->dry_run && local_mkdirs(w->lpath, 0755) != 0) {
        brix_status_set(w->st, XRDC_ESOCK, errno, "mkdir %s: %s",
                        w->lpath, strerror(errno));
        return -1;
    }
    if (brix_dirlist(w->c, w->rpath, 1, &ents, &n, w->st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (tree_dl_entry(w, &ents[i]) != 0) {
            free(ents);
            return -1;
        }
    }
    /* Mirror-delete pass: remove local entries that the remote no longer has.
     * Runs only when --sync --delete is active; ents[] is still live here so
     * the remote snapshot is coherent with the copies just done above. */
    if (w->o->sync_delete) {
        mirror_delete_local(w->lpath, ents, n, w->rel, w->o);
    }
    free(ents);
    return 0;
}


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


/* web transfer (davs:// / http(s):// / s3://) — production GET/PUT over  */
/* the streaming HTTP client. Auth: WebDAV bearer token or S3 SigV4.      */


/* Resolve the S3 access/secret key pair for SigV4 signing.
 *
 * WHY: precedence is frozen — explicit opts first, then the credential store
 * (co->cred) when set, then the AWS_* environment, so env-sourced credentials
 * behave identically to today.  A store-acquire failure is not an error: the
 * status is cleared and resolution falls through to the environment.  Either
 * pointer may come back NULL (anonymous access — the caller decides). */
static void
s3_resolve_keys(const brix_copy_opts *o, const brix_opts *co,
                const char **ak, const char **sk, brix_status *st)
{
    brix_cred_view sv;

    *ak = (o && o->s3_access) ? o->s3_access : NULL;
    *sk = (o && o->s3_secret) ? o->s3_secret : NULL;

    /* Prefer the cred store for S3 keys when no explicit opts override. */
    if ((*ak == NULL || *sk == NULL) && co != NULL && co->cred != NULL) {
        if (brix_cred_acquire(co->cred, XRDC_CRED_S3KEYS, 0, &sv, st) == 0) {
            if (*ak == NULL) { *ak = sv.s3_access; }
            if (*sk == NULL) { *sk = sv.s3_secret; }
        } else {
            brix_status_clear(st);
        }
    }
    /* Fall through to env when store not set or acquire failed. */
    if (*ak == NULL) { *ak = getenv("AWS_ACCESS_KEY_ID"); }
    if (*sk == NULL) { *sk = getenv("AWS_SECRET_ACCESS_KEY"); }
}


/* Build the S3 SigV4 Authorization block for a->u into hdrs[].
 *
 * HOW: resolve keys (opts → store → env; both missing = anonymous, empty
 * hdrs); host is signed as "host:port" to match the wire Host header
 * byte-for-byte (brackets IPv6 literals); UNSIGNED-PAYLOAD for every method
 * because the body streams and is not folded into the signature (both
 * nginx-xrootd's S3 and real AWS accept that).  Returns 0/-1 (a->st set). */
static int
auth_hdr_s3(const web_auth_ctx *a, char *hdrs, size_t hdrsz)
{
    const brix_weburl    *u  = a->u;
    const brix_copy_opts *o  = a->o;
    brix_status          *st = a->st;
    const char           *ak, *sk;
    const char           *rg = (o && o->s3_region) ? o->s3_region
                                                   : getenv("AWS_DEFAULT_REGION");
    char                  host[300], payhash[65];

    s3_resolve_keys(o, a->co, &ak, &sk, st);
    if (ak == NULL || sk == NULL) {
        return 0;   /* anonymous — server may permit unsigned access */
    }
    if (rg == NULL) { rg = "us-east-1"; }
    /* A '?' would split path vs query in the server's canonical request but
     * we sign the whole path as CanonicalURI — reject rather than mis-sign. */
    if (strchr(u->path, '?') != NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "s3: query strings in the URL are not supported");
        return -1;
    }
    /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
     * header brackets IPv6 literals ([::1]:9000), so sign the same form. */
    brix_format_host_port(u->host, (uint16_t) u->port, host, sizeof(host));
    /* UNSIGNED-PAYLOAD for every method: the body isn't folded into the
     * signature (it streams), which both nginx-xrootd's S3 and real AWS accept. */
    snprintf(payhash, sizeof(payhash), "UNSIGNED-PAYLOAD");
    if (brix_s3_sign_v4(a->method, host, u->path, ak, sk, rg, payhash,
                        hdrs, hdrsz) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "s3: failed to build SigV4 signature");
        return -1;
    }
    return 0;
}


/* Build the WebDAV/HTTP bearer Authorization header into hdrs[] (left empty
 * for an anonymous endpoint).
 *
 * WHY: precedence is frozen — explicit opts first, then the credential store
 * (co->cred) when set, then $BEARER_TOKEN; a store-acquire failure clears the
 * status and falls through to the environment.  Returns 0/-1 (st set). */
static int
auth_hdr_bearer(const brix_copy_opts *o, const brix_opts *co,
                char *hdrs, size_t hdrsz, brix_status *st)
{
    const char    *tok = (o && o->bearer) ? o->bearer : NULL;
    brix_cred_view bv;

    /* Prefer the cred store for the bearer token when no explicit opt override. */
    if (tok == NULL && co != NULL && co->cred != NULL) {
        if (brix_cred_acquire(co->cred, XRDC_CRED_BEARER, 0, &bv, st) == 0
            && bv.token != NULL) {
            tok = bv.token;
        } else {
            brix_status_clear(st);
        }
    }
    /* Fall through to env when store not set or acquire failed. */
    if (tok == NULL) { tok = getenv("BEARER_TOKEN"); }

    if (tok != NULL && tok[0] != '\0') {
        int n = snprintf(hdrs, hdrsz, "Authorization: Bearer %s\r\n", tok);
        if (n < 0 || (size_t) n >= hdrsz) {
            brix_status_set(st, XRDC_EUSAGE, 0, "bearer token too long");
            return -1;
        }
    }
    return 0;
}


/* Build the auth header block for a web request into hdrs[] (may be empty for an
 * anonymous endpoint). S3 → SigV4 (host signed as "host:port" to match the Host
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available.
 *
 * a->co carries the credential store (co->cred); when set the store is tried
 * first for both the bearer token and S3 keys, falling back to opts/env on
 * failure so env-sourced credentials behave identically to today. */
int
web_auth_headers(const web_auth_ctx *a, char *hdrs, size_t hdrsz)
{
    hdrs[0] = '\0';
    if (a->u->is_s3) {
        return auth_hdr_s3(a, hdrs, hdrsz);
    }
    return auth_hdr_bearer(a->o, a->co, hdrs, hdrsz, a->st);
}


/* Transfer result of one streaming HTTP GET (web_dl_fetch out-params).
 * Bundled so the fetch wrapper stays under the 5-parameter gate. */
typedef struct {
    int       outfd;    /* IN:  destination fd (file or STDOUT_FILENO) */
    int       status;   /* OUT: HTTP status                            */
    long long blen;     /* OUT: body bytes written                     */
} web_dl_io;

/* Run one streaming HTTP GET of su into io->outfd.
 *
 * WHY: both the stdout and to-file branches of copy_web_download issue the
 * same brix_http_download call (empty hdrs → NULL, co-optional verify/CA
 * defaults); centralizing it keeps the two call sites literally identical. */
static int
web_dl_fetch(const brix_weburl *su, const brix_opts *co, const char *hdrs,
             web_dl_io *io, brix_status *st)
{
    return brix_http_download(su->host, su->port, su->tls, su->path,
                              hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, io->outfd,
                              XRDC_WEB_TIMEOUT_MS, &io->status, &io->blen, st);
}


int
copy_web_download(const web_dl_req *rq, brix_status *st)
{
    const brix_weburl    *su = rq->su;
    const brix_url       *du = rq->du;
    const brix_copy_opts *o  = rq->o;
    const brix_opts      *co = rq->co;
    char                  hdrs[8192];
    char                  tmp[XRDC_PATH_MAX];
    int                   rc;
    web_dl_io             io = { -1, 0, 0 };
    web_auth_ctx          a  = { su, "GET", o, co, st };

    if (web_auth_headers(&a, hdrs, sizeof(hdrs)) != 0) {
        return -1;
    }
    if (rq->to_stdout) {
        io.outfd = STDOUT_FILENO;
        return web_dl_fetch(su, co, hdrs, &io, st);
    }
    /* Refuse to overwrite an existing destination unless -f. */
    if (!(o && o->force) && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s", du->path);
        return -1;
    }
    /* Download to a temp sibling and atomically rename on success: a failed
     * transfer must never truncate or delete a pre-existing destination. */
    io.outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
    if (io.outfd < 0) {
        return -1;
    }
    rc = web_dl_fetch(su, co, hdrs, &io, st);
    close(io.outfd);
    rc = atomic_dest_finish(tmp, du->path, rc, st);
    if (rc != 0) {
        return rc;
    }
    if (o && !o->silent) {
        fprintf(stderr, "xrdcp: downloaded %lld bytes (HTTP %d)\n",
                io.blen, io.status);
    }
    return 0;
}
