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
            if (de->d_name[0] == '.'
                && (de->d_name[1] == '\0'
                    || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                continue;
            }
            if ((size_t) snprintf(child, sizeof(child), "%s/%s", path,
                                  de->d_name) >= sizeof(child)) {
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


/* Prune local entries under lpath that are absent from the remote listing.
 *
 * WHAT: the download-direction mirror pass for xrdcp -r --sync --delete.
 * WHY:  after the download loop the ents[] array holds every name the remote
 *       directory contains; a local child absent from that set is an extra
 *       that must be removed to keep the local tree a faithful mirror of the
 *       remote.  Excluded paths are outside the sync scope and must never be
 *       deleted (the filter gate enforces this).
 * HOW:  opendir(lpath); for each local entry, linear-scan ents[] by name; if
 *       absent AND brix_copy_filter_match passes → dry-run print or delete via
 *       local_rmtree (for dirs) / unlink (for files). */
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
        char   relc[XRDC_PATH_MAX];
        char   lchild[XRDC_PATH_MAX];
        size_t i;
        int    in_remote = 0;

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }
        /* Is this local name present in the remote listing? */
        for (i = 0; i < nents; i++) {
            if (strcmp(ents[i].name, de->d_name) == 0) { in_remote = 1; break; }
        }
        if (in_remote) {
            continue;
        }
        /* Build relative and absolute paths for the filter check and deletion. */
        if ((size_t) snprintf(relc, sizeof(relc), "%s%s%s",
                              rel, rel[0] ? "/" : "", de->d_name) >= sizeof(relc)
            || (size_t) snprintf(lchild, sizeof(lchild), "%s/%s",
                                 lpath, de->d_name) >= sizeof(lchild)) {
            fprintf(stderr, "xrdcp: --delete: path too long under %s\n", lpath);
            continue;
        }
        /* Excluded entries are outside the sync scope — never delete them. */
        if (!brix_copy_filter_match(o, relc)) {
            continue;
        }
        if (o->dry_run) {
            printf("[dry-run] delete %s\n", lchild);
        } else if (local_rmtree(lchild) != 0) {
            fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                    lchild, strerror(errno));
        }
    }
    closedir(d);
}


/* Prune remote entries under rpath that have no local counterpart in lpath.
 *
 * WHAT: the upload-direction mirror pass for xrdcp -r --sync --delete.
 * WHY:  after the upload loop the local tree is authoritative; a remote entry
 *       with no local counterpart must be removed so the remote mirrors the
 *       local.  Excluded paths are outside the sync scope and must never be
 *       deleted.
 * HOW:  brix_dirlist(rpath) for the remote snapshot; for each remote entry,
 *       lstat the local counterpart; if absent AND filter passes → dry-run
 *       print or delete (brix_rmtree for dirs, brix_rm for files). */
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

        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(relc, sizeof(relc), "%s%s%s",
                              rel, rel[0] ? "/" : "", ents[i].name) >= sizeof(relc)
            || (size_t) snprintf(rchild, sizeof(rchild), "%s/%s",
                                 rpath, ents[i].name) >= sizeof(rchild)
            || (size_t) snprintf(lchild, sizeof(lchild), "%s/%s",
                                 lpath, ents[i].name) >= sizeof(lchild)) {
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
        is_dir = ents[i].have_stat && (ents[i].st.flags & kXR_isDir);
        if (o->dry_run) {
            printf("[dry-run] delete %s\n", rchild);
        } else if (is_dir) {
            brix_status_clear(&st);
            if (brix_rmtree(c, rchild, 0, NULL, NULL, &st) != 0) {
                fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                        rchild, st.msg);
            }
        } else {
            brix_status_clear(&st);
            if (brix_rm(c, rchild, &st) != 0) {
                fprintf(stderr, "xrdcp: --delete: cannot remove %s: %s\n",
                        rchild, st.msg);
            }
        }
    }
    free(ents);
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
 * HOW:  skip mkdir in dry-run mode; build relc for each entry; apply filter
 *       then dry-run guard before calling copy_one_r2l; recurse with relc. */
int
copy_tree_download(brix_conn *c, const char *rpath, const char *lpath,
                   const char *rel, const brix_copy_opts *o, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;

    if (!o->dry_run && local_mkdirs(lpath, 0755) != 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "mkdir %s: %s", lpath, strerror(errno));
        return -1;
    }
    if (brix_dirlist(c, rpath, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char relc[XRDC_PATH_MAX];
        char rc[XRDC_PATH_MAX], lc[XRDC_PATH_MAX];
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        /* Build the path of this entry relative to the copy root so that
         * brix_copy_filter_match can match at both full-rel and basename. */
        if ((size_t) snprintf(relc, sizeof(relc), "%s%s%s",
                              rel, rel[0] ? "/" : "", ents[i].name) >= sizeof(relc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: rel path too long under %s", rpath);
            free(ents);
            return -1;
        }
        if ((size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, ents[i].name)
                >= sizeof(rc)
            || (size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, ents[i].name)
                >= sizeof(lc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", rpath);
            free(ents);
            return -1;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            if (copy_tree_download(c, rc, lc, relc, o, st) != 0) {
                free(ents);
                return -1;
            }
        } else {
            /* For a symlink (kXR_other) the dirlist size is the lstat size — the
             * LENGTH OF THE LINK TARGET PATH, not the bytes the server serves
             * when it follows the link on open.  Trusting it truncates the copy
             * (a link to a 10-byte file named "two.txt" would copy 7 bytes), so
             * read to EOF (expected = -1) for those; regular files keep their
             * real size, whose short-read guard still catches truncation. */
            int64_t expected = (ents[i].have_stat
                                && !(ents[i].st.flags & kXR_other))
                               ? ents[i].st.size : -1;
            if (!brix_copy_filter_match(o, relc)) {
                continue;
            }
            if (o->dry_run) {
                printf("[dry-run] copy %s -> %s\n", rc, lc);
                continue;
            }
            /* --sync: skip an up-to-date destination.  Only when the remote
             * side has trustworthy dirlist stat data (no kXR_other — a
             * symlink's listed size is the link-target-path length, not the
             * served bytes) AND the local side stats as a regular file; any
             * undeterminable side falls through to the copy (data-loss rule). */
            if (o->sync && ents[i].have_stat && !(ents[i].st.flags & kXR_other)) {
                struct stat sb;
                if (stat(lc, &sb) == 0 && S_ISREG(sb.st_mode)
                    && brix_sync_should_skip(o->sync_cmp,
                                             (long long) ents[i].st.size,
                                             (long long) ents[i].st.mtime,
                                             (long long) sb.st_size,
                                             (long long) sb.st_mtime)
                    && (o->sync_cmp != XRDC_SYNC_CKSUM
                        || sync_cksum_match(c, rc, lc, o))) {
                    continue;   /* up-to-date — skip */
                }
            }
            if (copy_one_r2l(c, rc, lc, expected, st) != 0) {
                free(ents);
                return -1;
            }
        }
    }
    /* Mirror-delete pass: remove local entries that the remote no longer has.
     * Runs only when --sync --delete is active; ents[] is still live here so
     * the remote snapshot is coherent with the copies just done above. */
    if (o->sync_delete) {
        mirror_delete_local(lpath, ents, n, rel, o);
    }
    free(ents);
    return 0;
}


/* Recurse a local tree (lpath) into a remote tree (rpath) under conn c.
 *
 * WHAT: uploads every regular file under lpath to the mirrored remote path,
 *       applying --exclude/--include filters and honoring --dry-run and --sync
 *       (size/mtime/cksum up-to-date skip per o->sync_cmp).
 * WHY:  same rel-threading rationale as copy_tree_download — filter patterns
 *       must see the full relative path so they behave consistently at depth.
 * HOW:  skip brix_mkdir in dry-run mode; build relc from de->d_name; apply
 *       filter then dry-run guard before copy_one_l2r; recurse with relc. */
int
copy_tree_upload(brix_conn *c, const char *lpath, const char *rpath,
                 const char *rel, const brix_copy_opts *o, brix_status *st)
{
    DIR           *d;
    struct dirent *de;
    brix_status    mst;

    brix_status_clear(&mst);
    if (!o->dry_run) {
        (void) brix_mkdir(c, rpath, 0755, 1 /*parents*/, &mst);  /* may already exist */
    }
    d = opendir(lpath);
    if (d == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "opendir %s: %s", lpath, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char        relc[XRDC_PATH_MAX];
        char        lc[XRDC_PATH_MAX], rc[XRDC_PATH_MAX];
        struct stat sb;
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }
        /* Build the path of this entry relative to the copy root so that
         * brix_copy_filter_match can match at both full-rel and basename. */
        if ((size_t) snprintf(relc, sizeof(relc), "%s%s%s",
                              rel, rel[0] ? "/" : "", de->d_name) >= sizeof(relc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", lpath);
            closedir(d);
            return -1;
        }
        if ((size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, de->d_name)
                >= sizeof(lc)
            || (size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, de->d_name)
                >= sizeof(rc)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", lpath);
            closedir(d);
            return -1;
        }
        /* lstat (not stat) so symlinks are detected, not followed — a link to a
         * parent directory would otherwise drive unbounded recursion. */
        if (lstat(lc, &sb) != 0) {
            continue;   /* vanished between readdir and stat — skip */
        }
        if (S_ISLNK(sb.st_mode)) {
            continue;   /* skip symlinks (loop-safe; mirrors official -r default) */
        }
        if (S_ISDIR(sb.st_mode)) {
            if (copy_tree_upload(c, lc, rc, relc, o, st) != 0) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (!brix_copy_filter_match(o, relc)) {
                continue;
            }
            if (o->dry_run) {
                printf("[dry-run] copy %s -> %s\n", lc, rc);
                continue;
            }
            /* --sync: skip an up-to-date remote destination.  A failed remote
             * stat (missing file, error) or a directory in the way falls
             * through to the copy — never skip on an undeterminable compare. */
            if (o->sync) {
                brix_statinfo si;
                brix_status   sst;
                brix_status_clear(&sst);
                if (brix_stat(c, rc, &si, &sst) == 0 && !(si.flags & kXR_isDir)
                    && brix_sync_should_skip(o->sync_cmp,
                                             (long long) sb.st_size,
                                             (long long) sb.st_mtime,
                                             (long long) si.size,
                                             (long long) si.mtime)
                    && (o->sync_cmp != XRDC_SYNC_CKSUM
                        || sync_cksum_match(c, rc, lc, o))) {
                    continue;   /* up-to-date — skip */
                }
            }
            if (copy_one_l2r(c, lc, rc, o, st) != 0) {
                closedir(d);
                return -1;
            }
        }
    }
    closedir(d);
    /* Mirror-delete pass: remove remote entries that the local tree no longer
     * has.  Runs only when --sync --delete is active; lists the remote
     * directory here (post-upload) so the remote snapshot is fresh. */
    if (o->sync_delete) {
        mirror_delete_remote(c, rpath, lpath, rel, o);
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
copy_recursive(const brix_url *su, const brix_url *du, int download,
               const brix_copy_opts *o, const brix_opts *co, brix_status *st)
{
    brix_conn c;
    int       rc;
    char      destroot[XRDC_PATH_MAX];

    /* Nest under the source basename (stock parity); see recursive_dest_root. */
    if (recursive_dest_root(du->path, su->path, destroot, sizeof(destroot)) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy: destination path too long");
        return -1;
    }

    if (download) {
        if (brix_connect(&c, su, co, st) != 0) { return -1; }
        rc = copy_tree_download(&c, su->path, destroot, "", o, st);
    } else {
        if (brix_connect(&c, du, co, st) != 0) { return -1; }
        rc = copy_tree_upload(&c, su->path, destroot, "", o, st);
    }
    brix_close(&c);
    return rc;
}


/* web transfer (davs:// / http(s):// / s3://) — production GET/PUT over  */
/* the streaming HTTP client. Auth: WebDAV bearer token or S3 SigV4.      */


/* Build the auth header block for a web request into hdrs[] (may be empty for an
 * anonymous endpoint). S3 → SigV4 (host signed as "host:port" to match the Host
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available.
 *
 * co carries the credential store (co->cred); when set the store is tried first
 * for both the bearer token and S3 keys, falling back to opts/env on failure so
 * env-sourced credentials behave identically to today. */
int
web_auth_headers(const brix_weburl *u, const char *method,
                 const brix_copy_opts *o, const brix_opts *co,
                 char *hdrs, size_t hdrsz, brix_status *st)
{
    hdrs[0] = '\0';
    if (u->is_s3) {
        const char *ak = (o && o->s3_access) ? o->s3_access : NULL;
        const char *sk = (o && o->s3_secret) ? o->s3_secret : NULL;
        const char *rg = (o && o->s3_region) ? o->s3_region : getenv("AWS_DEFAULT_REGION");
        brix_cred_view sv;
        char host[300], payhash[65];

        /* Prefer the cred store for S3 keys when no explicit opts override. */
        if ((ak == NULL || sk == NULL) && co != NULL && co->cred != NULL) {
            if (brix_cred_acquire(co->cred, XRDC_CRED_S3KEYS, 0, &sv, st) == 0) {
                if (ak == NULL) { ak = sv.s3_access; }
                if (sk == NULL) { sk = sv.s3_secret; }
            } else {
                brix_status_clear(st);
            }
        }
        /* Fall through to env when store not set or acquire failed. */
        if (ak == NULL) { ak = getenv("AWS_ACCESS_KEY_ID"); }
        if (sk == NULL) { sk = getenv("AWS_SECRET_ACCESS_KEY"); }

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
        if (brix_s3_sign_v4(method, host, u->path, ak, sk, rg, payhash,
                            hdrs, hdrsz) != 0) {
            brix_status_set(st, XRDC_EAUTH, 0, "s3: failed to build SigV4 signature");
            return -1;
        }
        return 0;
    }
    {
        const char *tok = (o && o->bearer) ? o->bearer : NULL;
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
    }
    return 0;
}


int
copy_web_download(const brix_weburl *su, const brix_url *du, int to_stdout,
                  const brix_copy_opts *o, const brix_opts *co, brix_status *st)
{
    char      hdrs[8192];
    char      tmp[XRDC_PATH_MAX];
    int       outfd, status = 0, rc;
    long long blen = 0;

    if (web_auth_headers(su, "GET", o, co, hdrs, sizeof(hdrs), st) != 0) {
        return -1;
    }
    if (to_stdout) {
        rc = brix_http_download(su->host, su->port, su->tls, su->path,
                                hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                                co ? co->ca_dir : NULL, STDOUT_FILENO,
                                XRDC_WEB_TIMEOUT_MS, &status, &blen, st);
        return rc;
    }
    /* Refuse to overwrite an existing destination unless -f. */
    if (!(o && o->force) && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s", du->path);
        return -1;
    }
    /* Download to a temp sibling and atomically rename on success: a failed
     * transfer must never truncate or delete a pre-existing destination. */
    outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
    if (outfd < 0) {
        return -1;
    }
    rc = brix_http_download(su->host, su->port, su->tls, su->path,
                            hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                            co ? co->ca_dir : NULL, outfd, XRDC_WEB_TIMEOUT_MS,
                            &status, &blen, st);
    close(outfd);
    rc = atomic_dest_finish(tmp, du->path, rc, st);
    if (rc != 0) {
        return rc;
    }
    if (o && !o->silent) {
        fprintf(stderr, "xrdcp: downloaded %lld bytes (HTTP %d)\n", blen, status);
    }
    return 0;
}
