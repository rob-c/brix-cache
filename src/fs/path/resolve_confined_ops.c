#include "core/ngx_brix_module.h"
#include "path_internal.h"
#include "beneath.h"
#include "auth/impersonate/impersonate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <linux/openat2.h>

/* Helper declarations — defined in resolve_confined_helpers.c */
extern int brix_open_root_fd(ngx_log_t *log, const char *root_canon);
extern char *brix_split_relative_parent(const char *rel, char *parent, size_t parentsz,
    char *base, size_t basesz);
extern int brix_open_confined_parent_fallback(int rootfd, const char *parent);
extern int brix_open_confined_parent_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *base, size_t basesz);

/*
 * Confinement model for the open/op helpers in this file: defence-in-depth in
 * two layers — (1) canonical-path resolution by the caller (no symlinks, no
 * ".."), and (2) kernel-level confinement via openat2 RESOLVE_BENEATH (Linux
 * 5.6+) or an O_NOFOLLOW fallback. Both must pass, so a symlink swapped in
 * between resolve and open still cannot escape the export root.
 */

/*
 * brix_dirlist_access_ok — under impersonation, verify the mapped user may
 * enumerate <resolved> by asking the broker to open it O_RDONLY|O_DIRECTORY as
 * that user (EACCES ⇒ not entitled). NGX_OK when impersonation is off or the
 * open succeeds; fail-closed (NGX_ERROR) when map mode is on but no principal is
 * set for the request.
 */

ngx_int_t
brix_dirlist_access_ok(ngx_log_t *log, const char *root_canon,
    const char *resolved)
{
    char rel[PATH_MAX];
    int  fd;

    if (!brix_imp_enabled()) {
        return NGX_OK;                   /* impersonation off — existing gate holds */
    }
    if (!brix_imp_client_active()) {
        /*
         * Map mode is active but this request carries no per-request principal
         * (e.g. the principal was cleared by an async body read and not yet
         * re-established, or an anonymous request reached here).  We cannot
         * determine the mapped user's DAC, so FAIL CLOSED — refuse to enumerate
         * the directory rather than list it with the privileged worker's
         * credentials (which leaked entries of dirs the mapped user cannot read).
         */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "impersonate: dirlist access check with no principal set"
                      " — refusing to enumerate \"%s\" (fail closed)", resolved);
        return NGX_ERROR;
    }
    if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return NGX_ERROR;
    }
    /* Ask the broker to open the dir for READING as the mapped user.  readdir
     * needs read permission on the directory, so a successful O_RDONLY|O_DIRECTORY
     * open means the user is entitled to list it; EACCES means they are not. */
    fd = brix_imp_open(rel, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        return NGX_ERROR;
    }
    close(fd);
    return NGX_OK;
}

/*
 * brix_open_confined_canon — open <resolved> (already canonical, under
 * root_canon) with kernel confinement: openat2(RESOLVE_BENEATH), or on an older
 * kernel a confined parent open + O_NOFOLLOW openat of the final component.
 * Under impersonation the open is delegated to the broker (as the mapped user).
 * Returns a NON-pool fd (caller closes) or -1. Arg order is (…, flags, mode):
 * never pass permission bits in the flags slot (0644 sets O_EXCL).
 */
int
brix_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode)
{
    char rel[PATH_MAX];
    char parent[PATH_MAX];
    char base[NAME_MAX + 1];
    int  rootfd;
    int  parentfd;
    int  fd;

    if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return -1;
    }

    /*
     * Phase 40: when per-request impersonation is active (map mode + a principal
     * set for this request), delegate the open to the privileged broker, which
     * performs it as the mapped UNIX user under its own rootfd.  `rel` is already
     * the export-root-relative path the broker expects.  This is the HTTP/S3
     * (legacy confined-open) counterpart to the seam in beneath.c; off-path it is
     * an inert flag check.
     */
    if (brix_imp_client_active()) {
        return brix_imp_open(rel, flags, mode);
    }

    rootfd = brix_open_root_fd(log, root_canon);
    if (rootfd < 0) {
        return -1;
    }

#if (BRIX_HAVE_OPENAT2)
    fd = brix_openat2_confined(rootfd, rel, flags, mode);
    if (fd >= 0
        || (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP))
    {
        close(rootfd);
        return fd;
    }
#endif

    /*
     * Root-directory case: rel="." means the target IS the export root.
     * brix_split_relative_parent refuses "." (no parent to navigate to),
     * so open the current directory of rootfd directly with O_NOFOLLOW.
     */
    if (rel[0] == '.' && rel[1] == '\0') {
        fd = openat(rootfd, ".", flags | O_CLOEXEC | O_NOFOLLOW, mode);
        close(rootfd);
        return fd;
    }

    if (!brix_split_relative_parent(rel, parent, sizeof(parent),
                                      base, sizeof(base)))
    {
        close(rootfd);
        return -1;
    }

    parentfd = brix_open_confined_parent_fallback(rootfd, parent);
    close(rootfd);
    if (parentfd < 0) {
        return -1;
    }

    fd = openat(parentfd, base, flags | O_CLOEXEC | O_NOFOLLOW, mode);
    close(parentfd);
    return fd;
}

int
brix_open_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int flags, mode_t mode)
{
    char root_canon[PATH_MAX];

    if (!brix_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return brix_open_confined_canon(log, root_canon, resolved, flags, mode);
}

/* brix_unlink_confined_canon — unlinkat (AT_REMOVEDIR when is_dir) at the
 * confined parent of <resolved> (broker-routed under impersonation). 0/-1. */
int
brix_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_unlink(rel, is_dir);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }

    rc = unlinkat(parentfd, base, is_dir ? AT_REMOVEDIR : 0);
    close(parentfd);
    return rc;
}

/* brix_mkdir_confined_canon — mkdirat(mode) at the confined parent of
 * <resolved> (broker-routed under impersonation). 0/-1. */
int
brix_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_mkdir(rel, mode);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }

    rc = mkdirat(parentfd, base, mode);
    close(parentfd);
    return rc;
}

/* Confined rename/move: renameat at the confined parents of BOTH src and dst
 * (broker-routed under impersonation) so neither side can escape the export
 * root. The shared impl backs the plain and create-if-absent variants below. */

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif

/* Shared body for the plain and create-if-absent confined renames.  When
 * `noreplace` is set, uses renameat2(RENAME_NOREPLACE) and falls back to a plain
 * renameat (logged once) on kernels/filesystems without the flag. */
static int
rename_confined_canon_impl(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved, int noreplace)
{
    char src_base[NAME_MAX + 1];
    char dst_base[NAME_MAX + 1];
    int  src_parentfd;
    int  dst_parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rsrc[PATH_MAX], rdst[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, src_resolved,
                                              rsrc, sizeof(rsrc))
            || !brix_resolved_relative_to_root(log, root_canon, dst_resolved,
                                                 rdst, sizeof(rdst)))
        {
            return -1;
        }
        return noreplace ? brix_imp_rename_noreplace(rsrc, rdst)
                         : brix_imp_rename(rsrc, rdst);
    }

    src_parentfd = brix_open_confined_parent_canon(log, root_canon,
                                                     src_resolved, src_base,
                                                     sizeof(src_base));
    if (src_parentfd < 0) {
        return -1;
    }

    dst_parentfd = brix_open_confined_parent_canon(log, root_canon,
                                                     dst_resolved, dst_base,
                                                     sizeof(dst_base));
    if (dst_parentfd < 0) {
        close(src_parentfd);
        return -1;
    }

    if (noreplace) {
        rc = (int) syscall(SYS_renameat2, src_parentfd, src_base,
                           dst_parentfd, dst_base,
                           (unsigned int) RENAME_NOREPLACE);
        if (rc != 0 && (errno == ENOSYS || errno == EINVAL)) {
            static int warned = 0;
            if (!warned) {
                warned = 1;
                ngx_log_error(NGX_LOG_WARN, log, errno,
                              "brix: renameat2(RENAME_NOREPLACE) unsupported; "
                              "create-if-absent falls back to non-atomic rename");
            }
            rc = renameat(src_parentfd, src_base, dst_parentfd, dst_base);
        }
    } else {
        rc = renameat(src_parentfd, src_base, dst_parentfd, dst_base);
    }
    {
        int e = errno;
        close(src_parentfd);
        close(dst_parentfd);
        errno = e;
    }
    return rc;
}

int
brix_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    return rename_confined_canon_impl(log, root_canon, src_resolved,
                                      dst_resolved, 0);
}

int
brix_rename_confined_canon_excl(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    return rename_confined_canon_impl(log, root_canon, src_resolved,
                                      dst_resolved, 1);
}

/* brix_link_confined_canon — linkat at the confined parents of BOTH src and
 * dst (broker-routed under impersonation). 0/-1. */
int
brix_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved)
{
    char src_base[NAME_MAX + 1];
    char dst_base[NAME_MAX + 1];
    int  src_parentfd;
    int  dst_parentfd;
    int  rc;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rsrc[PATH_MAX], rdst[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, src_resolved,
                                              rsrc, sizeof(rsrc))
            || !brix_resolved_relative_to_root(log, root_canon, dst_resolved,
                                                 rdst, sizeof(rdst)))
        {
            return -1;
        }
        return brix_imp_link(rsrc, rdst);
    }

    src_parentfd = brix_open_confined_parent_canon(log, root_canon,
                                                     src_resolved, src_base,
                                                     sizeof(src_base));
    if (src_parentfd < 0) {
        return -1;
    }

    dst_parentfd = brix_open_confined_parent_canon(log, root_canon,
                                                     dst_resolved, dst_base,
                                                     sizeof(dst_base));
    if (dst_parentfd < 0) {
        close(src_parentfd);
        return -1;
    }

    rc = linkat(src_parentfd, src_base, dst_parentfd, dst_base, 0);
    close(src_parentfd);
    close(dst_parentfd);
    return rc;
}

/* Confined setattr/chmod/symlink/readlink → resolve_confined_ops_meta.c
 * Confined extended-attribute ops        → resolve_confined_ops_xattr.c */

/* Confined directory open — broker-routed fd + fdopendir under impersonation.
 *
 * open <resolved> as a directory stream that, under impersonation map mode,
 *       is opened BY THE BROKER as the mapped user (O_RDONLY|O_DIRECTORY via
 *       RESOLVE_BENEATH) and handed back as an fd that we fdopendir().  readdir on
 *       that stream then enumerates the directory with the mapped user's read
 *       permission — so a worker that cannot itself opendir a user-private dir
 *       (e.g. a 0700 multipart staging dir owned by the mapped user) can still
 *       list it on the user's behalf.  Off impersonation it is a plain opendir().
 *
 * WHY: S3 multipart ListParts / AbortMultipartUpload (and the staging-dir cleanup)
 *      enumerate a staging directory created+owned by the mapped user.  Done as a
 *      raw worker-side opendir() they fail EACCES under impersonation; routing the
 *      open through the broker fixes that while keeping per-entry removal on the
 *      already-brokered brix_unlink_confined_canon path.  Returns a DIR* (caller
 *      closedir()s it) or NULL (errno set). */
DIR *
brix_opendir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved)
{
    char rel[PATH_MAX];
    int  rootfd;
    DIR *d;

    if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return NULL;
    }

    if (brix_imp_client_active()) {
        int fd = brix_imp_open(rel, O_RDONLY | O_DIRECTORY, 0); /* mapped user */
        if (fd < 0) {
            return NULL;
        }
        d = fdopendir(fd);
        if (d == NULL) {
            close(fd);
        }
        return d;                          /* closedir() closes the fd */
    }

    /*
     * Off impersonation, open the directory chroot-style under an O_PATH rootfd
     * (openat2 RESOLVE_IN_ROOT) rather than a bare opendir() on the canonical
     * path: a bare opendir() follows a trailing in-export symlink with an
     * outward target (e.g. /_sym_dir -> /etc) straight out of the export root
     * and enumerates it — a confinement escape. RESOLVE_IN_ROOT confines the
     * resolution so an escaping target is refused.
     */
    rootfd = brix_open_root_fd(log, root_canon);
    if (rootfd < 0) {
        return NULL;
    }
    d = brix_opendir_beneath(rootfd, rel);
    close(rootfd);
    return d;
}

/* brix_lstat_confined_canon — lstat()/stat() a path *as the mapped user* under
 * impersonation, else a bare lstat/stat.  WHY: recursive walks (COPY/MOVE
 * collections, S3 multipart, remove-tree) lstat children of a directory owned
 * 0700 by the mapped user; a raw worker lstat would EACCES on the parent's
 * search bit.  Routes through the broker (which stat()s as the mapped user) so
 * the walk sees what that user can see.  nofollow!=0 → lstat semantics (do not
 * follow a trailing symlink — confinement: never resolve a link out of the
 * export).  Returns 0 on success, -1 on error (errno set). */
int
brix_lstat_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, struct stat *st, int nofollow)
{
    char rel[PATH_MAX];
    int  rootfd;
    int  rc;

    if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                          rel, sizeof(rel)))
    {
        return -1;
    }

    if (brix_imp_client_active()) {
        return brix_imp_stat(rel, st, nofollow);    /* as mapped user */
    }

    /*
     * Off impersonation, resolve chroot-style under an O_PATH rootfd via openat2
     * RESOLVE_IN_ROOT (brix_{,l}stat_beneath) rather than a bare stat()/lstat()
     * on the canonical path.  A bare follow-stat() dereferences a trailing
     * symlink against the REAL filesystem, so a planted in-export link with an
     * outward absolute target (e.g. /_sym -> /etc/passwd) would be followed
     * straight out of the export root — a confinement escape.  RESOLVE_IN_ROOT
     * resolves "/" and ".." relative to rootfd, so an outward target lands on a
     * non-existent in-root path (ENOENT) instead, which the stat handler's
     * realpath-confined fallback then rejects.  nofollow=1 still reports a
     * trailing link as itself (O_PATH|O_NOFOLLOW) without following it.
     */
    rootfd = brix_open_root_fd(log, root_canon);
    if (rootfd < 0) {
        return -1;
    }
    rc = nofollow ? brix_lstat_beneath(rootfd, rel, st)
                  : brix_stat_beneath(rootfd, rel, st);
    close(rootfd);
    return rc;
}
