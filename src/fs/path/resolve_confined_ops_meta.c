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
extern int brix_open_confined_parent_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *base, size_t basesz);

/* Confined setattr — utimensat + fchownat under parent confinement.
 *
 * Apply timestamps (set_times → utimensat) and/or owner (set_owner →
 *       fchownat) to <resolved>, both *at() syscalls anchored at the confined
 *       parent fd so a symlink/parent swap cannot redirect the change outside the
 *       root. AT_SYMLINK_NOFOLLOW is used so the operation never follows a final
 *       symlink. uid/gid of (uid_t)-1 / (gid_t)-1 leave that id unchanged.
 *       kXR_chmod already covers mode, so mode is intentionally not handled here.
 *       Returns 0 on success, -1 with errno set.
 */
int
brix_setattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int set_times, const struct timespec times[2],
    int set_owner, uid_t uid, gid_t gid)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc = 0;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_setattr(rel, set_times, times, set_owner, uid, gid);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    if (set_times && utimensat(parentfd, base, times, AT_SYMLINK_NOFOLLOW) != 0) {
        rc = -1;
    }
    if (rc == 0 && set_owner
        && fchownat(parentfd, base, uid, gid, AT_SYMLINK_NOFOLLOW) != 0) {
        rc = -1;
    }
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* Confined chmod — broker-routed under impersonation.
 *
 * Apply <mode> (low 12 bits) to <resolved>.  Under impersonation routes
 *       through the broker so the chmod runs AS THE MAPPED USER (a chmod requires
 *       being the file's owner; the unprivileged worker is not, so a worker-local
 *       chmod of a user-owned file would EPERM — even for the file's real owner).
 *       Off impersonation, fchmodat anchored at the confined parent fd (so a
 *       symlink/parent swap cannot redirect the change outside the root).
 *       Returns 0 on success, -1 with errno set.
 */
int
brix_chmod_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        /* Defense in depth: strip setuid/setgid centrally (not only in the
         * per-protocol handlers) so no chmod caller can set S_ISUID/S_ISGID on a
         * backend file; sticky is preserved. */
        return brix_imp_chmod(rel, mode & 0777);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    /* Strip setuid/setgid centrally (see the impersonation branch above). */
    rc = fchmodat(parentfd, base, mode & 0777, 0) == 0 ? 0 : -1;
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* Confined symlink creation — symlinkat under parent confinement.
 *
 * Create a symlink at <link_resolved> with literal contents <target>. Only
 *       the LINK location is confined (symlinkat anchored at the confined parent);
 *       the target string is stored verbatim — traversal safety for any later
 *       access THROUGH the link is enforced by the confined-open (RESOLVE_BENEATH),
 *       so a target that points outside the root simply cannot be followed.
 *       Returns 0 on success, -1 with errno set.
 */
int
brix_symlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *target, const char *link_resolved)
{
    char base[NAME_MAX + 1];
    int  parentfd;
    int  rc;
    int  saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, link_resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_symlink(target, rel);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, link_resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    rc = symlinkat(target, parentfd, base);
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return rc;
}

/* Confined readlink — readlinkat under parent confinement.
 *
 * Read the target of the symlink at <resolved> into <buf> (NOT
 *       NUL-terminated by readlinkat — the caller terminates). The parent is
 *       opened under confinement and readlinkat does not follow the final symlink.
 *       Returns the number of bytes placed in buf, or -1 with errno set.
 */
ssize_t
brix_readlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *buf, size_t bufsz)
{
    char    base[NAME_MAX + 1];
    int     parentfd;
    ssize_t n;
    int     saved_errno;

    /* Phase 40: route through the broker (as the mapped user) when active. */
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_readlink(rel, buf, bufsz);
    }

    parentfd = brix_open_confined_parent_canon(log, root_canon, resolved,
                                                 base, sizeof(base));
    if (parentfd < 0) {
        return -1;
    }
    n = readlinkat(parentfd, base, buf, bufsz);
    saved_errno = errno;
    close(parentfd);
    errno = saved_errno;
    return n;
}
