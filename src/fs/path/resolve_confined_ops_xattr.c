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

/* Confined extended-attribute ops — broker-routed under impersonation.
 *
 * WHAT: set/get/remove/list extended attributes on a resolved (already
 *       lexically-confined) path.  When impersonation map mode is active the op
 *       is routed to the privileged broker, which re-confines under its own
 *       export rootfd (openat2 RESOLVE_BENEATH) and performs the f*xattr as the
 *       mapped user — so the lock/dead-property xattr lands with, and is
 *       DAC-checked for, the real user (not the unprivileged worker).  When
 *       impersonation is off the behaviour is byte-for-byte the prior raw
 *       path-based syscall, so the non-impersonated path is unchanged.
 *
 * WHY: WebDAV LOCK tokens and PROPPATCH dead-properties are stored as `user.*`
 *       xattrs on the resource.  Without broker routing the worker (svc) would
 *       attempt setxattr on a file owned 0644 by the mapped user and fail EACCES
 *       — i.e. LOCK/PROPPATCH were broken under impersonation.  Routing fixes
 *       that and keeps the on-disk metadata owned by the right identity.
 *
 * Return values mirror the POSIX *xattr contract (get/list: byte count, or the
 * size when bufsz==0; -1/ERANGE when the caller buffer is too small).
 */
int
brix_setxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, const void *value, size_t len,
    int flags)
{
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_setxattr(rel, name, value, len, flags);
    }
    return setxattr(resolved, name, value, len, flags);
}

ssize_t
brix_getxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, void *buf, size_t bufsz)
{
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_getxattr(rel, name, buf, bufsz);
    }
    return getxattr(resolved, name, buf, bufsz);
}

int
brix_removexattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name)
{
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_removexattr(rel, name);
    }
    return removexattr(resolved, name);
}

ssize_t
brix_listxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, void *buf, size_t bufsz)
{
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        return brix_imp_listxattr(rel, buf, bufsz);
    }
    return listxattr(resolved, buf, bufsz);
}
