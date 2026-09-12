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

/* macOS xattr compatibility - different signatures than Linux */
#if defined(__APPLE__) && defined(__MACH__)
static ssize_t brix_getxattr_compat(const char *path, const char *name, void *value, size_t size) {
    return getxattr(path, name, value, size, 0, 0);
}
static int brix_setxattr_compat(const char *path, const char *name, const void *value, size_t size, int flags) {
    return setxattr(path, name, value, size, 0, flags);
}
static int brix_removexattr_compat(const char *path, const char *name) {
    return removexattr(path, name, 0);
}
static ssize_t brix_listxattr_compat(const char *path, char *list, size_t size) {
    return listxattr(path, list, size, 0);
}
#define getxattr(path, name, value, size) brix_getxattr_compat(path, name, value, size)
#define setxattr(path, name, value, size, flags) brix_setxattr_compat(path, name, value, size, flags)
#define removexattr(path, name) brix_removexattr_compat(path, name)
#define listxattr(path, list, size) brix_listxattr_compat(path, list, size)
#endif
#include <time.h>
#include <unistd.h>
/* macOS lacks openat2 - provide compatibility stubs */
#if defined(__APPLE__) && defined(__MACH__)
/* RESOLVE_* flags stubs for macOS */
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x8
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#endif
#ifndef RESOLVE_CACHED
#define RESOLVE_CACHED 0x20
#endif
#else
#include <linux/openat2.h>
#endif

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
typedef enum {
    XATTR_OP_SET,
    XATTR_OP_GET,
    XATTR_OP_REMOVE,
    XATTR_OP_LIST,
} xattr_confined_op_t;

/* Shared worker: one imp-gate + root-relative resolution, then dispatch.
 * setval is the SET payload, buf the GET/LIST output buffer; len carries the
 * payload/buffer size and flags is SET-only. */
static ssize_t
xattr_confined_op(xattr_confined_op_t op, ngx_log_t *log,
    const char *root_canon, const char *resolved, const char *name,
    const void *setval, void *buf, size_t len, int flags)
{
    if (brix_imp_client_active()) {
        char rel[PATH_MAX];
        if (!brix_resolved_relative_to_root(log, root_canon, resolved,
                                              rel, sizeof(rel)))
        {
            return -1;
        }
        switch (op) {
        case XATTR_OP_SET:    return brix_imp_setxattr(rel, name, setval,
                                                       len, flags);
        case XATTR_OP_GET:    return brix_imp_getxattr(rel, name, buf, len);
        case XATTR_OP_REMOVE: return brix_imp_removexattr(rel, name);
        default:              return brix_imp_listxattr(rel, buf, len);
        }
    }
    switch (op) {
    case XATTR_OP_SET:    return setxattr(resolved, name, setval, len, flags);
    case XATTR_OP_GET:    return getxattr(resolved, name, buf, len);
    case XATTR_OP_REMOVE: return removexattr(resolved, name);
    default:              return listxattr(resolved, buf, len);
    }
}

int
brix_setxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, const void *value, size_t len,
    int flags)
{
    return (int) xattr_confined_op(XATTR_OP_SET, log, root_canon, resolved,
                                   name, value, NULL, len, flags);
}

ssize_t
brix_getxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, void *buf, size_t bufsz)
{
    return xattr_confined_op(XATTR_OP_GET, log, root_canon, resolved, name,
                             NULL, buf, bufsz, 0);
}

int
brix_removexattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name)
{
    return (int) xattr_confined_op(XATTR_OP_REMOVE, log, root_canon, resolved,
                                   name, NULL, NULL, 0, 0);
}

ssize_t
brix_listxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, void *buf, size_t bufsz)
{
    return xattr_confined_op(XATTR_OP_LIST, log, root_canon, resolved, NULL,
                             NULL, buf, bufsz, 0);
}
