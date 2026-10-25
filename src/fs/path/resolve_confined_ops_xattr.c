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
#include "platform/platform_api.h"   /* xattr calls, RESOLVE_* on every host */
#include <time.h>
#include <unistd.h>

/* Confined extended-attribute ops — broker-routed under impersonation.
 *
 * WHAT: set/get/remove/list extended attributes on a resolved (already
 *       lexically-confined) path.  When impersonation map mode is active the op
 *       is routed to the privileged broker, which re-confines under its own
 *       export rootfd (openat2 RESOLVE_BENEATH) and performs the f*xattr as the
 *       mapped user — so the lock/dead-property xattr lands with, and is
 *       DAC-checked for, the real user (not the unprivileged worker). Without
 *       impersonation, the same confined-open boundary pins a descriptor and
 *       every operation uses f*xattr; a lexical prefix or an earlier stat is
 *       not sufficient protection against traversal or symlink replacement.
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

/* One attribute operation's borrowed input/output buffers; no ownership escapes. */
typedef struct {
    const char *name;
    const void *setval;
    void       *buf;
    size_t      len;
    int         flags;
} xattr_io_t;

/* ---- Apply an attribute operation to an already confined descriptor ----
 * WHAT: Return the native f*xattr result without reopening a pathname.
 * WHY: A path-based syscall could follow a link swapped in after resolution.
 * HOW: 1. Select the operation. 2. Pass the borrowed buffers to its fd API.
 */
static ssize_t
xattr_descriptor_op(xattr_confined_op_t op, int descriptor, const xattr_io_t *io)
{
    switch (op) {
    case XATTR_OP_SET:
        return fsetxattr(descriptor, io->name, io->setval, io->len, io->flags);
    case XATTR_OP_GET:
        return fgetxattr(descriptor, io->name, io->buf, io->len);
    case XATTR_OP_REMOVE:
        return fremovexattr(descriptor, io->name);
    default:
        return flistxattr(descriptor, io->buf, io->len);
    }
}

/* ---- Open the attribute target through the existing confinement boundary ----
 * WHAT: Return a confined descriptor, or -1 with the authoritative open errno.
 * WHY: Attribute writes on write-only files must not require data-read rights;
 *      directories still need the read-side open that their kernel permits.
 * HOW: 1. Try a nonblocking read open. 2. On EACCES only, mutators may try a
 *      nonblocking write open. 3. Leave all other confinement errors unchanged.
 */
static int
xattr_open_target(xattr_confined_op_t op, ngx_log_t *log,
    const char *root_canon, const char *resolved)
{
    int descriptor = brix_open_confined_canon(log, root_canon, resolved,
                                             O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);

    if (descriptor < 0 && errno == EACCES
        && (op == XATTR_OP_SET || op == XATTR_OP_REMOVE)) {
        return brix_open_confined_canon(log, root_canon, resolved,
                                        O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0);
    }
    return descriptor;
}

/* ---- Own a confined descriptor for one non-impersonated attribute operation ----
 * WHAT: Return the fd operation's result and preserve its failure errno.
 * WHY: Every local attribute caller needs the same race-resistant boundary.
 * HOW: 1. Open beneath the root. 2. Operate on that fd. 3. Close on every path.
 */
static ssize_t
xattr_local_op(xattr_confined_op_t op, ngx_log_t *log, const char *root_canon,
    const char *resolved, const xattr_io_t *io)
{
    int descriptor = xattr_open_target(op, log, root_canon, resolved);
    ssize_t result;
    int saved_errno;

    if (descriptor < 0) {
        return -1;
    }
    result = xattr_descriptor_op(op, descriptor, io);
    saved_errno = errno;
    close(descriptor);
    if (result < 0) {
        errno = saved_errno;
    }
    return result;
}

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
    xattr_io_t io = { name, setval, buf, len, flags };
    return xattr_local_op(op, log, root_canon, resolved, &io);
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
