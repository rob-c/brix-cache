/*
 *
 * WHAT: Iterates over requested attribute names and deletes each one using POSIX removexattr (path-based) or fremovexattr (open-file-handle). Records individual success/failure for every attribute deletion, then sends a vector status response summarizing how many deletions succeeded versus failed. Supports both operations modes: when path is provided uses removexattr on the filesystem; when fd is provided uses fremovexattr on the open file handle.
 *
 * WHY: Extended attribute deletion is batched — clients may request removal of multiple attributes in a single kXR_fattr_del opcode. Processing each attribute individually with error recording allows precise per-attribute status reporting rather than aborting on first failure. This matches XRootD semantics where partial success is valid and reported via vector status response (kXR_status, opcode 4007). Thread safety: no shared state — operates only on provided path/fd and local stack variables. */

#include "ngx_brix_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>

ngx_int_t
fattr_del(brix_ctx_t *ctx, ngx_connection_t *c, brix_vfs_ctx_t *vctx,
    const char *path, int fd, u_char *nvec_copy, size_t nvec_len, int numattr,
    brix_fattr_entry_t *attrs)
{
    int attr_index;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        int rc;

        if (path != NULL) {
            rc = brix_vfs_removexattr(vctx, attrs[attr_index].xkey);
        } else {
            rc = brix_vfs_fremovexattr(vctx, fd, attrs[attr_index].xkey);
        }

        if (rc != 0) {
            fattr_set_rc(&attrs[attr_index], fattr_errno_to_xrd(errno));
        }
    }

    return fattr_send_vector_status(ctx, c, nvec_copy, nvec_len,
                                    numattr, attrs);
}
