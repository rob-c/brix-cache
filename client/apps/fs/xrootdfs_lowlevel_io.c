/* Low-level handle replies. Data operations remain in the existing buffered
 * async I/O engine; namespace references protect identities, not data locks.
 */
#include "xrootdfs_lowlevel.h"

/* WHAT: Attach an authorized file handle to its inode. WHY: BSD GETATTR can omit
 * the handle even for fstat after unlink. HOW: 1. Record uid/list ownership.
 * 2. Retain the inode. 3. Apply caller-safe kernel cache policy. */
void
xfs_ll_handle_attach(xfs_node *node, struct fuse_file_info *fi, uid_t uid)
{
    afh *handle = (afh *) (uintptr_t) fi->fh;
    handle->caller_uid = uid;
    handle->node_next = node->open_handles;
    node->open_handles = handle;
    node->opens++;
    fi->keep_cache = g_kernel_cache && !g_sss_ident;
    fi->direct_io = g_sss_ident;
}

/* WHAT: Remove one exact open owner from its inode. WHY: No freed handle can be
 * selected by a concurrent getattr. HOW: 1. Find pointer. 2. Unchain under lock. */
static void
xfs_ll_handle_detach(xfs_node *node, afh *handle)
{
    afh **cursor = &node->open_handles;
    while (*cursor && *cursor != handle) {
        cursor = &(*cursor)->node_next;
    }
    if (*cursor) {
        *cursor = handle->node_next;
    }
}

/* WHAT: Open an authorized inode and retain its identity. WHY: Handle outlives name.
 * HOW: 1. Stat/open under caller identity. 2. Cache authorized handle attributes.
 *      3. Add open owner; roll back if the reply is interrupted. */
void
xfs_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    struct stat attr;
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) { rc = xfs_getattr(xfs_req_uid(req), path, &attr, NULL); }
    if (rc == 0) { rc = xfs_open(xfs_req_uid(req), path, fi); }
    if (rc != 0) {
        xfs_req_finish(req, session, rc);
        return;
    }
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    afh *handle = (afh *) (uintptr_t) fi->fh;
    attr.st_ino = (ino_t) ino;
    handle->attr = attr;
    handle->wsize = fi->flags & O_TRUNC ? 0 : attr.st_size;
    xfs_ll_handle_attach(node, fi, xfs_req_uid(req));
    if (fuse_reply_open(req, fi) != 0) {
        xfs_ll_handle_detach(node, handle);
        xfs_release(path, fi);
        xfs_nodes_close(&session->nodes, node);
    }
    pthread_mutex_unlock(&session->mutex);
}

/* WHAT: Return a bounded read buffer. WHY: A kernel request cannot exhaust memory.
 * HOW: 1. Validate negotiated request bounds. 2. Use the existing handle read.
 *      3. Reply exact bytes and free the request-local buffer. */
void
xfs_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
             struct fuse_file_info *fi)
{
    (void) ino;
    if (size > 16U * 1024U * 1024U || offset < 0) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    char *buffer = malloc(size ? size : 1);
    if (!buffer) {
        fuse_reply_err(req, ENOMEM);
        return;
    }
    int rc = xfs_read(NULL, buffer, size, offset, fi);
    if (rc < 0) {
        fuse_reply_err(req, -rc);
    } else {
        fuse_reply_buf(req, buffer, (size_t) rc);
    }
    free(buffer);
}

/* WHAT: Forward a bounded write. WHY: Preserve maintained buffering/error handling.
 * HOW: 1. Reject impossible offsets/sizes. 2. Write by authorized handle.
 *      3. Reply with the actual count, never conceal a failed write. */
void
xfs_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buffer, size_t size,
              off_t offset, struct fuse_file_info *fi)
{
    (void) ino;
    if (size > 16U * 1024U * 1024U || offset < 0
        || (uint64_t) offset > INT64_MAX - size) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    int rc = xfs_write(NULL, buffer, size, offset, fi);
    if (rc < 0) {
        fuse_reply_err(req, -rc);
        return;
    }
    fuse_reply_write(req, (size_t) rc);
}

/* WHAT: Flush a live handle. WHY: Keep close-time errors observable to the caller.
 * HOW: 1. Use the existing buffered flush. 2. Return positive errno on failure. */
void
xfs_ll_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    (void) ino;
    int rc = xfs_flush(NULL, fi);
    fuse_reply_err(req, rc < 0 ? -rc : rc);
}

/* WHAT: Synchronize a live handle. WHY: No pathname reopen after unlink/rename.
 * HOW: 1. Use existing handle sync. 2. Reply its precise result. */
void
xfs_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
    (void) ino;
    int rc = xfs_fsync(NULL, datasync, fi);
    fuse_reply_err(req, rc < 0 ? -rc : rc);
}

/* WHAT: Close a handle and its inode owner. WHY: Forget may have happened earlier.
 * HOW: 1. Close outside namespace lock. 2. Drop open owner under lock. 3. Reply. */
void
xfs_ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    xfs_session *session = xfs_req_lock(req);
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    if (node) {
        xfs_ll_handle_detach(node, (afh *) (uintptr_t) fi->fh);
    }
    pthread_mutex_unlock(&session->mutex);
    int rc = xfs_release(NULL, fi);
    pthread_mutex_lock(&session->mutex);
    if (node) {
        xfs_nodes_close(&session->nodes, node);
    }
    xfs_req_finish(req, session, rc);
}
