/* Inode-based lookup and metadata replies. Transport/auth/retry remain in the
 * existing xfs_* operations; this file only owns low-level kernel references.
 */
#include "xrootdfs_lowlevel.h"
#include <unistd.h>

/* WHAT: Look up one child with a stable node id. WHY: Paths are only aliases.
 * HOW: 1. Resolve and stat as caller. 2. Reserve bookkeeping. 3. Reply once. */
void
xfs_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    xfs_node_ticket ticket = {0};
    int rc = xfs_req_child(session, parent, name, path);
    if (rc == 0) {
        rc = xfs_nodes_prepare(&session->nodes, path, &ticket);
    }
    if (rc == 0) {
        rc = xfs_ll_entry(req, session, path, NULL, &ticket, NULL);
    }
    xfs_nodes_cancel(&session->nodes, &ticket);
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
    }
}

/* WHAT: Release kernel lookup references. WHY: Forget must not invalidate opens.
 * HOW: 1. Resolve id under lock. 2. Debit owners. 3. Send the no-response ack. */
void
xfs_ll_forget(fuse_req_t req, fuse_ino_t ino, uint64_t count)
{
    xfs_session *session = xfs_req_lock(req);
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    if (node) {
        xfs_nodes_forget(&session->nodes, node, count);
    }
    pthread_mutex_unlock(&session->mutex);
    fuse_reply_none(req);
}

/* WHAT: Stat a specific open handle, returning negative errno.
 * WHY: Open-time metadata cannot observe later writes or staged-file size.
 * HOW: 1. Lock handle. 2. Stat its actual remote fd. 3. Include pending writes.
 *      4. Preserve the kernel identity and unlock on every outcome. */
static int
xfs_ll_handle_stat(afh *handle, fuse_ino_t ino, struct stat *attr)
{
    pthread_mutex_lock(&handle->lock);
    *attr = handle->attr;
    int rc = 0;
    if (handle->mf) {
        brix_statinfo info;
        brix_status status;
        brix_status_clear(&status);
        rc = brix_mfile_stat(handle->mf, &info, &status);
        if (rc == 0) {
            xfs_fill_stat(&info, attr);
        } else {
            rc = xfs_err(&status);
        }
    }
    off_t pending_end = handle->io.wbuf_off + (off_t) handle->io.wbuf_len;
    if (rc == 0 && handle->io.wbuf_len && attr->st_size < pending_end) {
        attr->st_size = pending_end;
    }
    attr->st_ino = (ino_t) ino;
    pthread_mutex_unlock(&handle->lock);
    return rc;
}

/* WHAT: Select only this caller's live handle, or NULL.
 * WHY: BSD GETATTR can omit fh, but another user's open must not lend authority.
 * HOW: 1. Walk the mount-locked inode owner list. 2. Require the exact caller uid. */
static afh *
xfs_ll_caller_handle(fuse_req_t req, xfs_node *node)
{
    for (afh *handle = node->open_handles; handle; handle = handle->node_next) {
        if (handle->caller_uid == xfs_req_uid(req)) {
            return handle;
        }
    }
    return NULL;
}

/* WHAT: Fetch authorized attributes while preserving the kernel node id.
 * WHY: An unlinked open handle remains usable without reopening a stale name.
 * HOW: 1. Resolve inode. 2. Use handle metadata or caller-authorized stat.
 *      3. Replace only the transport inode with the mount identity. */
static int
xfs_ll_stat(fuse_req_t req, xfs_session *session, fuse_ino_t ino,
             struct fuse_file_info *fi, struct stat *attr)
{
    xfs_node *node = xfs_nodes_find(&session->nodes, ino);
    if (!node) {
        return -ESTALE;
    }
    afh *handle = fi && fi->fh ? (afh *) (uintptr_t) fi->fh
                              : xfs_ll_caller_handle(req, node);
    if (handle) {
        return xfs_ll_handle_stat(handle, ino, attr);
    }
    const char *path = xfs_node_path(node);
    if (!path) {
        return -ENOENT;
    }
    int rc = xfs_getattr(xfs_req_uid(req), path, attr, NULL);
    if (rc == 0 && node->backend && (uint64_t) attr->st_ino != node->backend) {
        return -ESTALE; /* the path now names a different backing inode */
    }
    attr->st_ino = (ino_t) ino;
    return rc;
}

/* WHAT: Reply to getattr. WHY: The same identity must survive every hard link.
 * HOW: 1. Read attributes under namespace lock. 2. Unlock. 3. Reply or refuse. */
void
xfs_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    xfs_session *session = xfs_req_lock(req);
    struct stat attr = {0};
    int rc = xfs_ll_stat(req, session, ino, fi, &attr);
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
        return;
    }
    fuse_reply_attr(req, &attr, g_sss_ident ? 0 : g_attr_timeout);
}

/* WHAT: Apply requested metadata fields, returning first error.
 * WHY: Low-level setattr combines the existing high-level operations.
 * HOW: 1. Mode. 2. Owner fields independently. 3. Size. 4. Requested times. */
static int
xfs_ll_apply_attr(uid_t uid, const char *path, struct stat *attr, int fields,
                   struct fuse_file_info *fi)
{
    int rc = 0;
    if (fields & FUSE_SET_ATTR_MODE) {
        rc = xfs_chmod(uid, path, attr->st_mode, fi);
    }
    if (rc == 0 && (fields & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))) {
        rc = xfs_chown(uid, path, fields & FUSE_SET_ATTR_UID ? attr->st_uid : (uid_t) -1,
                       fields & FUSE_SET_ATTR_GID ? attr->st_gid : (gid_t) -1, fi);
    }
    if (rc == 0 && (fields & FUSE_SET_ATTR_SIZE)) {
        rc = xfs_truncate(uid, path, attr->st_size, fi);
    }
    if (rc == 0 && (fields & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME
                              | FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW))) {
        /* The root:// extension carries whole seconds, not host-private stat
         * nanosecond members (which differ on Darwin). */
        struct timespec times[2] = {{attr->st_atime, 0}, {attr->st_mtime, 0}};
        if (!(fields & FUSE_SET_ATTR_ATIME)) { times[0].tv_nsec = UTIME_OMIT; }
        if (!(fields & FUSE_SET_ATTR_MTIME)) { times[1].tv_nsec = UTIME_OMIT; }
        if (fields & FUSE_SET_ATTR_ATIME_NOW) { times[0].tv_nsec = UTIME_NOW; }
        if (fields & FUSE_SET_ATTR_MTIME_NOW) { times[1].tv_nsec = UTIME_NOW; }
        rc = xfs_utimens(uid, path, times, fi);
    }
    return rc;
}

/* WHAT: Mutate metadata, then return current attributes. WHY: Keep error mapping.
 * HOW: 1. Resolve exact alias. 2. Apply requested fields. 3. Restat on success. */
void
xfs_ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int fields,
                struct fuse_file_info *fi)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_ll_apply_attr(xfs_req_uid(req), path, attr, fields, fi);
    }
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
        return;
    }
    xfs_ll_getattr(req, ino, fi);
}

/* WHAT: Resolve a symlink as the caller. WHY: Never use mount-owner credentials.
 * HOW: 1. Resolve alias. 2. Use maintained retry/auth helper. 3. Reply literal. */
void
xfs_ll_readlink(fuse_req_t req, fuse_ino_t ino)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX], target[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_readlink(xfs_req_uid(req), path, target, sizeof(target));
    }
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
        return;
    }
    fuse_reply_readlink(req, target);
}

/* WHAT: Report endpoint capacity. WHY: Keep the existing root/WebDAV contract.
 * HOW: 1. Resolve inode. 2. Query as caller. 3. Reply with bounded struct. */
void
xfs_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    struct statvfs info;
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_statfs(xfs_req_uid(req), path, &info);
    }
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
        return;
    }
    fuse_reply_statfs(req, &info);
}

/* WHAT: Check caller access. WHY: Metadata authorization cannot use cached uid.
 * HOW: 1. Resolve inode. 2. Forward the actual uid. 3. Reply status. */
void
xfs_ll_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_access(xfs_req_uid(req), path, mask);
    }
    xfs_req_finish(req, session, rc);
}
