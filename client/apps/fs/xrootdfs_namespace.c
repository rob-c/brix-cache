/* Low-level namespace mutations. All allocations precede the server operation;
 * the mount mutex keeps aliases coherent with rename/unlink/link replies.
 */
#include "xrootdfs_lowlevel.h"

typedef struct {
    mode_t mode;
    dev_t device;
    const char *target;
    struct fuse_file_info *fi;
} xfs_new_args;
typedef int (*xfs_new_fn)(uid_t uid, const char *path, xfs_new_args *args);

/* WHAT: Create a node entry and reply once. WHY: Preallocate identity ownership.
 * HOW: 1. Resolve child. 2. Reserve node/alias. 3. Mutate as caller. 4. Reply. */
static void
xfs_ll_new(fuse_req_t req, fuse_ino_t parent, const char *name,
             xfs_new_fn operation, xfs_new_args *args)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    xfs_node_ticket ticket = {0};
    int rc = xfs_req_child(session, parent, name, path);
    if (rc == 0) {
        rc = xfs_nodes_prepare(&session->nodes, path, &ticket);
    }
    if (rc == 0) {
        rc = operation(xfs_req_uid(req), path, args);
    }
    if (rc == 0) {
        rc = xfs_ll_entry(req, session, path, args->fi, &ticket, NULL);
        if (rc != 0 && args->fi && args->fi->fh) {
            xfs_release(path, args->fi);
        }
    }
    xfs_nodes_cancel(&session->nodes, &ticket);
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
    }
}

/* WHAT: Adapt regular mknod. WHY: Special files must retain EPERM refusal.
 * HOW: 1. Forward mode/device with caller identity to the maintained operation. */
static int
xfs_new_mknod(uid_t uid, const char *path, xfs_new_args *args)
{
    return xfs_mknod(uid, path, args->mode, args->device);
}

/* WHAT: Adapt mkdir. WHY: Preserve existing retry and policy semantics.
 * HOW: 1. Forward the requested mode and actual caller uid. */
static int
xfs_new_mkdir(uid_t uid, const char *path, xfs_new_args *args)
{
    return xfs_mkdir(uid, path, args->mode);
}

/* WHAT: Adapt symlink. WHY: Link content is literal, not a namespace key.
 * HOW: 1. Pass the target unchanged to the maintained helper. */
static int
xfs_new_symlink(uid_t uid, const char *path, xfs_new_args *args)
{
    return xfs_symlink(uid, args->target, path);
}

/* WHAT: Adapt create/open. WHY: The response must also own an open reference.
 * HOW: 1. Forward flags through the existing create helper. */
static int
xfs_new_create(uid_t uid, const char *path, xfs_new_args *args)
{
    return xfs_create(uid, path, args->mode, args->fi);
}

/* WHAT: Dispatch mknod. WHY: Share pre-mutation reservation and error handling.
 * HOW: 1. Bundle scalar arguments. 2. Run the common entry transaction. */
void
xfs_ll_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t device)
{
    xfs_new_args args = {.mode = mode, .device = device};
    xfs_ll_new(req, parent, name, xfs_new_mknod, &args);
}

/* WHAT: Dispatch mkdir. WHY: New directories also require stable identities.
 * HOW: 1. Bundle mode. 2. Run the common entry transaction. */
void
xfs_ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
    xfs_new_args args = {.mode = mode};
    xfs_ll_new(req, parent, name, xfs_new_mkdir, &args);
}

/* WHAT: Dispatch symlink. WHY: Keep literal target separate from parent/name.
 * HOW: 1. Bundle target. 2. Run the common entry transaction. */
void
xfs_ll_symlink(fuse_req_t req, const char *target, fuse_ino_t parent, const char *name)
{
    xfs_new_args args = {.target = target};
    xfs_ll_new(req, parent, name, xfs_new_symlink, &args);
}

/* WHAT: Dispatch create. WHY: The kernel needs entry and handle atomically.
 * HOW: 1. Bundle mode/handle. 2. Run the common entry transaction. */
void
xfs_ll_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
               struct fuse_file_info *fi)
{
    xfs_new_args args = {.mode = mode, .fi = fi};
    xfs_ll_new(req, parent, name, xfs_new_create, &args);
}

/* WHAT: Remove exactly one name. WHY: An inode's other aliases/opens survive.
 * HOW: 1. Resolve child. 2. Mutate as caller. 3. Unpublish only on success. */
static void
xfs_ll_remove(fuse_req_t req, fuse_ino_t parent, const char *name,
                int (*operation)(uid_t, const char *))
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_child(session, parent, name, path);
    if (rc == 0) {
        rc = operation(xfs_req_uid(req), path);
    }
    if (rc == 0) {
        xfs_nodes_unlink(&session->nodes, path);
    }
    xfs_req_finish(req, session, rc);
}

/* WHAT: Dispatch unlink. WHY: Reuse coherent alias removal.
 * HOW: 1. Pass the maintained file-removal operation. */
void
xfs_ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    xfs_ll_remove(req, parent, name, xfs_unlink);
}

/* WHAT: Dispatch rmdir. WHY: Never substitute file removal for directory policy.
 * HOW: 1. Pass the maintained directory-removal operation. */
void
xfs_ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    xfs_ll_remove(req, parent, name, xfs_rmdir);
}

/* WHAT: Create an alias with its source kernel identity. WHY: Fix BSD LINK EIO.
 * HOW: 1. Resolve source/destination. 2. Reserve alias. 3. Link as caller.
 *      4. Reply using the original node, never a second path-derived id. */
void
xfs_ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent, const char *name)
{
    xfs_session *session = xfs_req_lock(req);
    char from[XRDC_PATH_MAX], to[XRDC_PATH_MAX];
    xfs_node_ticket ticket = {0};
    int rc = xfs_req_path(session, ino, from);
    if (rc == 0) { rc = xfs_req_child(session, parent, name, to); }
    if (rc == 0) { rc = xfs_nodes_prepare(&session->nodes, to, &ticket); }
    if (rc == 0) { rc = xfs_link(xfs_req_uid(req), from, to); }
    if (rc == 0) {
        xfs_node *source = xfs_nodes_find(&session->nodes, ino);
        rc = xfs_ll_entry(req, session, to, NULL, &ticket, source);
    }
    xfs_nodes_cancel(&session->nodes, &ticket);
    pthread_mutex_unlock(&session->mutex);
    if (rc != 0) {
        fuse_reply_err(req, -rc);
    }
}

/* WHAT: Recognize rename between aliases of the same inode.
 * WHY: POSIX requires a no-op; deleting either alias would corrupt the registry.
 * HOW: 1. Resolve both keys. 2. Compare actual inode ownership. */
static int
xfs_rename_same(xfs_nodes *table, const char *from, const char *to)
{
    xfs_alias *source = xfs_nodes_alias(table, from);
    xfs_alias *target = xfs_nodes_alias(table, to);
    return source && target && source->node == target->node;
}

/* WHAT: Rename a file/subtree without invalidating descendant identities.
 * WHY: Open directories and files remain addressable after parent rename.
 * HOW: 1. Resolve both names. 2. Reserve all replacement keys. 3. Mutate as uid.
 *      4. Commit keys only on success, or release reservations unchanged. */
void
xfs_ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
               fuse_ino_t newparent, const char *newname, unsigned flags)
{
    xfs_session *session = xfs_req_lock(req);
    char from[XRDC_PATH_MAX], to[XRDC_PATH_MAX];
    xfs_rename_change *changes = NULL;
    int rc = xfs_req_child(session, parent, name, from);
    if (rc == 0) { rc = xfs_req_child(session, newparent, newname, to); }
    int same = rc == 0 && xfs_rename_same(&session->nodes, from, to);
    if (rc == 0 && !same) {
        rc = xfs_nodes_rename_prepare(&session->nodes, from, to, &changes);
    }
    if (rc == 0) {
        rc = xfs_rename(xfs_req_uid(req), from, to, flags);
    }
    xfs_nodes_rename_finish(&session->nodes, changes, to, rc == 0 && !same);
    xfs_req_finish(req, session, rc);
}
