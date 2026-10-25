/* Low-level xattr replies over existing caller-aware attribute operations.
 * Size queries and value reads are distinct public libfuse response types.
 */
#include "xrootdfs_lowlevel.h"

/* WHAT: Read one xattr or a name list. WHY: Reuse bounded allocation/reply logic.
 * HOW: 1. Check reply budget. 2. Resolve inode and query as caller.
 *      3. Emit size or bytes, preserving ERANGE and unsupported errors. */
static void
xfs_ll_xattr_read(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
    if (size > 1024U * 1024U) {
        fuse_reply_err(req, E2BIG);
        return;
    }
    char *value = size ? malloc(size) : NULL;
    if (size && !value) {
        fuse_reply_err(req, ENOMEM);
        return;
    }
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = name ? xfs_getxattr(xfs_req_uid(req), path, name, value, size)
                  : xfs_listxattr(xfs_req_uid(req), path, value, size);
    }
    pthread_mutex_unlock(&session->mutex);
    if (rc < 0) {
        fuse_reply_err(req, -rc);
    } else if (!size) {
        fuse_reply_xattr(req, (size_t) rc);
    } else {
        fuse_reply_buf(req, value, (size_t) rc);
    }
    free(value);
}

/* WHAT: Dispatch xattr get. WHY: Size-query replies differ from data replies.
 * HOW: 1. Delegate to the bounded shared reader with an explicit name. */
void
xfs_ll_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
    xfs_ll_xattr_read(req, ino, name, size);
}

/* WHAT: Dispatch xattr list. WHY: Preserve all existing namespace translations.
 * HOW: 1. Delegate to the reader with the list selector. */
void
xfs_ll_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    xfs_ll_xattr_read(req, ino, NULL, size);
}

/* WHAT: Write one xattr. WHY: Retain checksum/read-only and caller auth gates.
 * HOW: 1. Resolve exact inode. 2. Invoke maintained mutation. 3. Reply status. */
void
xfs_ll_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                 const char *value, size_t size, int flags)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_setxattr(xfs_req_uid(req), path, name, value, size, flags);
    }
    xfs_req_finish(req, session, rc);
}

/* WHAT: Delete one xattr. WHY: Never bypass opt-in or protected checksum names.
 * HOW: 1. Resolve inode. 2. Invoke maintained caller-aware removal. 3. Reply. */
void
xfs_ll_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    xfs_session *session = xfs_req_lock(req);
    char path[XRDC_PATH_MAX];
    int rc = xfs_req_path(session, ino, path);
    if (rc == 0) {
        rc = xfs_removexattr(xfs_req_uid(req), path, name);
    }
    xfs_req_finish(req, session, rc);
}
