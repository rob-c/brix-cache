/* Low-level FUSE request adapter. Requires: xrootdfs_internal.h (included).
 * Session userdata, never globals, owns inode references and namespace locking.
 */
#pragma once
#include "xrootdfs_internal.h"
#include "xrootdfs_nodes.h"
#include <fuse3/fuse_lowlevel.h>

typedef struct {
    pthread_mutex_t mutex;
    xfs_nodes nodes;
} xfs_session;

extern const struct fuse_lowlevel_ops xfs_lowlevel_ops;
uid_t xfs_req_uid(fuse_req_t req);
xfs_session *xfs_req_lock(fuse_req_t req);
void xfs_req_finish(fuse_req_t req, xfs_session *session, int rc);
int xfs_req_path(xfs_session *session, fuse_ino_t ino, char *out);
int xfs_req_child(xfs_session *session, fuse_ino_t parent, const char *name, char *out);
int xfs_ll_entry(fuse_req_t req, xfs_session *session, const char *path,
                 struct fuse_file_info *fi, xfs_node_ticket *ticket, xfs_node *preferred);
void xfs_ll_handle_attach(xfs_node *node, struct fuse_file_info *fi, uid_t uid);
void xfs_ll_lookup(fuse_req_t, fuse_ino_t, const char *);
void xfs_ll_forget(fuse_req_t, fuse_ino_t, uint64_t);
void xfs_ll_getattr(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_setattr(fuse_req_t, fuse_ino_t, struct stat *, int, struct fuse_file_info *);
void xfs_ll_readlink(fuse_req_t, fuse_ino_t);
void xfs_ll_mknod(fuse_req_t, fuse_ino_t, const char *, mode_t, dev_t);
void xfs_ll_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
void xfs_ll_unlink(fuse_req_t, fuse_ino_t, const char *);
void xfs_ll_rmdir(fuse_req_t, fuse_ino_t, const char *);
void xfs_ll_symlink(fuse_req_t, const char *, fuse_ino_t, const char *);
void xfs_ll_rename(fuse_req_t, fuse_ino_t, const char *, fuse_ino_t, const char *, unsigned);
void xfs_ll_link(fuse_req_t, fuse_ino_t, fuse_ino_t, const char *);
void xfs_ll_open(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_create(fuse_req_t, fuse_ino_t, const char *, mode_t, struct fuse_file_info *);
void xfs_ll_read(fuse_req_t, fuse_ino_t, size_t, off_t, struct fuse_file_info *);
void xfs_ll_write(fuse_req_t, fuse_ino_t, const char *, size_t, off_t, struct fuse_file_info *);
void xfs_ll_flush(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_release(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_fsync(fuse_req_t, fuse_ino_t, int, struct fuse_file_info *);
void xfs_ll_opendir(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_readdir(fuse_req_t, fuse_ino_t, size_t, off_t, struct fuse_file_info *);
void xfs_ll_releasedir(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
void xfs_ll_statfs(fuse_req_t, fuse_ino_t);
void xfs_ll_access(fuse_req_t, fuse_ino_t, int);
void xfs_ll_getxattr(fuse_req_t, fuse_ino_t, const char *, size_t);
void xfs_ll_listxattr(fuse_req_t, fuse_ino_t, size_t);
void xfs_ll_setxattr(fuse_req_t, fuse_ino_t, const char *, const char *, size_t, int);
void xfs_ll_removexattr(fuse_req_t, fuse_ino_t, const char *);
