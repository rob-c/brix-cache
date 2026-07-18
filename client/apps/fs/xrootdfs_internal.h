/*
 * xrootdfs_internal.h - private split contract for xrootdfs.c and its Phase-38 siblings.
 * Not a public API: include only from client/apps/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_XROOTDFS_INTERNAL_H
#define BRIX_XROOTDFS_INTERNAL_H

#define FUSE_USE_VERSION 31
#include "brix.h"
#include "core/aio/aio.h"
#include "posix/posix_map.h"       
#include "fs/iobuf.h"           
#include "posix/fuse_ops.h"        
#include "core/compat/crypto.h"   
#include "protocols/root/protocol/open_flags.h" 
#include <fuse3/fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>

#define XFS_CKS_XATTR_PFX "user.XrdCks."
typedef struct {
    brix_mfile     *mf;             /* root:// async handle (NULL on web mounts) */
    brix_webfile   *wf;            /* http(s)/WebDAV handle (NULL on root mounts) */
    pthread_mutex_t lock;
    int             writable;
    int64_t         wsize;  /* high-water byte size written through this handle —
                             * lets getattr report a still-staged (uncommitted)
                             * new file before its close-time commit (the server
                             * stages writes, so the final path stats ENOENT). */
    brix_iobuf      io;   /* shared read-ahead / write-back engine (iobuf.c) */
} afh;

extern const struct fuse_operations xfs_ops;

/* shared op-context structs (Phase 38) */
struct ctx_qspace { const char *path; char *out; size_t outsz; };
struct ctx_cks { const char *path; const char *algo; char *hex; size_t hexsz; };
struct ctx_faget { const char *path; const char *name; void *val; size_t bufsz; size_t *vlen; };
struct ctx_faset { const char *path; const char *name; const void *val; size_t vlen; int create_only; };
struct ctx_fadel { const char *path; const char *name; };
struct ctx_falist { const char *path; char *raw; size_t rawsz; size_t *rawlen; };

/* shared globals (Phase 38) */
extern double     g_attr_timeout;
extern char         g_base[XRDC_PATH_MAX];
extern const char  *g_bearer;
extern char       g_compress[32];
extern double     g_entry_timeout;
extern int        g_ext_link;
extern int        g_ext_readlink;
extern int        g_ext_setattr;
extern int        g_ext_symlink;
extern int        g_keepalive;
extern int        g_kernel_cache;
extern int        g_max_conns;
extern int        g_max_retries;
extern int        g_max_stall;
extern brix_mgr  *g_mgr;
extern brix_opts  g_opts;
extern brix_pool *g_pool;
extern struct brix_cpool *g_web_pool;   /* Phase-86: pooled WebDAV metadata (web mounts) */
extern size_t     g_readahead;
extern int        g_streams;
extern brix_url   g_url;
extern int          g_web;
extern const char  *g_web_ca;
extern int          g_web_verify;
extern brix_weburl  g_weburl;
extern size_t     g_writeback;
extern int        g_xattr;



/* xrootdfs.c */
const char *srv_path(const char *p, char *buf, size_t sz);
int xfs_err(const brix_status *st);
int xfs_conn_healthy(const brix_status *st);
int xfs_meta(brix_fuse_op_fn fn, void *ctx, brix_status *st);
int xfs_meta_idem(brix_fuse_op_fn fn, void *ctx, int benign_errno,
                  brix_status *st);
void xfs_fill_stat(const brix_statinfo *si, struct stat *stbuf);

/* xrootdfs_meta.c */
int xfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int xfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int xfs_mkdir(const char *path, mode_t mode);
int xfs_unlink(const char *path);
int xfs_rmdir(const char *path);
int xfs_rename(const char *from, const char *to, unsigned int flags);
int xfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_truncate(const char *path, off_t size, struct fuse_file_info *fi);
int xfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi);
int xfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi);
int xfs_symlink(const char *target, const char *linkpath);

/* xrootdfs.c */
int xfs_link(const char *from, const char *to);

/* xrootdfs_meta.c */
int xfs_readlink(const char *path, char *buf, size_t size);

/* xrootdfs_xattr.c */
int op_qspace(brix_conn *c, void *v, brix_status *st);

/* xrootdfs_meta.c */
int xfs_statfs(const char *path, struct statvfs *stbuf);
int xfs_access(const char *path, int mask);

/* xrootdfs_io.c */
ssize_t afh_pread(afh *h, int64_t off, void *buf, size_t len, brix_status *st);
ssize_t afh_io_pread(void *be, int64_t off, void *buf, size_t n, brix_status *st);
int afh_io_pwrite(void *be, int64_t off, const void *buf, size_t n, brix_status *st);
int afh_flush_wbuf(afh *h, brix_status *st);
void afh_free(afh *h);
int afh_open(const char *path, int writable, int force, struct fuse_file_info *fi);
int xfs_open(const char *path, struct fuse_file_info *fi);
int xfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_flush(const char *path, struct fuse_file_info *fi);
int xfs_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int xfs_release(const char *path, struct fuse_file_info *fi);

/* xrootdfs_xattr.c */
const char * xfs_xattr_to_fattr(const char *name);
int op_cks(brix_conn *c, void *v, brix_status *st);
int op_faget(brix_conn *c, void *v, brix_status *st);
int xfs_getxattr(const char *path, const char *name, char *value, size_t size);
int xfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
int op_faset(brix_conn *c, void *v, brix_status *st);
int op_fadel(brix_conn *c, void *v, brix_status *st);
int xfs_removexattr(const char *path, const char *name);
int op_falist(brix_conn *c, void *v, brix_status *st);
int xfs_listxattr(const char *path, char *list, size_t size);

/* xrootdfs.c */
void * xfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg);
void usage(void);

#endif /* BRIX_XROOTDFS_INTERNAL_H */
