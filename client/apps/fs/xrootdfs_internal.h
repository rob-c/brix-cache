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
#include "platform/platform.h"   /* PAL: Linux-shaped xattr calls on every host */

#define XFS_CKS_XATTR_PFX "user.XrdCks."
typedef struct afh {
    brix_mfile     *mf;             /* root:// async handle (NULL on web mounts) */
    brix_webfile   *wf;            /* http(s)/WebDAV handle (NULL on root mounts) */
    pthread_mutex_t lock;
    int             writable;
    struct stat     attr;           /* authorized open attributes, also after unlink */
    uid_t           caller_uid;
    struct afh     *node_next;      /* mount mutex protects this intrusive owner */
    int64_t         wsize;  /* high-water byte size written through this handle —
                             * lets getattr report a still-staged (uncommitted)
                             * new file before its close-time commit (the server
                             * stages writes, so the final path stats ENOENT). */
    brix_iobuf      io;   /* shared read-ahead / write-back engine (iobuf.c) */
} afh;

int xfs_session_main(int argc, char **argv);
void xfs_daemon_ready(unsigned char status);

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

/* ---- per-caller sss identity (W7.2, xrootdfs_identity.c) ---------------- */
extern int g_sss_ident;       /* --sss-identity: one connection set per caller */
extern int g_ident_max;       /* --max-identities: distinct uids this mount serves */
extern int g_ident_conns;     /* --identity-conns: per-identity meta pool width */
extern int g_ident_streams;   /* --identity-streams: per-identity data streams */

int  xfs_ident_init(void);
/* 0 with the pool/mgr out-params set, or -EMFILE (no slot) / -EACCES (the
 * identity would not connect).  Never falls back to the mount owner's. */
int  xfs_ident_get(uid_t caller_uid, brix_pool **pool, brix_mgr **mgr);
void xfs_ident_shutdown(void);
extern struct brix_cpool *g_web_pool;   /* Phase-86: pooled WebDAV metadata (web mounts) */
extern size_t     g_readahead;
extern int        g_streams;
extern brix_url   g_url;
extern int          g_web;
extern int          g_dir_fanout;  /* --cluster-readdir: union every holder's listing */
extern const char  *g_web_ca;
extern const char  *g_web_proxy;
extern int          g_web_verify;
extern brix_weburl  g_weburl;
extern size_t     g_writeback;
extern int        g_xattr;



/* xrootdfs.c */
const char *srv_path(const char *p, char *buf, size_t sz);
int xfs_err(const brix_status *st);
int xfs_conn_healthy(const brix_status *st);
int xfs_meta(uid_t caller_uid, brix_fuse_op_fn fn, void *ctx, brix_status *st);
int xfs_meta_idem(uid_t caller_uid, brix_fuse_op_fn fn, void *ctx, int benign_errno,
                  brix_status *st);
void xfs_fill_stat(const brix_statinfo *si, struct stat *stbuf);

/* xrootdfs_meta.c */
int xfs_getattr(uid_t caller_uid, const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int xfs_readdir(uid_t caller_uid, const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int xfs_mkdir(uid_t caller_uid, const char *path, mode_t mode);
int xfs_unlink(uid_t caller_uid, const char *path);
int xfs_rmdir(uid_t caller_uid, const char *path);
int xfs_rename(uid_t caller_uid, const char *from, const char *to, unsigned int flags);
int xfs_chmod(uid_t caller_uid, const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_truncate(uid_t caller_uid, const char *path, off_t size, struct fuse_file_info *fi);
int xfs_utimens(uid_t caller_uid, const char *path, const struct timespec tv[2], struct fuse_file_info *fi);
int xfs_chown(uid_t caller_uid, const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi);
int xfs_symlink(uid_t caller_uid, const char *target, const char *linkpath);

/* xrootdfs.c */
int xfs_link(uid_t caller_uid, const char *from, const char *to);

/* xrootdfs_meta.c */
int xfs_readlink(uid_t caller_uid, const char *path, char *buf, size_t size);

/* xrootdfs_xattr.c */
int op_qspace(brix_conn *c, void *v, brix_status *st);

/* xrootdfs_meta.c */
int xfs_statfs(uid_t caller_uid, const char *path, struct statvfs *stbuf);
int xfs_access(uid_t caller_uid, const char *path, int mask);

/* xrootdfs_io.c */
ssize_t afh_pread(afh *h, int64_t off, void *buf, size_t len, brix_status *st);
ssize_t afh_io_pread(void *be, int64_t off, void *buf, size_t n, brix_status *st);
int afh_io_pwrite(void *be, int64_t off, const void *buf, size_t n, brix_status *st);
int afh_flush_wbuf(afh *h, brix_status *st);
void afh_free(afh *h);
int afh_open(uid_t caller_uid, const char *path, int writable, int force, struct fuse_file_info *fi);
int xfs_open(uid_t caller_uid, const char *path, struct fuse_file_info *fi);
int xfs_create(uid_t caller_uid, const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_mknod(uid_t caller_uid, const char *path, mode_t mode, dev_t rdev);
int xfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_flush(const char *path, struct fuse_file_info *fi);
int xfs_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int xfs_release(const char *path, struct fuse_file_info *fi);

/* xrootdfs_xattr.c */
const char * xfs_xattr_to_fattr(const char *name);
int op_cks(brix_conn *c, void *v, brix_status *st);
int op_faget(brix_conn *c, void *v, brix_status *st);
int xfs_getxattr(uid_t caller_uid, const char *path, const char *name, char *value, size_t size);
int xfs_setxattr(uid_t caller_uid, const char *path, const char *name, const char *value, size_t size, int flags);
int op_faset(brix_conn *c, void *v, brix_status *st);
int op_fadel(brix_conn *c, void *v, brix_status *st);
int xfs_removexattr(uid_t caller_uid, const char *path, const char *name);
int op_falist(brix_conn *c, void *v, brix_status *st);
int xfs_listxattr(uid_t caller_uid, const char *path, char *list, size_t size);

/* xrootdfs.c */
void usage(void);
void usage_fp(FILE *out);   /* xrootdfs_usage.c */

#endif /* BRIX_XROOTDFS_INTERNAL_H */
