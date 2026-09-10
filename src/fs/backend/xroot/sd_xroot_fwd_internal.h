#ifndef BRIX_FS_BACKEND_XROOT_SD_XROOT_FWD_INTERNAL_H
#define BRIX_FS_BACKEND_XROOT_SD_XROOT_FWD_INTERNAL_H

/*
 * sd_xroot_fwd_internal.h — driver-private state + cross-file entry points of
 * the forwarding root:// driver.
 *
 * The instance state, the key→child resolver and the relay guard are shared by
 * the lifecycle/open path (sd_xroot_fwd.c), the object-keyed relays
 * (sd_xroot_fwd_obj.c) and the namespace relays (sd_xroot_fwd_ns.c); the slot
 * functions of the latter two are referenced by the driver table in
 * sd_xroot_fwd.c.  Driver-private: not part of sd_xroot_fwd.h.
 */

#include "sd_xroot_fwd.h"
#include "sd_xroot_fwd_key.h"

#include <pthread.h>

#define SD_XROOT_FWD_MAX_CHILDREN  256   /* distinct host:port:tls per worker */
#define SD_XROOT_FWD_PERMIT_MAX    512   /* the joined permit= list */

/* One per-origin sd_xroot child, keyed by the parsed target. */
typedef struct sd_xroot_fwd_child_s {
    char                           host[BRIX_SD_XROOT_FWD_HOST_MAX];
    int                            port;
    int                            tls;
    brix_sd_instance_t          *inst;
    struct sd_xroot_fwd_child_s   *next;
} sd_xroot_fwd_child_t;

/* Per-export instance state (inst->state).  `tmpl` points at the string
 * copies below so a child can be created from it at any time; the child list
 * is mutated only under `mtx`. */
typedef struct {
    brix_sd_xroot_origin_cfg_t  tmpl;
    char                          bearer[4096];
    char                          x509_proxy[1024];
    char                          x509_key[1024];
    char                          ca_dir[1024];
    char                          sss_keytab[1024];
    char                          permit[SD_XROOT_FWD_PERMIT_MAX];
    unsigned                      allow_root:1;
    unsigned                      allow_roots:1;
    pthread_mutex_t               mtx;
    sd_xroot_fwd_child_t         *children;
    unsigned                      nchildren;
} sd_xroot_fwd_inst_state;

/* Parse `key`, apply the protocol list and the permit allowlist, and return
 * the (possibly freshly created) child for its origin, with *t filled.  NULL
 * with errno: the parser's ENOENT / ENOTSUP / EINVAL / ENAMETOOLONG, ENOTSUP
 * for a scheme outside the protocol list, EACCES for a host the permit list
 * refuses, EMFILE at the child cap, or the child factory's errno. */
brix_sd_instance_t *sd_xroot_fwd_resolve(brix_sd_instance_t *inst,
    const char *key, brix_sd_xroot_fwd_target_t *t);

/* The driver an object-keyed relay may forward to: `d` unless it is NULL or
 * this driver itself (a handle that somehow carries the forwarding driver
 * must not recurse).  NULL = refuse with ENOSYS. */
const brix_sd_driver_t *sd_xroot_fwd_relay_driver(const brix_sd_driver_t *d);

/* ---- object / dir / staged relays (sd_xroot_fwd_obj.c) ------------------- */
ngx_int_t sd_xroot_fwd_close(brix_sd_obj_t *obj);
ssize_t   sd_xroot_fwd_pread(brix_sd_obj_t *obj, void *buf, size_t len,
    off_t off);
ssize_t   sd_xroot_fwd_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
    off_t off);
ssize_t   sd_xroot_fwd_preadv(brix_sd_obj_t *obj, const struct iovec *iov,
    int iovcnt, off_t off);
ngx_int_t sd_xroot_fwd_ftruncate(brix_sd_obj_t *obj, off_t len);
ngx_int_t sd_xroot_fwd_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_xroot_fwd_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_int_t sd_xroot_fwd_query_checksum(brix_sd_obj_t *obj, const char *algo,
    char *hex_out, size_t hex_sz);
ngx_int_t sd_xroot_fwd_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_xroot_fwd_closedir(brix_sd_dir_t *d);
ssize_t   sd_xroot_fwd_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_xroot_fwd_staged_commit(brix_sd_staged_t *st,
    brix_sd_precond_t *pre);
void      sd_xroot_fwd_staged_abort(brix_sd_staged_t *st);

/* ---- namespace relays (sd_xroot_fwd_ns.c) -------------------------------- */
ngx_int_t sd_xroot_fwd_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_xroot_fwd_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_xroot_fwd_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_xroot_fwd_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_xroot_fwd_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_xroot_fwd_server_copy_cred(brix_sd_instance_t *inst,
    const char *src, const char *dst, off_t *bytes_out,
    const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
ngx_int_t sd_xroot_fwd_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_truncate_path(brix_sd_instance_t *inst,
    const char *path, off_t len);
ngx_int_t sd_xroot_fwd_truncate_path_cred(brix_sd_instance_t *inst,
    const char *path, off_t len, const brix_sd_cred_t *cred);
ssize_t   sd_xroot_fwd_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t   sd_xroot_fwd_getxattr_cred(brix_sd_instance_t *inst,
    const char *path, const char *name, void *buf, size_t cap,
    const brix_sd_cred_t *cred);
ssize_t   sd_xroot_fwd_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ssize_t   sd_xroot_fwd_listxattr_cred(brix_sd_instance_t *inst,
    const char *path, void *buf, size_t cap, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_xroot_fwd_setxattr_cred(brix_sd_instance_t *inst,
    const char *path, const char *name, const void *val, size_t len,
    int flags, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
ngx_int_t sd_xroot_fwd_removexattr_cred(brix_sd_instance_t *inst,
    const char *path, const char *name, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_fwd_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40]);
ngx_int_t sd_xroot_fwd_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40]);
ngx_int_t sd_xroot_fwd_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out);
ngx_int_t sd_xroot_fwd_evict(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out);
ngx_int_t sd_xroot_fwd_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred);

#endif /* BRIX_FS_BACKEND_XROOT_SD_XROOT_FWD_INTERNAL_H */
