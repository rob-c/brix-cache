#ifndef BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H
#define BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H

/*
 * sd_xroot_internal.h — driver-private state + cross-file entry points for the
 * root:// origin driver.
 *
 * The per-export instance state and the errno helper are shared by the I/O /
 * lifecycle path (sd_xroot.c) and the namespace + metadata path
 * (sd_xroot_ns.c); the namespace vtable ops are defined in sd_xroot_ns.c but
 * referenced by the driver struct in sd_xroot.c.  Driver-private: not part of
 * the sd_xroot public surface (sd_xroot.h).
 */

#include "sd_xroot.h"                    /* brix_sd_instance_t, module conf */
#include "fs/cache/cache_internal.h"     /* brix_cache_fill_t + origin wire client */

/* Per-export instance state (inst->state): the resolved origin params.  For a
 * cache-constructed instance `conf` is the real export conf; for a registry-built
 * PRIMARY backend (a stream/http export with no stream conf) `synth` owns a
 * minimal conf carrying just cache_origin_host/port/tls (+ trusted_ca, TLS-only). */
typedef struct {
    ngx_stream_brix_srv_conf_t *conf;    /* origin params (real or synthetic) */
    ngx_stream_brix_srv_conf_t *synth;   /* owned synthetic conf, or NULL */
    char                          host[256];
    char                          bearer[4096]; /* §14/C-3 ztn token ("" = anon) */
    char                          x509_proxy[1024]; /* §14/C-3 GSI proxy (or cert) path */
    char                          x509_key[1024];   /* §14/C-3 GSI key ("" = in proxy) */
    char                          ca_dir[1024];     /* §14/C-3 GSI origin-cert CA */
    char                          sss_keytab[1024]; /* §14 SSS shared-secret keytab */
} sd_xroot_inst_state;

/* errno for a completed fill task (sd_xroot.c), shared by both paths. */
int sd_xroot_errno(const brix_cache_fill_t *t);

/* ---- shared origin-open machinery (phase-79 file-size split) --------------
 *
 * The per-open object state, the open request bundle, and the connect →
 * bootstrap → kXR_open orchestrator live in sd_xroot.c (the driver core) and
 * are shared with the object I/O + open + stat path (sd_xroot_io.c).  The
 * credential-copy and teardown helpers are also reused by the staged-write
 * path (sd_xroot_staged.c).  Driver-private: not part of the public surface. */

/* Per-open state: a live origin connection + open file handle + the synthetic
 * fill-task the origin functions need (conf + clean_path + error scratch). */
typedef struct {
    brix_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    brix_cache_fill_t        *t;
    int                         file_open;   /* 1 once kXR_open succeeded */
    int                         is_write;    /* 1 = opened for write (open_write) */
} sd_xroot_obj_state;

/* Inputs to a single origin file open. Bundling the seven loose arguments into a
 * struct keeps sd_xroot_origin_open() and its callers (open_common, stat,
 * stat_cred) below the parameter-count gate.  `size_out`/`err_out` may be NULL;
 * the remaining fields are required. */
typedef struct {
    ngx_stream_brix_srv_conf_t  *conf;       /* origin params (real or synthetic) */
    const brix_sd_cred_t          *cred;       /* per-user credential, or NULL      */
    const char                    *path;       /* remote path to open               */
    int                            want_write; /* 1 = writable open, 0 = read open  */
    mode_t                         mode;        /* create mode (write opens only)    */
    off_t                         *size_out;   /* out: file size (may be NULL)      */
    int                           *err_out;    /* out: errno on failure (may be NULL) */
} sd_xroot_origin_open_req_t;

/* Copy a per-user credential into the fill task before bootstrap; no-op on NULL
 * cred (sd_xroot.c).  Shared by the plain, cred, and staged open paths. */
void sd_xroot_copy_cred_into_task(brix_cache_fill_t *t,
              const brix_sd_cred_t *cred);

/* Free an object's origin connection + open file handle + fill task (sd_xroot.c).
 * Used by the open failure paths, close, and the stat probes (sd_xroot_io.c). */
void sd_xroot_obj_teardown(sd_xroot_obj_state *st);

/* Connect → bootstrap → kXR_open for one origin session; returns the populated
 * object state, or NULL with *req->err_out set (sd_xroot.c).  Called by the open
 * + stat vtable slots in sd_xroot_io.c. */
sd_xroot_obj_state *sd_xroot_origin_open(
              const sd_xroot_origin_open_req_t *req);

/* Object I/O + open + stat vtable slots (sd_xroot_io.c), referenced by the
 * driver struct in sd_xroot.c. */
brix_sd_obj_t *sd_xroot_open(brix_sd_instance_t *inst, const char *path,
              int sd_flags, mode_t mode, int *err_out);
brix_sd_obj_t *sd_xroot_open_cred(brix_sd_instance_t *inst, const char *path,
              int sd_flags, mode_t mode, const brix_sd_cred_t *cred,
              int *err_out);
ngx_int_t sd_xroot_close(brix_sd_obj_t *obj);
ssize_t   sd_xroot_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ssize_t   sd_xroot_preadv(brix_sd_obj_t *obj, const struct iovec *iov,
              int iovcnt, off_t off);
ssize_t   sd_xroot_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
              off_t off);
ngx_int_t sd_xroot_ftruncate(brix_sd_obj_t *obj, off_t len);
ngx_int_t sd_xroot_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_xroot_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_int_t sd_xroot_stat(brix_sd_instance_t *inst, const char *path,
              brix_sd_stat_t *out);

/* Staged atomic-publish vtable slots (sd_xroot_staged.c), referenced by the
 * driver struct in sd_xroot.c. */
brix_sd_staged_t *sd_xroot_staged_open(brix_sd_instance_t *inst,
              const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_xroot_staged_open_cred(brix_sd_instance_t *inst,
              const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
              int *err_out);
ssize_t   sd_xroot_staged_write(brix_sd_staged_t *handle, const void *buf,
              size_t len, off_t off);
ngx_int_t sd_xroot_staged_commit(brix_sd_staged_t *handle, int noreplace);
void      sd_xroot_staged_abort(brix_sd_staged_t *handle);

/* ---- shared namespace helpers (defined in sd_xroot_ns.c) ------------------
 * Reused by the credential-scoped wrappers (sd_xroot_ns_cred.c) and the
 * directory-listing path (sd_xroot_ns_dir.c) after the file-size split. */

/* The kXR_fattr handler stores user attr "X" as on-disk "user.U.X"; strip one
 * prefix before forwarding to another origin, re-add it on list (see
 * sd_xroot_ns.c for the full rationale). */
#define SD_XROOT_FATTR_PFX     "user.U."
#define SD_XROOT_FATTR_PFX_LEN 7

/* Strip a leading "user.U." so a forwarded fattr key is not double-prefixed. */
const char *sd_xroot_fattr_unmap(const char *name);

/* Connect + bootstrap a fresh origin session (no file open) for a path-based op;
 * cred NULL ⇒ service credential.  Fills *oc + *t_out; -1 with *err_out on
 * failure. */
int sd_xroot_session(ngx_stream_brix_srv_conf_t *conf,
              const brix_sd_cred_t *cred, brix_cache_origin_conn_t *oc,
              brix_cache_fill_t **t_out, int *err_out);

/* Byte-copy src_fh→dst_fh on an open session, then truncate+sync dst. */
ngx_int_t sd_xroot_copy_body(brix_cache_fill_t *t,
              brix_cache_origin_conn_t *oc, const u_char *src_fh,
              const u_char *dst_fh, off_t *bytes_out);

/* Namespace + metadata vtable ops (sd_xroot_ns.c), wired into the driver struct
 * in sd_xroot.c.  Plain ops (service credential / anonymous): */
ssize_t   sd_xroot_getxattr(brix_sd_instance_t *inst, const char *path,
              const char *name, void *buf, size_t cap);
ssize_t   sd_xroot_listxattr(brix_sd_instance_t *inst, const char *path,
              void *buf, size_t cap);
ngx_int_t sd_xroot_setxattr(brix_sd_instance_t *inst, const char *path,
              const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_xroot_removexattr(brix_sd_instance_t *inst, const char *path,
              const char *name);
ngx_int_t sd_xroot_rename(brix_sd_instance_t *inst, const char *src,
              const char *dst, int noreplace);
ngx_int_t sd_xroot_unlink(brix_sd_instance_t *inst, const char *path, int is_dir);
ngx_int_t sd_xroot_server_copy(brix_sd_instance_t *inst, const char *src,
              const char *dst, off_t *bytes_out);

/* Credential-scoped namespace vtable ops — Phase 2 Task 1.
 * stat_cred is in sd_xroot_io.c (reuses the file-open path); the remainder are
 * in sd_xroot_ns.c.  Each mirrors the plain op but presents the per-user proxy. */
ngx_int_t sd_xroot_stat_cred(brix_sd_instance_t *inst, const char *path,
              brix_sd_stat_t *out, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_unlink_cred(brix_sd_instance_t *inst, const char *path,
              int is_dir, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_rename_cred(brix_sd_instance_t *inst, const char *src,
              const char *dst, int noreplace, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_server_copy_cred(brix_sd_instance_t *inst,
              const char *src, const char *dst, off_t *bytes_out,
              const brix_sd_cred_t *cred);
ssize_t   sd_xroot_getxattr_cred(brix_sd_instance_t *inst, const char *path,
              const char *name, void *buf, size_t cap,
              const brix_sd_cred_t *cred);
ssize_t   sd_xroot_listxattr_cred(brix_sd_instance_t *inst, const char *path,
              void *buf, size_t cap, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_setxattr_cred(brix_sd_instance_t *inst, const char *path,
              const char *name, const void *val, size_t len, int flags,
              const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_removexattr_cred(brix_sd_instance_t *inst,
              const char *path, const char *name,
              const brix_sd_cred_t *cred);

/* Directory listing (kXR_dirlist, fetch-all-then-iterate — sd_xroot_ns.c).
 * opendir/readdir/closedir mirror the plain namespace ops (fresh session per
 * opendir, closed before returning); opendir_cred presents the per-user
 * credential so a remote dirlist authenticates as the requesting user. */
brix_sd_dir_t *sd_xroot_opendir(brix_sd_instance_t *inst, const char *path,
              int *err_out);
brix_sd_dir_t *sd_xroot_opendir_cred(brix_sd_instance_t *inst,
              const char *path, int *err_out, const brix_sd_cred_t *cred);
ngx_int_t sd_xroot_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_xroot_closedir(brix_sd_dir_t *d);

#endif /* BRIX_FS_BACKEND_XROOT_SD_XROOT_INTERNAL_H */
