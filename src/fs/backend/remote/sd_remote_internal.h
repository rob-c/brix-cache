#ifndef BRIX_SD_REMOTE_INTERNAL_H
#define BRIX_SD_REMOTE_INTERNAL_H

/*
 * sd_remote_internal.h — cross-file internals for the remote-origin (s3://)
 * storage driver, split across sd_remote.c (read path + driver table),
 * sd_remote_meta.c (HEAD-based stat/xattr) and sd_remote_write.c (staged
 * whole-object writes + unlink). Not a public API — the external surface stays
 * brix_sd_remote_create/destroy in sd_remote.h.
 */

#include "sd_remote.h"
#include "fs/backend/s3/sd_s3.h"

/* ---- shared helpers (defined in sd_remote.c) -------------------------------
 *
 * The three small builders every slot shares: compose the "/bucket/key" object
 * path, fill sd_s3_open_params from the instance config, and classify a
 * per-user credential (1 = sign with override, 0 = static fallback, -1 = deny).
 */
void sd_remote_s3_key(const brix_sd_remote_cfg_t *cfg, const char *key,
    char *dst, size_t dstcap);
void sd_remote_s3_dirkey(const brix_sd_remote_cfg_t *cfg, const char *key,
    char *dst, size_t dstcap);
void sd_remote_s3_params(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    sd_s3_open_params *p);
int sd_remote_cred_gate(const brix_sd_cred_t *cred);
/* Overlay a per-user ak/sk/region/session on a filled params (NULL = keep the
 * static service credential). Shared by sd_remote_meta.c and sd_remote_xattr.c. */
void sd_remote_params_cred(sd_s3_open_params *p, const char *ak, const char *sk,
    const char *region, const char *session);

/* ---- xattr / setattr slots (defined in sd_remote_xattr.c) ------------------
 * Metadata mutation over an s3:// object: setxattr/removexattr rewrite the
 * user.<name> ↔ x-amz-meta-<name> surface, setattr patches the reserved advisory
 * unix-attr blob. All three read the object's complete user-metadata set and
 * rewrite it as a whole (an S3 metadata write REPLACES the entire set), so no
 * co-existing attribute is dropped; they need the transport's raw-header
 * enumeration (ENOTSUP otherwise, as listxattr). */
ngx_int_t sd_remote_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
ngx_int_t sd_remote_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred);
ngx_int_t sd_remote_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_remote_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred);
ngx_int_t sd_remote_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
ngx_int_t sd_remote_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred);

/* ---- HEAD-based metadata slots (defined in sd_remote_meta.c) --------------- */
ssize_t sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_remote_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);
ngx_int_t sd_remote_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_remote_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_remote_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred);
ngx_int_t sd_remote_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_remote_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred);

/* ---- staged write path + unlink slots (defined in sd_remote_write.c) ------- */
brix_sd_staged_t *sd_remote_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_remote_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t sd_remote_staged_write(brix_sd_staged_t *h, const void *buf, size_t len,
    off_t off);
ngx_int_t sd_remote_staged_commit(brix_sd_staged_t *h, int noreplace);
void sd_remote_staged_abort(brix_sd_staged_t *h);
ngx_int_t sd_remote_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_remote_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred);

#endif /* BRIX_SD_REMOTE_INTERNAL_H */
