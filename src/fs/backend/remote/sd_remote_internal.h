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
void sd_remote_s3_params(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    sd_s3_open_params *p);
int sd_remote_cred_gate(const brix_sd_cred_t *cred);

/* ---- HEAD-based metadata slots (defined in sd_remote_meta.c) --------------- */
ssize_t sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_remote_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);

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
