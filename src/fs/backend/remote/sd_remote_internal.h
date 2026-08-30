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

/* Per-open state: the delegated S3 read handle. Shared beyond sd_remote.c so the
 * object-keyed slots in the siblings (the checksum offload) can reuse the handle
 * the open already signed — a probe on the object's own key and identity. */
typedef struct {
    sd_s3_file *s3;
} sd_remote_obj_state;

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

/* ---- checksum offload (defined in sd_remote_checksum.c) --------------------
 * The object-keyed `query_checksum` slot: the digest the S3 origin already
 * stores, read off one signed HEAD on the handle the open established, instead
 * of a full-object read-back. NGX_DECLINED whenever the store's answer is not
 * authoritative for exactly the requested algorithm. */
ngx_int_t sd_remote_query_checksum(brix_sd_obj_t *obj, const char *algo,
    char *hex_out, size_t hex_sz);

/* ---- nearline (archive) slots (defined in sd_remote_nearline.c) -----------
 * residency classifies a key from the archive headers of ONE signed HEAD (a
 * pure read — it never touches the archive tier); recall posts RestoreObject.
 * Reachable only on an instance carrying BRIX_SD_CAP_NEARLINE, which
 * brix_sd_remote_create arms from cfg->nearline alone — the cap is a contract
 * the composing registry enforces, never an inference from an object. */
ngx_int_t sd_remote_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out);
ngx_int_t sd_remote_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40]);

/* ---- HEAD-based metadata slots (defined in sd_remote_meta.c) --------------- */
ssize_t sd_remote_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t sd_remote_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
/* The credential-scoped read siblings of the setxattr/removexattr pair above:
 * without them the cred forwarder fell through to the plain slots, so a per-user
 * metadata READ was signed with the export's shared service credential and could
 * return attributes the caller's own S3 keys would have been denied. */
ssize_t sd_remote_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred);
ssize_t sd_remote_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred);
ngx_int_t sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_remote_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);
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
/* Server-side copy (S3 CopyObject) — a mutation, so it lives with the write
 * slots. The _cred sibling matters more here than anywhere else on this driver:
 * one signed request READS one key and WRITES another, so signing it as the
 * export could duplicate an object the caller cannot read into a prefix they
 * cannot write. */
ngx_int_t sd_remote_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_remote_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred);

/* Directory listing over the S3 catalog (sd_remote_dir.c) — ListObjectsV2 with
 * a delimiter, paged lazily. Non-static because the driver vtable in
 * sd_remote.c registers these slots. */
/* Backend-catalog enumeration (sd_remote_enum.c): every stored object once,
 * with size/mtime from the flat listing itself. Signed as the export. */
ngx_int_t sd_remote_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx);

brix_sd_dir_t *sd_remote_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
/* The credential-scoped sibling: without it the cred forwarder fell through to
 * the plain slot, so a per-user LIST was signed with the export's service key
 * and enumerated prefixes the caller's own S3 keys would have been denied. The
 * signing material is copied onto the handle because the pages are fetched
 * lazily from readdir, after *cred stops being ours to hold. */
brix_sd_dir_t *sd_remote_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred);
ngx_int_t sd_remote_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_remote_closedir(brix_sd_dir_t *d);

#endif /* BRIX_SD_REMOTE_INTERNAL_H */
