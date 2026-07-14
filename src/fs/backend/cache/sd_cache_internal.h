#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H

/*
 * sd_cache_internal.h — shared internal state for the read-through cache driver.
 *
 * The per-export instance state (inst->state) is split into this header so it is
 * visible to both the vtable adapters (sd_cache.c) and the admission/policy +
 * metrics helpers (sd_cache_policy.c) without either file re-declaring it.  This
 * is a driver-private header: it is not part of the sd_cache public surface
 * (sd_cache.h).
 */

#include "fs/backend/sd.h"       /* brix_sd_instance_t */
#include "fs/cache/cstore.h"     /* brix_cstore_t */
#include "fs/tier/tier.h"        /* brix_cache_policy_t */

/* Per-export instance state (inst->state). */
typedef struct {
    brix_sd_instance_t  *source;         /* the tier below (stage | backend)    */
    brix_cstore_t        cstore;
    brix_cache_policy_t  policy;
    ngx_log_t             *log;
} sd_cache_inst_state;

#define SD_CACHE_ST(inst)   ((sd_cache_inst_state *) (inst)->state)
#define SD_CACHE_SRC(inst)  (SD_CACHE_ST(inst)->source)

/* ---- cross-file entry points (phase-79 size split) ----------------------- *
 * sd_cache.c was one 1404-line file. It is split by concept into the vtable
 * adapters + lifecycle + async-offload seam (sd_cache.c), the whole-file fill
 * spine (sd_cache_fill.c), the slice/partial machinery + partial byte slots
 * (sd_cache_partial.c), and the namespace/xattr/dir/staged forwarders
 * (sd_cache_forward.c). Exactly the functions defined in one unit but called
 * from another are declared here and made non-static; nothing below is part of
 * the public surface (sd_cache.h). */

/* ---- whole-file fill spine (sd_cache_fill.c) ----------------------------- */

/* Fill `key` from the source into the cache store and record its cinfo. NGX_OK
 * (cached or stale-served), NGX_DECLINED (admission), NGX_ERROR. `cred` may be
 * NULL (service-credential path). Called by the interposed read-open miss path
 * and the async fill-key entrypoint in sd_cache.c. */
ngx_int_t sd_cache_fill(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred);

/* ---- slice / partial caching (sd_cache_partial.c) ------------------------ */

/* Build a partial-serve object for `key` (slice mode) — on-demand block fills
 * from the source. Returns the new object or NULL with *err_out set. */
brix_sd_obj_t *sd_cache_partial_open(brix_sd_instance_t *inst,
    sd_cache_inst_state *st, const char *key, const brix_sd_cred_t *cred,
    int *err_out);

/* Decorator byte slots, reached only for a slice partial object (wired into the
 * driver vtable in sd_cache.c). */
ssize_t   sd_cache_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ngx_int_t sd_cache_close(brix_sd_obj_t *obj);
ngx_int_t sd_cache_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_fd_t  sd_cache_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy);

/* ---- namespace / xattr / dir / staged forwarders (sd_cache_forward.c) ---- *
 * Delegating vtable slots wired into the driver in sd_cache.c. */
ngx_int_t sd_cache_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_cache_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_cache_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_cache_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_cache_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_cache_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
brix_sd_dir_t *sd_cache_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
ngx_int_t sd_cache_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_cache_closedir(brix_sd_dir_t *d);
ssize_t   sd_cache_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t   sd_cache_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_cache_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_cache_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
brix_sd_staged_t *sd_cache_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_cache_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t   sd_cache_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_cache_staged_commit(brix_sd_staged_t *st, int noreplace);
void      sd_cache_staged_abort(brix_sd_staged_t *st);

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H */
