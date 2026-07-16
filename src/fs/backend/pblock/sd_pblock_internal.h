/*
 * sd_pblock_internal.h — cross-file declarations shared between the translation
 * units of the pblock ("pseudo-block") storage-driver vtable after the phase-79
 * size split.
 *
 * WHAT: Publishes the one per-open-object state struct that both the driver core
 *       and the byte-I/O file touch (pblock_obj_t), plus the driver-vtable slot
 *       functions that were split out of sd_pblock.c and are now called across a
 *       file boundary — every slot is still named in the descriptor in
 *       sd_pblock.c, so all of them are non-static — together with the two
 *       internal helpers that cross a boundary directly (sd_pblock_ftruncate,
 *       called by the object-open O_TRUNC path in the core, and sd_pblock_drop_dst,
 *       called by both rename and staged-commit).
 *
 * WHY:  sd_pblock.c was one 1111-line file. It is split by concept into the
 *       driver core — instance + object lifecycle and the descriptor (stays in
 *       sd_pblock.c) — the worker-safe byte I/O (sd_pblock_io.c), the namespace,
 *       directory-iteration and xattr operations (sd_pblock_namespace.c), and the
 *       staged atomic-publish path (sd_pblock_staged.c). The descriptor in the
 *       core references every slot, so the moved functions become non-static and
 *       are declared here; nothing here is exported beyond the pblock backend.
 *
 * HOW:  Every pblock driver-vtable translation unit includes this header (in
 *       addition to sd.h / sd_pblock_catalog.h / pblock_store.h). It is gated by
 *       BRIX_HAVE_SQLITE exactly like its includers, so a no-sqlite build stays
 *       byte-for-byte unchanged.
 *
 * Requires: fs/backend/sd.h (brix_sd_* types, ngx_int_t/ngx_fd_t),
 *           sd_pblock_catalog.h (pblock_meta, PBLOCK_BLOB_ID_CAP),
 *           pblock_store.h (pblock_state_t), <limits.h> (PATH_MAX),
 *           <stdint.h>, <sys/types.h>, <sys/uio.h> before inclusion.
 */
#ifndef BRIX_SD_PBLOCK_INTERNAL_H
#define BRIX_SD_PBLOCK_INTERNAL_H

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "pblock_store.h"

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

/* ---- per-open object state (obj->state) ---------------------------------- *
 * obj->fd is the block-0 fd (or NGX_INVALID_FILE for directories); higher
 * blocks are opened transiently per I/O. Shared between the driver core (which
 * builds and tears it down) and the byte-I/O file (which reads/writes through
 * it), so its layout lives here. */
typedef struct {
    pblock_state_t *st;                   /* borrowed from inst->state          */
    char            path[PATH_MAX];       /* logical path (catalog key)         */
    char            blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t         block_size;           /* this file's stripe size            */
    pblock_meta     meta;                 /* cached metadata row                */
    unsigned        dirty:1;              /* size/mtime need catalog write-back */
} pblock_obj_t;

/* ---- worker-safe byte I/O (sd_pblock_io.c) ------------------------------- */
ssize_t sd_pblock_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ssize_t sd_pblock_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
    off_t off);
ssize_t sd_pblock_preadv(brix_sd_obj_t *obj, const struct iovec *iov,
    int iovcnt, off_t off);
ssize_t sd_pblock_preadv2(brix_sd_obj_t *obj, const struct iovec *iov,
    int iovcnt, off_t off, int flags);
ssize_t sd_pblock_copy_range(brix_sd_obj_t *src, off_t src_off,
    brix_sd_obj_t *dst, off_t dst_off, size_t len);
ngx_fd_t sd_pblock_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy);
/* Block-aware truncate; also the object-open O_TRUNC path in the core. */
ngx_int_t sd_pblock_ftruncate(brix_sd_obj_t *obj, off_t len);
ngx_int_t sd_pblock_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_pblock_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);

/* ---- namespace / directory / xattr (sd_pblock_namespace.c) --------------- */
ngx_int_t sd_pblock_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_pblock_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_pblock_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_pblock_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
/* Clear a rename/copy destination; also called by staged-commit's replace. */
ngx_int_t sd_pblock_drop_dst(pblock_state_t *st, const char *dst,
    const pblock_meta *dmeta);
ngx_int_t sd_pblock_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_pblock_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
brix_sd_dir_t *sd_pblock_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
ngx_int_t sd_pblock_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_pblock_closedir(brix_sd_dir_t *d);
ssize_t sd_pblock_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t sd_pblock_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_pblock_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_pblock_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);

/* ---- staged atomic publish (sd_pblock_staged.c) -------------------------- */
brix_sd_staged_t *sd_pblock_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
ssize_t sd_pblock_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_pblock_staged_commit(brix_sd_staged_t *st, int noreplace);
void sd_pblock_staged_abort(brix_sd_staged_t *st);

/* ---- owner-parameterized create internals --------------------------------- *
 * Each is the real implementation of its plain vtable slot, extended with the
 * catalog-internal synthetic (uid, gid) recorded as the owner of any row the
 * op creates. The plain slots call these with 0/0 (the service); the identity
 * slots (sd_pblock_cred.c) call them with the requester's resolved ids. */
brix_sd_obj_t *sd_pblock_open_as(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, uint32_t uid, uint32_t gid, int *err_out);
ngx_int_t sd_pblock_mkdir_as(brix_sd_instance_t *inst, const char *path,
    mode_t mode, uint32_t uid, uint32_t gid);
ngx_int_t sd_pblock_server_copy_as(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, uint32_t uid, uint32_t gid);
brix_sd_staged_t *sd_pblock_staged_open_as(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, uint32_t uid, uint32_t gid,
    int *err_out);

/* ---- identity resolution + POSIX access checks (sd_pblock_ident.c) ------- *
 * A request identity resolved to catalog-internal synthetic ids: the
 * principal's uid plus one gid per VO the credential lists (group = VO).
 * `service` set (NULL/empty principal) means "no identity" — every check
 * passes, preserving service (root-like) semantics for identity-less callers. */
#define PBLOCK_MAX_GIDS 16

typedef struct {
    int      service;              /* 1 = bypass all checks               */
    uint32_t uid;                  /* principal's synthetic uid           */
    uint32_t gid;                  /* primary gid (first VO, or uid — a
                                    * user-private group — when VO-less)  */
    uint32_t gids[PBLOCK_MAX_GIDS];/* every VO gid, gids[0] == gid        */
    int      ngids;
} pblock_ids_t;

ngx_int_t pblock_ident_resolve(pblock_state_t *st, const brix_sd_cred_t *cred,
    pblock_ids_t *out);
ngx_int_t pblock_ident_access(const pblock_meta *meta, const pblock_ids_t *ids,
    int want);
ngx_int_t pblock_ident_check(pblock_state_t *st, const char *path,
    const pblock_ids_t *ids, int want, pblock_meta *meta_out);
ngx_int_t pblock_ident_check_parent(pblock_state_t *st, const char *path,
    const pblock_ids_t *ids, int want, pblock_meta *parent_out);
ngx_int_t pblock_ident_sticky_gate(const pblock_meta *parent,
    const pblock_meta *entry, const pblock_ids_t *ids);

/* ---- identity-enforcing *_cred vtable slots (sd_pblock_cred.c) ------------ */
brix_sd_obj_t *sd_pblock_open_cred(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out);
brix_sd_staged_t *sd_pblock_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ngx_int_t sd_pblock_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred);
ssize_t sd_pblock_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred);
ssize_t sd_pblock_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_removexattr_cred(brix_sd_instance_t *inst,
    const char *path, const char *name, const brix_sd_cred_t *cred);
ngx_int_t sd_pblock_server_copy_cred(brix_sd_instance_t *inst,
    const char *src, const char *dst, off_t *bytes_out,
    const brix_sd_cred_t *cred);
brix_sd_dir_t *sd_pblock_opendir_cred(brix_sd_instance_t *inst,
    const char *path, int *err_out, const brix_sd_cred_t *cred);

#endif /* BRIX_SD_PBLOCK_INTERNAL_H */
