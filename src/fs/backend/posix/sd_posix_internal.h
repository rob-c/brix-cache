/*
 * sd_posix_internal.h — implementation-private definitions shared by the
 * sd_posix_*.c units of the POSIX storage driver.
 *
 * WHAT: Holds the driver-private instance-state struct and the cross-unit
 *       prototypes for the vtable slot functions that were split out of
 *       sd_posix.c (the worker-safe raw byte ops in sd_posix_io.c and the
 *       nginx-coupled namespace/dir/xattr/staged ops in sd_posix_ns.c), plus
 *       the shared sd_posix_fill_stat helper. The registration descriptor
 *       (brix_sd_posix_driver) in sd_posix.c references these symbols; keeping
 *       them non-static + declared here lets the descriptor stay in one file.
 *
 * WHY:  A behaviour-preserving file-size split needs the moved clusters to see
 *       the same struct/helper the descriptor does, with zero change to what
 *       each function does.
 *
 * HOW:  Include-guarded. The raw byte ops are always compiled (they build into
 *       the ngx-free shared libxrdproto too); the namespace/instance ops are
 *       module-only and their prototypes sit under !XRDPROTO_NO_NGX to mirror
 *       their definitions.
 */

#ifndef BRIX_SD_POSIX_INTERNAL_H
#define BRIX_SD_POSIX_INTERNAL_H

#include "fs/backend/sd.h"

#include <sys/stat.h>
#include <sys/uio.h>

/* Driver-private instance state. */
typedef struct {
    int       rootfd;        /* persistent O_PATH fd on root_canon, or -1 */
    char     *root_canon;    /* pool-owned copy (or borrowed when borrowed=1) */
    unsigned  borrowed:1;    /* rootfd/root_canon are owned by the caller's conf:
                              * cleanup must NOT close the fd or free the string */
} sd_posix_state_t;

/* sd_posix_fill_stat — copy the protocol-neutral fields out of a struct stat into
 * the brix_sd_stat_t the VFS consumes, deriving is_dir/is_reg from the mode.
 * Defined in sd_posix.c; used by the fstat op (sd_posix_io.c) and the stat op
 * (sd_posix_ns.c). */
void sd_posix_fill_stat(const struct stat *st, brix_sd_stat_t *out);

/* worker-safe raw byte I/O (sd_posix_io.c) — always compiled */
ssize_t sd_posix_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ssize_t sd_posix_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
    off_t off);
ssize_t sd_posix_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off);
ssize_t sd_posix_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags);
ssize_t sd_posix_copy_range(brix_sd_obj_t *src, off_t src_off, brix_sd_obj_t *dst,
    off_t dst_off, size_t len);
ngx_fd_t sd_posix_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy);
ngx_int_t sd_posix_ftruncate(brix_sd_obj_t *obj, off_t len);
ngx_int_t sd_posix_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_posix_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);

#ifndef XRDPROTO_NO_NGX   /* namespace/dir/xattr/staged: module-only (sd_posix_ns.c) */
ngx_int_t sd_posix_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_posix_unlink(brix_sd_instance_t *inst, const char *path, int is_dir);
ngx_int_t sd_posix_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode);
ngx_int_t sd_posix_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
ngx_int_t sd_posix_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_posix_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
brix_sd_dir_t *sd_posix_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
ngx_int_t sd_posix_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_posix_closedir(brix_sd_dir_t *d);
ssize_t sd_posix_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t sd_posix_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_posix_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_posix_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
brix_sd_staged_t *sd_posix_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
ssize_t sd_posix_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off);
ngx_int_t sd_posix_staged_commit(brix_sd_staged_t *st, int noreplace);
void sd_posix_staged_abort(brix_sd_staged_t *st);
const char *sd_posix_staged_path(const brix_sd_staged_t *st);
#endif /* !XRDPROTO_NO_NGX */

#endif /* BRIX_SD_POSIX_INTERNAL_H */
