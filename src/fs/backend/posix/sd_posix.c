/*
 * sd_posix.c — the POSIX Storage Driver: a behaviour-preserving wrapper.
 *
 * WHAT: Implements brix_sd_posix_driver, the default backend. Every vtable
 *       slot delegates to an EXISTING confined helper (brix_open_beneath,
 *       brix_vfs_pread_full/pwrite_full, brix_ns_*, brix_lstat_beneath,
 *       the *xattr_confined_canon family, brix_staged_*), so the POSIX path
 *       is byte-identical to today's VFS once the VFS is wired to it (55.B+).
 *
 * WHY:  Cutting the SD seam must not change POSIX behaviour. The safest way to
 *       guarantee that is for the POSIX driver to call the same code the VFS
 *       calls now, rather than re-implement any syscall. Confinement stays the
 *       kernel RESOLVE_BENEATH API; an EXDEV still means an escape attempt.
 *
 * HOW:  The instance holds a persistent O_PATH rootfd + the root_canon string.
 *       Object handles carry the open fd and a metadata snapshot. The raw byte
 *       ops are worker-safe (no pool/metrics/log). Namespace ops translate the
 *       brix_ns_result_t status to errno via brix_vfs_ns_status_errno().
 *
 * NOTE: The worker-safe raw byte ops live in sd_posix_io.c and the nginx-coupled
 *       namespace/dir/xattr/staged ops in sd_posix_ns.c; this file keeps the
 *       instance lifecycle + the brix_sd_posix_driver descriptor, which
 *       references the split-out slots via sd_posix_internal.h.
 */

#include "fs/backend/sd.h"

/* The instance lifecycle + namespace/dir/xattr/staged ops below are nginx-coupled
 * (confined open, ngx pool, the shared brix_ns_* helpers). They — and these
 * headers — compile only in the module. The worker-safe raw fd byte ops
 * (pread/pwrite/preadv/...) are pure POSIX and also build into the ngx-free
 * shared libxrdproto, so a shared kernel (src/compat/checksum_core.c) can route
 * its fd reads through brix_sd_posix_driver in both worlds. */
#ifndef XRDPROTO_NO_NGX
#include "fs/vfs/vfs_internal.h"          /* pread_full/pwrite_full + ns_status_errno */
#include "core/compat/crc32c.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/staged_file.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sd_posix_internal.h"

/* sd_posix_flags — map the backend-neutral BRIX_SD_O_* bits to an open(2) flag
 * set (the vtable speaks SD flags; only the POSIX driver knows O_*). Always
 * compiled: the server's confined open and the client's unconfined open
 * (brix_sd_posix_open_unconfined) both use it, so the mapping is single-sourced. */
static int
sd_posix_flags(int sd_flags)
{
    int flags = 0;

    if ((sd_flags & BRIX_SD_O_WRITE) && (sd_flags & BRIX_SD_O_READ)) {
        flags = O_RDWR;
    } else if (sd_flags & BRIX_SD_O_WRITE) {
        flags = O_WRONLY;
    } else {
        flags = O_RDONLY;
    }

    if (sd_flags & BRIX_SD_O_CREATE)   { flags |= O_CREAT; }
    if (sd_flags & BRIX_SD_O_EXCL)     { flags |= O_EXCL; }
    if (sd_flags & BRIX_SD_O_TRUNC)    { flags |= O_TRUNC; }
    if (sd_flags & BRIX_SD_O_APPEND)   { flags |= O_APPEND; }
    if (sd_flags & BRIX_SD_O_DIR)      { flags |= O_DIRECTORY; }
    if (sd_flags & BRIX_SD_O_NOFOLLOW) { flags |= O_NOFOLLOW; }

    return flags;
}

/* brix_sd_posix_open_unconfined — plain open(2) of `path` (no export-root
 * confinement), the client-side counterpart of the server's confined
 * sd_posix_open. ngx-free + always compiled so the userland clients open through
 * the one driver. Returns an fd, or -1 with errno set. */
int
brix_sd_posix_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    return open(path, sd_posix_flags(sd_flags), mode);
}

/* sd_posix_fill_stat — copy the protocol-neutral fields out of a struct stat into
 * the brix_sd_stat_t the VFS consumes, deriving is_dir/is_reg from the mode.
 * Non-static + declared in sd_posix_internal.h: used by the split-out fstat op
 * (sd_posix_io.c) and stat op (sd_posix_ns.c). */
void
sd_posix_fill_stat(const struct stat *st, brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size  = st->st_size;
    out->mtime = st->st_mtime;
    out->ctime = st->st_ctime;
    out->mode  = st->st_mode;
    out->ino   = st->st_ino;
    out->is_dir = S_ISDIR(st->st_mode) ? 1 : 0;
    out->is_reg = S_ISREG(st->st_mode) ? 1 : 0;
}

#ifndef XRDPROTO_NO_NGX   /* instance lifecycle: ngx pool + confined open (module only) */
/* sd_posix_init — pcalloc the instance state, copy root_canon, and open its
 * persistent O_PATH anchor fd (the beneath API needs one per worker for hot
 * opens; a -1 rootfd is tolerated). */
static ngx_int_t
sd_posix_init(brix_sd_instance_t *inst, void *driver_conf)
{
    sd_posix_state_t *st;
    const char       *root_canon = driver_conf;

    if (root_canon == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    st->root_canon = ngx_pnalloc(inst->pool, ngx_strlen(root_canon) + 1);
    if (st->root_canon == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(st->root_canon, root_canon, ngx_strlen(root_canon) + 1);

    st->rootfd = brix_beneath_open_root(root_canon);  /* -1 tolerated */
    inst->state = st;
    return NGX_OK;
}

/* sd_posix_cleanup — close the persistent O_PATH rootfd (a kernel resource that
 * must not leak on reconfig); the pool reclaims the state struct. A borrowed fd
 * is left alone. */
static void
sd_posix_cleanup(brix_sd_instance_t *inst)
{
    sd_posix_state_t *st = inst->state;

    if (st != NULL && !st->borrowed && st->rootfd >= 0) {
        close(st->rootfd);
        st->rootfd = -1;
    }
}

/* brix_sd_posix_borrow_instance — build a pool-lived POSIX instance whose
 * confinement anchor BORROWS an already-open persistent rootfd + root_canon owned
 * by the caller's config (cleanup never closes a borrowed fd). Lets the VFS route
 * its hot-path confined open through driver->open with no second openat() per
 * request. NULL (errno set) for rootfd < 0 or OOM. */
brix_sd_instance_t *
brix_sd_posix_borrow_instance(ngx_pool_t *pool, ngx_log_t *log, int rootfd,
    const char *root_canon)
{
    brix_sd_instance_t *inst;
    sd_posix_state_t     *st;

    if (rootfd < 0) {
        errno = EINVAL;
        return NULL;
    }

    inst = ngx_pcalloc(pool, sizeof(*inst));
    st = ngx_pcalloc(pool, sizeof(*st));
    if (inst == NULL || st == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    st->rootfd = rootfd;
    st->root_canon = (char *) root_canon;
    st->borrowed = 1;
    inst->driver = &brix_sd_posix_driver;
    inst->log = log;
    inst->pool = pool;
    inst->state = st;
    return inst;
}

/* sd_posix_open — the POSIX realization of the VFS open cascade's beneath branch:
 * brix_open_beneath under RESOLVE_BENEATH into an object carrying the fd. It does
 * NOT fstat (metadata is the separate fstat slot, so a caller that doesn't need it
 * pays no syscall; the VFS open path fstats once in adopt_fd). */
static brix_sd_obj_t *
sd_posix_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_posix_state_t *st = inst->state;
    brix_sd_obj_t  *obj;
    int               fd;

    fd = brix_open_beneath(st->rootfd, path, sd_posix_flags(sd_flags), mode);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    /* Heap-allocate the obj shell (ngx_calloc), NOT from inst->pool. inst->pool is
     * ngx_cycle->pool — thread-UNSAFE and also allocated from by the main event
     * loop — but sd_posix_open runs in cache-fill worker threads too (a POSIX
     * cache origin is opened per fill). A pool alloc there races the main thread
     * and corrupts the pool -> SIGSEGV (confirmed via ThreadSanitizer). heap_shell
     * makes the adopting layer free this shell: the VFS frees it after copying
     * *obj by value (vfs_open.c adopt), and a pointer-holder (sd_cache/stage_engine
     * source objects) frees it at close via brix_sd_obj_release(). */
    obj = ngx_calloc(sizeof(*obj), inst->log);
    if (obj == NULL) {
        close(fd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    obj->driver = inst->driver;
    obj->inst = inst;
    obj->fd = fd;
    obj->heap_shell = 1;
    return obj;
}

/* sd_posix_close — close the handle fd (idempotent; the obj lives on the pool);
 * a close(2) error maps to NGX_ERROR. The VFS owns the close via brix_vfs_close. */
static ngx_int_t
sd_posix_close(brix_sd_obj_t *obj)
{
    if (obj == NULL || obj->fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }
    if (close(obj->fd) != 0) {
        obj->fd = NGX_INVALID_FILE;
        return NGX_ERROR;
    }
    obj->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

#endif /* !XRDPROTO_NO_NGX */

/* the driver descriptor.
 * POSIX advertises every capability: it is the full-featured reference backend
 * and the behaviour oracle for all others. In the ngx-free shared build only
 * the worker-safe raw fd ops are present (the namespace/instance/registry slots
 * are NULL and the matching caps are dropped), which is all a shared kernel
 * (checksum_core.c) ever calls — brix_sd_posix_driver.pread. */
const brix_sd_driver_t brix_sd_posix_driver = {
    .name = "posix",
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_SENDFILE
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_APPEND
          | BRIX_SD_CAP_IOURING
#ifndef XRDPROTO_NO_NGX
          | BRIX_SD_CAP_SERVER_COPY | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_DIRS
          | BRIX_SD_CAP_DIRS_WRITE | BRIX_SD_CAP_XATTR_WRITE
#endif
          ,

#ifndef XRDPROTO_NO_NGX
    .init = sd_posix_init,
    .cleanup = sd_posix_cleanup,
    .open = sd_posix_open,
    .close = sd_posix_close,
#endif
    .pread = sd_posix_pread,
    .pwrite = sd_posix_pwrite,
    .preadv = sd_posix_preadv,
    .preadv2 = sd_posix_preadv2,
    .copy_range = sd_posix_copy_range,
    .read_sendfile_fd = sd_posix_read_sendfile_fd,
    .ftruncate = sd_posix_ftruncate,
    .fsync = sd_posix_fsync,
    .fstat = sd_posix_fstat,
#ifndef XRDPROTO_NO_NGX
    .stat = sd_posix_stat,
    .unlink = sd_posix_unlink,
    .mkdir = sd_posix_mkdir,
    .rename = sd_posix_rename,
    .server_copy = sd_posix_server_copy,
    .opendir = sd_posix_opendir,
    .readdir = sd_posix_readdir,
    .closedir = sd_posix_closedir,
    .getxattr = sd_posix_getxattr,
    .listxattr = sd_posix_listxattr,
    .setxattr = sd_posix_setxattr,
    .removexattr = sd_posix_removexattr,
    .staged_open = sd_posix_staged_open,
    .staged_write = sd_posix_staged_write,
    .staged_commit = sd_posix_staged_commit,
    .staged_abort = sd_posix_staged_abort,
    .staged_path = sd_posix_staged_path,
#endif
};
