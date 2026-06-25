/*
 * sd_posix.c — the POSIX Storage Driver: a behaviour-preserving wrapper.
 *
 * WHAT: Implements xrootd_sd_posix_driver, the default backend. Every vtable
 *       slot delegates to an EXISTING confined helper (xrootd_open_beneath,
 *       xrootd_vfs_pread_full/pwrite_full, xrootd_ns_*, xrootd_lstat_beneath,
 *       the *xattr_confined_canon family, xrootd_staged_*), so the POSIX path
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
 *       xrootd_ns_result_t status to errno via xrootd_vfs_ns_status_errno().
 */

#include "sd.h"

#include "../vfs_internal.h"          /* pread_full/pwrite_full + ns_status_errno */
#include "../../compat/crc32c.h"
#include "../../compat/namespace_ops.h"
#include "../../compat/staged_file.h"
#include "../../path/beneath.h"
#include "../../path/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Driver-private instance state. */
typedef struct {
    int       rootfd;        /* persistent O_PATH fd on root_canon, or -1 */
    char     *root_canon;    /* pool-owned copy (or borrowed when borrowed=1) */
    unsigned  borrowed:1;    /* rootfd/root_canon are owned by the caller's conf:
                              * cleanup must NOT close the fd or free the string */
} sd_posix_state_t;

/* ---- sd_posix_flags — map SD open flags to POSIX O_* -----------------------
 *
 * WHAT: Translates the backend-neutral XROOTD_SD_O_* bits to an open(2) flag set.
 * WHY:  The vtable open() speaks SD flags; only the POSIX driver knows O_*.
 * HOW:  OR in the corresponding O_* bit per SD flag; default read-only.
 */
static int
sd_posix_flags(int sd_flags)
{
    int flags = 0;

    if ((sd_flags & XROOTD_SD_O_WRITE) && (sd_flags & XROOTD_SD_O_READ)) {
        flags = O_RDWR;
    } else if (sd_flags & XROOTD_SD_O_WRITE) {
        flags = O_WRONLY;
    } else {
        flags = O_RDONLY;
    }

    if (sd_flags & XROOTD_SD_O_CREATE) { flags |= O_CREAT; }
    if (sd_flags & XROOTD_SD_O_EXCL)   { flags |= O_EXCL; }
    if (sd_flags & XROOTD_SD_O_TRUNC)  { flags |= O_TRUNC; }
    if (sd_flags & XROOTD_SD_O_APPEND) { flags |= O_APPEND; }
    if (sd_flags & XROOTD_SD_O_DIR)    { flags |= O_DIRECTORY; }

    return flags;
}

/* ---- sd_posix_fill_stat — struct stat -> xrootd_sd_stat_t ------------------
 *
 * WHAT: Copies the protocol-neutral fields out of a struct stat.
 * WHY:  The VFS consumes xrootd_sd_stat_t, never a raw struct stat.
 * HOW:  Zero *out, copy size/times/mode/ino, derive is_dir/is_reg from mode.
 */
static void
sd_posix_fill_stat(const struct stat *st, xrootd_sd_stat_t *out)
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

/* ---- sd_posix_init — open the persistent rootfd ---------------------------
 *
 * WHAT: Stores the root_canon and opens its O_PATH anchor fd on the instance.
 * WHY:  The beneath API needs a persistent rootfd per worker for hot opens.
 * HOW:  pcalloc a state struct, copy the root_canon, open the rootfd.
 */
static ngx_int_t
sd_posix_init(xrootd_sd_instance_t *inst, void *driver_conf)
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

    st->rootfd = xrootd_beneath_open_root(root_canon);  /* -1 tolerated */
    inst->state = st;
    return NGX_OK;
}

/* ---- sd_posix_cleanup — close the rootfd ----------------------------------
 *
 * WHAT: Closes the persistent rootfd; the pool reclaims the state struct.
 * WHY:  An O_PATH fd is a kernel resource that must not leak on reconfig.
 * HOW:  Close rootfd if open and mark it closed.
 */
static void
sd_posix_cleanup(xrootd_sd_instance_t *inst)
{
    sd_posix_state_t *st = inst->state;

    if (st != NULL && !st->borrowed && st->rootfd >= 0) {
        close(st->rootfd);
        st->rootfd = -1;
    }
}

/* ---- xrootd_sd_posix_borrow_instance — wrap an existing rootfd as a POSIX inst
 *
 * WHAT: Builds a pool-lived POSIX instance whose confinement anchor BORROWS an
 *       already-open persistent rootfd (and root_canon) owned by the caller's
 *       config — it does not open or close that fd. Returns NULL (errno set) for
 *       rootfd < 0 (the borrow path is only for the persistent-rootfd hot path)
 *       or on OOM.
 *
 * WHY:  Lets the VFS route its hot-path confined open through driver->open
 *       without a second openat() per request and without transferring fd
 *       ownership to the transient instance (cleanup skips a borrowed fd).
 *
 * HOW:  pcalloc the instance + state, store the borrowed rootfd/root_canon, set
 *       the borrowed flag, and bind the POSIX driver.
 */
xrootd_sd_instance_t *
xrootd_sd_posix_borrow_instance(ngx_pool_t *pool, ngx_log_t *log, int rootfd,
    const char *root_canon)
{
    xrootd_sd_instance_t *inst;
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
    inst->driver = &xrootd_sd_posix_driver;
    inst->log = log;
    inst->pool = pool;
    inst->state = st;
    return inst;
}

/* ---- sd_posix_open — confined open into an object handle -------------------
 *
 * WHAT: Opens path under RESOLVE_BENEATH and returns an object carrying the fd.
 * WHY:  This is the POSIX realization of the VFS open cascade's beneath branch.
 *       It does NOT stat the fd — metadata is a separate concern obtained via
 *       the fstat slot, so a caller that does not need it pays no syscall (the
 *       VFS open path fstats once in adopt_fd; a pre-open stat here would be a
 *       redundant second one).
 * HOW:  xrootd_open_beneath -> pcalloc obj carrying driver + instance + fd.
 */
static xrootd_sd_obj_t *
sd_posix_open(xrootd_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_posix_state_t *st = inst->state;
    xrootd_sd_obj_t  *obj;
    int               fd;

    fd = xrootd_open_beneath(st->rootfd, path, sd_posix_flags(sd_flags), mode);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    obj = ngx_pcalloc(inst->pool, sizeof(*obj));
    if (obj == NULL) {
        close(fd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    obj->driver = inst->driver;
    obj->inst = inst;
    obj->fd = fd;
    return obj;
}

/* ---- sd_posix_close — close the object fd ---------------------------------
 *
 * WHAT: Closes the handle fd (idempotent); the obj struct lives on the pool.
 * WHY:  Symmetry with open; the VFS owns the close via xrootd_vfs_close.
 * HOW:  close fd if valid, mark invalid, map a close error to NGX_ERROR.
 */
static ngx_int_t
sd_posix_close(xrootd_sd_obj_t *obj)
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

/* ---- worker-safe raw byte I/O (no pool/metrics/log) ----------------------- */

/* ---- sd_posix_pread — single pread(2) primitive ---------------------------
 * WHAT: One pread(2) at off; returns bytes read (0 = EOF), or -1 (errno set).
 * WHY:  The raw storage primitive. The VFS owns the EINTR/short-read loop
 *       (xrootd_vfs_pread_full), which calls this once per iteration, so all
 *       VFS reads funnel through the Storage Driver without changing semantics.
 * HOW:  Return pread(obj->fd, ...) verbatim.
 */
static ssize_t
sd_posix_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

/* ---- sd_posix_pwrite — single pwrite(2) primitive -------------------------
 * WHAT: One pwrite(2) at off; returns bytes written, or -1 (errno set).
 * WHY:  The raw storage primitive. The VFS owns the EINTR/short-write loops
 *       (xrootd_vfs_pwrite_full, xrootd_vfs_io_write_counted), which call this
 *       once per iteration, so all VFS writes funnel through the driver.
 * HOW:  Return pwrite(obj->fd, ...) verbatim.
 */
static ssize_t
sd_posix_pwrite(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    return pwrite(obj->fd, buf, len, off);
}

/* ---- sd_posix_preadv — single preadv(2) primitive -------------------------
 * WHAT: One preadv(2) of iovcnt segments at off; returns bytes read or -1.
 * WHY:  The raw vectored-read primitive behind kXR_readv coalescing and the
 *       kXR_pgread batch reader. The VFS owns the EINTR loop and the coalescing
 *       policy; this routes the syscall through the Storage Driver.
 * HOW:  Return preadv(obj->fd, ...) verbatim.
 */
static ssize_t
sd_posix_preadv(xrootd_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    return preadv(obj->fd, iov, iovcnt, off);
}

/* ---- sd_posix_preadv2 — single preadv2(2) primitive (flags) ---------------
 * WHAT: One preadv2(2) of iovcnt segments at off with flags (e.g. RWF_NOWAIT);
 *       returns bytes read or -1. WHY: the kXR_read warm-cache probe needs a
 *       non-blocking page-cache read through the Storage Driver. HOW: verbatim.
 */
static ssize_t
sd_posix_preadv2(xrootd_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    return preadv2(obj->fd, iov, iovcnt, off, flags);
}

/* ---- sd_posix_copy_range — single copy_file_range(2) primitive ------------
 * WHAT: One copy_file_range(2) of up to len bytes src->dst; returns bytes
 *       copied (0 = EOF), or -1 (errno; ENOSYS where unavailable). The VFS owns
 *       the loop and the pread/pwrite fallback. WHY: route the server-side
 *       zero-copy primitive through the Storage Driver. HOW: the raw syscall.
 */
static ssize_t
sd_posix_copy_range(xrootd_sd_obj_t *src, off_t src_off, xrootd_sd_obj_t *dst,
    off_t dst_off, size_t len)
{
#if defined(__linux__) && defined(__NR_copy_file_range)
    loff_t si = (loff_t) src_off;
    loff_t di = (loff_t) dst_off;

    return (ssize_t) syscall(__NR_copy_file_range, src->fd, &si, dst->fd, &di,
                             len, 0u);
#else
    (void) src; (void) src_off; (void) dst; (void) dst_off; (void) len;
    errno = ENOSYS;
    return -1;
#endif
}

/* ---- sd_posix_read_sendfile_fd — POSIX sendfile decision -------------------
 * WHAT: Returns the object's kernel fd when the caller will accept a zero-copy
 *       transfer (want_zerocopy), else NGX_INVALID_FILE. WHY: POSIX files are
 *       seekable kernel fds, so any byte range is sendfile-able whenever the
 *       transport permits zero-copy; the backend, not the VFS, makes this call.
 *       HOW: gate on want_zerocopy and a valid fd; offset/len are irrelevant for
 *       a plain file (they matter only to backends with alignment/residency
 *       constraints).
 */
static ngx_fd_t
sd_posix_read_sendfile_fd(xrootd_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) off;
    (void) len;

    if (!want_zerocopy || obj->fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    return obj->fd;
}

/* ---- sd_posix_ftruncate / _fsync / _fstat — direct fd ops ----------------- */
static ngx_int_t
sd_posix_ftruncate(xrootd_sd_obj_t *obj, off_t len)
{
    return ftruncate(obj->fd, len) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_posix_fsync(xrootd_sd_obj_t *obj)
{
    return fsync(obj->fd) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_posix_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    sd_posix_fill_stat(&sb, out);
    return NGX_OK;
}

/* ---- namespace ops --------------------------------------------------------
 * Each delegates to the shared xrootd_ns_* helper and maps its status to errno
 * via xrootd_vfs_ns_status_errno(), preserving today's exact error semantics. */

static ngx_int_t
sd_posix_stat(xrootd_sd_instance_t *inst, const char *path,
    xrootd_sd_stat_t *out)
{
    sd_posix_state_t *st = inst->state;
    struct stat       sb;

    if (xrootd_lstat_beneath(st->rootfd, path, &sb) != 0) {
        return NGX_ERROR;
    }
    sd_posix_fill_stat(&sb, out);
    return NGX_OK;
}

/* ---- sd_posix_ns_result — collapse a namespace result to NGX_OK/ERROR ------
 * WHAT: Returns NGX_OK on XROOTD_NS_OK, else sets errno and returns NGX_ERROR.
 * WHY:  Every namespace slot shares the same status->errno collapse.
 * HOW:  Prefer sys_errno; fall back to the status mapping for derived states.
 */
static ngx_int_t
sd_posix_ns_result(xrootd_ns_result_t res)
{
    if (res.status == XROOTD_NS_OK) {
        return NGX_OK;
    }
    errno = res.sys_errno != 0 ? res.sys_errno
                               : xrootd_vfs_ns_status_errno(res.status);
    return NGX_ERROR;
}

static ngx_int_t
sd_posix_unlink(xrootd_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_posix_state_t       *st = inst->state;
    xrootd_ns_delete_opts_t opts;

    ngx_memzero(&opts, sizeof(opts));
    opts.require_directory = is_dir ? 1 : 0;
    return sd_posix_ns_result(
        xrootd_ns_delete(inst->log, st->root_canon, path, &opts));
}

static ngx_int_t
sd_posix_mkdir(xrootd_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_posix_state_t *st = inst->state;

    return sd_posix_ns_result(
        xrootd_ns_mkdir(inst->log, st->root_canon, path, mode, 0));
}

static ngx_int_t
sd_posix_rename(xrootd_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_posix_state_t *st = inst->state;

    (void) noreplace;   /* overwrite_dirs=0: stock replace-file semantics */
    return sd_posix_ns_result(
        xrootd_ns_rename(inst->log, st->root_canon, src, dst, 0));
}

static ngx_int_t
sd_posix_server_copy(xrootd_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    sd_posix_state_t     *st = inst->state;
    xrootd_ns_copy_opts_t opts;
    ngx_int_t             rc;

    ngx_memzero(&opts, sizeof(opts));
    opts.overwrite = 1;
    rc = sd_posix_ns_result(
        xrootd_ns_local_copy(inst->log, st->root_canon, src, dst, &opts));

    if (rc == NGX_OK && bytes_out != NULL) {
        struct stat sb;
        *bytes_out = (sd_posix_stat(inst, dst, &(xrootd_sd_stat_t){0}) == NGX_OK
                      && xrootd_lstat_beneath(st->rootfd, dst, &sb) == 0)
                         ? sb.st_size : 0;
    }
    return rc;
}

/* ---- directory iteration -------------------------------------------------- */

/* Driver-private dir state: the fdopendir stream. */
typedef struct {
    DIR *dp;
} sd_posix_dir_t;

static xrootd_sd_dir_t *
sd_posix_opendir(xrootd_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_posix_state_t *st = inst->state;
    xrootd_sd_dir_t  *dir;
    sd_posix_dir_t   *pd;
    int               fd;
    DIR              *dp;

    fd = xrootd_open_beneath(st->rootfd, path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    dp = fdopendir(fd);
    if (dp == NULL) {
        if (err_out != NULL) { *err_out = errno; }
        close(fd);
        return NULL;
    }

    dir = ngx_pcalloc(inst->pool, sizeof(*dir));
    pd = ngx_pcalloc(inst->pool, sizeof(*pd));
    if (dir == NULL || pd == NULL) {
        closedir(dp);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    pd->dp = dp;
    dir->inst = inst;
    dir->state = pd;
    return dir;
}

static ngx_int_t
sd_posix_readdir(xrootd_sd_dir_t *d, xrootd_sd_dirent_t *out)
{
    sd_posix_dir_t *pd = d->state;
    struct dirent  *de;

    for ( ;; ) {
        errno = 0;
        de = readdir(pd->dp);
        if (de == NULL) {
            return errno != 0 ? NGX_ERROR : NGX_DONE;
        }
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;   /* skip "." and ".." */
        }
        ngx_cpystrn((u_char *) out->name, (u_char *) de->d_name,
                    sizeof(out->name));
        return NGX_OK;
    }
}

static ngx_int_t
sd_posix_closedir(xrootd_sd_dir_t *d)
{
    sd_posix_dir_t *pd = d->state;

    if (pd != NULL && pd->dp != NULL) {
        closedir(pd->dp);
        pd->dp = NULL;
    }
    return NGX_OK;
}

/* ---- xattr / metadata ----------------------------------------------------- */

static ssize_t
sd_posix_getxattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_posix_state_t *st = inst->state;

    return xrootd_getxattr_confined_canon(inst->log, st->root_canon, path,
                                          name, buf, cap);
}

static ssize_t
sd_posix_listxattr(xrootd_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_posix_state_t *st = inst->state;

    return xrootd_listxattr_confined_canon(inst->log, st->root_canon, path,
                                           buf, cap);
}

static ngx_int_t
sd_posix_setxattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_posix_state_t *st = inst->state;

    return xrootd_setxattr_confined_canon(inst->log, st->root_canon, path,
                                          name, val, len, flags) == 0
               ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_posix_removexattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_posix_state_t *st = inst->state;

    return xrootd_removexattr_confined_canon(inst->log, st->root_canon, path,
                                             name) == 0
               ? NGX_OK : NGX_ERROR;
}

/* ---- staged write (temp + atomic rename) ---------------------------------- */

/* Driver-private staged state: the compat primitive + final path. */
typedef struct {
    xrootd_staged_file_t staged;
    char                 final_path[PATH_MAX];
} sd_posix_staged_t;

static xrootd_sd_staged_t *
sd_posix_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_posix_state_t   *st = inst->state;
    xrootd_sd_staged_t *handle;
    sd_posix_staged_t  *ps;

    handle = ngx_pcalloc(inst->pool, sizeof(*handle));
    ps = ngx_pcalloc(inst->pool, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (xrootd_staged_open(inst->log, st->root_canon, final_path,
                           O_WRONLY | O_CREAT | O_EXCL, mode, 8, &ps->staged)
        != NGX_OK)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    ngx_cpystrn((u_char *) ps->final_path, (u_char *) final_path,
                sizeof(ps->final_path));
    handle->inst = inst;
    handle->state = ps;
    return handle;
}

static ssize_t
sd_posix_staged_write(xrootd_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    sd_posix_staged_t *ps = st->state;

    if (xrootd_vfs_pwrite_full(ps->staged.fd, buf, len, off) != NGX_OK) {
        return -1;
    }
    return (ssize_t) len;
}

static ngx_int_t
sd_posix_staged_commit(xrootd_sd_staged_t *st, int noreplace)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;

    return noreplace
        ? xrootd_staged_commit_excl(st->inst->log, inst_st->root_canon,
                                    &ps->staged, ps->final_path)
        : xrootd_staged_commit(st->inst->log, inst_st->root_canon,
                               &ps->staged, ps->final_path);
}

static void
sd_posix_staged_abort(xrootd_sd_staged_t *st)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;

    xrootd_staged_abort(st->inst->log, inst_st->root_canon, &ps->staged, 1);
}

/* ---- the driver descriptor ------------------------------------------------
 * POSIX advertises every capability: it is the full-featured reference backend
 * and the behaviour oracle for all others. */
const xrootd_sd_driver_t xrootd_sd_posix_driver = {
    .name = "posix",
    .caps = XROOTD_SD_CAP_FD | XROOTD_SD_CAP_SENDFILE
          | XROOTD_SD_CAP_RANDOM_WRITE | XROOTD_SD_CAP_RANGE_READ
          | XROOTD_SD_CAP_TRUNCATE | XROOTD_SD_CAP_SERVER_COPY
          | XROOTD_SD_CAP_XATTR | XROOTD_SD_CAP_HARD_RENAME
          | XROOTD_SD_CAP_DIRS | XROOTD_SD_CAP_APPEND | XROOTD_SD_CAP_IOURING,

    .init = sd_posix_init,
    .cleanup = sd_posix_cleanup,
    .open = sd_posix_open,
    .close = sd_posix_close,
    .pread = sd_posix_pread,
    .pwrite = sd_posix_pwrite,
    .preadv = sd_posix_preadv,
    .preadv2 = sd_posix_preadv2,
    .copy_range = sd_posix_copy_range,
    .read_sendfile_fd = sd_posix_read_sendfile_fd,
    .ftruncate = sd_posix_ftruncate,
    .fsync = sd_posix_fsync,
    .fstat = sd_posix_fstat,
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
};
