/*
 * sd_posix_ns.c — the POSIX Storage Driver's namespace/dir/xattr/staged ops.
 *
 * WHAT: The nginx-coupled vtable slots of brix_sd_posix_driver — stat/unlink/
 *       mkdir/rename/server_copy, directory iteration, xattr metadata, and the
 *       staged-write (temp + atomic rename) family — split VERBATIM out of
 *       sd_posix.c. The driver descriptor stays in sd_posix.c and references
 *       these via sd_posix_internal.h.
 *
 * WHY:  These ops delegate to the shared brix_ns_* / *_confined_canon /
 *       brix_staged_* helpers and only build in the module (they are guarded by
 *       !XRDPROTO_NO_NGX). Splitting them keeps every unit under the file-size
 *       cap with zero behaviour change.
 *
 * HOW:  Each op translates the brix_ns_result_t status to errno via
 *       brix_vfs_ns_status_errno() and builds root-absolute paths where the
 *       underlying helper works in absolute paths under root_canon.
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

#ifndef XRDPROTO_NO_NGX   /* namespace/dir/xattr/staged: confined paths + ns_* (module only) */
/* namespace ops — each delegates to the shared brix_ns_* helper and maps its
 * status to errno via brix_vfs_ns_status_errno(), preserving exact semantics. */

ngx_int_t
sd_posix_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_posix_state_t *st = inst->state;
    struct stat       sb;

    if (brix_lstat_beneath(st->rootfd, path, &sb) != 0) {
        return NGX_ERROR;
    }
    sd_posix_fill_stat(&sb, out);
    return NGX_OK;
}

/* sd_posix_ns_result — collapse a namespace result to NGX_OK, or set errno (prefer
 * sys_errno, else the status mapping for derived states) and return NGX_ERROR. */
static ngx_int_t
sd_posix_ns_result(brix_ns_result_t res)
{
    if (res.status == BRIX_NS_OK) {
        return NGX_OK;
    }
    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    return NGX_ERROR;
}

ngx_int_t
sd_posix_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_posix_state_t       *st = inst->state;
    brix_ns_delete_opts_t opts;
    char                    abspath[PATH_MAX];

    /* The vtable contract is a root-RELATIVE key (leading slash), matching
     * sd_posix_open/stat and the non-POSIX drivers. brix_ns_delete works in
     * ABSOLUTE paths under root_canon (strip_root), so build the absolute here. */
    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    ngx_memzero(&opts, sizeof(opts));
    opts.require_directory = is_dir ? 1 : 0;
    return sd_posix_ns_result(
        brix_ns_delete(inst->log, st->root_canon, abspath, &opts));
}

ngx_int_t
sd_posix_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_posix_state_t *st = inst->state;
    char              abspath[PATH_MAX];

    /* The vtable contract is a root-RELATIVE key; brix_ns_mkdir works in
     * ABSOLUTE paths under root_canon (strip_root), so build the absolute here
     * (matches sd_posix_unlink — the relative-path form silently failed). */
    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return sd_posix_ns_result(
        brix_ns_mkdir(inst->log, st->root_canon, abspath, mode, 0));
}

ngx_int_t
sd_posix_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_posix_state_t *st = inst->state;

    (void) noreplace;   /* overwrite_dirs=0: stock replace-file semantics */
    return sd_posix_ns_result(
        brix_ns_rename(inst->log, st->root_canon, src, dst, 0));
}

ngx_int_t
sd_posix_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    sd_posix_state_t     *st = inst->state;
    brix_ns_copy_opts_t opts;
    ngx_int_t             rc;

    ngx_memzero(&opts, sizeof(opts));
    opts.overwrite = 1;
    rc = sd_posix_ns_result(
        brix_ns_local_copy(inst->log, st->root_canon, src, dst, &opts));

    if (rc == NGX_OK && bytes_out != NULL) {
        struct stat sb;
        *bytes_out = (sd_posix_stat(inst, dst, &(brix_sd_stat_t){0}) == NGX_OK
                      && brix_lstat_beneath(st->rootfd, dst, &sb) == 0)
                         ? sb.st_size : 0;
    }
    return rc;
}

/* directory iteration */

/* Driver-private dir state: the fdopendir stream. */
typedef struct {
    DIR *dp;
} sd_posix_dir_t;

brix_sd_dir_t *
sd_posix_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_posix_state_t *st = inst->state;
    brix_sd_dir_t  *dir;
    sd_posix_dir_t   *pd;
    int               fd;
    DIR              *dp;

    fd = brix_open_beneath(st->rootfd, path, O_RDONLY | O_DIRECTORY, 0);
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

ngx_int_t
sd_posix_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
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

ngx_int_t
sd_posix_closedir(brix_sd_dir_t *d)
{
    sd_posix_dir_t *pd = d->state;

    if (pd != NULL && pd->dp != NULL) {
        closedir(pd->dp);
        pd->dp = NULL;
    }
    return NGX_OK;
}

/* xattr / metadata */

/* The vtable contract is a root-RELATIVE key; the *_confined_canon helpers work in
 * ABSOLUTE paths under root_canon (they strip root_canon), so build the absolute
 * here - matching sd_posix_unlink/mkdir. (The VFS reaches posix xattrs via the
 * canon helpers directly; these driver slots are used by cstore over a posix cache
 * store, where the relative-path form silently failed.) */
ssize_t
sd_posix_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_posix_state_t *st = inst->state;
    char              abspath[PATH_MAX];

    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    return brix_getxattr_confined_canon(inst->log, st->root_canon, abspath,
                                          name, buf, cap);
}

ssize_t
sd_posix_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_posix_state_t *st = inst->state;
    char              abspath[PATH_MAX];

    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    return brix_listxattr_confined_canon(inst->log, st->root_canon, abspath,
                                           buf, cap);
}

ngx_int_t
sd_posix_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_posix_state_t *st = inst->state;
    char              abspath[PATH_MAX];

    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return brix_setxattr_confined_canon(inst->log, st->root_canon, abspath,
                                          name, val, len, flags) == 0
               ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_posix_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_posix_state_t *st = inst->state;
    char              abspath[PATH_MAX];

    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, path) >= sizeof(abspath))
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return brix_removexattr_confined_canon(inst->log, st->root_canon, abspath,
                                             name) == 0
               ? NGX_OK : NGX_ERROR;
}

/* staged write (temp + atomic rename) */

/* Driver-private staged state: the compat primitive + final path. */
typedef struct {
    brix_staged_file_t staged;
    char                 final_path[PATH_MAX];
} sd_posix_staged_t;

brix_sd_staged_t *
sd_posix_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_posix_state_t   *st = inst->state;
    brix_sd_staged_t *handle;
    sd_posix_staged_t  *ps;
    char                abspath[PATH_MAX];

    /* Allocate the staged handle on the heap (ngx_calloc), NOT from inst->pool.
     * staged_open runs in a cache-fill thread-pool thread (brix_cache_fill_*),
     * but inst->pool is the shared, thread-UNSAFE backend pool the main thread
     * also allocates from (sd_posix_open/opendir). Concurrent fills racing on
     * inst->pool corrupt its `last` pointer -> a bad allocation whose memzero
     * SIGSEGVs. The handle + ps are freed explicitly in staged_commit /
     * staged_abort (the terminal ops — the driver vtable has no close). */
    handle = ngx_calloc(sizeof(*handle), inst->log);
    ps = ngx_calloc(sizeof(*ps), inst->log);
    if (handle == NULL || ps == NULL) {
        if (handle != NULL) { ngx_free(handle); }
        if (ps != NULL) { ngx_free(ps); }
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    /* The vtable contract is a root-RELATIVE key (leading slash), matching
     * sd_posix_open and the non-POSIX drivers' staged_open. brix_staged_open
     * (and _commit/_abort) work in ABSOLUTE paths under root_canon, so build the
     * absolute final path here and store it for commit/abort. */
    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, final_path) >= sizeof(abspath))
    {
        ngx_free(handle);
        ngx_free(ps);
        if (err_out != NULL) { *err_out = ENAMETOOLONG; }
        return NULL;
    }

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = st->root_canon,
            .final_path = abspath,
            .open_flags = O_WRONLY | O_CREAT | O_EXCL,
            .mode       = mode,
            .attempts   = 8,
        };
        if (brix_staged_open(inst->log, &oreq, &ps->staged) != NGX_OK) {
            ngx_free(handle);
            ngx_free(ps);
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
    }

    ngx_cpystrn((u_char *) ps->final_path, (u_char *) abspath,
                sizeof(ps->final_path));
    handle->inst = inst;
    handle->state = ps;
    return handle;
}

ssize_t
sd_posix_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    sd_posix_staged_t *ps = st->state;

    if (brix_vfs_pwrite_full(ps->staged.fd, buf, len, off) != NGX_OK) {
        return -1;
    }
    return (ssize_t) len;
}

ngx_int_t
sd_posix_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;
    ngx_int_t          rc;

    rc = noreplace
        ? brix_staged_commit_excl(st->inst->log, inst_st->root_canon,
                                    &ps->staged, ps->final_path)
        : brix_staged_commit(st->inst->log, inst_st->root_canon,
                               &ps->staged, ps->final_path);
    /* Terminal op — release the heap-allocated handle (see staged_open). */
    ngx_free(ps);
    ngx_free(st);
    return rc;
}

void
sd_posix_staged_abort(brix_sd_staged_t *st)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;

    brix_staged_abort(st->inst->log, inst_st->root_canon, &ps->staged, 1);
    /* Terminal op — release the heap-allocated handle (see staged_open). */
    ngx_free(ps);
    ngx_free(st);
}

/* Physical staged-temp path — lets the cache tier digest-verify a fill (and
 * quarantine a mismatch) before commit (phase-68). */
const char *
sd_posix_staged_path(const brix_sd_staged_t *st)
{
    const sd_posix_staged_t *ps = st->state;

    return (ps != NULL && ps->staged.tmp_path[0] != '\0') ? ps->staged.tmp_path
                                                          : NULL;
}

#endif /* !XRDPROTO_NO_NGX */
