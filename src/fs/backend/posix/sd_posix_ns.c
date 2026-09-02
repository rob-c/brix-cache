/*
 * sd_posix_ns.c — the POSIX Storage Driver's namespace/dir/xattr ops.
 *
 * WHAT: The nginx-coupled vtable slots of brix_sd_posix_driver — stat/unlink/
 *       mkdir/rename/server_copy, directory iteration and xattr metadata —
 *       split VERBATIM out of sd_posix.c. The staged-write family moved on to
 *       sd_posix_staged.c (phase-107 C6). The driver descriptor stays in
 *       sd_posix.c and references these via sd_posix_internal.h.
 *
 * WHY:  These ops delegate to the shared brix_ns_* / *_confined_canon
 *       helpers and only build in the module (they are guarded by
 *       !XRDPROTO_NO_NGX). Splitting them keeps every unit under the file-size
 *       cap with zero behaviour change.
 *
 * HOW:  Each op translates the brix_ns_result_t status to errno via
 *       brix_vfs_ns_status_errno() and builds root-absolute paths where the
 *       underlying helper works in absolute paths under root_canon.
 */

#include "fs/backend/sd.h"

/* The instance lifecycle + namespace/dir/xattr ops below are nginx-coupled
 * (confined open, ngx pool, the shared brix_ns_* helpers). They — and these
 * headers — compile only in the module. The worker-safe raw fd byte ops
 * (pread/pwrite/preadv/...) are pure POSIX and also build into the ngx-free
 * shared libxrdproto, so a shared kernel (src/compat/checksum_core.c) can route
 * its fd reads through brix_sd_posix_driver in both worlds. */
#ifndef XRDPROTO_NO_NGX
#include "fs/vfs/vfs_internal.h"          /* pread_full/pwrite_full + ns_status_errno */
#include "core/compat/crc32c.h"
#include "core/compat/namespace_ops.h"
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

#ifndef XRDPROTO_NO_NGX   /* namespace/dir/xattr: confined paths + ns_* (module only) */
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

/* sd_posix_abs_key — materialise the vtable's root-RELATIVE key (leading
 * slash, matching sd_posix_open/stat and the non-POSIX drivers) as the
 * ABSOLUTE path under root_canon that the brix_ns_* / *_confined_canon
 * helpers take (they strip root_canon; the relative form silently failed).
 * Returns root_canon for the helper call that follows, or NULL with errno
 * ENAMETOOLONG when the key does not fit. */
static const char *
sd_posix_abs_key(brix_sd_instance_t *inst, const char *path, char *abs,
    size_t cap)
{
    sd_posix_state_t *st = inst->state;

    if ((size_t) snprintf(abs, cap, "%s%s", st->root_canon, path) >= cap) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return st->root_canon;
}

ngx_int_t
sd_posix_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    brix_ns_delete_opts_t opts;
    sd_posix_state_t       *st;
    char                    abspath[PATH_MAX];
    const char             *root;

    root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));
    if (root == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(&opts, sizeof(opts));
    opts.require_directory = is_dir ? 1 : 0;

    st = inst->state;
    if (st->rootfd >= 0) {
        /* Borrow the driver's persistent confinement rootfd: same beneath
         * semantics, minus a root open/close per delete. */
        return sd_posix_ns_result(
            brix_ns_delete_at(inst->log, st->rootfd, root, abspath, &opts));
    }
    return sd_posix_ns_result(
        brix_ns_delete(inst->log, root, abspath, &opts));
}

/* WHAT: Apply a metadata mutation (mode / times / owner) to `path`, kernel-
 *       confined under the export root.
 * WHY:  The setattr slot was unimplemented for the default POSIX driver, so a
 *       tier decorator's metadata fixup (sd_stage hydration forcing the write
 *       spool owner-rw, sd_cache's forward) silently no-opped on a posix
 *       store; kXR_setattr parity for driver-backed exports needs it too.
 * HOW:  Root-relative key -> absolute path (the unlink/mkdir convention), then
 *       the existing confined helpers: brix_chmod_confined_canon for set_mode,
 *       brix_setattr_confined_canon for set_times/set_owner. First failure
 *       returns NGX_ERROR with errno left set. */
ngx_int_t
sd_posix_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    char        abspath[PATH_MAX];
    const char *root;

    root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));
    if (root == NULL) {
        return NGX_ERROR;
    }
    if (attr->set_mode
        && brix_chmod_confined_canon(inst->log, root, abspath,
                                       attr->mode & 07777) != 0)
    {
        return NGX_ERROR;
    }
    if (attr->set_times || attr->set_owner) {
        struct timespec times[2];

        times[0] = attr->atime;
        times[1] = attr->mtime;
        if (brix_setattr_confined_canon(inst->log, root, abspath,
                attr->set_times ? 1 : 0, times,
                attr->set_owner ? 1 : 0, attr->uid, attr->gid) != 0)
        {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

ngx_int_t
sd_posix_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_posix_state_t *st;
    char              abspath[PATH_MAX];
    const char       *root;

    root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));
    if (root == NULL) {
        return NGX_ERROR;
    }

    st = inst->state;
    if (st->rootfd >= 0) {
        /* Borrowed persistent rootfd — see sd_posix_unlink. */
        return sd_posix_ns_result(
            brix_ns_mkdir_at(inst->log, st->rootfd, root, abspath, mode, 0));
    }
    return sd_posix_ns_result(
        brix_ns_mkdir(inst->log, root, abspath, mode, 0));
}

ngx_int_t
sd_posix_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    char        abssrc[PATH_MAX];
    char        absdst[PATH_MAX];
    const char *root;

    (void) noreplace;   /* overwrite_dirs=0: stock replace-file semantics */

    /* brix_ns_rename refuses anything outside root_canon as a cross-root
     * move (EXDEV), so both endpoints go absolute. */
    root = sd_posix_abs_key(inst, src, abssrc, sizeof(abssrc));
    if (root == NULL
        || sd_posix_abs_key(inst, dst, absdst, sizeof(absdst)) == NULL)
    {
        return NGX_ERROR;
    }
    return sd_posix_ns_result(
        brix_ns_rename(inst->log, root, abssrc, absdst, 0));
}

/* Atomic two-name exchange (phase-107 C6): renameat2(RENAME_EXCHANGE) via the
 * confined beneath helper — both keys resolve under rootfd, both must exist
 * (ENOENT otherwise), and a kernel/filesystem without the flag reports
 * ENOTSUP, never a two-rename emulation (sd.h contract, §3.5). */
ngx_int_t
sd_posix_exchange(brix_sd_instance_t *inst, const char *a, const char *b)
{
    sd_posix_state_t *st = inst->state;

    return brix_exchange_beneath(st->rootfd, a, b) == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_posix_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    sd_posix_state_t     *st = inst->state;
    brix_ns_copy_opts_t   opts;
    char                  abssrc[PATH_MAX];
    char                  absdst[PATH_MAX];
    ngx_int_t             rc;

    /* Same contract as sd_posix_rename: the vtable key is root-RELATIVE, but
     * brix_ns_local_copy strips root_canon off ABSOLUTE paths and treats a
     * non-match as a cross-root copy (EXDEV).  Handing it the relative form
     * failed every server-side COPY on a driver-backed export — WebDAV COPY
     * answered 403 and S3 CopyObject 500 — while a plain export (NULL driver,
     * VFS namespace path) worked, which is why it went unnoticed. */
    if (sd_posix_abs_key(inst, src, abssrc, sizeof(abssrc)) == NULL
        || sd_posix_abs_key(inst, dst, absdst, sizeof(absdst)) == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.overwrite = 1;
    rc = sd_posix_ns_result(
        brix_ns_local_copy(inst->log, st->root_canon, abssrc, absdst, &opts));

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
        /* The kernel's own classification, DT_UNKNOWN on filesystems that
         * don't fill it — never guessed here (consumers stat on UNKNOWN). */
        out->d_type = de->d_type;
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

/* The VFS reaches posix xattrs via the canon helpers directly; these driver
 * slots are used by cstore over a posix cache store, where the relative-path
 * form silently failed — hence the sd_posix_abs_key derivation. */
ssize_t
sd_posix_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    char        abspath[PATH_MAX];
    const char *root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));

    return root == NULL
               ? -1
               : brix_getxattr_confined_canon(inst->log, root, abspath,
                                                name, buf, cap);
}

ssize_t
sd_posix_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    char        abspath[PATH_MAX];
    const char *root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));

    return root == NULL
               ? -1
               : brix_listxattr_confined_canon(inst->log, root, abspath,
                                                 buf, cap);
}

ngx_int_t
sd_posix_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    char        abspath[PATH_MAX];
    const char *root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));

    return root != NULL
                   && brix_setxattr_confined_canon(inst->log, root, abspath,
                                                     name, val, len, flags) == 0
               ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_posix_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    char        abspath[PATH_MAX];
    const char *root = sd_posix_abs_key(inst, path, abspath, sizeof(abspath));

    return root != NULL
                   && brix_removexattr_confined_canon(inst->log, root, abspath,
                                                        name) == 0
               ? NGX_OK : NGX_ERROR;
}

/* Durable-publish barrier (phase-107 C3): fsync the parent directory of the
 * just-published `path` so the NAME survives a crash, not just the bytes.
 * Routed through brix_publish_dirsync — the same confined derivation the
 * staged commit uses — anchored on this instance's persistent rootfd (or a
 * transient one when the instance carries none). */
ngx_int_t
sd_posix_sync_publish(brix_sd_instance_t *inst, const char *path)
{
    sd_posix_state_t *st = inst->state;

    return brix_publish_dirsync(inst->log, st->rootfd, st->root_canon, path);
}

#endif /* !XRDPROTO_NO_NGX */
