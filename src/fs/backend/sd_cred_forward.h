/*
 * sd_cred_forward.h — credential-scoped open + namespace forwarders for the
 *                     Storage Driver seam.
 *
 * A verbatim relocation of the brix_sd_*_maybe_cred inline forwarders out of
 * sd.h (pure textual split to keep every SD header < 600 LOC). These inlines
 * dereference the full brix_sd_instance_t / brix_sd_driver_t definitions, so
 * this header is a transitive fragment of sd.h and is included from there AFTER
 * those structs are defined — never on its own. The include guard and <errno.h>
 * pull-in below keep it self-consistent; all SD types + ngx macros come from the
 * sd.h include site. Do NOT include this header directly — include "sd.h".
 */
#ifndef BRIX_SD_CRED_FORWARD_H
#define BRIX_SD_CRED_FORWARD_H

#include <errno.h>       /* errno/ENOSYS/EACCES in the *_maybe_cred fallbacks */

/* ---- credential-scoped open forwarders ----
 * WHAT: Route through the cred-scoped slot when a per-user credential is
 *       present AND the driver implements it; else the plain slot.
 * WHY:  One forwarding rule shared by the VFS and every decorator, so no
 *       tier can accidentally drop the credential on the floor.
 * HOW:  cred+slot → *_cred; otherwise the legacy slot — UNLESS the caller is
 *       in DENY mode (cred->fallback_deny) and the plain slot would actually
 *       run (driver-><op> != NULL): that combination means a per-user op
 *       would silently execute on the shared service credential in a mode
 *       that explicitly forbids the fallback, so refuse instead (EACCES).
 *       Defensive hardening (phase-3 T1): today inert (no driver has the
 *       cred-slot-missing/plain-slot-present shape), but prevents a future
 *       driver from silently leaking onto the service credential. Does NOT
 *       change allow-mode (fallback_deny==0 keeps falling back) or the
 *       legitimate no-op cases (a NULL plain slot with no *_cred slot either
 *       means "this driver has nothing to do here", not a leak). */
static ngx_inline brix_sd_obj_t *
brix_sd_open_maybe_cred(brix_sd_instance_t *inst, const char *path,
    int sd_flags, mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    if (cred != NULL && inst->driver->open_cred != NULL) {
        return inst->driver->open_cred(inst, path, sd_flags, mode, cred,
                                       err_out);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->open_cred == NULL && inst->driver->open != NULL)
    {
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        errno = EACCES;
        return NULL;
    }
    if (inst->driver->open == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        errno = ENOSYS;
        return NULL;
    }
    return inst->driver->open(inst, path, sd_flags, mode, err_out);
}

static ngx_inline brix_sd_staged_t *
brix_sd_staged_open_maybe_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    if (cred != NULL && inst->driver->staged_open_cred != NULL) {
        return inst->driver->staged_open_cred(inst, final_path, mode, cred,
                                              err_out);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->staged_open_cred == NULL
        && inst->driver->staged_open != NULL)
    {
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        errno = EACCES;
        return NULL;
    }
    if (inst->driver->staged_open == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        errno = ENOSYS;
        return NULL;
    }
    return inst->driver->staged_open(inst, final_path, mode, err_out);
}

/* ---- credential-scoped namespace forwarders --------------------------------
 *
 * WHAT: Route each namespace op through the cred-scoped slot when a per-user
 *       credential is present AND the driver implements the matching *_cred slot;
 *       otherwise fall back to the plain slot.
 *
 * WHY:  A single forwarding rule for each namespace op ensures no tier can
 *       accidentally drop the credential for stat/unlink/mkdir/rename/copy/
 *       setattr/xattr/opendir — the same guarantee brix_sd_open_maybe_cred
 *       provides for data-plane opens.
 *
 * HOW:  cred non-NULL and driver has the *_cred slot → the cred slot;
 *       otherwise the plain slot (or NULL-safe ENOSYS for ops with no plain
 *       slot either — callers always check NULL before dispatching). */

static ngx_inline ngx_int_t
brix_sd_stat_maybe_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->stat_cred != NULL) {
        return inst->driver->stat_cred(inst, path, out, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->stat_cred == NULL && inst->driver->stat != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->stat == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->stat(inst, path, out);
}

static ngx_inline ngx_int_t
brix_sd_unlink_maybe_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->unlink_cred != NULL) {
        return inst->driver->unlink_cred(inst, path, is_dir, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->unlink_cred == NULL && inst->driver->unlink != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->unlink == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->unlink(inst, path, is_dir);
}

static ngx_inline ngx_int_t
brix_sd_mkdir_maybe_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->mkdir_cred != NULL) {
        return inst->driver->mkdir_cred(inst, path, mode, cred);
    }
    if (inst->driver->mkdir == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    if (cred != NULL && cred->fallback_deny && inst->driver->mkdir_cred == NULL) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return inst->driver->mkdir(inst, path, mode);
}

static ngx_inline ngx_int_t
brix_sd_rename_maybe_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->rename_cred != NULL) {
        return inst->driver->rename_cred(inst, src, dst, noreplace, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->rename_cred == NULL && inst->driver->rename != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->rename == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->rename(inst, src, dst, noreplace);
}

static ngx_inline ngx_int_t
brix_sd_setattr_maybe_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->setattr_cred != NULL) {
        return inst->driver->setattr_cred(inst, path, attr, cred);
    }
    if (inst->driver->setattr == NULL) {
        return NGX_OK;   /* no mutable metadata — no-op success, same as plain path */
    }
    /* A per-user op in deny mode must never silently run the REAL (mutable-
     * metadata) setattr on the service credential; refuse (mirrors the other
     * *_maybe_cred forwarders). The setattr==NULL no-op above is exempt — it
     * touches no origin state, so there is nothing to leak. */
    if (cred != NULL && cred->fallback_deny
        && inst->driver->setattr_cred == NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    return inst->driver->setattr(inst, path, attr);
}

static ngx_inline ssize_t
brix_sd_getxattr_maybe_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->getxattr_cred != NULL) {
        return inst->driver->getxattr_cred(inst, path, name, buf, cap, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->getxattr_cred == NULL
        && inst->driver->getxattr != NULL)
    {
        errno = EACCES;
        return -1;
    }
    if (inst->driver->getxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return inst->driver->getxattr(inst, path, name, buf, cap);
}

static ngx_inline ssize_t
brix_sd_listxattr_maybe_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->listxattr_cred != NULL) {
        return inst->driver->listxattr_cred(inst, path, buf, cap, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->listxattr_cred == NULL
        && inst->driver->listxattr != NULL)
    {
        errno = EACCES;
        return -1;
    }
    if (inst->driver->listxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return inst->driver->listxattr(inst, path, buf, cap);
}

static ngx_inline ngx_int_t
brix_sd_setxattr_maybe_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->setxattr_cred != NULL) {
        return inst->driver->setxattr_cred(inst, path, name, val, len, flags,
                                           cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->setxattr_cred == NULL
        && inst->driver->setxattr != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->setxattr == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->setxattr(inst, path, name, val, len, flags);
}

static ngx_inline ngx_int_t
brix_sd_removexattr_maybe_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->removexattr_cred != NULL) {
        return inst->driver->removexattr_cred(inst, path, name, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->removexattr_cred == NULL
        && inst->driver->removexattr != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->removexattr == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->removexattr(inst, path, name);
}

static ngx_inline ngx_int_t
brix_sd_server_copy_maybe_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->server_copy_cred != NULL) {
        return inst->driver->server_copy_cred(inst, src, dst, bytes_out, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->server_copy_cred == NULL
        && inst->driver->server_copy != NULL)
    {
        errno = EACCES;
        return NGX_ERROR;
    }
    if (inst->driver->server_copy == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return inst->driver->server_copy(inst, src, dst, bytes_out);
}

static ngx_inline brix_sd_dir_t *
brix_sd_opendir_maybe_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    if (cred != NULL && inst->driver->opendir_cred != NULL) {
        return inst->driver->opendir_cred(inst, path, err_out, cred);
    }
    if (cred != NULL && cred->fallback_deny
        && inst->driver->opendir_cred == NULL && inst->driver->opendir != NULL)
    {
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        errno = EACCES;
        return NULL;
    }
    if (inst->driver->opendir == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        errno = ENOSYS;
        return NULL;
    }
    return inst->driver->opendir(inst, path, err_out);
}

#endif /* BRIX_SD_CRED_FORWARD_H */
