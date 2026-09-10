/*
 * sd_xroot_fwd_ns.c — path-keyed relays of the forwarding driver.
 *
 * WHAT: Every namespace slot resolves the key to a child origin, then hands
 *       the origin-relative path to that child through the shared
 *       brix_sd_*_maybe_cred forwarders (sd_cred_forward.h).
 * WHY:  The forwarders own the cred/fallback_deny/ENOSYS contract, so a
 *       forwarded call behaves exactly as a call on a fixed root:// export;
 *       the plain slots are their `_cred` twins with no credential.
 * HOW:  Two-key operations (rename, server_copy) resolve both keys and refuse
 *       EXDEV unless they land on the same origin — an origin cannot move a
 *       file it does not hold, and the wire maps EXDEV to kXR_NotAuthorized.
 */
#include "sd_xroot_fwd_internal.h"

#include <errno.h>

/* SD_XROOT_FWD_HOP — the whole body of a one-key relay: resolve the slot's
 * `key` parameter against `inst` (errno set by the resolver on refusal),
 * return `errval` when it refuses, else RETURN the delegated `call`, which
 * names the origin child as `child` and the origin-relative path as `t.path`.
 * Same shape as PBLOCK_CRED_GATED (sd_pblock_cred.c). */
#define SD_XROOT_FWD_HOP(key, errval, call)                                   \
    do {                                                                      \
        brix_sd_xroot_fwd_target_t  t;                                        \
        brix_sd_instance_t         *child = sd_xroot_fwd_resolve(inst, key,   \
                                                                 &t);         \
        if (child == NULL) {                                                  \
            return errval;                                                    \
        }                                                                     \
        return call;                                                          \
    } while (0)

ngx_int_t
sd_xroot_fwd_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_stat_maybe_cred(child, t.path, out, cred));
}

ngx_int_t
sd_xroot_fwd_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    return sd_xroot_fwd_stat_cred(inst, path, out, NULL);
}

ngx_int_t
sd_xroot_fwd_unlink_cred(brix_sd_instance_t *inst, const char *path,
    int is_dir, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_unlink_maybe_cred(child, t.path, is_dir, cred));
}

ngx_int_t
sd_xroot_fwd_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_xroot_fwd_unlink_cred(inst, path, is_dir, NULL);
}

ngx_int_t
sd_xroot_fwd_mkdir_cred(brix_sd_instance_t *inst, const char *path,
    mode_t mode, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_mkdir_maybe_cred(child, t.path, mode, cred));
}

ngx_int_t
sd_xroot_fwd_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return sd_xroot_fwd_mkdir_cred(inst, path, mode, NULL);
}

/* Resolve a two-key operation: both keys must land on one origin. */
static brix_sd_instance_t *
sd_xroot_fwd_resolve_pair(brix_sd_instance_t *inst, const char *src,
    const char *dst, brix_sd_xroot_fwd_target_t *ts,
    brix_sd_xroot_fwd_target_t *td)
{
    brix_sd_instance_t  *child_src = sd_xroot_fwd_resolve(inst, src, ts);
    brix_sd_instance_t  *child_dst;

    if (child_src == NULL) {
        return NULL;
    }
    child_dst = sd_xroot_fwd_resolve(inst, dst, td);
    if (child_dst == NULL) {
        return NULL;
    }
    if (child_src != child_dst) {
        errno = EXDEV;
        return NULL;
    }
    return child_src;
}

ngx_int_t
sd_xroot_fwd_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    brix_sd_xroot_fwd_target_t  ts, td;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve_pair(inst, src,
                                                                 dst, &ts, &td);

    if (child == NULL) {
        return NGX_ERROR;
    }
    return brix_sd_rename_maybe_cred(child, ts.path, td.path, noreplace, cred);
}

ngx_int_t
sd_xroot_fwd_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace)
{
    return sd_xroot_fwd_rename_cred(inst, src, dst, noreplace, NULL);
}

ngx_int_t
sd_xroot_fwd_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    brix_sd_xroot_fwd_target_t  ts, td;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve_pair(inst, src,
                                                                 dst, &ts, &td);

    if (child == NULL) {
        return NGX_ERROR;
    }
    return brix_sd_server_copy_maybe_cred(child, ts.path, td.path, bytes_out,
                                          cred);
}

ngx_int_t
sd_xroot_fwd_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_xroot_fwd_server_copy_cred(inst, src, dst, bytes_out, NULL);
}

ngx_int_t
sd_xroot_fwd_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_setattr_maybe_cred(child, t.path, attr, cred));
}

ngx_int_t
sd_xroot_fwd_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return sd_xroot_fwd_setattr_cred(inst, path, attr, NULL);
}

ngx_int_t
sd_xroot_fwd_truncate_path_cred(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_truncate_path_maybe_cred(child, t.path, len,
                                                      cred));
}

ngx_int_t
sd_xroot_fwd_truncate_path(brix_sd_instance_t *inst, const char *path,
    off_t len)
{
    return sd_xroot_fwd_truncate_path_cred(inst, path, len, NULL);
}

/* ---- xattr ------------------------------------------------------------- */

ssize_t
sd_xroot_fwd_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, -1,
                     brix_sd_getxattr_maybe_cred(child, t.path, name, buf,
                                                 cap, cred));
}

ssize_t
sd_xroot_fwd_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    return sd_xroot_fwd_getxattr_cred(inst, path, name, buf, cap, NULL);
}

ssize_t
sd_xroot_fwd_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, -1,
                     brix_sd_listxattr_maybe_cred(child, t.path, buf, cap,
                                                  cred));
}

ssize_t
sd_xroot_fwd_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    return sd_xroot_fwd_listxattr_cred(inst, path, buf, cap, NULL);
}

ngx_int_t
sd_xroot_fwd_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_setxattr_maybe_cred(child, t.path, name, val,
                                                 len, flags, cred));
}

ngx_int_t
sd_xroot_fwd_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    return sd_xroot_fwd_setxattr_cred(inst, path, name, val, len, flags, NULL);
}

ngx_int_t
sd_xroot_fwd_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_removexattr_maybe_cred(child, t.path, name,
                                                    cred));
}

ngx_int_t
sd_xroot_fwd_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_xroot_fwd_removexattr_cred(inst, path, name, NULL);
}

/* ---- nearline ---------------------------------------------------------- */

ngx_int_t
sd_xroot_fwd_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    SD_XROOT_FWD_HOP(key, NGX_ERROR,
                     brix_sd_recall_maybe_cred(child, t.path, reqid_out,
                                               cred));
}

ngx_int_t
sd_xroot_fwd_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40])
{
    return sd_xroot_fwd_recall_cred(inst, key, NULL, reqid_out);
}

ngx_int_t
sd_xroot_fwd_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out)
{
    brix_sd_xroot_fwd_target_t  t;
    brix_sd_instance_t        *child = sd_xroot_fwd_resolve(inst, key, &t);

    if (child == NULL) {
        return NGX_ERROR;
    }
    if (child->driver->residency == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    return child->driver->residency(child, t.path, out);
}

ngx_int_t
sd_xroot_fwd_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    SD_XROOT_FWD_HOP(path, NGX_ERROR,
                     brix_sd_evict_maybe_cred(child, t.path, bytes_out, cred));
}

ngx_int_t
sd_xroot_fwd_evict(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out)
{
    return sd_xroot_fwd_evict_cred(inst, path, bytes_out, NULL);
}
