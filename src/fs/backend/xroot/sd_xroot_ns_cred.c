/*
 * sd_xroot_ns_cred.c — credential-scoped root:// namespace + metadata wrappers.
 *
 * The per-user variants of the path-based namespace ops (unlink/rename/copy and
 * the kXR_fattr get/list/set/remove).  Split out of sd_xroot_ns.c so the plain
 * (service-credential / anonymous) ops and the shared session/fattr helpers stay
 * in one file; each wrapper here delegates the operation body verbatim to the
 * matching plain op but opens the origin session under the caller's credential.
 * The vtable ops are wired into the driver struct in sd_xroot.c via
 * sd_xroot_internal.h.
 */

#include "sd_xroot_internal.h"
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI origin verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* ---- credential-scoped namespace wrappers (Phase 2 Task 1) -----------------
 *
 * WHAT: One wrapper per supported ns op that opens a per-user origin session
 *       (via sd_xroot_session with a non-NULL cred) instead of the anonymous /
 *       service-credential session the plain slots use.
 *
 * WHY:  A deny-mode request whose data-plane credential gate fires must also
 *       present the user proxy for every pre-flight probe and metadata mutation
 *       (unlink, rename, copy, xattr).  Without these wrappers the probe stat
 *       still runs under the static service credential even when the protocol
 *       handler correctly denied the operation.
 *
 * HOW:  Each wrapper delegates the operation body verbatim to the matching plain
 *       op helper but passes the cred to sd_xroot_session so the bootstrap uses
 *       the per-user proxy.  The plain ops now call sd_xroot_session(…, NULL, …);
 *       these wrappers call sd_xroot_session(…, cred, …) — the only difference.
 *       stat_cred is implemented in sd_xroot.c (alongside sd_xroot_stat, which
 *       reuses sd_xroot_origin_open — a file-private type). */

/* unlink_cred: remove a file or directory under the user's credential. */
ngx_int_t
sd_xroot_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e; return NGX_ERROR;
    }
    rc = is_dir ? brix_cache_origin_rmdir(t, &oc, path)
                : brix_cache_origin_rm(t, &oc, path);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* rename_cred: move src→dst under the user's credential. */
ngx_int_t
sd_xroot_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) noreplace;   /* kXR_mv has no NOREPLACE flag */
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e; return NGX_ERROR;
    }
    rc = brix_cache_origin_rename(t, &oc, src, dst);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* server_copy_cred: server-side byte copy under the user's credential. */
ngx_int_t
sd_xroot_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    u_char                      src_fh[XRD_FHANDLE_LEN], dst_fh[XRD_FHANDLE_LEN];
    ngx_int_t                   rc;
    int                         e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        errno = e; return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) src, sizeof(t->clean_path));
    if (brix_cache_origin_open(t, &oc, src_fh) != 0) {
        e = sd_xroot_errno(t);
        brix_cache_origin_close(&oc); free(t); errno = e; return NGX_ERROR;
    }
    if (brix_cache_origin_open_write(t, &oc, dst, 0644, dst_fh) != 0) {
        e = sd_xroot_errno(t);
        brix_cache_origin_close_file(&oc, src_fh);
        brix_cache_origin_close(&oc); free(t); errno = e; return NGX_ERROR;
    }
    rc = sd_xroot_copy_body(t, &oc, src_fh, dst_fh, bytes_out);
    e  = errno;
    brix_cache_origin_close_file(&oc, dst_fh);
    brix_cache_origin_close_file(&oc, src_fh);
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc;
}

/* getxattr_cred: read an extended attribute under the user's credential. */
ssize_t
sd_xroot_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    ssize_t                     n;
    int                         e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) { errno = e; return -1; }
    n = brix_cache_origin_getfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                     buf, cap);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return n;
}

/* listxattr_cred: enumerate extended attributes under the user's credential. */
ssize_t
sd_xroot_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    char                       *raw;
    const size_t                rawcap = 65536;
    ssize_t                     n;
    size_t                      out = 0, i;
    int                         e = 0;

    raw = malloc(rawcap);
    if (raw == NULL) { errno = ENOMEM; return -1; }
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        free(raw); errno = e; return -1;
    }
    n = brix_cache_origin_listfattr(t, &oc, path, raw, rawcap);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (n < 0) { free(raw); errno = e; return -1; }

    for (i = 0; i < (size_t) n; ) {
        size_t nl = strnlen(raw + i, (size_t) n - i);

        if (nl == 0) { i += 1; continue; }
        if (buf != NULL && cap > 0) {
            if (out + SD_XROOT_FATTR_PFX_LEN + nl + 1 > cap) {
                free(raw); errno = ERANGE; return -1;
            }
            ngx_memcpy((char *) buf + out, SD_XROOT_FATTR_PFX,
                       SD_XROOT_FATTR_PFX_LEN);
            ngx_memcpy((char *) buf + out + SD_XROOT_FATTR_PFX_LEN, raw + i, nl);
            ((char *) buf)[out + SD_XROOT_FATTR_PFX_LEN + nl] = '\0';
        }
        out += SD_XROOT_FATTR_PFX_LEN + nl + 1;
        i   += nl + 1;
    }
    free(raw);
    return (ssize_t) out;
}

/* setxattr_cred: write an extended attribute under the user's credential. */
ngx_int_t
sd_xroot_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) flags;
    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_setfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                      val, len);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* removexattr_cred: delete an extended attribute under the user's credential. */
ngx_int_t
sd_xroot_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_delfattr(t, &oc, path, sd_xroot_fattr_unmap(name));
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}
