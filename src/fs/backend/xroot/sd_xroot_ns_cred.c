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
 * HOW:  Each op opens the origin session through the shared ns_open/ns_close
 *       helpers below, passing the caller's cred to sd_xroot_session (NULL =
 *       anonymous / service credential — the plain vtable slots in
 *       sd_xroot_ns.c delegate here with cred=NULL, so these bodies are the
 *       single implementation of every path-based ns op).
 *       stat_cred is implemented in sd_xroot.c (alongside sd_xroot_stat, which
 *       reuses sd_xroot_origin_open — a file-private type). */

/* One fresh origin session per path-based op: connection + fill task. */
typedef struct {
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
} ns_session_t;

/* Open a fresh origin session under cred (NULL = service credential).
 * On failure sets errno and returns NGX_ERROR. */
static ngx_int_t
ns_open(brix_sd_instance_t *inst, const brix_sd_cred_t *cred, ns_session_t *s)
{
    sd_xroot_inst_state *is = inst->state;
    int                  e  = 0;

    if (sd_xroot_session(is->conf, cred, &s->oc, &s->t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Tear the session down, preserving errno across close/free. */
static void
ns_close(ns_session_t *s)
{
    int e = errno;

    brix_cache_origin_close(&s->oc);
    free(s->t);
    errno = e;
}

/* Close the session and map a 0/-1 origin rc to NGX_OK/NGX_ERROR (errno is
 * already set by the origin call, or by the caller for mapped kXR errors). */
static ngx_int_t
ns_result(ns_session_t *s, int rc)
{
    ns_close(s);
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* unlink_cred: remove a file or directory under the user's credential. */
ngx_int_t
sd_xroot_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    ns_session_t s;
    int          rc;

    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    rc = is_dir ? brix_cache_origin_rmdir(s.t, &s.oc, path)
                : brix_cache_origin_rm(s.t, &s.oc, path);
    return ns_result(&s, rc);
}

/* rename_cred: move src→dst under the user's credential. */
ngx_int_t
sd_xroot_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    ns_session_t s;

    (void) noreplace;   /* kXR_mv has no NOREPLACE flag; overwrite is default */
    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    return ns_result(&s, brix_cache_origin_rename(s.t, &s.oc, src, dst));
}

/* mkdir_cred: create a directory (kXR_mkdir) under the user's credential — the
 * per-user variant of sd_xroot_mkdir, so an explicit client MKDIR or the mkpath
 * prefix-walk against a root:// backend authenticates AS the mapped user instead
 * of the static service credential (parity with unlink_cred/rename_cred). */
ngx_int_t
sd_xroot_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    ns_session_t s;
    int          rc;

    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    rc = brix_cache_origin_mkdir(s.t, &s.oc, path, mode);
    return ns_result(&s, rc);
}

/* truncate_path_cred: resize an origin object by path under the user's
 * credential (path-based kXR_truncate, no write-open). The origin's kXR error
 * is mapped to errno via sd_xroot_errno (ENOENT for a miss). */
ngx_int_t
sd_xroot_truncate_path_cred(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    ns_session_t s;
    int          rc;

    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    rc = brix_cache_origin_truncate_path(s.t, &s.oc, path, (uint64_t) len);
    if (rc != 0) { errno = sd_xroot_errno(s.t); }
    return ns_result(&s, rc);
}

/* server_copy_cred: server-side byte copy under the user's credential. */
ngx_int_t
sd_xroot_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    ns_session_t s;
    u_char       src_fh[XRD_FHANDLE_LEN], dst_fh[XRD_FHANDLE_LEN];
    ngx_int_t    rc;
    int          e;

    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    ngx_cpystrn((u_char *) s.t->clean_path, (u_char *) src,
                sizeof(s.t->clean_path));
    if (brix_cache_origin_open(s.t, &s.oc, src_fh) != 0) {
        errno = sd_xroot_errno(s.t);
        ns_close(&s);
        return NGX_ERROR;
    }
    if (brix_cache_origin_open_write(s.t, &s.oc, dst, 0644, dst_fh) != 0) {
        errno = sd_xroot_errno(s.t);
        brix_cache_origin_close_file(&s.oc, src_fh);
        ns_close(&s);
        return NGX_ERROR;
    }
    rc = sd_xroot_copy_body(s.t, &s.oc, src_fh, dst_fh, bytes_out);
    e  = errno;
    brix_cache_origin_close_file(&s.oc, dst_fh);
    brix_cache_origin_close_file(&s.oc, src_fh);
    errno = e;
    ns_close(&s);
    return rc;
}

/* getxattr_cred: read an extended attribute under the user's credential. */
ssize_t
sd_xroot_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    ns_session_t s;
    ssize_t      n;

    if (ns_open(inst, cred, &s) != NGX_OK) { return -1; }
    n = brix_cache_origin_getfattr(s.t, &s.oc, path, sd_xroot_fattr_unmap(name),
                                   buf, cap);
    ns_close(&s);
    return n;
}

/* listxattr_cred: enumerate extended attributes under the user's credential.
 * The origin returns its user attrs as a NUL-separated list of CLIENT names
 * (its own "user.U." stripped). Re-add the "user.U." prefix to each so the
 * kXR_fattr list handler — which keeps "user.U.*" keys — recognizes them. */
ssize_t
sd_xroot_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    ns_session_t  s;
    char         *raw;
    const size_t  rawcap = 65536;
    ssize_t       n;
    size_t        out = 0, i;

    raw = malloc(rawcap);
    if (raw == NULL) { errno = ENOMEM; return -1; }
    if (ns_open(inst, cred, &s) != NGX_OK) { free(raw); return -1; }
    n = brix_cache_origin_listfattr(s.t, &s.oc, path, raw, rawcap);
    ns_close(&s);
    if (n < 0) { free(raw); return -1; }

    for (i = 0; i < (size_t) n; ) {
        size_t nl = strnlen(raw + i, (size_t) n - i);

        if (nl == 0) { i += 1; continue; }       /* skip an empty entry */
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
    ns_session_t s;

    (void) flags;   /* XATTR_CREATE/REPLACE not distinguished on the wire here */
    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    return ns_result(&s, brix_cache_origin_setfattr(s.t, &s.oc, path,
                                                    sd_xroot_fattr_unmap(name),
                                                    val, len));
}

/* removexattr_cred: delete an extended attribute under the user's credential. */
ngx_int_t
sd_xroot_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    ns_session_t s;
    int          rc;

    if (ns_open(inst, cred, &s) != NGX_OK) { return NGX_ERROR; }
    rc = brix_cache_origin_delfattr(s.t, &s.oc, path,
                                    sd_xroot_fattr_unmap(name));
    return ns_result(&s, rc);
}
