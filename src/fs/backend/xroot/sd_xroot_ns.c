/*
 * sd_xroot_ns.c — root:// origin namespace + metadata operations.
 *
 * Path-based ops that open a fresh anonymous origin session per call: extended
 * attributes (kXR_fattr get/list/set/del), rename (kXR_mv), unlink (kXR_rm), and
 * server-side copy (third-party fetch).  Split out of sd_xroot.c so the I/O +
 * lifecycle path stays focused; the vtable ops here are wired into the driver
 * struct in sd_xroot.c via sd_xroot_internal.h.  fattr_unmap / session /
 * copy_body stay file-private.
 */

#include "sd_xroot_internal.h"
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI origin verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* ---- namespace + metadata (path-based, fresh anonymous session per op) ----- */

/* The kXR_fattr protocol handler stores a user attribute "X" under the on-disk key
 * "user.U.X" (BRIX_FATTR_XKEY_PFX, applied ABOVE the VFS). When we forward to
 * ANOTHER xrootd server it re-applies the SAME mapping, so handing it the already-
 * mapped key would double-prefix it on the origin ("user.U.user.U.X") and break
 * direct-origin interop. So strip one "user.U." before forwarding get/set/remove,
 * and re-add it on list — the origin then carries a single, standard "user.U.X".
 * (Kept in sync with src/fattr/ngx_brix_fattr.h rather than #included, to avoid a
 * backend→protocol-handler dependency. Names from other consumers — webdav locks/
 * dead-props, s3 tags — have no "user.U." prefix and pass through unchanged.) */
/* SD_XROOT_FATTR_PFX / _LEN live in sd_xroot_internal.h — shared with the
 * credential-scoped wrappers (sd_xroot_ns_cred.c). */
const char *
sd_xroot_fattr_unmap(const char *name)
{
    if (strncmp(name, SD_XROOT_FATTR_PFX, SD_XROOT_FATTR_PFX_LEN) == 0) {
        return name + SD_XROOT_FATTR_PFX_LEN;
    }
    return name;
}

/* WHAT: Report whether a fallback_deny credential must be refused outright.
 * WHY:  A fallback_deny cred whose selected kind (e.g. S3 ak/sk) this driver
 *       cannot present carries neither x509_proxy nor bearer.  Falling back to
 *       the static service credential would silently serve the request under
 *       the wrong identity, so it must be refused before any session is opened.
 *       Every *_cred namespace wrapper (unlink_cred, rename_cred, opendir_cred,
 *       ...) reaches this via the shared sd_xroot_session choke point.
 * HOW:  True only when cred is non-NULL, has fallback_deny set, and carries
 *       none of the driver's presentable kinds (x509_proxy, bearer, sss_keytab,
 *       krb5 forwarded-TGT ccache).  NULL cred and creds with a presentable
 *       kind return false (allowed). */
static int
sd_xroot_cred_must_deny(const brix_sd_cred_t *cred)
{
    return cred != NULL && cred->fallback_deny
        && (cred->x509_proxy == NULL || cred->x509_proxy[0] == '\0')
        && (cred->bearer == NULL || cred->bearer[0] == '\0')
        && (cred->sss_keytab == NULL || cred->sss_keytab[0] == '\0')
        && (cred->krb5_ccache == NULL || cred->krb5_ccache[0] == '\0');
}

/* WHAT: Copy a per-user credential into a fill task so the origin bootstrap
 *       presents it at authentication instead of the static service cred.
 * WHY:  Namespace ops that carry a user credential must NOT fall back to the
 *       static service credential; this mirrors sd_xroot_origin_open.
 * HOW:  Exactly one of {x509_proxy, bearer, sss_keytab, krb5 ccache} is
 *       non-NULL for a credential-scoped session; copy whichever is set, plus
 *       principal (sss_keytab REQUIRES it — it is the asserted identity — and
 *       the krb5 leg carries krb5_princ, the origin service principal).  Caller
 *       guarantees the
 *       task's cred_* fields are already zeroed (calloc), so a NULL cred is a
 *       no-op and the service-cred path is left unchanged. */
static void
sd_xroot_cred_copy(brix_cache_fill_t *t, const brix_sd_cred_t *cred)
{
    if (cred == NULL) {
        return;
    }
    if (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_x509_proxy, (u_char *) cred->x509_proxy,
                    sizeof(t->cred_x509_proxy));
    }
    if (cred->bearer != NULL && cred->bearer[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_bearer, (u_char *) cred->bearer,
                    sizeof(t->cred_bearer));
    }
    if (cred->principal != NULL) {
        ngx_cpystrn((u_char *) t->cred_principal,
                    (u_char *) cred->principal, sizeof(t->cred_principal));
    }
    if (cred->sss_keytab != NULL && cred->sss_keytab[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_sss_keytab,
                    (u_char *) cred->sss_keytab, sizeof(t->cred_sss_keytab));
    }
    if (cred->krb5_ccache != NULL && cred->krb5_ccache[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_krb5_ccache,
                    (u_char *) cred->krb5_ccache, sizeof(t->cred_krb5_ccache));
    }
    if (cred->krb5_princ != NULL && cred->krb5_princ[0] != '\0') {
        ngx_cpystrn((u_char *) t->cred_krb5_princ,
                    (u_char *) cred->krb5_princ, sizeof(t->cred_krb5_princ));
    }
}

/* Connect + bootstrap a fresh origin session (no file open) for a path-based op.
 * When cred is non-NULL the bootstrap uses the per-user credential instead of
 * the static service credential.  Supports both x509 proxies (cred->x509_proxy)
 * and WLCG bearer tokens (cred->bearer); they are mutually exclusive per the
 * brix_sd_cred_t contract.  NULL cred → service credential / anonymous.
 * On success fills *oc + *t_out (caller closes oc + frees t); returns -1 with
 * *err_out on failure.
 *
 * WHAT: Refuse an unpresentable fallback_deny cred, then allocate and wire a
 *       fill task, copying any per-user credential, and connect+bootstrap.
 * WHY:  This function opens its own origin session independent of
 *       sd_xroot_open_common, so the wrong-kind cred leak is reachable via
 *       every *_cred namespace wrapper unless checked at this shared point.
 * HOW:  sd_xroot_cred_must_deny gates unusable creds up front; calloc zeroes
 *       all cred_* fields so sd_xroot_cred_copy is a no-op for NULL cred.
 * Prototype in sd_xroot_internal.h — shared with the credential-scoped
 * wrappers (sd_xroot_ns_cred.c) and the directory-listing path
 * (sd_xroot_ns_dir.c). */
int
sd_xroot_session(ngx_stream_brix_srv_conf_t *conf,
    const brix_sd_cred_t *cred,
    brix_cache_origin_conn_t *oc, brix_cache_fill_t **t_out, int *err_out)
{
    brix_cache_fill_t *t;

    if (sd_xroot_cred_must_deny(cred)) {
        if (err_out) { *err_out = EACCES; }
        errno = EACCES;
        return -1;
    }

    t = calloc(1, sizeof(*t));
    if (t == NULL) {
        if (err_out) { *err_out = ENOMEM; }
        return -1;
    }
    oc->fd  = -1;
    t->conf = conf;

    sd_xroot_cred_copy(t, cred);

    if (brix_cache_origin_connect(t, oc) != 0
        || brix_cache_origin_bootstrap(t, oc) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        brix_cache_origin_close(oc);
        free(t);
        return -1;
    }
    *t_out = t;
    return 0;
}

/* ---- plain (service-credential / anonymous) vtable ops ---------------------
 *
 * Each op is the credential-scoped implementation in sd_xroot_ns_cred.c run
 * with a NULL cred: sd_xroot_session(…, NULL, …) is the anonymous / service-
 * credential session, so the wrappers there are the single implementation and
 * these slots delegate. */

ssize_t
sd_xroot_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    return sd_xroot_getxattr_cred(inst, path, name, buf, cap, NULL);
}

ssize_t
sd_xroot_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    return sd_xroot_listxattr_cred(inst, path, buf, cap, NULL);
}

ngx_int_t
sd_xroot_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    return sd_xroot_setxattr_cred(inst, path, name, val, len, flags, NULL);
}

ngx_int_t
sd_xroot_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_xroot_removexattr_cred(inst, path, name, NULL);
}

ngx_int_t
sd_xroot_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return sd_xroot_rename_cred(inst, src, dst, noreplace, NULL);
}

/* Apply mode (kXR_chmod) to an origin path; times/owner are accepted-and-ignored
 * — see sd_xroot_setattr_cred for why the vendor kXR_setattr opcode is not used
 * here. Without this slot the VFS reports a chmod as a no-op success. */
ngx_int_t
sd_xroot_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return sd_xroot_setattr_cred(inst, path, attr, NULL);
}

/* Path-based truncate (kXR_truncate with a path payload): resize the origin
 * object to `len` by NAME — no write-open, so a truncate over a staged remote
 * backend never RECALLs the whole file nor takes a staged write-open that would
 * self-collide on commit. */
ngx_int_t
sd_xroot_truncate_path(brix_sd_instance_t *inst, const char *path, off_t len)
{
    return sd_xroot_truncate_path_cred(inst, path, len, NULL);
}

/* Delete a file or empty directory on the remote node. Required so a remote
 * xroot node can serve as a cache_store (cstore eviction) or a stage_store
 * (post-flush reclaim). Files use kXR_rm; directories use kXR_rmdir. Returns
 * NGX_OK / NGX_ERROR (errno set — ENOTEMPTY if the directory is not empty,
 * ENOENT if the path is already gone). */
ngx_int_t
sd_xroot_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_xroot_unlink_cred(inst, path, is_dir, NULL);
}

/* Create a directory on the remote node (kXR_mkdir). Required so an explicit
 * client MKDIR — or the mkpath prefix-walk (brix_vfs_backend_mkpath) — resolves
 * against a root:// backend instead of failing the NULL-slot path. Returns
 * NGX_OK / NGX_ERROR (errno set — EEXIST when the directory already exists,
 * tolerated by the mkpath walk). */
ngx_int_t
sd_xroot_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return sd_xroot_mkdir_cred(inst, path, mode, NULL);
}

/* Export capacity from the ORIGIN (optional `space` vtable slot).
 *
 * WHAT: kXR_query/kXR_Qspace on a fresh anonymous session, decoded by the
 *       shared oss.* grammar into a brix_sd_space_t.
 * WHY:  A root:// gateway's statvfs/Qspace/QFSinfo/SRR answers described the
 *       LOCAL export directory's filesystem — meaningless for capacity planning
 *       when the bytes actually live on the origin. Any failure returns
 *       NGX_ERROR so brix_query_backend_usage / statvfs consumers fall back to
 *       the local statvfs rather than erroring the client op.
 * HOW:  sd_xroot_session (bounded by the origin socket timeouts, same cost
 *       class as sd_xroot_stat) → brix_cache_origin_query_space → close; used
 *       is derived as total − free since the oss.* report carries both. */
ngx_int_t
sd_xroot_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    sd_xroot_inst_state       *is = inst->state;
    brix_cache_origin_conn_t   oc;
    brix_cache_fill_t         *t;
    uint64_t                   total = 0, freeb = 0;
    int                        rc, e = 0;

    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) {
        errno = e;
        return NGX_ERROR;
    }
    rc = brix_cache_origin_query_space(t, &oc, &total, &freeb);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (rc != 0) {
        errno = e;
        return NGX_ERROR;
    }
    out->total_bytes = total;
    out->free_bytes  = freeb;
    out->used_bytes  = total > freeb ? total - freeb : 0;
    return NGX_OK;
}

/* Copy src→dst byte stream on an open session (read each chunk from src_fh, write
 * to dst_fh), then truncate+sync dst. Returns NGX_OK + *bytes_out, or NGX_ERROR.
 * Prototype in sd_xroot_internal.h — shared with the credential-scoped
 * server_copy_cred wrapper (sd_xroot_ns_cred.c). */
ngx_int_t
sd_xroot_copy_body(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const u_char *src_fh, const u_char *dst_fh, off_t *bytes_out)
{
    const size_t cap = 1u << 20;
    u_char      *buf = malloc(cap);
    off_t        off = 0;

    if (buf == NULL) { errno = ENOMEM; return NGX_ERROR; }

    for (;;) {
        brix_cache_sink_t        sink;
        brix_cache_read_range_t  rng;

        ngx_memzero(&sink, sizeof(sink));
        sink.fd = -1;
        sink.mem = buf;
        sink.mem_cap = cap;

        ngx_memzero(&rng, sizeof(rng));
        rng.read_off = (uint64_t) off;
        rng.want     = cap;

        if (brix_cache_origin_read_chunk(t, oc, src_fh, &sink, &rng) != 0) {
            free(buf); errno = EIO; return NGX_ERROR;
        }
        if (rng.got == 0) {
            break;
        }
        if (brix_cache_origin_write_chunk(t, oc, dst_fh, (uint64_t) off, buf,
                                            rng.got) != 0)
        {
            free(buf); errno = EIO; return NGX_ERROR;
        }
        off += (off_t) rng.got;
        if (rng.got < cap) {
            break;                               /* short read = EOF */
        }
    }
    free(buf);

    if (brix_cache_origin_truncate(t, oc, dst_fh, (uint64_t) off) != 0
        || brix_cache_origin_sync(t, oc, dst_fh) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    if (bytes_out) { *bytes_out = off; }
    return NGX_OK;
}

/* Server-side copy: the gateway reads src and writes dst on the origin (no client
 * round-trip). Not zero-copy on the origin (no remote TPC) — a read+write relay. */
ngx_int_t
sd_xroot_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_xroot_server_copy_cred(inst, src, dst, bytes_out, NULL);
}
