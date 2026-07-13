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
#define SD_XROOT_FATTR_PFX     "user.U."
#define SD_XROOT_FATTR_PFX_LEN 7

static const char *
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
 *       neither a non-empty x509_proxy nor a non-empty bearer.  NULL cred and
 *       creds with a presentable kind return false (allowed). */
static int
sd_xroot_cred_must_deny(const brix_sd_cred_t *cred)
{
    return cred != NULL && cred->fallback_deny
        && (cred->x509_proxy == NULL || cred->x509_proxy[0] == '\0')
        && (cred->bearer == NULL || cred->bearer[0] == '\0');
}

/* WHAT: Copy a per-user credential into a fill task so the origin bootstrap
 *       presents it at authentication instead of the static service cred.
 * WHY:  Namespace ops that carry a user credential must NOT fall back to the
 *       static service credential; this mirrors sd_xroot_origin_open.
 * HOW:  Exactly one of {x509_proxy, bearer} is non-NULL for a credential-scoped
 *       session; copy whichever is set, plus principal.  Caller guarantees the
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
 *       all cred_* fields so sd_xroot_cred_copy is a no-op for NULL cred. */
static int
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

ssize_t
sd_xroot_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    ssize_t                     n;
    int                         e = 0;

    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return -1; }
    n = brix_cache_origin_getfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                     buf, cap);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return n;
}

ssize_t
sd_xroot_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
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
    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) {
        free(raw); errno = e; return -1;
    }
    /* The origin returns its user attrs as a NUL-separated list of CLIENT names
     * (its own "user.U." stripped). Re-add the "user.U." prefix to each so the
     * kXR_fattr list handler — which keeps "user.U.*" keys — recognizes them. */
    n = brix_cache_origin_listfattr(t, &oc, path, raw, rawcap);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    if (n < 0) { free(raw); errno = e; return -1; }

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

ngx_int_t
sd_xroot_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) flags;   /* XATTR_CREATE/REPLACE not distinguished on the wire here */
    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_setfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                      val, len);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_xroot_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_delfattr(t, &oc, path, sd_xroot_fattr_unmap(name));
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_xroot_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) noreplace;   /* kXR_mv has no NOREPLACE flag; overwrite is the default */
    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_rename(t, &oc, src, dst);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* Delete a file or empty directory on the remote node. Required so a remote
 * xroot node can serve as a cache_store (cstore eviction) or a stage_store
 * (post-flush reclaim). Files use kXR_rm; directories use kXR_rmdir (the two
 * opcodes share the same wire shape: reserved 16-byte body + path payload).
 * Returns NGX_OK / NGX_ERROR (errno set — ENOTEMPTY if the directory is not
 * empty, ENOENT if the path is already gone). */
ngx_int_t
sd_xroot_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = is_dir ? brix_cache_origin_rmdir(t, &oc, path)
                : brix_cache_origin_rm(t, &oc, path);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* Copy src→dst byte stream on an open session (read each chunk from src_fh, write
 * to dst_fh), then truncate+sync dst. Returns NGX_OK + *bytes_out, or NGX_ERROR. */
static ngx_int_t
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
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    u_char                      src_fh[XRD_FHANDLE_LEN], dst_fh[XRD_FHANDLE_LEN];
    ngx_int_t                   rc;
    int                         e = 0;

    if (sd_xroot_session(is->conf, NULL, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }

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

/* ---- directory listing (kXR_dirlist, fetch-all-then-iterate) --------------
 *
 * WHAT: opendir issues ONE kXR_dirlist against the origin, buffers every
 *       name into a brix_cache_dirlist_t held as the brix_sd_dir_t's driver-
 *       private state, then closes the origin session immediately (mirrors
 *       every other ns op in this file — no op here holds a live origin
 *       connection across separate VFS calls). readdir yields one buffered
 *       name per call; closedir frees the buffer.
 * WHY:  brix_sd_dir_t iteration (opendir/readdir/closedir) is 3 separate VFS
 *       calls with no guarantee they run back-to-back on the same thread, so
 *       a streamed/session-held approach would need to keep an origin TCP
 *       connection open across arbitrary VFS-call gaps — fragile and unlike
 *       every other sd_xroot op. Fetch-all-then-iterate trades a larger
 *       up-front read for a stateless, connection-free readdir/closedir.
 * HOW:  opendir_common does the session + dirlist fetch + dir handle alloc;
 *       opendir/opendir_cred differ only in which credential (NULL vs the
 *       caller's) sd_xroot_session presents at the origin. readdir walks the
 *       buffered brix_cache_dirlist_t by index; closedir frees it.
 */

/* Driver-private dir state: the fetched name buffer plus a read cursor. */
typedef struct {
    brix_cache_dirlist_t dl;      /* heap-owned name array (see cache_internal.h) */
    size_t                 next;    /* index of the next name readdir will yield */
} sd_xroot_dir_state;

/* sd_xroot_opendir_common — shared body for opendir/opendir_cred: open a
 * session under `cred` (NULL ⇒ service credential), fetch the whole listing,
 * close the session, and wrap the result in a brix_sd_dir_t. Returns the dir
 * handle, or NULL with *err_out set. */
static brix_sd_dir_t *
sd_xroot_opendir_common(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    sd_xroot_dir_state        *ds;
    brix_sd_dir_t             *dir;
    int                         e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        if (err_out) { *err_out = e; }
        return NULL;
    }

    ds = calloc(1, sizeof(*ds));
    if (ds == NULL) {
        brix_cache_origin_close(&oc);
        free(t);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    brix_cache_dirlist_init(&ds->dl);

    if (brix_cache_origin_dirlist(t, &oc, path, &ds->dl) != 0) {
        e = sd_xroot_errno(t);
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        brix_cache_origin_close(&oc);
        free(t);
        if (err_out) { *err_out = e; }
        return NULL;
    }

    /* The listing is fully buffered — the origin session is no longer
     * needed for readdir/closedir (fetch-all-then-iterate, see above). */
    brix_cache_origin_close(&oc);
    free(t);

    dir = calloc(1, sizeof(*dir));
    if (dir == NULL) {
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

/* opendir — vtable opendir slot: service credential / anonymous. */
brix_sd_dir_t *
sd_xroot_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_xroot_opendir_common(inst, path, NULL, err_out);
}

/* opendir_cred — vtable opendir_cred slot: per-user credential, so a remote
 * dirlist authenticates to the origin as the requesting user. */
brix_sd_dir_t *
sd_xroot_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    return sd_xroot_opendir_common(inst, path, cred, err_out);
}

/* readdir — vtable readdir slot: yield the next buffered name, bound-copied
 * into out->name (255 chars + NUL — brix_sd_dirent_t's fixed field). Returns
 * NGX_OK (out filled), NGX_DONE (end of the buffered listing — matches the
 * POSIX driver's readdir contract that brix_vfs_readdir relies on), or
 * NGX_ERROR (malformed state; errno set). */
ngx_int_t
sd_xroot_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_xroot_dir_state *ds = d->state;

    if (ds == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (ds->next >= ds->dl.count) {
        return NGX_DONE;
    }
    ngx_cpystrn((u_char *) out->name, (u_char *) ds->dl.names[ds->next],
                sizeof(out->name));
    ds->next++;
    return NGX_OK;
}

/* closedir — vtable closedir slot: free the buffered name array, the dir
 * state, and the brix_sd_dir_t handle itself. No origin session to close
 * (opendir already released it). The VFS (brix_vfs_closedir, vfs_dir.c)
 * calls driver->closedir(dh->sd_dir) but never frees dh->sd_dir itself, so
 * — unlike sd_posix's pool-allocated dir handle, which the pool reclaims —
 * this heap-allocated handle (calloc'd in sd_xroot_opendir_common) MUST be
 * freed here or every dirlist leaks one brix_sd_dir_t. NULL-safe (both on
 * `d` and on `d->state`) so a double-close is harmless. */
ngx_int_t
sd_xroot_closedir(brix_sd_dir_t *d)
{
    sd_xroot_dir_state *ds;

    if (d == NULL) {
        return NGX_OK;
    }
    ds = d->state;
    if (ds != NULL) {
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        d->state = NULL;
    }
    free(d);
    return NGX_OK;
}
