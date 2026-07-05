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

/* Connect + bootstrap a fresh anonymous origin session (no file open) for a
 * path-based op. On success fills *oc + *t_out (caller closes oc + frees t);
 * returns -1 with *err_out on failure. */
static int
sd_xroot_session(ngx_stream_brix_srv_conf_t *conf,
    brix_cache_origin_conn_t *oc, brix_cache_fill_t **t_out, int *err_out)
{
    brix_cache_fill_t *t = calloc(1, sizeof(*t));

    if (t == NULL) {
        if (err_out) { *err_out = ENOMEM; }
        return -1;
    }
    oc->fd  = -1;
    t->conf = conf;
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

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return -1; }
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
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) {
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
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
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

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
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
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_rename(t, &oc, src, dst);
    e = errno;
    brix_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* Delete a file on the remote node (kXR_rm). Required so a remote xroot node can
 * serve as a cache_store (cstore eviction) or a stage_store (post-flush reclaim of
 * the staged copy). Only regular files are removed; is_dir is refused (no
 * kXR_rmdir path over the wire yet). Returns NGX_OK / NGX_ERROR (errno set). */
ngx_int_t
sd_xroot_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    int                         rc, e = 0;

    if (is_dir) {
        errno = ENOSYS;                 /* directory removal over the wire: TODO */
        return NGX_ERROR;
    }
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = brix_cache_origin_rm(t, &oc, path);
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
        brix_cache_sink_t sink;
        size_t              got = 0;

        ngx_memzero(&sink, sizeof(sink));
        sink.fd = -1;
        sink.mem = buf;
        sink.mem_cap = cap;
        if (brix_cache_origin_read_chunk(t, oc, src_fh, &sink, (uint64_t) off,
                                           0, cap, &got) != 0)
        {
            free(buf); errno = EIO; return NGX_ERROR;
        }
        if (got == 0) {
            break;
        }
        if (brix_cache_origin_write_chunk(t, oc, dst_fh, (uint64_t) off, buf,
                                            got) != 0)
        {
            free(buf); errno = EIO; return NGX_ERROR;
        }
        off += (off_t) got;
        if (got < cap) {
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

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }

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
