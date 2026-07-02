/*
 * sd_xroot.c — read-only remote root:// origin storage driver. See the header.
 *
 * Wraps the in-process XRootD origin wire client (cache/origin_*.c) behind the SD
 * vtable. The per-open object holds a live origin connection + open file handle;
 * pread issues a kXR_read range into a memory sink. Anonymous login only (the
 * client's native mode); authenticated origins use the cache's native-client
 * delegation. Only the read slots are populated → CAP_RANGE_READ.
 */

#include "sd_xroot.h"
#include "fs/cache/cache_internal.h"   /* origin wire client + fill-task ctx */
#include "auth/crypto/pki_build.h"       /* xrootd_build_ca_store (GSI MITM verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Instance state: the server conf the origin client reads (host/port/tls). For a
 * cache-constructed instance `conf` is the real export conf. For a registry-built
 * PRIMARY backend (stream OR http export, which has no stream conf) we synthesize a
 * minimal conf carrying just the origin connection params — the only fields the
 * wire client reads are cache_origin_host/port/tls (+ trusted_ca, TLS-only). */
typedef struct {
    ngx_stream_xrootd_srv_conf_t *conf;    /* origin params (real or synthetic) */
    ngx_stream_xrootd_srv_conf_t *synth;   /* owned synthetic conf, or NULL */
    char                          host[256];
    char                          bearer[4096]; /* §14/C-3 ztn token ("" = anon) */
    char                          x509_proxy[1024]; /* §14/C-3 GSI proxy path */
    char                          ca_dir[1024];     /* §14/C-3 GSI origin-cert CA */
    char                          sss_keytab[1024]; /* §14 SSS shared-secret keytab */
} sd_xroot_inst_state;

/* Per-open state: a live origin connection + open file handle + the synthetic
 * fill-task the origin functions need (conf + clean_path + error scratch). */
typedef struct {
    xrootd_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    xrootd_cache_fill_t        *t;
    int                         file_open;   /* 1 once kXR_open succeeded */
    int                         is_write;    /* 1 = opened for write (open_write) */
} sd_xroot_obj_state;

/* Map a fill-task XRootD error (kXR_*) to an errno-style fact for *err_out. */
static int
sd_xroot_errno(const xrootd_cache_fill_t *t)
{
    switch (t->xrd_error) {
    case kXR_NotFound:      return ENOENT;
    case kXR_NotAuthorized: return EACCES;
    case kXR_isDirectory:   return EISDIR;
    default:                return EIO;
    }
}

static void
sd_xroot_obj_teardown(sd_xroot_obj_state *st)
{
    if (st == NULL) {
        return;
    }
    if (st->file_open) {
        xrootd_cache_origin_close_file(&st->oc, st->fhandle);
    }
    xrootd_cache_origin_close(&st->oc);
    free(st->t);
    free(st);
}

/* Open the origin file: connect → bootstrap (handshake + anon login) → kXR_open.
 * `want_write` selects kXR_open(update+delete+mkpath) (a fresh writable handle,
 * size 0) over the read open (read|retstat for the size). Returns the populated
 * object state, or NULL with *err_out set. */
static sd_xroot_obj_state *
sd_xroot_origin_open(ngx_stream_xrootd_srv_conf_t *conf, const char *path,
    int want_write, mode_t mode, off_t *size_out, int *err_out)
{
    sd_xroot_obj_state *st = calloc(1, sizeof(*st));
    xrootd_cache_fill_t *t = calloc(1, sizeof(*t));

    if (st == NULL || t == NULL) {
        free(st);
        free(t);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    st->t      = t;
    st->oc.fd  = -1;
    t->conf    = conf;
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) path,
                sizeof(t->clean_path));

    if (xrootd_cache_origin_connect(t, &st->oc) != 0
        || xrootd_cache_origin_bootstrap(t, &st->oc) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        sd_xroot_obj_teardown(st);
        return NULL;
    }

    if (want_write) {
        uint16_t mode_bits = (uint16_t) ((mode != 0) ? (mode & 0777) : 0644);

        if (xrootd_cache_origin_open_write(t, &st->oc, path, mode_bits,
                                           st->fhandle) != 0)
        {
            if (err_out) { *err_out = sd_xroot_errno(t); }
            sd_xroot_obj_teardown(st);
            return NULL;
        }
        st->is_write = 1;
        if (size_out) { *size_out = 0; }     /* open_write truncates to empty */
    } else {
        if (xrootd_cache_origin_open(t, &st->oc, st->fhandle) != 0) {
            if (err_out) { *err_out = sd_xroot_errno(t); }
            sd_xroot_obj_teardown(st);
            return NULL;
        }
        if (size_out) { *size_out = t->file_size; }
    }
    st->file_open = 1;
    return st;
}

static xrootd_sd_obj_t *
sd_xroot_open(xrootd_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    xrootd_sd_obj_t     *obj;
    off_t                size = 0;
    int                  want_write;

    want_write = (sd_flags & (XROOTD_SD_O_WRITE | XROOTD_SD_O_CREATE
                              | XROOTD_SD_O_TRUNC | XROOTD_SD_O_APPEND)) != 0;

    st = sd_xroot_origin_open(is->conf, path, want_write, mode, &size, err_out);
    if (st == NULL) {
        return NULL;
    }

    obj = calloc(1, sizeof(*obj));
    if (obj == NULL) {
        sd_xroot_obj_teardown(st);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    obj->driver      = inst->driver;
    obj->inst        = inst;
    obj->fd          = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state       = st;
    obj->heap_shell  = 1;
    obj->snap.size   = size;
    obj->snap.mode   = S_IFREG | (want_write ? 0644 : 0444);
    obj->snap.is_reg = 1;
    return obj;
}

static ngx_int_t
sd_xroot_close(xrootd_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        sd_xroot_obj_teardown(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

static ssize_t
sd_xroot_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;
    xrootd_cache_sink_t sink;
    size_t              got = 0;

    if (len == 0) {
        return 0;
    }
    ngx_memzero(&sink, sizeof(sink));
    sink.fd      = -1;
    sink.mem     = buf;
    sink.mem_cap = len;

    if (xrootd_cache_origin_read_chunk(st->t, &st->oc, st->fhandle, &sink,
                                       (uint64_t) off, 0, len, &got) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) got;
}

/* Write `len` bytes at `off` to the origin file via kXR_write. The origin file
 * is offset-addressed, so sequential and random writes both map directly. Only
 * valid on a write handle. Returns bytes written, or -1 with errno. */
static ssize_t
sd_xroot_pwrite(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (xrootd_cache_origin_write_chunk(st->t, &st->oc, st->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* kXR_truncate the origin file. Write handles only. */
static ngx_int_t
sd_xroot_ftruncate(xrootd_sd_obj_t *obj, off_t len)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return NGX_ERROR;
    }
    if (xrootd_cache_origin_truncate(st->t, &st->oc, st->fhandle,
                                     (uint64_t) len) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* kXR_sync the origin file (flush to stable storage). A no-op on a read handle. */
static ngx_int_t
sd_xroot_fsync(xrootd_sd_obj_t *obj)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        return NGX_OK;
    }
    if (xrootd_cache_origin_sync(st->t, &st->oc, st->fhandle) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
sd_xroot_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_xroot_stat(xrootd_sd_instance_t *inst, const char *path,
    xrootd_sd_stat_t *out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    off_t                size = 0;
    int                  e = 0;

    st = sd_xroot_origin_open(is->conf, path, 0 /* read */, 0, &size, &e);
    if (st == NULL) {
        errno = e;
        return NGX_ERROR;
    }
    sd_xroot_obj_teardown(st);

    ngx_memzero(out, sizeof(*out));
    out->size   = size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

/* ---- staged atomic publish (Mode A passthrough) --------------------------- *
 * The staged handle is a live origin write handle. With NO local staging store
 * the write streams straight to the FINAL remote path (transparent write-through,
 * no local copy), so it is NOT atomic — a failed upload can leave a partial object
 * on the origin. Configure a local staging directory (Mode B) for atomic / durable
 * publish (a later phase). The opaque xrootd_sd_staged_t (sd.h) carries our state
 * in ->state. */

typedef struct {
    xrootd_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    xrootd_cache_fill_t        *t;
    int                         file_open;
} sd_xroot_staged_state;

/* Free a staged handle + its origin connection (closing an open file handle). */
static void
sd_xroot_staged_teardown(xrootd_sd_staged_t *handle)
{
    sd_xroot_staged_state *ss;

    if (handle == NULL) {
        return;
    }
    ss = handle->state;
    if (ss != NULL) {
        if (ss->file_open) {
            xrootd_cache_origin_close_file(&ss->oc, ss->fhandle);
        }
        xrootd_cache_origin_close(&ss->oc);
        free(ss->t);
        free(ss);
    }
    free(handle);
}

static xrootd_sd_staged_t *
sd_xroot_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_xroot_inst_state   *is = inst->state;
    xrootd_sd_staged_t    *handle = calloc(1, sizeof(*handle));
    sd_xroot_staged_state *ss = calloc(1, sizeof(*ss));
    xrootd_cache_fill_t   *t = calloc(1, sizeof(*t));

    if (handle == NULL || ss == NULL || t == NULL) {
        free(handle);
        free(ss);
        free(t);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->t     = t;
    ss->oc.fd = -1;
    t->conf   = is->conf;
    ngx_cpystrn((u_char *) t->clean_path, (u_char *) final_path,
                sizeof(t->clean_path));

    if (xrootd_cache_origin_connect(t, &ss->oc) != 0
        || xrootd_cache_origin_bootstrap(t, &ss->oc) != 0
        || xrootd_cache_origin_open_write(t, &ss->oc, final_path,
               (uint16_t) ((mode != 0) ? (mode & 0777) : 0644), ss->fhandle) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        xrootd_cache_origin_close(&ss->oc);
        free(t);
        free(ss);
        free(handle);
        return NULL;
    }
    ss->file_open = 1;
    handle->inst  = inst;
    handle->state = ss;
    return handle;
}

static ssize_t
sd_xroot_staged_write(xrootd_sd_staged_t *handle, const void *buf, size_t len,
    off_t off)
{
    sd_xroot_staged_state *ss = handle->state;

    if (len == 0) {
        return 0;
    }
    if (xrootd_cache_origin_write_chunk(ss->t, &ss->oc, ss->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* Publish: sync + close the origin file. On success the handle is consumed (freed);
 * on failure it stays valid for the caller to staged_abort. `noreplace` cannot be
 * enforced on a Mode-A direct write (open_write already created the destination) —
 * use a staging dir (Mode B) for exclusive/atomic publish. */
static ngx_int_t
sd_xroot_staged_commit(xrootd_sd_staged_t *handle, int noreplace)
{
    sd_xroot_staged_state *ss = handle->state;

    (void) noreplace;

    if (xrootd_cache_origin_sync(ss->t, &ss->oc, ss->fhandle) != 0) {
        return NGX_ERROR;                    /* leave valid; caller aborts */
    }
    sd_xroot_staged_teardown(handle);        /* close_file + free (consumed) */
    return NGX_OK;
}

static void
sd_xroot_staged_abort(xrootd_sd_staged_t *handle)
{
    /* Mode A: the partial bytes already streamed to the final remote path; closing
     * leaves them (non-atomic by design). Mode B staging gives a clean abort. */
    sd_xroot_staged_teardown(handle);
}

/* Vectored read: serve each iov segment from the origin (contiguous from `off`).
 * Reuses sd_xroot_pread per segment — short read on any segment ends the read. */
static ssize_t
sd_xroot_preadv(xrootd_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_xroot_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                   off + total);
        if (n < 0) {
            return (total > 0) ? total : -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                               /* short read = EOF */
        }
    }
    return total;
}

/* ---- namespace + metadata (path-based, fresh anonymous session per op) ----- */

/* The kXR_fattr protocol handler stores a user attribute "X" under the on-disk key
 * "user.U.X" (XROOTD_FATTR_XKEY_PFX, applied ABOVE the VFS). When we forward to
 * ANOTHER xrootd server it re-applies the SAME mapping, so handing it the already-
 * mapped key would double-prefix it on the origin ("user.U.user.U.X") and break
 * direct-origin interop. So strip one "user.U." before forwarding get/set/remove,
 * and re-add it on list — the origin then carries a single, standard "user.U.X".
 * (Kept in sync with src/fattr/ngx_xrootd_fattr.h rather than #included, to avoid a
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
sd_xroot_session(ngx_stream_xrootd_srv_conf_t *conf,
    xrootd_cache_origin_conn_t *oc, xrootd_cache_fill_t **t_out, int *err_out)
{
    xrootd_cache_fill_t *t = calloc(1, sizeof(*t));

    if (t == NULL) {
        if (err_out) { *err_out = ENOMEM; }
        return -1;
    }
    oc->fd  = -1;
    t->conf = conf;
    if (xrootd_cache_origin_connect(t, oc) != 0
        || xrootd_cache_origin_bootstrap(t, oc) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        xrootd_cache_origin_close(oc);
        free(t);
        return -1;
    }
    *t_out = t;
    return 0;
}

static ssize_t
sd_xroot_getxattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    ssize_t                     n;
    int                         e = 0;

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return -1; }
    n = xrootd_cache_origin_getfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                     buf, cap);
    e = errno;
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return n;
}

static ssize_t
sd_xroot_listxattr(xrootd_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
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
    n = xrootd_cache_origin_listfattr(t, &oc, path, raw, rawcap);
    e = errno;
    xrootd_cache_origin_close(&oc);
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

static ngx_int_t
sd_xroot_setxattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) flags;   /* XATTR_CREATE/REPLACE not distinguished on the wire here */
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = xrootd_cache_origin_setfattr(t, &oc, path, sd_xroot_fattr_unmap(name),
                                      val, len);
    e = errno;
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_xroot_removexattr(xrootd_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    int                         rc, e = 0;

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = xrootd_cache_origin_delfattr(t, &oc, path, sd_xroot_fattr_unmap(name));
    e = errno;
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_xroot_rename(xrootd_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    int                         rc, e = 0;

    (void) noreplace;   /* kXR_mv has no NOREPLACE flag; overwrite is the default */
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = xrootd_cache_origin_rename(t, &oc, src, dst);
    e = errno;
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* Delete a file on the remote node (kXR_rm). Required so a remote xroot node can
 * serve as a cache_store (cstore eviction) or a stage_store (post-flush reclaim of
 * the staged copy). Only regular files are removed; is_dir is refused (no
 * kXR_rmdir path over the wire yet). Returns NGX_OK / NGX_ERROR (errno set). */
static ngx_int_t
sd_xroot_unlink(xrootd_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    int                         rc, e = 0;

    if (is_dir) {
        errno = ENOSYS;                 /* directory removal over the wire: TODO */
        return NGX_ERROR;
    }
    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }
    rc = xrootd_cache_origin_rm(t, &oc, path);
    e = errno;
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc == 0 ? NGX_OK : NGX_ERROR;
}

/* Copy src→dst byte stream on an open session (read each chunk from src_fh, write
 * to dst_fh), then truncate+sync dst. Returns NGX_OK + *bytes_out, or NGX_ERROR. */
static ngx_int_t
sd_xroot_copy_body(xrootd_cache_fill_t *t, xrootd_cache_origin_conn_t *oc,
    const u_char *src_fh, const u_char *dst_fh, off_t *bytes_out)
{
    const size_t cap = 1u << 20;
    u_char      *buf = malloc(cap);
    off_t        off = 0;

    if (buf == NULL) { errno = ENOMEM; return NGX_ERROR; }

    for (;;) {
        xrootd_cache_sink_t sink;
        size_t              got = 0;

        ngx_memzero(&sink, sizeof(sink));
        sink.fd = -1;
        sink.mem = buf;
        sink.mem_cap = cap;
        if (xrootd_cache_origin_read_chunk(t, oc, src_fh, &sink, (uint64_t) off,
                                           0, cap, &got) != 0)
        {
            free(buf); errno = EIO; return NGX_ERROR;
        }
        if (got == 0) {
            break;
        }
        if (xrootd_cache_origin_write_chunk(t, oc, dst_fh, (uint64_t) off, buf,
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

    if (xrootd_cache_origin_truncate(t, oc, dst_fh, (uint64_t) off) != 0
        || xrootd_cache_origin_sync(t, oc, dst_fh) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    if (bytes_out) { *bytes_out = off; }
    return NGX_OK;
}

/* Server-side copy: the gateway reads src and writes dst on the origin (no client
 * round-trip). Not zero-copy on the origin (no remote TPC) — a read+write relay. */
static ngx_int_t
sd_xroot_server_copy(xrootd_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    sd_xroot_inst_state        *is = inst->state;
    xrootd_cache_origin_conn_t  oc;
    xrootd_cache_fill_t        *t;
    u_char                      src_fh[XRD_FHANDLE_LEN], dst_fh[XRD_FHANDLE_LEN];
    ngx_int_t                   rc;
    int                         e = 0;

    if (sd_xroot_session(is->conf, &oc, &t, &e) != 0) { errno = e; return NGX_ERROR; }

    ngx_cpystrn((u_char *) t->clean_path, (u_char *) src, sizeof(t->clean_path));
    if (xrootd_cache_origin_open(t, &oc, src_fh) != 0) {
        e = sd_xroot_errno(t);
        xrootd_cache_origin_close(&oc); free(t); errno = e; return NGX_ERROR;
    }
    if (xrootd_cache_origin_open_write(t, &oc, dst, 0644, dst_fh) != 0) {
        e = sd_xroot_errno(t);
        xrootd_cache_origin_close_file(&oc, src_fh);
        xrootd_cache_origin_close(&oc); free(t); errno = e; return NGX_ERROR;
    }

    rc = sd_xroot_copy_body(t, &oc, src_fh, dst_fh, bytes_out);
    e  = errno;
    xrootd_cache_origin_close_file(&oc, dst_fh);
    xrootd_cache_origin_close_file(&oc, src_fh);
    xrootd_cache_origin_close(&oc);
    free(t);
    errno = e;
    return rc;
}

/* Remote root:// driver (anonymous). Read slots + the write data path
 * (pwrite/ftruncate/fsync over kXR_write/_truncate/_sync) — the foundation for a
 * writable remote backend (Phase 1; staged-write and namespace slots are later
 * phases). No fd, so reads/writes are memory-served like every object backend. */
static const xrootd_sd_driver_t xrootd_sd_xroot_driver = {
    .name      = "xroot",
    .caps      = XROOTD_SD_CAP_RANGE_READ | XROOTD_SD_CAP_RANDOM_WRITE
                 | XROOTD_SD_CAP_TRUNCATE | XROOTD_SD_CAP_XATTR
                 | XROOTD_SD_CAP_HARD_RENAME | XROOTD_SD_CAP_SERVER_COPY,
    .open          = sd_xroot_open,
    .close         = sd_xroot_close,
    .pread         = sd_xroot_pread,
    .preadv        = sd_xroot_preadv,
    .pwrite        = sd_xroot_pwrite,
    .fstat         = sd_xroot_fstat,
    .ftruncate     = sd_xroot_ftruncate,
    .fsync         = sd_xroot_fsync,
    .stat          = sd_xroot_stat,
    .rename        = sd_xroot_rename,
    .unlink        = sd_xroot_unlink,
    .server_copy   = sd_xroot_server_copy,
    .getxattr      = sd_xroot_getxattr,
    .listxattr     = sd_xroot_listxattr,
    .setxattr      = sd_xroot_setxattr,
    .removexattr   = sd_xroot_removexattr,
    .staged_open   = sd_xroot_staged_open,
    .staged_write  = sd_xroot_staged_write,
    .staged_commit = sd_xroot_staged_commit,
    .staged_abort  = sd_xroot_staged_abort,
};

void
xrootd_sd_xroot_query_checksum(xrootd_sd_obj_t *obj, char *alg, size_t algsz,
    char *hex, size_t hexsz)
{
    sd_xroot_obj_state *st;

    if (algsz) { alg[0] = '\0'; }
    if (hexsz) { hex[0] = '\0'; }
    if (obj == NULL || obj->state == NULL) {
        return;
    }
    st = obj->state;
    (void) xrootd_cache_origin_query_checksum(st->t, &st->oc, alg, algsz,
                                              hex, hexsz);
}

xrootd_sd_instance_t *
xrootd_sd_xroot_create(void *conf, ngx_log_t *log)
{
    xrootd_sd_instance_t *inst;
    sd_xroot_inst_state  *is;

    if (conf == NULL) {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    is->conf     = conf;
    is->synth    = NULL;                       /* borrowed real conf */
    inst->driver = &xrootd_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

xrootd_sd_instance_t *
xrootd_sd_xroot_create_origin(const char *host, int port, int tls,
    int af_policy, const char *bearer, const char *x509_proxy,
    const char *ca_dir, const char *sss_keytab, ngx_log_t *log)
{
    xrootd_sd_instance_t         *inst;
    sd_xroot_inst_state          *is;
    ngx_stream_xrootd_srv_conf_t *synth;

    if (host == NULL || host[0] == '\0' || port <= 0 || port > 65535) {
        errno = EINVAL;
        return NULL;
    }
    inst  = calloc(1, sizeof(*inst));
    is    = calloc(1, sizeof(*is));
    synth = calloc(1, sizeof(*synth));         /* minimal: just the origin params */
    if (inst == NULL || is == NULL || synth == NULL) {
        free(inst);
        free(is);
        free(synth);
        errno = ENOMEM;
        return NULL;
    }
    ngx_cpystrn((u_char *) is->host, (u_char *) host, sizeof(is->host));
    synth->cache_origin_host.data = (u_char *) is->host;
    synth->cache_origin_host.len  = ngx_strlen(is->host);
    synth->cache_origin_port      = (uint16_t) port;
    synth->cache_origin_tls       = tls ? 1 : 0;
    synth->cache_origin_family    = (ngx_uint_t) af_policy;

    /* §14/C-3: present this bearer via ztn when the origin demands authentication.
     * Store the bytes on the instance so synth's ngx_str_t stays valid for life. */
    if (bearer != NULL && bearer[0] != '\0') {
        ngx_cpystrn((u_char *) is->bearer, (u_char *) bearer, sizeof(is->bearer));
        synth->cache_origin_bearer.data = (u_char *) is->bearer;
        synth->cache_origin_bearer.len  = ngx_strlen(is->bearer);
    }
    if (x509_proxy != NULL && x509_proxy[0] != '\0') {
        ngx_cpystrn((u_char *) is->x509_proxy, (u_char *) x509_proxy,
                    sizeof(is->x509_proxy));
        synth->cache_origin_x509_proxy.data = (u_char *) is->x509_proxy;
        synth->cache_origin_x509_proxy.len  = ngx_strlen(is->x509_proxy);
    }
    /* §14 SSS: present a shared-secret credential minted from this keytab when the
     * origin advertises &P=sss. Bytes on the instance so synth's str stays valid. */
    if (sss_keytab != NULL && sss_keytab[0] != '\0') {
        ngx_cpystrn((u_char *) is->sss_keytab, (u_char *) sss_keytab,
                    sizeof(is->sss_keytab));
        synth->cache_origin_sss_keytab.data = (u_char *) is->sss_keytab;
        synth->cache_origin_sss_keytab.len  = ngx_strlen(is->sss_keytab);
    }
    if (ca_dir != NULL && ca_dir[0] != '\0') {
        struct stat ca_st;
        int         is_dir;
        int         crl_count = 0;

        ngx_cpystrn((u_char *) is->ca_dir, (u_char *) ca_dir, sizeof(is->ca_dir));
        synth->cache_origin_ca_dir.data = (u_char *) is->ca_dir;
        synth->cache_origin_ca_dir.len  = ngx_strlen(is->ca_dir);

        /* Build the verify store once (per worker): a hashed CA dir vs a bundle
         * file, with proxy certs allowed (GSI). Failure leaves gsi_store NULL ⇒ the
         * handshake then refuses rather than trusting an unverifiable origin. */
        is_dir = (stat(is->ca_dir, &ca_st) == 0 && S_ISDIR(ca_st.st_mode));
        synth->gsi_store = xrootd_build_ca_store(log,
            is_dir ? is->ca_dir : NULL, is_dir ? NULL : is->ca_dir, NULL,
            X509_V_FLAG_ALLOW_PROXY_CERTS, &crl_count);
        if (synth->gsi_store == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "xrootd: gsi origin CA store build failed for \"%s\" — GSI to this "
                "origin will be refused", ca_dir);
        }
    }

    is->conf     = synth;
    is->synth    = synth;                       /* owned: free on destroy */
    inst->driver = &xrootd_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
xrootd_sd_xroot_destroy(xrootd_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    if (inst->state != NULL) {
        sd_xroot_inst_state *is = inst->state;

        if (is->synth != NULL && is->synth->gsi_store != NULL) {
            X509_STORE_free(is->synth->gsi_store);
        }
        free(is->synth);
    }
    free(inst->state);
    free(inst);
}
