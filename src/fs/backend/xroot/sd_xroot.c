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
#include "sd_xroot_internal.h"    /* inst_state + errno + ns ops (split out) */
#include "fs/cache/cache_internal.h"   /* origin wire client + fill-task ctx */
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI MITM verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Per-open state: a live origin connection + open file handle + the synthetic
 * fill-task the origin functions need (conf + clean_path + error scratch). */
typedef struct {
    brix_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    brix_cache_fill_t        *t;
    int                         file_open;   /* 1 once kXR_open succeeded */
    int                         is_write;    /* 1 = opened for write (open_write) */
} sd_xroot_obj_state;

/* Map a fill-task XRootD error (kXR_*) to an errno-style fact for *err_out. */
int
sd_xroot_errno(const brix_cache_fill_t *t)
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
        brix_cache_origin_close_file(&st->oc, st->fhandle);
    }
    brix_cache_origin_close(&st->oc);
    free(st->t);
    free(st);
}

/* Open the origin file: connect → bootstrap (handshake + anon login) → kXR_open.
 * `want_write` selects kXR_open(update+delete+mkpath) (a fresh writable handle,
 * size 0) over the read open (read|retstat for the size). Returns the populated
 * object state, or NULL with *err_out set. */
static sd_xroot_obj_state *
sd_xroot_origin_open(ngx_stream_brix_srv_conf_t *conf, const char *path,
    int want_write, mode_t mode, off_t *size_out, int *err_out)
{
    sd_xroot_obj_state *st = calloc(1, sizeof(*st));
    brix_cache_fill_t *t = calloc(1, sizeof(*t));

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

    if (brix_cache_origin_connect(t, &st->oc) != 0
        || brix_cache_origin_bootstrap(t, &st->oc) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        sd_xroot_obj_teardown(st);
        return NULL;
    }

    if (want_write) {
        uint16_t mode_bits = (uint16_t) ((mode != 0) ? (mode & 0777) : 0644);

        if (brix_cache_origin_open_write(t, &st->oc, path, mode_bits,
                                           st->fhandle) != 0)
        {
            if (err_out) { *err_out = sd_xroot_errno(t); }
            sd_xroot_obj_teardown(st);
            return NULL;
        }
        st->is_write = 1;
        if (size_out) { *size_out = 0; }     /* open_write truncates to empty */
    } else {
        if (brix_cache_origin_open(t, &st->oc, st->fhandle) != 0) {
            if (err_out) { *err_out = sd_xroot_errno(t); }
            sd_xroot_obj_teardown(st);
            return NULL;
        }
        if (size_out) { *size_out = t->file_size; }
    }
    st->file_open = 1;
    return st;
}

static brix_sd_obj_t *
sd_xroot_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_xroot_inst_state *is = inst->state;
    sd_xroot_obj_state  *st;
    brix_sd_obj_t     *obj;
    off_t                size = 0;
    int                  want_write;

    want_write = (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                              | BRIX_SD_O_TRUNC | BRIX_SD_O_APPEND)) != 0;

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
sd_xroot_close(brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        sd_xroot_obj_teardown(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

static ssize_t
sd_xroot_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;
    brix_cache_sink_t sink;
    size_t              got = 0;

    if (len == 0) {
        return 0;
    }
    ngx_memzero(&sink, sizeof(sink));
    sink.fd      = -1;
    sink.mem     = buf;
    sink.mem_cap = len;

    if (brix_cache_origin_read_chunk(st->t, &st->oc, st->fhandle, &sink,
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
sd_xroot_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (brix_cache_origin_write_chunk(st->t, &st->oc, st->fhandle,
            (uint64_t) off, (const u_char *) buf, len) != 0)
    {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

/* kXR_truncate the origin file. Write handles only. */
static ngx_int_t
sd_xroot_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        errno = EBADF;
        return NGX_ERROR;
    }
    if (brix_cache_origin_truncate(st->t, &st->oc, st->fhandle,
                                     (uint64_t) len) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* kXR_sync the origin file (flush to stable storage). A no-op on a read handle. */
static ngx_int_t
sd_xroot_fsync(brix_sd_obj_t *obj)
{
    sd_xroot_obj_state *st = obj->state;

    if (st == NULL || !st->is_write) {
        return NGX_OK;
    }
    if (brix_cache_origin_sync(st->t, &st->oc, st->fhandle) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
sd_xroot_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_xroot_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
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
 * publish (a later phase). The opaque brix_sd_staged_t (sd.h) carries our state
 * in ->state. */

typedef struct {
    brix_cache_origin_conn_t  oc;
    u_char                      fhandle[XRD_FHANDLE_LEN];
    brix_cache_fill_t        *t;
    int                         file_open;
} sd_xroot_staged_state;

/* Free a staged handle + its origin connection (closing an open file handle). */
static void
sd_xroot_staged_teardown(brix_sd_staged_t *handle)
{
    sd_xroot_staged_state *ss;

    if (handle == NULL) {
        return;
    }
    ss = handle->state;
    if (ss != NULL) {
        if (ss->file_open) {
            brix_cache_origin_close_file(&ss->oc, ss->fhandle);
        }
        brix_cache_origin_close(&ss->oc);
        free(ss->t);
        free(ss);
    }
    free(handle);
}

static brix_sd_staged_t *
sd_xroot_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_xroot_inst_state   *is = inst->state;
    brix_sd_staged_t    *handle = calloc(1, sizeof(*handle));
    sd_xroot_staged_state *ss = calloc(1, sizeof(*ss));
    brix_cache_fill_t   *t = calloc(1, sizeof(*t));

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

    if (brix_cache_origin_connect(t, &ss->oc) != 0
        || brix_cache_origin_bootstrap(t, &ss->oc) != 0
        || brix_cache_origin_open_write(t, &ss->oc, final_path,
               (uint16_t) ((mode != 0) ? (mode & 0777) : 0644), ss->fhandle) != 0)
    {
        if (err_out) { *err_out = sd_xroot_errno(t); }
        brix_cache_origin_close(&ss->oc);
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
sd_xroot_staged_write(brix_sd_staged_t *handle, const void *buf, size_t len,
    off_t off)
{
    sd_xroot_staged_state *ss = handle->state;

    if (len == 0) {
        return 0;
    }
    if (brix_cache_origin_write_chunk(ss->t, &ss->oc, ss->fhandle,
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
sd_xroot_staged_commit(brix_sd_staged_t *handle, int noreplace)
{
    sd_xroot_staged_state *ss = handle->state;

    (void) noreplace;

    if (brix_cache_origin_sync(ss->t, &ss->oc, ss->fhandle) != 0) {
        return NGX_ERROR;                    /* leave valid; caller aborts */
    }
    sd_xroot_staged_teardown(handle);        /* close_file + free (consumed) */
    return NGX_OK;
}

static void
sd_xroot_staged_abort(brix_sd_staged_t *handle)
{
    /* Mode A: the partial bytes already streamed to the final remote path; closing
     * leaves them (non-atomic by design). Mode B staging gives a clean abort. */
    sd_xroot_staged_teardown(handle);
}

/* Vectored read: serve each iov segment from the origin (contiguous from `off`).
 * Reuses sd_xroot_pread per segment — short read on any segment ends the read. */
static ssize_t
sd_xroot_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
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


/* Remote root:// driver (anonymous). Read slots + the write data path
 * (pwrite/ftruncate/fsync over kXR_write/_truncate/_sync) — the foundation for a
 * writable remote backend (Phase 1; staged-write and namespace slots are later
 * phases). No fd, so reads/writes are memory-served like every object backend. */
static const brix_sd_driver_t brix_sd_xroot_driver = {
    .name      = "xroot",
    .caps      = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY,
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
brix_sd_xroot_query_checksum(brix_sd_obj_t *obj, char *alg, size_t algsz,
    char *hex, size_t hexsz)
{
    sd_xroot_obj_state *st;

    if (algsz) { alg[0] = '\0'; }
    if (hexsz) { hex[0] = '\0'; }
    if (obj == NULL || obj->state == NULL) {
        return;
    }
    st = obj->state;
    (void) brix_cache_origin_query_checksum(st->t, &st->oc, alg, algsz,
                                              hex, hexsz);
}

brix_sd_instance_t *
brix_sd_xroot_create(void *conf, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
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
    inst->driver = &brix_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

brix_sd_instance_t *
brix_sd_xroot_create_origin(const char *host, int port, int tls,
    int af_policy, const char *bearer, const char *x509_proxy,
    const char *ca_dir, const char *sss_keytab, ngx_log_t *log)
{
    brix_sd_instance_t         *inst;
    sd_xroot_inst_state          *is;
    ngx_stream_brix_srv_conf_t *synth;

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
        /* Outbound cache→origin client: keep the pre-existing trust behaviour
         * (no signing_policy namespace enforcement, best-effort CRL) so this
         * change does not alter which origins a cache node will talk to. */
        synth->gsi_store = brix_build_ca_store(log,
            is_dir ? is->ca_dir : NULL, is_dir ? NULL : is->ca_dir, NULL,
            X509_V_FLAG_ALLOW_PROXY_CERTS, &crl_count,
            BRIX_SP_MODE_OFF, BRIX_CRL_MODE_TRY);
        if (synth->gsi_store == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "brix: gsi origin CA store build failed for \"%s\" — GSI to this "
                "origin will be refused", ca_dir);
        }
    }

    is->conf     = synth;
    is->synth    = synth;                       /* owned: free on destroy */
    inst->driver = &brix_sd_xroot_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
brix_sd_xroot_destroy(brix_sd_instance_t *inst)
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
