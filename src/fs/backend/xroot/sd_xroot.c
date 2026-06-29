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
#include "../../../cache/cache_internal.h"   /* origin wire client + fill-task ctx */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Instance state: the server conf the origin client reads (host/port/tls/ssl_ctx). */
typedef struct {
    ngx_stream_xrootd_srv_conf_t *conf;
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

/* Remote root:// driver (anonymous). Read slots + the write data path
 * (pwrite/ftruncate/fsync over kXR_write/_truncate/_sync) — the foundation for a
 * writable remote backend (Phase 1; staged-write and namespace slots are later
 * phases). No fd, so reads/writes are memory-served like every object backend. */
static const xrootd_sd_driver_t xrootd_sd_xroot_driver = {
    .name      = "xroot",
    .caps      = XROOTD_SD_CAP_RANGE_READ | XROOTD_SD_CAP_RANDOM_WRITE
                 | XROOTD_SD_CAP_TRUNCATE,
    .open      = sd_xroot_open,
    .close     = sd_xroot_close,
    .pread     = sd_xroot_pread,
    .pwrite    = sd_xroot_pwrite,
    .fstat     = sd_xroot_fstat,
    .ftruncate = sd_xroot_ftruncate,
    .fsync     = sd_xroot_fsync,
    .stat      = sd_xroot_stat,
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
    free(inst->state);
    free(inst);
}
