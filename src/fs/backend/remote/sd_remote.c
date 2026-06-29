/*
 * sd_remote.c — read-only remote-origin storage driver. See the header.
 *
 * s3:// delegates entirely to the shared S3 driver (sd_s3): the SD object wraps an
 * sd_s3_file*; pread is a signed Range GET; stat/fstat report the HEAD size. Only
 * the read slots are populated — the driver advertises CAP_RANGE_READ alone.
 */

#include "sd_remote.h"
#include "../s3/sd_s3.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Per-open state: the delegated S3 read handle. */
typedef struct {
    sd_s3_file *s3;
} sd_remote_obj_state;

/* Compose the sd_s3 object path "/bucket/key" from the instance bucket and the
 * export-relative key (which already carries a leading '/'). */
static void
sd_remote_s3_key(const xrootd_sd_remote_cfg_t *cfg, const char *key,
    char *dst, size_t dstcap)
{
    snprintf(dst, dstcap, "/%s%s", cfg->bucket, (key != NULL) ? key : "/");
}

/* Fill sd_s3_open_params from the instance config + a composed object path. */
static void
sd_remote_s3_params(const xrootd_sd_remote_cfg_t *cfg, const char *objpath,
    sd_s3_open_params *p)
{
    memset(p, 0, sizeof(*p));
    p->host       = cfg->host;
    p->port       = cfg->port;
    p->tls        = cfg->tls;
    p->key        = objpath;
    p->ak         = cfg->access_key;
    p->sk         = cfg->secret_key;
    p->region     = cfg->region;
    p->transport  = cfg->transport;
    p->tctx       = cfg->tctx;
    p->timeout_ms = cfg->timeout_ms;
}

static xrootd_sd_obj_t *
sd_remote_open(xrootd_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    const xrootd_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    sd_remote_obj_state          *st;
    xrootd_sd_obj_t              *obj;
    int64_t                       size = 0;

    (void) mode;

    /* Read-only origin: refuse any write/create/trunc intent up front. */
    if (sd_flags & (XROOTD_SD_O_WRITE | XROOTD_SD_O_CREATE | XROOTD_SD_O_TRUNC
                    | XROOTD_SD_O_APPEND)) {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (err_out) { *err_out = ENOENT; }   /* origin miss / unreachable */
        return NULL;
    }
    if (sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) != 0) {
        sd_s3_close(s3);
        if (err_out) { *err_out = EIO; }
        return NULL;
    }

    st  = calloc(1, sizeof(*st));
    obj = calloc(1, sizeof(*obj));
    if (st == NULL || obj == NULL) {
        free(st);
        free(obj);
        sd_s3_close(s3);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    st->s3 = s3;

    obj->driver        = inst->driver;
    obj->inst          = inst;
    obj->fd            = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state         = st;
    obj->heap_shell    = 1;                    /* malloc'd shell; caller may free */
    obj->snap.size     = (off_t) size;
    obj->snap.mode     = S_IFREG | 0444;
    obj->snap.is_reg   = 1;

    return obj;
}

static ngx_int_t
sd_remote_close(xrootd_sd_obj_t *obj)
{
    sd_remote_obj_state *st;

    if (obj == NULL || obj->state == NULL) {
        return NGX_OK;
    }
    st = obj->state;
    sd_s3_close(st->s3);
    free(st);
    obj->state = NULL;
    return NGX_OK;
}

static ssize_t
sd_remote_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_remote_obj_state *st = obj->state;
    char                 errbuf[256];
    ssize_t              n;

    n = sd_s3_pread(st->s3, buf, len, off, errbuf, sizeof(errbuf));
    if (n < 0) {
        errno = EIO;
        return -1;
    }
    return n;
}

static ngx_int_t
sd_remote_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_remote_stat(xrootd_sd_instance_t *inst, const char *path,
    xrootd_sd_stat_t *out)
{
    const xrootd_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    int64_t                       size = 0;

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) != 0) {
        sd_s3_close(s3);
        errno = EIO;
        return NGX_ERROR;
    }
    sd_s3_close(s3);

    memset(out, 0, sizeof(*out));
    out->size   = (off_t) size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

/* Read-only remote driver: only the read slots are populated. The absent write/
 * dir/xattr/staged slots make it impossible to use as a writable export primary. */
static const xrootd_sd_driver_t xrootd_sd_remote_driver = {
    .name  = "remote",
    .caps  = XROOTD_SD_CAP_RANGE_READ,
    .open  = sd_remote_open,
    .close = sd_remote_close,
    .pread = sd_remote_pread,
    .fstat = sd_remote_fstat,
    .stat  = sd_remote_stat,
};

xrootd_sd_instance_t *
xrootd_sd_remote_create(const xrootd_sd_remote_cfg_t *cfg, ngx_log_t *log)
{
    xrootd_sd_instance_t   *inst;
    xrootd_sd_remote_cfg_t *copy;

    if (cfg == NULL || cfg->scheme != XROOTD_SD_REMOTE_S3
        || cfg->transport == NULL) {
        errno = EINVAL;
        return NULL;
    }

    inst = calloc(1, sizeof(*inst));
    copy = malloc(sizeof(*copy));
    if (inst == NULL || copy == NULL) {
        free(inst);
        free(copy);
        errno = ENOMEM;
        return NULL;
    }
    *copy = *cfg;

    inst->driver = &xrootd_sd_remote_driver;
    inst->log    = log;
    inst->pool   = NULL;          /* malloc-owned: safe off the event loop */
    inst->state  = copy;
    return inst;
}

void
xrootd_sd_remote_destroy(xrootd_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}
