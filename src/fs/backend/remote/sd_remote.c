/*
 * sd_remote.c — read-only remote-origin storage driver. See the header.
 *
 * s3:// delegates entirely to the shared S3 driver (sd_s3): the SD object wraps an
 * sd_s3_file*; pread is a signed Range GET; stat/fstat report the HEAD size. Only
 * the read slots are populated — the driver advertises CAP_RANGE_READ alone.
 */

#include "sd_remote.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Per-open state: the delegated S3 read handle. */
typedef struct {
    sd_s3_file *s3;
} sd_remote_obj_state;

/* Per-staged-write state: the delegated S3 write handle. */
typedef struct {
    sd_s3_file *s3;
} sd_remote_staged_state;

/* Multipart part size for a staged upload of unknown final size (S3's 5 MiB
 * minimum for non-final parts; 16 MiB balances request count vs. buffering). */
#define SD_REMOTE_PART_SIZE  (16 * 1024 * 1024)

/* Compose the sd_s3 object path "/bucket/key" from the instance bucket and the
 * export-relative key (which already carries a leading '/'). */
static void
sd_remote_s3_key(const brix_sd_remote_cfg_t *cfg, const char *key,
    char *dst, size_t dstcap)
{
    snprintf(dst, dstcap, "/%s%s", cfg->bucket, (key != NULL) ? key : "/");
}

/* Fill sd_s3_open_params from the instance config + a composed object path. */
static void
sd_remote_s3_params(const brix_sd_remote_cfg_t *cfg, const char *objpath,
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

static brix_sd_obj_t *
sd_remote_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    sd_remote_obj_state          *st;
    brix_sd_obj_t              *obj;
    int64_t                       size = 0;

    (void) mode;

    /* Read-only origin: refuse any write/create/trunc intent up front. */
    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND)) {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (err_out) { *err_out = ENOMEM; }   /* open_read only fails on bad args/OOM */
        return NULL;
    }
    if (sd_s3_size(s3, &size, errbuf, sizeof(errbuf)) != 0) {
        int e = errno;                         /* HEAD set errno (ENOENT on 404) */

        sd_s3_close(s3);
        if (err_out) { *err_out = e ? e : EIO; }
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
sd_remote_close(brix_sd_obj_t *obj)
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
sd_remote_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
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
sd_remote_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_remote_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
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

/* ---- write path (SP3): the S3 store as a writable backend / cache / stage tier.
 * A staged write delegates to sd_s3's single-PUT/multipart upload; the object only
 * becomes visible at commit, so a staged upload is atomic from the reader's view. */

static brix_sd_staged_t *
sd_remote_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];
    sd_s3_file                   *s3;
    sd_remote_staged_state       *ss;
    brix_sd_staged_t           *h;

    (void) mode;
    sd_remote_s3_key(cfg, final_path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);

    /* Unknown final size -> multipart upload (handles any object size). */
    s3 = sd_s3_open_write(&p, -1, SD_REMOTE_PART_SIZE, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        if (err_out) { *err_out = EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        free(ss);
        free(h);
        sd_s3_abort(s3);
        sd_s3_close(s3);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->s3   = s3;
    h->inst  = inst;
    h->state = ss;
    return h;
}

static ssize_t
sd_remote_staged_write(brix_sd_staged_t *h, const void *buf, size_t len,
    off_t off)
{
    sd_remote_staged_state *ss = h->state;
    char                    errbuf[256];

    if (sd_s3_pwrite(ss->s3, buf, len, off, errbuf, sizeof(errbuf)) != 0) {
        errno = EIO;
        return -1;
    }
    return (ssize_t) len;
}

static ngx_int_t
sd_remote_staged_commit(brix_sd_staged_t *h, int noreplace)
{
    sd_remote_staged_state *ss = h->state;
    char                    errbuf[256];
    int                     rc;

    (void) noreplace;                          /* S3 PUT/MPU always replaces */
    rc = sd_s3_commit(ss->s3, errbuf, sizeof(errbuf));
    sd_s3_close(ss->s3);
    free(ss);
    free(h);
    if (rc != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
sd_remote_staged_abort(brix_sd_staged_t *h)
{
    sd_remote_staged_state *ss = h->state;

    sd_s3_abort(ss->s3);
    sd_s3_close(ss->s3);
    free(ss);
    free(h);
}

static ngx_int_t
sd_remote_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_s3_open_params             p;
    char                          objpath[768];
    char                          errbuf[256];

    (void) is_dir;
    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    sd_remote_s3_params(cfg, objpath, &p);

    if (sd_s3_delete(&p, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Read + write: the S3 store serves as a read origin (Range GET) and a writable
 * cache_store / stage_store / backend (staged single-PUT / multipart upload, plus
 * DELETE for eviction and post-flush stage cleanup). */
static const brix_sd_driver_t brix_sd_remote_driver = {
    .name  = "remote",
    .caps  = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE,
    .open  = sd_remote_open,
    .close = sd_remote_close,
    .pread = sd_remote_pread,
    .fstat = sd_remote_fstat,
    .stat  = sd_remote_stat,
    .unlink        = sd_remote_unlink,
    .staged_open   = sd_remote_staged_open,
    .staged_write  = sd_remote_staged_write,
    .staged_commit = sd_remote_staged_commit,
    .staged_abort  = sd_remote_staged_abort,
};

brix_sd_instance_t *
brix_sd_remote_create(const brix_sd_remote_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t   *inst;
    brix_sd_remote_cfg_t *copy;

    if (cfg == NULL || cfg->scheme != BRIX_SD_REMOTE_S3
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

    inst->driver = &brix_sd_remote_driver;
    inst->log    = log;
    inst->pool   = NULL;          /* malloc-owned: safe off the event loop */
    inst->state  = copy;
    return inst;
}

void
brix_sd_remote_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}
