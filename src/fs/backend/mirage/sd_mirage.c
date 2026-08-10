/*
 * sd_mirage.c — sizes-only SYNTHETIC storage backend (parity audit §3 row 14,
 * the Mirage zero-storage pattern-read analog).
 *
 * WHAT: a read-only backend that stores NOTHING: every path opens as a regular
 *       file of the configured size, and reads return a deterministic
 *       offset-derived byte pattern (byte at absolute offset o is
 *       (o * 131 + 7) & 0xFF), so any range read is independently verifiable
 *       by the client.
 * WHY:  protocol/throughput testing without disks — drive the full root://
 *       (or HTTP) stack at wire speed with zero storage behind it, exactly
 *       what stock's Mirage OSS is used for on WLCG links.
 * HOW:  no syscalls at all (tier-1 rule satisfied trivially): open heap-allocs
 *       the object shell (heap_shell — mirroring sd_block), pread/preadv fill
 *       the pattern clamped to the synthetic size, fstat/stat synthesize a
 *       fixed regular-file record. No CAP_FD (nothing to sendfile — reads are
 *       served through the memory path), no write caps: a write open is
 *       refused EROFS at the door.
 */

#include "fs/backend/sd.h"
#include "fs/backend/sd_registry.h"

#include <errno.h>
#include <string.h>

typedef struct {
    int64_t size;   /* every path reports/serves exactly this many bytes */
} sd_mirage_state_t;

/* byte at absolute offset o — keep in sync with the doc line above and the
 * pattern check in tests/test_mirage_backend.py. */
#define MIRAGE_BYTE(o)  ((u_char) (((uint64_t) (o) * 131u + 7u) & 0xFFu))

static ngx_int_t
sd_mirage_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_mirage_conf_t *conf = driver_conf;
    sd_mirage_state_t           *st;

    if (conf == NULL || conf->size < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->size = conf->size;
    inst->state = st;
    return NGX_OK;
}

static brix_sd_obj_t *
sd_mirage_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    brix_sd_obj_t *obj;

    (void) path;   /* every path names the same synthetic object */
    (void) mode;

    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND))
    {
        if (err_out != NULL) { *err_out = EROFS; }
        return NULL;
    }

    /* Heap shell, exactly like sd_block: open may run off the event loop and
     * inst->pool is not thread-safe. */
    obj = ngx_calloc(sizeof(*obj), inst->log);
    if (obj == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = NGX_INVALID_FILE;   /* nothing kernel-backed */
    obj->state      = NULL;
    obj->heap_shell = 1;
    return obj;
}

static ngx_int_t
sd_mirage_close(brix_sd_obj_t *obj)
{
    (void) obj;   /* no state, no fd; the shell is freed by the adopting layer */
    return NGX_OK;
}

static ssize_t
sd_mirage_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    const sd_mirage_state_t *st = obj->inst->state;
    u_char                  *p = buf;
    size_t                   i;

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    if (off >= st->size) {
        return 0;   /* EOF */
    }
    if ((int64_t) len > st->size - off) {
        len = (size_t) (st->size - off);
    }
    for (i = 0; i < len; i++) {
        p[i] = MIRAGE_BYTE((uint64_t) off + i);
    }
    return (ssize_t) len;
}

static ssize_t
sd_mirage_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_mirage_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                    off + total);
        if (n < 0) {
            return total > 0 ? total : n;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;   /* EOF inside this segment */
        }
    }
    return total;
}

/* Synthesize the one fixed record every path shares. */
static void
sd_mirage_fill_stat(const sd_mirage_state_t *st, brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = st->size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    out->mtime  = 1;   /* fixed nonzero epoch: synthetic, never "changes" */
    out->ctime  = 1;
    out->ino    = 1;
}

static ngx_int_t
sd_mirage_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_mirage_fill_stat(obj->inst->state, out);
    return NGX_OK;
}

static ngx_int_t
sd_mirage_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    (void) path;
    sd_mirage_fill_stat(inst->state, out);
    return NGX_OK;
}

const brix_sd_driver_t brix_sd_mirage_driver = {
    .name = "mirage",
    .caps = BRIX_SD_CAP_RANGE_READ,   /* read-only, memory-served, no kernel fd */

    .init   = sd_mirage_init,
    .open   = sd_mirage_open,
    .close  = sd_mirage_close,
    .pread  = sd_mirage_pread,
    .preadv = sd_mirage_preadv,
    .fstat  = sd_mirage_fstat,
    .stat   = sd_mirage_stat,
};
