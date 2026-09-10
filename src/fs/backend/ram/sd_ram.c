/*
 * sd_ram.c — the RAM object store (parity audit §3.6 row 6, §4.12 row 12: the
 * oss.memfile / XrdRmc analog), spelled `ram:<size>`.
 *
 * WHAT: a complete, bounded, heap-resident object store — objects live in this
 *       worker's own memory and nowhere else. Its intended role is a CACHE
 *       store (`brix_cache_store ram:512m`): a RAM tier in front of the origin
 *       that never touches a disk, for nodes whose working set fits in memory
 *       and whose latency budget cannot absorb a page-cache miss.
 *
 * WHY:  stock xrootd has two RAM caches — oss.memfile (mmap/mlock a file into
 *       RAM) and XrdRmc (an in-process block cache). Both are per-process, and
 *       both exist because the OS page cache is advisory: it can be reclaimed
 *       under pressure and gives no capacity guarantee. A store with its OWN
 *       hard cap gives the guarantee the page cache cannot.
 *
 * HOW:  a hash table of refcounted entries under one pthread mutex — the store
 *       is read from the event loop and written from cache-fill worker threads,
 *       the exact mix that cost cinfo_l1 a TSan-found corruption before it grew
 *       the same lock. No fd, so no sendfile: CAP_MEMFILE says bytes are served
 *       memory-backed. The cap is enforced where the bytes are actually claimed
 *       (fill reservation and buffer growth), so a full store returns ENOSPC to
 *       the fill and the cache decorator degrades to a plain source read — a
 *       full cache slows reads down, it never fails them.
 *
 * SCOPE: the store is PER WORKER, like both of the stock caches it mirrors, so
 *       an N-worker server holds up to N copies and N x <size> bytes. That is a
 *       property of the design, not an oversight; docs/03-configuration states
 *       it and tests/test_phase115_ram_tier.py pins it.
 */

#include "sd_ram_internal.h"

#include "fs/backend/sd_registry.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Bucket count: fixed and modest. The store is capacity-bounded, not count-
 * bounded, and a cache store's population is dominated by object SIZE, so a
 * few thousand chains cost 8 KB and keep every lookup short. */
#define SD_RAM_BUCKETS   1024

/* ---- instance lifecycle --------------------------------------------------- */

static ngx_int_t
sd_ram_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_ram_conf_t *conf = driver_conf;
    sd_ram_state_t           *st;

    if (conf == NULL || conf->capacity == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->buckets = calloc(SD_RAM_BUCKETS, sizeof(*st->buckets));
    if (st->buckets == NULL) {
        free(st);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    if (pthread_mutex_init(&st->mtx, NULL) != 0) {
        free(st->buckets);
        free(st);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->nbuckets = SD_RAM_BUCKETS;
    st->capacity = conf->capacity;
    st->log      = inst->log;
    inst->state  = st;

    /* Say PER WORKER out loud. `ram:8g` on a 16-worker server is 128 GB of
     * resident memory, and the size in the directive is the one number an
     * operator reads as the answer — the log is where that gets corrected. */
    ngx_log_error(NGX_LOG_NOTICE, inst->log, 0,
                  "brix: ram cache store ready, capacity=%uL bytes PER WORKER",
                  (uint64_t) st->capacity);
    return NGX_OK;
}

static void
sd_ram_cleanup(brix_sd_instance_t *inst)
{
    sd_ram_state_t *st = inst->state;
    size_t          i;

    if (st == NULL) {
        return;
    }
    for (i = 0; i < st->nbuckets; i++) {
        sd_ram_ent_t *e = st->buckets[i];

        while (e != NULL) {
            sd_ram_ent_t *next = e->hnext;

            e->refs = 1;                 /* worker teardown: drop every holder */
            brix_sd_ram_unref(st, e);
            e = next;
        }
    }
    (void) pthread_mutex_destroy(&st->mtx);
    free(st->buckets);
    free(st);
    inst->state = NULL;
}

/* ---- object lifecycle ----------------------------------------------------- */

/* A write/create open is refused: the ONLY writer of this store is the staged
 * fill spine (staged_open/write/commit), which is what a cache store uses and
 * what keeps a partially written object from ever being visible under its final
 * name. A direct write open would defeat that, so it is ENOTSUP, never a silent
 * degradation. */

/* Report `err` through both channels the open contract uses, and decline. */
static brix_sd_obj_t *
sd_ram_open_fail(int err, int *err_out)
{
    if (err_out != NULL) {
        *err_out = err;
    }
    errno = err;
    return NULL;
}

/* Attach a handle to the entry at `path`, taking its reference. Returns 0, or
 * the errno the open must report. Caller holds no lock; this takes it. */
static int
sd_ram_open_attach(sd_ram_state_t *st, const char *path, sd_ram_open_t *oh)
{
    sd_ram_ent_t *ent;
    int           err = 0;

    (void) pthread_mutex_lock(&st->mtx);
    ent = brix_sd_ram_find(st, path);
    if (ent == NULL) {
        err = ENOENT;
    } else if (ent->is_dir) {
        err = EISDIR;
    } else {
        ent->refs++;                     /* the handle's own reference */
        brix_sd_ram_lru_touch(st, ent);  /* an open is a use */
        oh->ent = ent;
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return err;
}

static brix_sd_obj_t *
sd_ram_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_ram_state_t *st = inst->state;
    brix_sd_obj_t  *obj;
    sd_ram_open_t  *oh;
    int             err;

    (void) mode;
    if (!brix_sd_ram_path_ok(path)) {
        return sd_ram_open_fail(EINVAL, err_out);
    }
    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND))
    {
        return sd_ram_open_fail(ENOTSUP, err_out);
    }

    /* Heap shell (open may run off the event loop; inst->pool is not
     * thread-safe) with the handle state in its OWN allocation, never inline
     * behind the shell: the VFS adopts the obj BY VALUE and frees a heap_shell
     * (open_resolved_file_open.c), so anything allocated behind the shell dies
     * with it while the copy's `state` still points there. Inlining it was the
     * 2.0 root:// read crash — sd_ram_pread on a freed handle. */
    obj = ngx_calloc(sizeof(*obj), inst->log);
    if (obj == NULL) {
        return sd_ram_open_fail(ENOMEM, err_out);
    }
    oh = ngx_calloc(sizeof(*oh), inst->log);
    if (oh == NULL) {
        ngx_free(obj);
        return sd_ram_open_fail(ENOMEM, err_out);
    }

    err = sd_ram_open_attach(st, path, oh);
    if (err != 0) {
        ngx_free(oh);
        ngx_free(obj);
        return sd_ram_open_fail(err, err_out);
    }

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = NGX_INVALID_FILE;  /* memory-served: no fd, no sendfile */
    obj->state      = oh;
    obj->heap_shell = 1;
    return obj;
}

static ngx_int_t
sd_ram_close(brix_sd_obj_t *obj)
{
    sd_ram_state_t *st = obj->inst->state;
    sd_ram_open_t  *oh = obj->state;

    if (oh == NULL) {
        return NGX_OK;
    }
    if (oh->ent != NULL) {
        (void) pthread_mutex_lock(&st->mtx);
        brix_sd_ram_unref(st, oh->ent);
        (void) pthread_mutex_unlock(&st->mtx);
    }
    ngx_free(oh);                        /* ours; the shell (or the adopter's
                                          * by-value copy) is the caller's */
    obj->state = NULL;
    return NGX_OK;
}

/* ---- worker-safe byte I/O ------------------------------------------------- */

static ssize_t
sd_ram_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_ram_state_t *st = obj->inst->state;
    sd_ram_open_t  *oh = obj->state;
    sd_ram_ent_t   *e;
    size_t          n;

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = oh->ent;
    if (e == NULL) {
        (void) pthread_mutex_unlock(&st->mtx);
        errno = EBADF;
        return -1;
    }
    if ((uint64_t) off >= (uint64_t) e->size) {
        (void) pthread_mutex_unlock(&st->mtx);
        return 0;                        /* EOF */
    }
    n = e->size - (size_t) off;
    if (n > len) {
        n = len;
    }
    memcpy(buf, e->data + off, n);
    (void) pthread_mutex_unlock(&st->mtx);
    return (ssize_t) n;
}

static ssize_t
sd_ram_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_ram_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                 off + total);

        if (n < 0) {
            return total > 0 ? total : n;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                       /* EOF inside this segment */
        }
    }
    return total;
}

/* ---- namespace ------------------------------------------------------------ */

static void
sd_ram_fill_stat(const sd_ram_ent_t *e, brix_sd_stat_t *out)
{
    memset(out, 0, sizeof(*out));
    out->size   = e->is_dir ? 0 : (off_t) e->size;
    out->mtime  = e->mtime;
    out->ctime  = e->ctime;
    out->mode   = e->is_dir ? (S_IFDIR | 0700) : (S_IFREG | 0600);
    out->ino    = e->ino;
    out->is_dir = e->is_dir;
    out->is_reg = e->is_dir ? 0 : 1;
}

static ngx_int_t
sd_ram_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_ram_state_t *st = obj->inst->state;
    sd_ram_open_t  *oh = obj->state;
    ngx_int_t       rc = NGX_OK;

    (void) pthread_mutex_lock(&st->mtx);
    if (oh->ent == NULL) {
        errno = EBADF;
        rc = NGX_ERROR;
    } else {
        sd_ram_fill_stat(oh->ent, out);
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return rc;
}

static ngx_int_t
sd_ram_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    sd_ram_state_t *st = inst->state;
    sd_ram_ent_t   *e;
    ngx_int_t       rc = NGX_OK;

    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = brix_sd_ram_find(st, path);
    if (e == NULL) {
        errno = ENOENT;
        rc = NGX_ERROR;
    } else {
        sd_ram_fill_stat(e, out);
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return rc;
}

static ngx_int_t
sd_ram_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_ram_state_t *st = inst->state;
    ngx_int_t       rc;

    (void) is_dir;
    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    (void) pthread_mutex_lock(&st->mtx);
    rc = brix_sd_ram_detach(st, path);
    (void) pthread_mutex_unlock(&st->mtx);
    if (rc != NGX_OK) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Directories are implicit in this key-prefix namespace (opendir lists by
 * prefix), so mkdir only has to record the name so an explicit stat/listing of
 * an empty directory answers. Idempotent, like the cache store needs. */
static ngx_int_t
sd_ram_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_ram_state_t *st = inst->state;
    sd_ram_ent_t   *e;
    ngx_int_t       rc = NGX_OK;

    (void) mode;
    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    (void) pthread_mutex_lock(&st->mtx);
    if (brix_sd_ram_find(st, path) == NULL) {
        e = brix_sd_ram_ent_new(st, path, 1);
        if (e == NULL) {
            rc = NGX_ERROR;
        } else {
            brix_sd_ram_insert(st, e);
        }
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return rc;
}

/* ---- space ---------------------------------------------------------------- */

/*
 * The store's own view of its capacity — the ONLY honest source, since there is
 * no filesystem under it to statvfs. brix_cstore_freespace consults this for a
 * non-LOCAL store, so occupancy reporting (kXR_statvfs, the cache metrics) is
 * truthful for a RAM tier. It is NOT what bounds the store: the watermark
 * reaper needs a physical state root this store has not got, so the cap is
 * enforced where the bytes are, by brix_sd_ram_make_room.
 *
 * In-flight fill reservations count as USED: a reader told there is room for
 * bytes another fill has already promised would be reading a number that is
 * about to be false.
 */
static ngx_int_t
sd_ram_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    sd_ram_state_t *st = inst->state;
    uint64_t        used;

    (void) pthread_mutex_lock(&st->mtx);
    used = st->used + st->reserved;
    (void) pthread_mutex_unlock(&st->mtx);

    out->total_bytes = st->capacity;
    out->used_bytes  = used;
    out->free_bytes  = (used < st->capacity) ? st->capacity - used : 0;
    return NGX_OK;
}

const brix_sd_driver_t brix_sd_ram_driver = {
    .name = "ram",
    /* No CAP_FD/CAP_SENDFILE: there is no kernel fd, so reads are served
     * memory-backed (CAP_MEMFILE). CAP_PRECOND because a staged commit decides
     * its precondition under the store's own mutex — genuinely at the storage,
     * with no window a concurrent writer could slip into. */
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_XATTR_WRITE | BRIX_SD_CAP_PRECOND,

    .init    = sd_ram_init,
    .cleanup = sd_ram_cleanup,

    .open   = sd_ram_open,
    .close  = sd_ram_close,
    .pread  = sd_ram_pread,
    .preadv = sd_ram_preadv,
    .fstat  = sd_ram_fstat,

    .stat   = sd_ram_stat,
    .unlink = sd_ram_unlink,
    .mkdir  = sd_ram_mkdir,

    .opendir  = brix_sd_ram_opendir,
    .readdir  = brix_sd_ram_readdir,
    .closedir = brix_sd_ram_closedir,

    .getxattr    = brix_sd_ram_getxattr,
    .listxattr   = brix_sd_ram_listxattr,
    .setxattr    = brix_sd_ram_setxattr,
    .removexattr = brix_sd_ram_removexattr,

    .staged_open   = brix_sd_ram_staged_open,
    .staged_write  = brix_sd_ram_staged_write,
    .staged_commit = brix_sd_ram_staged_commit,
    .staged_abort  = brix_sd_ram_staged_abort,
    /* No staged_path: a RAM fill has no local file for the verify plane to
     * digest by name — it verifies from the bytes it just wrote instead. */

    .space = sd_ram_space,
};
