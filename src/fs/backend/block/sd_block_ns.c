/*
 * sd_block_ns.c — the block driver's SERVER plane: the per-export instance and
 * the fixed-extent namespace built on top of it.
 *
 * WHAT: init (probe the device capacity and derive the extent geometry), the
 *       namespace slots that present the device as N equal-size logical objects
 *       named by their 0-based index ("/0", "/1", ...), and the space report
 *       that answers with the DEVICE capacity rather than the statvfs of
 *       whatever filesystem the mount point happens to sit on.
 * WHY:  A block device has no directory namespace of its own, so the export
 *       synthesizes one. Split out of sd_block.c, which carries the raw byte
 *       plane and had reached the 600-line file cap; this plane needs an nginx
 *       pool and log, so it compiles only in the module build (it is listed in
 *       ./config and deliberately absent from shared/xrdproto/Makefile).
 * HOW:  Opening "/N" returns the device fd WINDOWED to the extent's byte range
 *       [N*extent_size, (N+1)*extent_size); the window travels on obj->state and
 *       every raw op in sd_block.c shifts and clamps against it, so one object
 *       can never read or scribble into its neighbour.
 */
#include "sd_block_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>   /* BLKGETSIZE64 */
#endif

/* Per-export instance state: the device path, its probed capacity, and the
 * fixed extent geometry derived at init. */
typedef struct {
    char    *device;
    off_t    capacity;
    off_t    extent_size;
    uint32_t extents;
} sd_block_state_t;

/* Per-open directory cursor for the root listing. */
typedef struct {
    uint32_t next;
    uint32_t extents;
} sd_block_dir_t;

/* sd_block_is_root — the empty path or a lone "/" is the namespace root. */
static int
sd_block_is_root(const char *path)
{
    return path == NULL || path[0] == '\0'
        || (path[0] == '/' && path[1] == '\0');
}

/* sd_block_parse_index — an extent name is a leading-'/'-optional run of
 * decimal digits ("/0", "12"). Anything else — a non-numeric component, an
 * embedded '/', a path-escape attempt — is not an extent: return -1 so the
 * caller reports ENOENT (the namespace exposes ONLY the fixed extents). */
static int64_t
sd_block_parse_index(const char *path)
{
    const char *p = path;
    int64_t     idx = 0;

    if (p == NULL) {
        return -1;
    }
    if (*p == '/') {
        p++;
    }
    if (*p == '\0') {
        return -1;                      /* the root dir, not an extent */
    }
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        idx = idx * 10 + (*p - '0');
        if (idx > 0x7fffffff) {
            return -1;
        }
    }
    return idx;
}

/* sd_block_init — probe the device capacity (BLKGETSIZE64 for a real block
 * device, st_size for a regular file used as one) and derive the fixed extent
 * geometry. extent_size == 0 makes the whole device one extent. */
ngx_int_t
sd_block_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_block_conf_t *conf = driver_conf;
    sd_block_state_t           *st;
    struct stat                 sb;
    off_t                       cap;
    size_t                      dlen;
    int                         fd;

    if (conf == NULL || conf->device == NULL || conf->device[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }

    fd = open(conf->device, O_RDONLY);
    if (fd < 0) {
        return NGX_ERROR;               /* errno set by open(2) */
    }
    if (fstat(fd, &sb) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NGX_ERROR;
    }
    cap = sb.st_size;
#ifdef BLKGETSIZE64
    if (S_ISBLK(sb.st_mode)) {
        uint64_t sz = 0;
        if (ioctl(fd, BLKGETSIZE64, &sz) == 0) {
            cap = (off_t) sz;
        }
    }
#endif
    close(fd);

    if (cap <= 0) {
        errno = ENODEV;
        return NGX_ERROR;               /* an empty/zero-length device */
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    dlen = ngx_strlen(conf->device);
    st->device = ngx_pnalloc(inst->pool, dlen + 1);
    if (st->device == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(st->device, conf->device, dlen + 1);

    st->capacity    = cap;
    st->extent_size = (conf->extent_size > 0) ? (off_t) conf->extent_size : cap;
    st->extents     = (uint32_t) ((cap + st->extent_size - 1) / st->extent_size);
    inst->state     = st;
    return NGX_OK;
}

/* sd_block_open — resolve an extent name to a windowed handle on the device. A
 * non-extent name is ENOENT; the root is EISDIR; a valid extent opens the device
 * (never create/truncate) and binds the extent window into obj->state. */
brix_sd_obj_t *
sd_block_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_block_state_t *st = inst->state;
    brix_sd_obj_t    *obj;
    sd_block_obj_t   *os;
    int64_t           idx;
    int               fd;

    if (sd_block_is_root(path)) {
        if (err_out != NULL) { *err_out = EISDIR; }
        return NULL;
    }
    idx = sd_block_parse_index(path);
    if (idx < 0 || (uint32_t) idx >= st->extents) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }

    /* A device is opened in place: create/truncate/exclusive are meaningless. */
    sd_flags &= ~(BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC | BRIX_SD_O_EXCL);
    fd = brix_sd_block_open_unconfined(st->device, sd_flags, mode);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    /* Heap-allocate the shell + window (ngx_calloc, NOT inst->pool): open can run
     * on a cache-fill worker thread and inst->pool is the thread-unsafe cycle
     * pool. heap_shell frees the shell in the adopting layer; sd_block_close
     * frees the window. */
    obj = ngx_calloc(sizeof(*obj), inst->log);
    os  = ngx_calloc(sizeof(*os), inst->log);
    if (obj == NULL || os == NULL) {
        if (obj != NULL) { ngx_free(obj); }
        if (os != NULL)  { ngx_free(os); }
        close(fd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    os->base = (off_t) idx * st->extent_size;
    os->len  = st->extent_size;
    if (os->base + os->len > st->capacity) {
        os->len = st->capacity - os->base;   /* short device tail */
    }

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = fd;
    obj->state      = os;
    obj->heap_shell = 1;
    return obj;
}

/* sd_block_close — close the handle fd and free the extent window. */
ngx_int_t
sd_block_close(brix_sd_obj_t *obj)
{
    ngx_int_t rc = NGX_OK;

    if (obj == NULL) {
        return NGX_OK;
    }
    if (obj->fd != NGX_INVALID_FILE) {
        if (close(obj->fd) != 0) {
            rc = NGX_ERROR;
        }
        obj->fd = NGX_INVALID_FILE;
    }
    if (obj->state != NULL) {
        ngx_free(obj->state);
        obj->state = NULL;
    }
    return rc;
}

/* sd_block_stat — the root is a directory; a valid extent index is a fixed-size
 * regular object (the last extent may be a short device tail); anything else is
 * ENOENT. */
ngx_int_t
sd_block_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    sd_block_state_t *st = inst->state;
    int64_t           idx;

    ngx_memzero(out, sizeof(*out));
    if (sd_block_is_root(path)) {
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        return NGX_OK;
    }
    idx = sd_block_parse_index(path);
    if (idx < 0 || (uint32_t) idx >= st->extents) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    out->mode   = S_IFREG | 0644;
    out->is_reg = 1;
    out->size   = ((uint32_t) idx == st->extents - 1)
                ? st->capacity - (off_t) idx * st->extent_size
                : st->extent_size;
    return NGX_OK;
}

/* sd_block_opendir — only the root lists (the extents are a flat namespace); any
 * other path is ENOTDIR. */
brix_sd_dir_t *
sd_block_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_block_state_t *st = inst->state;
    brix_sd_dir_t    *dir;
    sd_block_dir_t   *bd;

    if (!sd_block_is_root(path)) {
        if (err_out != NULL) { *err_out = ENOTDIR; }
        return NULL;
    }
    dir = ngx_pcalloc(inst->pool, sizeof(*dir));
    bd  = ngx_pcalloc(inst->pool, sizeof(*bd));
    if (dir == NULL || bd == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    bd->next    = 0;
    bd->extents = st->extents;
    dir->inst   = inst;
    dir->state  = bd;
    return dir;
}

ngx_int_t
sd_block_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_block_dir_t *bd = d->state;

    if (bd->next >= bd->extents) {
        return NGX_DONE;
    }
    ngx_memzero(out, sizeof(*out));
    (void) ngx_snprintf((u_char *) out->name, sizeof(out->name), "%ui%Z",
                        (ngx_uint_t) bd->next);
    out->d_type = DT_REG;
    bd->next++;
    return NGX_OK;
}

ngx_int_t
sd_block_closedir(brix_sd_dir_t *d)
{
    (void) d;   /* the cursor lives on inst->pool */
    return NGX_OK;
}

/* sd_block_space — the export's capacity as the DEVICE, not as a filesystem.
 *
 * WHAT: total = the probed device capacity; used = the same; free = 0.
 * WHY:  Without this slot kXR_Qspace/kXR_statvfs fall back to statvfs(2) on the
 *       local export root, which for a block export describes an unrelated
 *       filesystem — usually the root fs holding the mount point, whose free
 *       bytes have nothing to do with the raw device the objects live on.
 *       free = 0 is the honest answer rather than a pessimistic one: the extent
 *       set is fixed at init and no operation on this driver creates an object,
 *       so there is genuinely no space in which a NEW object could be made.
 *       Writes into an existing extent are unaffected — they never consult it.
 * HOW:  Report st->capacity, which init probed with BLKGETSIZE64 (or st_size
 *       for a regular file standing in for a device). */
ngx_int_t
sd_block_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    const sd_block_state_t *st = inst->state;

    if (st == NULL || out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    out->total_bytes = (uint64_t) st->capacity;
    out->used_bytes  = (uint64_t) st->capacity;
    out->free_bytes  = 0;
    return NGX_OK;
}

