/*
 * sd_block.c — block-device storage driver (shared by the nginx server and the
 * userland clients).
 *
 * WHAT: brix_sd_block_driver — a backend for writing/reading a raw block
 *       device (or a file used as one) in place. The raw byte I/O is identical to
 *       POSIX, so the pread/pwrite/preadv/fsync slots delegate to the POSIX
 *       driver; the only block-specific behaviour is `fstat`, which reports the
 *       true device capacity via BLKGETSIZE64 (a block device's struct.st_size is
 *       0), and `open`, which never creates or truncates the device.
 *
 *       SERVER PLANE (module build only): a block device has no directory
 *       namespace, so the export presents a FIXED-EXTENT namespace — the device
 *       capacity is divided into equal-size extents, each a logical object named
 *       by its 0-based index ("/0", "/1", ...). "/" is the namespace root that
 *       lists them. Opening "/N" returns the device fd WINDOWED to the extent's
 *       byte range [N*extent_size, (N+1)*extent_size); every read/write is
 *       shifted by the extent base and clamped to the extent length, so one
 *       object can never read or scribble into its neighbour. extent_size == 0
 *       (the default — the directive carries no block_size) makes the whole
 *       device a single extent "/0".
 * WHY:  block was previously implemented only in client/lib/vfs_block.c — a
 *       second storage driver outside src/. This is the single home: both the
 *       client (block:// copy endpoints) and a block-backed server export use the
 *       same driver. ngx-free (dual-build via sd.h's XRDPROTO_NO_NGX fallback) so
 *       the client links the raw-I/O surface from libxrdproto; the namespace /
 *       instance ops (which need an nginx pool + log) compile only in the module.
 * HOW:  flat, POD-pointer-only vtable. A per-open object carries its extent
 *       window (sd_block_obj_t base/len); a NULL window (the client/unconfined
 *       path, which wraps a bare fd) means "absolute offset, no clamp" so the raw
 *       ops serve both worlds from one implementation.
 */
#include "fs/backend/sd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>   /* BLKGETSIZE64 */
#endif

/* Per-open extent window (obj->state). base/len confine an opened extent to its
 * slice of the device; a NULL obj->state is the client/unconfined path (a bare
 * fd wrapped for raw I/O) where offsets are absolute and unclamped. */
typedef struct {
    off_t base;   /* absolute device offset of this extent            */
    off_t len;    /* extent length in bytes (device tail may be short) */
} sd_block_obj_t;

/* Trailing-cap on a single windowed preadv so the iovec trim uses a bounded
 * stack copy; a larger iovcnt is honoured as a (legal) short read. */
#define BRIX_BLOCK_IOV_MAX 64

/* sd_block_read_window — translate a logical read [*off, *len) within an extent
 * to an absolute device range. Returns 0 when the request starts at/after the
 * extent end (the caller returns a 0-byte EOF read), else clamps *len to the
 * extent tail and shifts *off by the extent base. os == NULL (client path) is a
 * no-op pass-through: the offset stays absolute. */
static int
sd_block_read_window(const sd_block_obj_t *os, off_t *off, size_t *len)
{
    off_t avail;

    if (os == NULL) {
        return 1;                       /* unconfined: absolute offset */
    }
    if (*off < 0 || *off >= os->len) {
        return 0;                       /* past the extent → EOF */
    }
    avail = os->len - *off;
    if ((off_t) *len > avail) {
        *len = (size_t) avail;
    }
    *off += os->base;
    return 1;
}

/* Raw byte I/O == POSIX: delegate to the POSIX driver's slots so the syscall
 * loop policy stays single-sourced (vfs_core) and there is no second copy. For a
 * server extent the offset is first windowed; the client path (state == NULL)
 * passes straight through. */
static ssize_t
sd_block_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    if (!sd_block_read_window(obj->state, &off, &len)) {
        return 0;                       /* read wholly past the extent → EOF */
    }
    return brix_sd_posix_driver.pread(obj, buf, len, off);
}

/* sd_block_pwrite — a fixed extent cannot grow: a write that starts at/after the
 * extent end, or that would cross the extent boundary, is refused with ENOSPC
 * (never silently truncated into the neighbouring extent). */
static ssize_t
sd_block_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    const sd_block_obj_t *os = obj->state;

    if (os != NULL) {
        if (off < 0 || off >= os->len
            || (off_t) len > os->len - off)
        {
            errno = ENOSPC;
            return -1;
        }
        off += os->base;
    }
    return brix_sd_posix_driver.pwrite(obj, buf, len, off);
}

/* sd_block_preadv_window — the vectored counterpart of sd_block_read_window:
 * shift the base offset and trim the iovec run so the total never crosses the
 * extent end. The client path (state == NULL) delegates unmodified. */
static ssize_t
sd_block_preadv_window(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags, int has_flags)
{
    const sd_block_obj_t *os = obj->state;
    struct iovec          tmp[BRIX_BLOCK_IOV_MAX];
    off_t                 remaining;
    int                   i, n;

    if (os == NULL) {
        return has_flags
             ? brix_sd_posix_driver.preadv2(obj, iov, iovcnt, off, flags)
             : brix_sd_posix_driver.preadv(obj, iov, iovcnt, off);
    }
    if (iovcnt < 0) {
        errno = EINVAL;
        return -1;
    }
    if (off < 0 || off >= os->len) {
        return 0;                       /* past the extent → EOF */
    }
    if (iovcnt > BRIX_BLOCK_IOV_MAX) {
        iovcnt = BRIX_BLOCK_IOV_MAX;    /* bounded; the tail is a short read */
    }
    remaining = os->len - off;
    for (i = 0, n = 0; i < iovcnt && remaining > 0; i++) {
        size_t l = iov[i].iov_len;

        if ((off_t) l > remaining) {
            l = (size_t) remaining;
        }
        tmp[n].iov_base = iov[i].iov_base;
        tmp[n].iov_len  = l;
        remaining -= l;
        n++;
    }
    off += os->base;
    return has_flags
         ? brix_sd_posix_driver.preadv2(obj, tmp, n, off, flags)
         : brix_sd_posix_driver.preadv(obj, tmp, n, off);
}

static ssize_t
sd_block_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    return sd_block_preadv_window(obj, iov, iovcnt, off, 0, 0);
}

static ssize_t
sd_block_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    return sd_block_preadv_window(obj, iov, iovcnt, off, flags, 1);
}

static ngx_int_t
sd_block_fsync(brix_sd_obj_t *obj)
{
    return brix_sd_posix_driver.fsync(obj);
}

/* sd_block_fstat — a server extent reports as a fixed-size regular object (its
 * window length); the client/unconfined path reports the real file, and for a
 * true block device (st_size == 0) queries the capacity via BLKGETSIZE64. */
static ngx_int_t
sd_block_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    const sd_block_obj_t *os = obj->state;
    struct stat           sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->ino    = sb.st_ino;

    if (os != NULL) {
        out->size   = os->len;
        out->mode   = S_IFREG | 0644;
        out->is_reg = 1;
        return NGX_OK;
    }

    out->size   = sb.st_size;
    out->mode   = sb.st_mode;
    out->is_dir = S_ISDIR(sb.st_mode) ? 1 : 0;
    out->is_reg = S_ISREG(sb.st_mode) ? 1 : 0;

#ifdef BLKGETSIZE64
    if (S_ISBLK(sb.st_mode)) {
        uint64_t sz = 0;
        if (ioctl(obj->fd, BLKGETSIZE64, &sz) == 0) {
            out->size = (off_t) sz;
        }
    }
#endif
    return NGX_OK;
}

/* brix_sd_block_open_unconfined — open a block device (no O_CREAT/O_TRUNC: the
 * device exists and must not be re-created or zeroed). Returns an fd or -1. */
int
brix_sd_block_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    /* Strip create/truncate intent — a block device is opened in place. */
    sd_flags &= ~(BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC);
    return brix_sd_posix_open_unconfined(path, sd_flags, mode);
}

#ifndef XRDPROTO_NO_NGX   /* server plane: instance + fixed-extent namespace */

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
static ngx_int_t
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
static brix_sd_obj_t *
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
static ngx_int_t
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
static ngx_int_t
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
static brix_sd_dir_t *
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

static ngx_int_t
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

static ngx_int_t
sd_block_closedir(brix_sd_dir_t *d)
{
    (void) d;   /* the cursor lives on inst->pool */
    return NGX_OK;
}

#endif /* !XRDPROTO_NO_NGX */

/* The block driver: raw-I/O caps everywhere; in the module build it also grows a
 * fixed-extent server namespace (open/stat/dir + CAP_DIRS). No truncate (a fixed
 * extent), no rename, no xattr, no staged commit, no sendfile (the extent window
 * must be honoured by pread — a zero-copy fd would ignore the base offset). */
const brix_sd_driver_t brix_sd_block_driver = {
    .name = "block",
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_RANGE_READ
#ifndef XRDPROTO_NO_NGX
          | BRIX_SD_CAP_DIRS
#endif
          ,
    .pread    = sd_block_pread,
    .pwrite   = sd_block_pwrite,
    .preadv   = sd_block_preadv,
    .preadv2  = sd_block_preadv2,
    .fsync    = sd_block_fsync,
    .fstat    = sd_block_fstat,
#ifndef XRDPROTO_NO_NGX
    .init     = sd_block_init,
    .open     = sd_block_open,
    .close    = sd_block_close,
    .stat     = sd_block_stat,
    .opendir  = sd_block_opendir,
    .readdir  = sd_block_readdir,
    .closedir = sd_block_closedir,
#endif
};
