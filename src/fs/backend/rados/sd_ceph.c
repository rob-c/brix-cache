/*
 * sd_ceph.c — Ceph/RADOS Storage Driver (phase-60, basic librados backend).
 *
 * WHAT: brix_sd_ceph_driver — a backend that maps the VFS's logical paths onto
 *       flat RADOS objects via raw librados (rados_read/write/trunc/stat/remove).
 *       Two layers live here:
 *         1. The pure LFN->object-key map (sd_ceph_normalize/_key/_ino) — libc
 *            only, always compiled, unit-tested standalone (sd_ceph_unittest.c).
 *         2. The driver vtable — only when the build found librados
 *            (BRIX_HAVE_CEPH); otherwise this file is just the pure helpers and
 *            the build is byte-for-byte unchanged (the driver row in
 *            sd_registry.c is #if-guarded too).
 *
 * WHY:  RADOS has no kernel fd, no sendfile, no directory tree and no atomic
 *       rename, so this driver advertises only range-read / random-write /
 *       truncate (see .caps). The VFS already serves a no-CAP_FD backend memory-
 *       backed and degrades the absent namespace/rename/xattr ops — the data
 *       plane (root:// read/write, WebDAV/S3 GET/PUT) rides the same VFS seam as
 *       POSIX once the handle path is de-fd'd (phase-60 W0).
 *
 * HOW:  One rados_t + ioctx per export instance, connected at init() on the event
 *       loop (worker init); the blocking rados_* calls are meant to run on the
 *       nginx thread pool (phase-60 §8 / ADR-4). Object handles carry the object
 *       id + a cached size; the raw byte ops are worker-safe (no pool/log/metrics).
 *       libradosstriper (large-object striping + stock XrdCeph on-disk interop,
 *       ADR-3) is a deliberate follow-on; this basic backend uses raw librados.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

/* ===================================================================== *
 * Pure LFN -> object-key mapping (always compiled; no librados, no nginx) *
 * ===================================================================== */

/* sd_ceph_normalize — see sd_ceph.h. Builds the canonical path in `out` by
 * walking segments: skip empties and ".", pop on "..", append otherwise. A ".."
 * with nothing to pop is an escape above the root and is rejected. */
int
sd_ceph_normalize(const char *lfn, char *out, size_t cap)
{
    const char *p = lfn;
    size_t      w = 0;

    if (lfn == NULL || out == NULL || cap < 2) {
        errno = EINVAL;
        return -1;
    }
    out[0] = '\0';

    while (*p != '\0') {
        const char *seg;
        size_t      seglen;

        while (*p == '/') {           /* skip run of slashes */
            p++;
        }
        if (*p == '\0') {
            break;
        }

        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        seglen = (size_t) (p - seg);

        if (seglen == 1 && seg[0] == '.') {
            continue;                 /* "." — no-op */
        }
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (w == 0) {
                errno = EINVAL;       /* escape above the root */
                return -1;
            }
            while (w > 0 && out[w - 1] != '/') {
                w--;                  /* back over the last component */
            }
            if (w > 0) {
                w--;                  /* drop its leading '/' */
            }
            out[w] = '\0';
            continue;
        }

        if (w + 1 + seglen + 1 > cap) {
            errno = ENAMETOOLONG;
            return -1;
        }
        out[w++] = '/';
        memcpy(out + w, seg, seglen);
        w += seglen;
        out[w] = '\0';
    }

    if (w == 0) {                     /* everything collapsed -> bare root */
        out[0] = '/';
        out[1] = '\0';
    }
    return 0;
}

/* sd_ceph_key — prefix + sd_ceph_normalize(lfn). See sd_ceph.h. */
int
sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap)
{
    char   norm[1024];
    size_t plen = (key_prefix != NULL) ? strlen(key_prefix) : 0;
    size_t nlen;

    if (sd_ceph_normalize(lfn, norm, sizeof(norm)) != 0) {
        return -1;
    }
    nlen = strlen(norm);

    if (plen + nlen + 1 > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (plen > 0) {
        memcpy(out, key_prefix, plen);
    }
    memcpy(out + plen, norm, nlen + 1);
    return 0;
}

/* sd_ceph_ino — FNV-1a/64 over the object id. See sd_ceph.h. */
uint64_t
sd_ceph_ino(const char *oid)
{
    const unsigned char *p = (const unsigned char *) oid;
    uint64_t             h = 1469598103934665603ULL;   /* FNV offset basis */

    while (*p != '\0') {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;                          /* FNV prime */
    }
    return h;
}

/* ===================================================================== *
 * librados driver (only when the build found librados)                   *
 * ===================================================================== */
#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
#include <time.h>

/* Driver-private per-export state (inst->state): one connected cluster handle +
 * ioctx, plus the resolved configuration. */
typedef struct {
    rados_t        cluster;
    rados_ioctx_t  ioctx;
    char          *pool;
    char          *user;
    char          *conf_file;
    char          *keyring;
    char          *key_prefix;
    unsigned       connected:1;
#if defined(BRIX_HAVE_RADOSSTRIPER)
    rados_striper_t striper;        /* lazily created, shared across this export */
    unsigned        striper_ready:1;
#endif
} sd_ceph_state_t;

/* Driver-private per-open state (obj->state): the object id + a cached size.
 * `striped` is set when the object is stored in the stock-XrdCeph libradosstriper
 * layout and must be read back through the striper to reassemble its bytes. */
typedef struct {
    char     oid[1024];
    uint64_t size;
    unsigned for_write:1;
    unsigned striped:1;
} sd_ceph_obj_state_t;

/* Driver-private staged-write state (staged->state): the final object id. RADOS
 * has no atomic rename, so — like the root:// write path — the staged target IS
 * the final object (trunc-on-open, write in place, commit is a no-op). */
typedef struct {
    char oid[1024];
} sd_ceph_staged_t;

/* sd_ceph_pstrdup — copy a C string onto the instance pool (NULL-safe source
 * yields NULL). Keeps the driver's retained strings on the export-lifetime pool. */
static char *
sd_ceph_pstrdup(ngx_pool_t *pool, const char *s)
{
    size_t  n;
    char   *d;

    if (s == NULL) {
        return NULL;
    }
    n = strlen(s) + 1;
    d = ngx_pnalloc(pool, n);
    if (d != NULL) {
        memcpy(d, s, n);
    }
    return d;
}

/* sd_ceph_set_errno — librados returns 0/negative-errno; translate a negative rc
 * into errno and the driver's failure code, returning 1 iff rc indicated error. */
static int
sd_ceph_set_errno(int rc)
{
    if (rc < 0) {
        errno = -rc;
        return 1;
    }
    return 0;
}

/* worker-safe raw byte I/O (no pool/log/metrics) */

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* Lazily create (once per export) the libradosstriper handle bound to this
 * instance's ioctx, so reads of stock-XrdCeph striped objects reassemble the file
 * byte-for-byte. NULL on failure (the caller falls back to a raw read). */
static rados_striper_t
sd_ceph_striper(sd_ceph_state_t *st)
{
    if (!st->striper_ready) {
        if (sd_ceph_striper_create(st->ioctx, NULL, &st->striper) != 0) {
            return NULL;
        }
        st->striper_ready = 1;
    }
    return st->striper;
}

/* 1 iff a striper-format object exists for `name` (its libradosstriper metadata
 * is present), i.e. it was written by stock XrdCeph and must be read striped. */
static int
sd_ceph_is_striped(sd_ceph_state_t *st, const char *name)
{
    rados_striper_t s = sd_ceph_striper(st);
    uint64_t        size = 0;
    time_t          mtime = 0;

    return (s != NULL && sd_ceph_striper_stat(s, name, &size, &mtime) == 0)
           ? 1 : 0;
}
#endif /* BRIX_HAVE_RADOSSTRIPER */

/* sd_ceph_pread — read at off from the object. A striper-format object (stock
 * XrdCeph) is read through libradosstriper so its bytes reassemble exactly;
 * everything else is a flat rados_read. Returns bytes read (>=0, 0 = at/after
 * EOF) or -1 with errno. The VFS owns the EINTR/short-read loop (vfs_core). */
static ssize_t
sd_ceph_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_ceph_state_t     *st = obj->inst->state;
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (os->striped) {
        rados_striper_t s = sd_ceph_striper(st);
        ssize_t         n;

        if (s == NULL) {
            errno = EIO;
            return -1;
        }
        n = sd_ceph_striper_read(s, os->oid, buf, len, (uint64_t) off);
        if (n < 0) {
            errno = (int) -n;
            return -1;
        }
        return n;
    }
#endif

    rc = rados_read(st->ioctx, os->oid, buf, len, (uint64_t) off);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return (ssize_t) rc;
}

/* sd_ceph_pwrite — one rados_write at off; returns len on success or -1. Bumps
 * the cached object size so a subsequent fstat reflects in-flight writes. */
static ssize_t
sd_ceph_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_ceph_state_t     *st = obj->inst->state;
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

    rc = rados_write(st->ioctx, os->oid, buf, len, (uint64_t) off);
    if (sd_ceph_set_errno(rc)) {
        return -1;
    }
    if ((uint64_t) off + len > os->size) {
        os->size = (uint64_t) off + len;
    }
    return (ssize_t) len;
}

/* sd_ceph_preadv — vectored read as a loop of sd_ceph_pread (RADOS has no native
 * preadv); stops at the first short/EOF segment. Bytes read or -1. */
static ssize_t
sd_ceph_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_ceph_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                  off + total);
        if (n < 0) {
            return -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                    /* short read / EOF */
        }
    }
    return total;
}

/* sd_ceph_preadv2 — RADOS has no per-read flags (e.g. RWF_NOWAIT); ignore them
 * and serve via the plain vectored read. */
static ssize_t
sd_ceph_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    (void) flags;
    return sd_ceph_preadv(obj, iov, iovcnt, off);
}

/* sd_ceph_read_sendfile_fd — RADOS exposes no kernel fd, so reads are always
 * served memory-backed; signal that to the VFS with NGX_INVALID_FILE. */
static ngx_fd_t
sd_ceph_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) obj; (void) off; (void) len; (void) want_zerocopy;
    return NGX_INVALID_FILE;
}

/* sd_ceph_ftruncate — rados_trunc to len; updates the cached size. */
static ngx_int_t
sd_ceph_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_ceph_state_t     *st = obj->inst->state;
    sd_ceph_obj_state_t *os = obj->state;

    if (sd_ceph_set_errno(rados_trunc(st->ioctx, os->oid, (uint64_t) len))) {
        return NGX_ERROR;
    }
    os->size = (uint64_t) len;
    return NGX_OK;
}

/* sd_ceph_fsync — a synchronous rados_write is durably acked on return, so there
 * is nothing to flush; succeed. (aio flush belongs to the async follow-on.) */
static ngx_int_t
sd_ceph_fsync(brix_sd_obj_t *obj)
{
    (void) obj;
    return NGX_OK;
}

/* sd_ceph_fill_stat — shape a RADOS (size, mtime) pair into the neutral stat the
 * VFS consumes: a regular object, mode 0644, a stable synthesized inode. */
static void
sd_ceph_fill_stat(const char *oid, uint64_t size, time_t mtime,
    brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mtime  = mtime;
    out->ctime  = mtime;
    out->mode   = 0100644;            /* S_IFREG | 0644 */
    out->ino    = (ino_t) sd_ceph_ino(oid);
    out->is_reg = 1;
}

/* sd_ceph_fstat — rados_stat on the open object's id. */
static ngx_int_t
sd_ceph_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_ceph_state_t     *st = obj->inst->state;
    sd_ceph_obj_state_t *os = obj->state;
    uint64_t             size = 0;
    time_t               mtime = 0;

    if (sd_ceph_set_errno(rados_stat(st->ioctx, os->oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(os->oid, size, mtime, out);
    return NGX_OK;
}

/* object lifecycle */

/* sd_ceph_open — resolve the LFN to an object id, honour create/excl/trunc intent
 * against a stat probe, and return a handle carrying the id + cached size. There
 * is no fd: obj->fd stays NGX_INVALID_FILE (the VFS serves such handles memory-
 * backed). */
static brix_sd_obj_t *
sd_ceph_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t     *st = inst->state;
    brix_sd_obj_t     *obj;
    sd_ceph_obj_state_t *os;
    uint64_t             size = 0;
    time_t               mtime = 0;
    int                  rc;

    (void) mode;

    obj = ngx_pcalloc(inst->pool, sizeof(*obj));
    os  = ngx_pcalloc(inst->pool, sizeof(*os));
    if (obj == NULL || os == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (sd_ceph_key(st->key_prefix, path, os->oid, sizeof(os->oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    rc = -ENOENT;
#if defined(BRIX_HAVE_RADOSSTRIPER)
    /* On a read open, prefer the stock-XrdCeph striper view: if a striped object
     * exists for this name, mark it so pread reassembles via libradosstriper. */
    if (!(sd_flags & BRIX_SD_O_WRITE)) {
        rados_striper_t s = sd_ceph_striper(st);
        if (s != NULL && sd_ceph_striper_stat(s, os->oid, &size, &mtime) == 0) {
            os->striped = 1;
            rc = 0;
        }
    }
#endif
    if (rc != 0) {
        rc = rados_stat(st->ioctx, os->oid, &size, &mtime);
    }
    if (rc == -ENOENT && !(sd_flags & BRIX_SD_O_CREATE)) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    if (rc < 0 && rc != -ENOENT) {
        if (err_out != NULL) { *err_out = -rc; }
        return NULL;
    }
    if (rc == 0 && (sd_flags & BRIX_SD_O_EXCL)) {
        if (err_out != NULL) { *err_out = EEXIST; }
        return NULL;
    }
    if (sd_flags & BRIX_SD_O_TRUNC) {
        if (sd_ceph_set_errno(rados_trunc(st->ioctx, os->oid, 0))) {
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
        size = 0;
    }
    (void) mtime;

    os->size      = (rc == 0) ? size : 0;
    os->for_write = (sd_flags & BRIX_SD_O_WRITE) ? 1 : 0;
    obj->driver   = inst->driver;
    obj->inst     = inst;
    obj->fd       = NGX_INVALID_FILE;
    obj->state    = os;

    /* Populate the metadata snapshot the caller copies into its handle and uses
     * to build the open reply (open_resolved_file.c). RADOS has no fd/inode, so
     * synthesize a stable inode from the object id and present a regular file. */
    obj->snap.size   = (off_t) os->size;
    obj->snap.mtime  = mtime;
    obj->snap.ctime  = mtime;
    obj->snap.mode   = S_IFREG | 0644;
    obj->snap.ino    = (ino_t) sd_ceph_ino(os->oid);
    obj->snap.is_reg = 1;
    return obj;
}

/* sd_ceph_close — no per-object kernel resource to release (the cluster/ioctx are
 * instance-lived); the handle lives on the pool. */
static ngx_int_t
sd_ceph_close(brix_sd_obj_t *obj)
{
    (void) obj;
    return NGX_OK;
}

/* namespace (logical paths) */

/* sd_ceph_stat — rados_stat on the object id for a logical path. */
static ngx_int_t
sd_ceph_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    uint64_t         size = 0;
    time_t           mtime = 0;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_stat(st->ioctx, oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(oid, size, mtime, out);
    return NGX_OK;
}

/* sd_ceph_unlink — remove the object for a logical path. There are no real
 * directories in this basic backend, so is_dir is advisory only. */
static ngx_int_t
sd_ceph_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) is_dir;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_remove(st->ioctx, oid))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* xattr / object metadata — RADOS objects carry their own xattrs, so the
 * checksum-at-rest seam (user.XrdCks.*) and protocol GETFATTR/SETFATTR work on a
 * Ceph export exactly as on POSIX. All four key the object id off the logical
 * path; the object must already exist (set/get/list/remove on a missing oid
 * return -ENOENT via librados). */

/* Bound on a single xattr value we buffer for the size-probe path. */
#define SD_CEPH_XATTR_MAX (64u * 1024)

static ssize_t
sd_ceph_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    char             tmp[SD_CEPH_XATTR_MAX];
    int              n;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    n = rados_getxattr(st->ioctx, oid, name, tmp, sizeof(tmp));
    if (n < 0) {
        errno = -n;
        return -1;
    }
    if (cap == 0) {
        return n;                  /* size probe (getxattr(2) convention) */
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, tmp, (size_t) n);
    return n;
}

static ssize_t
sd_ceph_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_ceph_state_t    *st = inst->state;
    char                oid[1024];
    rados_xattrs_iter_t it;
    char               *out = buf;
    size_t              total = 0;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_getxattrs(st->ioctx, oid, &it))) {
        return -1;
    }
    for (;;) {
        const char *nm = NULL;
        const char *val = NULL;
        size_t      vlen = 0;
        size_t      nlen;

        if (sd_ceph_set_errno(rados_getxattrs_next(it, &nm, &val, &vlen))) {
            rados_getxattrs_end(it);
            return -1;
        }
        if (nm == NULL) {
            break;                 /* end of iteration */
        }
        nlen = strlen(nm) + 1;     /* listxattr(2): names are NUL-separated */
        if (cap != 0) {
            if (total + nlen > cap) {
                rados_getxattrs_end(it);
                errno = ERANGE;
                return -1;
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    rados_getxattrs_end(it);
    return (ssize_t) total;
}

static ngx_int_t
sd_ceph_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) flags;   /* RADOS has no XATTR_CREATE/REPLACE; a plain set is applied */

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_setxattr(st->ioctx, oid, name, val, len))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
sd_ceph_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_rmxattr(st->ioctx, oid, name))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* staged/atomic write — WebDAV PUT and other staged-upload paths.
 *
 * RADOS has no atomic rename, so (matching the root:// write path, which writes
 * straight to the final object) the staged target IS the final object: trunc it
 * to zero at open, write in place, commit is a no-op, abort removes it. A
 * temp-object + server-side copy-on-commit would add true atomicity at O(size)
 * cost; that is a follow-on, not needed for basic PUT parity with root://. */
static brix_sd_staged_t *
sd_ceph_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t    *st = inst->state;
    brix_sd_staged_t *handle;
    sd_ceph_staged_t   *ps;

    (void) mode;

    handle = ngx_pcalloc(inst->pool, sizeof(*handle));
    ps     = ngx_pcalloc(inst->pool, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    if (sd_ceph_key(st->key_prefix, final_path, ps->oid, sizeof(ps->oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (sd_ceph_set_errno(rados_trunc(st->ioctx, ps->oid, 0))) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    handle->inst  = inst;
    handle->state = ps;
    return handle;
}

static ssize_t
sd_ceph_staged_write(brix_sd_staged_t *sh, const void *buf, size_t len,
    off_t off)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    if (sd_ceph_set_errno(rados_write(st->ioctx, ps->oid, buf, len,
                                      (uint64_t) off)))
    {
        return -1;
    }
    return (ssize_t) len;
}

static ngx_int_t
sd_ceph_staged_commit(brix_sd_staged_t *sh, int noreplace)
{
    (void) sh;
    (void) noreplace;   /* the object is already written in place */
    return NGX_OK;
}

static void
sd_ceph_staged_abort(brix_sd_staged_t *sh)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    (void) rados_remove(st->ioctx, ps->oid);
}

/* instance lifecycle (event loop / worker init) */

/* sd_ceph_user_id — librados wants the entity id without the "client." prefix
 * (rados_create prepends "client."); a NULL id selects the default client.admin. */
static const char *
sd_ceph_user_id(const char *user)
{
    if (user != NULL && strncmp(user, "client.", 7) == 0) {
        return user + 7;
    }
    return user;
}

/* sd_ceph_cluster_connect — create + configure + connect a rados cluster handle
 * and open the pool ioctx. Shared by the flat driver's init and the oid-level
 * connection (sd_ceph_conn_create). 0 / -1 with errno; on failure nothing leaks. */
static int
sd_ceph_cluster_connect(const char *conf_file, const char *user,
    const char *keyring, const char *pool,
    rados_t *cluster_out, rados_ioctx_t *ioctx_out)
{
    rados_t       cluster;
    rados_ioctx_t ioctx;

    if (sd_ceph_set_errno(rados_create(&cluster, sd_ceph_user_id(user)))) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_conf_read_file(cluster,
            conf_file ? conf_file : "/etc/ceph/ceph.conf")))
    {
        rados_shutdown(cluster);
        return -1;
    }
    if (keyring != NULL) {
        rados_conf_set(cluster, "keyring", keyring);
    }
    if (sd_ceph_set_errno(rados_connect(cluster))) {
        rados_shutdown(cluster);
        return -1;
    }
    if (sd_ceph_set_errno(rados_ioctx_create(cluster, pool, &ioctx))) {
        rados_shutdown(cluster);
        return -1;
    }
    *cluster_out = cluster;
    *ioctx_out   = ioctx;
    return 0;
}

/* sd_ceph_init — resolve config onto the pool, create + configure + connect the
 * cluster handle, and open the pool ioctx. Any failure tears down what was built
 * and returns NGX_ERROR with errno set so the export fails closed at init. */
static ngx_int_t
sd_ceph_init(brix_sd_instance_t *inst, void *driver_conf)
{
    brix_sd_ceph_conf_t *dc = driver_conf;
    sd_ceph_state_t       *st;

    if (dc == NULL || dc->pool == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->pool       = sd_ceph_pstrdup(inst->pool, dc->pool);
    st->user       = sd_ceph_pstrdup(inst->pool, dc->user);
    st->conf_file  = sd_ceph_pstrdup(inst->pool,
                         dc->conf_file ? dc->conf_file : "/etc/ceph/ceph.conf");
    st->keyring    = sd_ceph_pstrdup(inst->pool, dc->keyring);
    st->key_prefix = sd_ceph_pstrdup(inst->pool,
                         dc->key_prefix ? dc->key_prefix : "");
    inst->state = st;

    if (sd_ceph_cluster_connect(st->conf_file, st->user, st->keyring, st->pool,
                                &st->cluster, &st->ioctx) != 0)
    {
        return NGX_ERROR;
    }
    st->connected = 1;
    return NGX_OK;
}

/* sd_ceph_cleanup — destroy the ioctx and shut the cluster handle down (a kernel/
 * network resource that must not leak across reconfig); the pool reclaims state. */
static void
sd_ceph_cleanup(brix_sd_instance_t *inst)
{
    sd_ceph_state_t *st = inst->state;

    if (st != NULL && st->connected) {
#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (st->striper_ready) {
            sd_ceph_striper_destroy(st->striper);
            st->striper_ready = 0;
        }
#endif
        rados_ioctx_destroy(st->ioctx);
        rados_shutdown(st->cluster);
        st->connected = 0;
    }
}

/* ---- shared oid-level layer (reused by cephfsro + recovery tools) --------- */

struct sd_ceph_conn_s {
    rados_t        cluster;
    rados_ioctx_t  ioctx;
    ngx_pool_t    *pool;
    unsigned       connected:1;
};

sd_ceph_conn_t *
sd_ceph_conn_create(const brix_sd_ceph_conf_t *conf, ngx_pool_t *pool, int *err)
{
    sd_ceph_conn_t *c;

    if (conf == NULL || conf->pool == NULL) {
        if (err != NULL) { *err = EINVAL; }
        return NULL;
    }
    c = ngx_pcalloc(pool, sizeof(*c));
    if (c == NULL) {
        if (err != NULL) { *err = ENOMEM; }
        return NULL;
    }
    c->pool = pool;
    if (sd_ceph_cluster_connect(conf->conf_file, conf->user, conf->keyring,
                                conf->pool, &c->cluster, &c->ioctx) != 0)
    {
        if (err != NULL) { *err = errno; }
        return NULL;
    }
    c->connected = 1;
    return c;
}

void
sd_ceph_conn_destroy(sd_ceph_conn_t *c)
{
    if (c != NULL && c->connected) {
        rados_ioctx_destroy(c->ioctx);
        rados_shutdown(c->cluster);
        c->connected = 0;
    }
}

rados_ioctx_t
sd_ceph_conn_ioctx(sd_ceph_conn_t *c)
{
    return c->ioctx;
}

ssize_t
sd_ceph_oid_read(sd_ceph_conn_t *c, const char *oid, void *buf, size_t len,
    off_t off)
{
    int rc = rados_read(c->ioctx, oid, buf, len, (uint64_t) off);

    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return (ssize_t) rc;
}

ssize_t
sd_ceph_oid_write(sd_ceph_conn_t *c, const char *oid, const void *buf,
    size_t len, off_t off)
{
    if (sd_ceph_set_errno(rados_write(c->ioctx, oid, buf, len, (uint64_t) off))) {
        return -1;
    }
    return (ssize_t) len;
}

int
sd_ceph_oid_stat(sd_ceph_conn_t *c, const char *oid, uint64_t *size,
    time_t *mtime)
{
    uint64_t sz = 0;
    time_t   mt = 0;

    if (sd_ceph_set_errno(rados_stat(c->ioctx, oid, &sz, &mt))) {
        return -1;
    }
    if (size != NULL)  { *size = sz; }
    if (mtime != NULL) { *mtime = mt; }
    return 0;
}

int
sd_ceph_oid_trunc(sd_ceph_conn_t *c, const char *oid, uint64_t len)
{
    return sd_ceph_set_errno(rados_trunc(c->ioctx, oid, len)) ? -1 : 0;
}

int
sd_ceph_oid_remove(sd_ceph_conn_t *c, const char *oid)
{
    return sd_ceph_set_errno(rados_remove(c->ioctx, oid)) ? -1 : 0;
}

ssize_t
sd_ceph_oid_getxattr(sd_ceph_conn_t *c, const char *oid, const char *name,
    void *buf, size_t cap)
{
    char tmp[SD_CEPH_XATTR_MAX];
    int  n = rados_getxattr(c->ioctx, oid, name, tmp, sizeof(tmp));

    if (n < 0) {
        errno = -n;
        return -1;
    }
    if (cap == 0) {
        return n;
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, tmp, (size_t) n);
    return n;
}

ssize_t
sd_ceph_oid_listxattr(sd_ceph_conn_t *c, const char *oid, void *buf, size_t cap)
{
    rados_xattrs_iter_t it;
    char               *out = buf;
    size_t              total = 0;

    if (sd_ceph_set_errno(rados_getxattrs(c->ioctx, oid, &it))) {
        return -1;
    }
    for (;;) {
        const char *nm = NULL;
        const char *val = NULL;
        size_t      vlen = 0;
        size_t      nlen;

        if (sd_ceph_set_errno(rados_getxattrs_next(it, &nm, &val, &vlen))) {
            rados_getxattrs_end(it);
            return -1;
        }
        if (nm == NULL) {
            break;
        }
        nlen = strlen(nm) + 1;
        if (cap != 0) {
            if (total + nlen > cap) {
                rados_getxattrs_end(it);
                errno = ERANGE;
                return -1;
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    rados_getxattrs_end(it);
    return (ssize_t) total;
}

int
sd_ceph_oid_setxattr(sd_ceph_conn_t *c, const char *oid, const char *name,
    const void *val, size_t len)
{
    return sd_ceph_set_errno(rados_setxattr(c->ioctx, oid, name, val, len))
               ? -1 : 0;
}

int
sd_ceph_oid_rmxattr(sd_ceph_conn_t *c, const char *oid, const char *name)
{
    return sd_ceph_set_errno(rados_rmxattr(c->ioctx, oid, name)) ? -1 : 0;
}

/* sd_ceph_enumerate — backend-catalog enumeration (inventory/drift, §E1/D2).
 * Lists the pool's RADOS objects and reports ONE catalog entry per logical file,
 * byte-compatibly with stock XrdCeph's libradosstriper layout:
 *   - a striper FIRST stripe ("<name>.0000000000000000") represents one file →
 *     recover its physical name by stripping the suffix and report it once;
 *   - striper DATA stripes ("<name>.%016x", index > 0) are skipped (already
 *     accounted by their first stripe);
 *   - a flat object (this basic driver's own, no 16-hex stripe suffix) is itself.
 * The logical path is recovered by stripping the export key_prefix; a key outside
 * the prefix yields path=NULL (an orphan candidate). want_stat adds a rados_stat
 * per reported object. Worker-safe: synchronous librados, no pool/log/metrics.
 * Returns NGX_OK (enumeration ran; the callback may have aborted early) or
 * NGX_ERROR (errno set) if the pool list could not be opened. */
static ngx_int_t
sd_ceph_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    sd_ceph_state_t  *st = inst->state;
    rados_list_ctx_t  lc;
    const char       *oid;
    size_t            plen = (st->key_prefix != NULL) ? strlen(st->key_prefix) : 0;

    if (sd_ceph_set_errno(rados_nobjects_list_open(st->ioctx, &lc))) {
        return NGX_ERROR;
    }

    while (rados_nobjects_list_next(lc, &oid, NULL, NULL) == 0) {
        char                    pfn[1024];
        const char             *key_name;
        brix_sd_catalog_ent_t ent;
        uint64_t                size = 0;
        time_t                  mtime = 0;

        if (sd_ceph_oid_is_stripe_data(oid)) {
            continue;                  /* data stripe → counted by its first stripe */
        }
        if (sd_ceph_oid_is_first_stripe(oid)) {
            if (sd_ceph_oid_to_pfn(oid, pfn, sizeof(pfn)) != 0) {
                continue;              /* unrepresentable physical name → skip */
            }
            key_name = pfn;            /* the striper file's physical name */
        } else {
            key_name = oid;            /* flat object: it IS its own key */
        }

        ngx_memzero(&ent, sizeof(ent));
        ent.key  = key_name;
        ent.path = (plen == 0)
                   ? key_name
                   : (strncmp(key_name, st->key_prefix, plen) == 0
                          ? key_name + plen     /* recovered logical path */
                          : NULL);              /* outside prefix → orphan candidate */
        if (want_stat && rados_stat(st->ioctx, oid, &size, &mtime) == 0) {
            ent.have_stat = 1;
            ent.size  = (off_t) size;
            ent.mtime = mtime;
        }
        if (cb(ctx, &ent) != 0) {
            break;                     /* caller asked to stop — not an error */
        }
    }

    rados_nobjects_list_close(lc);
    return NGX_OK;
}

/* The Ceph driver descriptor. Honest caps: range read, random write, truncate —
 * no CAP_FD/SENDFILE (no fd; VFS serves memory-backed), no CAP_DIRS (flat key
 * namespace), no CAP_HARD_RENAME (no atomic rename). Directory iteration, rename,
 * xattr and staged commit are deliberately absent from this basic backend. */
const brix_sd_driver_t brix_sd_ceph_driver = {
    .name = "ceph",
    /* XATTR: the get/set/removexattr slots store object xattrs via rados_*xattr,
     * so a ceph object can carry the cinfo/meta records (phase-64 SP3 cache-store
     * role, XATTR cinfo mode - the cache state lives on the RADOS object itself). */
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_CATALOG,

    .init    = sd_ceph_init,
    .cleanup = sd_ceph_cleanup,
    .open    = sd_ceph_open,
    .close   = sd_ceph_close,

    .pread            = sd_ceph_pread,
    .pwrite           = sd_ceph_pwrite,
    .preadv           = sd_ceph_preadv,
    .preadv2          = sd_ceph_preadv2,
    .read_sendfile_fd = sd_ceph_read_sendfile_fd,
    .ftruncate        = sd_ceph_ftruncate,
    .fsync            = sd_ceph_fsync,
    .fstat            = sd_ceph_fstat,

    .stat   = sd_ceph_stat,
    .unlink = sd_ceph_unlink,

    .getxattr    = sd_ceph_getxattr,
    .listxattr   = sd_ceph_listxattr,
    .setxattr    = sd_ceph_setxattr,
    .removexattr = sd_ceph_removexattr,

    .staged_open   = sd_ceph_staged_open,
    .staged_write  = sd_ceph_staged_write,
    .staged_commit = sd_ceph_staged_commit,
    .staged_abort  = sd_ceph_staged_abort,

    .enumerate     = sd_ceph_enumerate,
};

#endif /* BRIX_HAVE_CEPH */
