/*
 * sd_cephfs_ro.c — read-only CephFS-via-RADOS storage driver ("cephfsro").
 *
 * WHAT: A Storage Driver that serves a real CephFS filesystem by reading its
 *       on-RADOS structures directly — directory entries from the metadata pool's
 *       omaps, file bytes from the data pool's objects — with no kernel mount, no
 *       MDS, and no libcephfs. It implements the read side of the vtable
 *       (open/pread/fstat/stat/opendir/readdir/getxattr/listxattr); every
 *       mutating slot is absent (the driver advertises no write capability).
 *
 * WHY:  When a CephFS cannot be mounted but its pools are intact, this is the
 *       rescue path to get the data back. It reuses sd_ceph's cluster/oid layer
 *       for raw RADOS access and the cephfs_layout decoders for the MDS encodings.
 *
 * HOW:  Path resolution walks dentries from the root inode (1): for each name it
 *       reads the omap key "<name>_head" from the parent directory's fragment
 *       object(s) "<dirino>.<frag>" and decodes the embedded inode. File reads map
 *       (offset,len) through the inode's file_layout_t to "<ino>.<objno>" data
 *       objects. Directory listing enumerates every leaf-fragment omap. xattrs and
 *       symlink targets come straight from the decoded inode.
 *
 * SAFETY: a pure-RADOS reader only sees a consistent namespace on a QUIESCED fs
 *       (MDS journal flushed, no live writers). init() refuses to bind unless the
 *       operator asserts this via `assume_quiesced` (no active MDS probing — by
 *       design). See the program design doc referenced in sd_ceph.h.
 *
 * LAYOUT: this driver is split across three TUs for file size / auditability —
 *       this file (lifecycle + open/read/stat/xattr + the driver descriptor),
 *       sd_cephfs_ro_resolve.c (path resolution + retry policy) and
 *       sd_cephfs_ro_dir.c (directory iteration). Cross-TU symbols live in
 *       sd_cephfs_ro_internal.h.
 *
 * The whole driver compiles only when the build found librados (BRIX_HAVE_CEPH);
 * otherwise this is an empty translation unit and the registry never references
 * the symbol.
 */
#include "sd_ceph.h"

#if BRIX_HAVE_CEPH

#include "cephfs_layout.h"
#include "sd_cephfs_ro_internal.h"

#include <rados/librados.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CEPHFS_RO_MAX_RETRY   3               /* bounded retries on transient/race */

/* ---- driver-private state ------------------------------------------------- */

/* per-open object: the resolved inode identity + (for files) its layout/size. */
typedef struct {
    uint64_t        ino;
    uint64_t        size;
    cephfs_layout_t layout;
    int             is_dir;
} cephfsro_obj_t;

/* ---- instance lifecycle --------------------------------------------------- */

static sd_ceph_conn_t *
cephfsro_connect_pool(const brix_sd_cephfs_ro_conf_t *dc, const char *pool,
                      ngx_pool_t *ngxpool, int *err)
{
    brix_sd_ceph_conf_t cc;

    memset(&cc, 0, sizeof(cc));
    cc.pool      = pool;
    cc.conf_file = dc->conf_file;
    cc.user      = dc->user;
    cc.keyring   = dc->keyring;
    cc.key_prefix = "";
    return sd_ceph_conn_create(&cc, ngxpool, err);
}

static ngx_int_t
cephfsro_init(brix_sd_instance_t *inst, void *driver_conf)
{
    brix_sd_cephfs_ro_conf_t *dc = driver_conf;
    cephfsro_state_t           *st;
    int                         err = 0;

    if (dc == NULL || dc->meta_pool == NULL || dc->data_pool == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    /* operator safety assertion — refuse to bind unless the consistency model is
     * acknowledged: `quiesced` (fs frozen) OR `live` (still mounted; best-effort
     * eventually-consistent, with optimistic revalidation + retry). */
    if (!dc->assume_quiesced && !dc->live) {
        errno = EPERM;
        return NGX_ERROR;
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) { errno = ENOMEM; return NGX_ERROR; }
    st->live      = dc->live ? 1 : 0;
    st->max_retry = CEPHFS_RO_MAX_RETRY;
    inst->state = st;

    st->meta = cephfsro_connect_pool(dc, dc->meta_pool, inst->pool, &err);
    if (st->meta == NULL) { errno = err ? err : EIO; return NGX_ERROR; }
    st->data = cephfsro_connect_pool(dc, dc->data_pool, inst->pool, &err);
    if (st->data == NULL) {
        sd_ceph_conn_destroy(st->meta);
        st->meta = NULL;
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
cephfsro_cleanup(brix_sd_instance_t *inst)
{
    cephfsro_state_t *st = inst->state;

    if (st != NULL) {
        sd_ceph_conn_destroy(st->data);
        sd_ceph_conn_destroy(st->meta);
        st->data = st->meta = NULL;
    }
}

/* ---- object lifecycle ----------------------------------------------------- */

static brix_sd_obj_t *
cephfsro_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
              mode_t mode, int *err_out)
{
    cephfsro_state_t *st = inst->state;
    cephfs_dentry_t   dn;
    brix_sd_obj_t  *obj;
    cephfsro_obj_t   *os;
    int               rc;

    (void) mode;

    /* read-only: reject any write/create intent up front */
    if (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC)) {
        if (err_out != NULL) { *err_out = EROFS; }
        return NULL;
    }

    rc = cephfsro_resolve_retry(st, path, &dn);
    if (rc != 0) {
        if (err_out != NULL) { *err_out = (rc == 1) ? ENOENT : errno; }
        return NULL;
    }
    if (dn.kind != CEPHFS_DENTRY_PRIMARY) {
        /* a remote (hardlink) target: we have only ino+d_type, not a full inode */
        if (err_out != NULL) { *err_out = ENOTSUP; }
        return NULL;
    }
    if ((sd_flags & BRIX_SD_O_DIR) && !cephfs_mode_is_dir(dn.inode.mode)) {
        if (err_out != NULL) { *err_out = ENOTDIR; }
        return NULL;
    }

    obj = ngx_pcalloc(inst->pool, sizeof(*obj));
    os  = ngx_pcalloc(inst->pool, sizeof(*os));
    if (obj == NULL || os == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    os->ino    = dn.inode.ino;
    os->size   = dn.inode.size;
    os->layout = dn.inode.layout;
    os->is_dir = cephfs_mode_is_dir(dn.inode.mode) ? 1 : 0;

    obj->driver = &brix_sd_cephfs_ro_driver;
    obj->inst   = inst;
    obj->fd     = NGX_INVALID_FILE;            /* no kernel fd — memory-backed */
    obj->state  = os;
    cephfsro_stat_from_inode(&dn.inode, &obj->snap);
    return obj;
}

static ngx_int_t
cephfsro_close(brix_sd_obj_t *obj)
{
    (void) obj;        /* obj + state are on the instance pool */
    return NGX_OK;
}

/* ---- file read ------------------------------------------------------------ */

/* Map a file offset to its data object + in-object offset via the file layout
 * (the standard Ceph striping math), and return how many contiguous bytes can be
 * read there (bounded by the stripe unit). su==os, sc==1 is the default layout. */
static size_t
cephfsro_map(const cephfs_layout_t *L, off_t off, uint64_t *objno_out,
             off_t *objoff_out)
{
    uint64_t su = L->stripe_unit;
    uint64_t sc = (L->stripe_count > 0) ? L->stripe_count : 1;
    uint64_t os = L->object_size;
    uint64_t blockno, blockoff, stripeno, stripepos, objsetno, opo;

    if (su == 0 || os == 0 || (os % su) != 0) {
        return 0;                       /* implausible layout */
    }
    blockno   = (uint64_t) off / su;
    blockoff  = (uint64_t) off % su;
    stripeno  = blockno / sc;
    stripepos = blockno % sc;
    objsetno  = stripeno / (os / su);
    opo       = stripeno % (os / su);

    *objno_out  = objsetno * sc + stripepos;
    *objoff_out = (off_t) (opo * su + blockoff);
    return (size_t) (su - blockoff);    /* contiguous run within this stripe unit */
}

static ssize_t
cephfsro_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    cephfsro_state_t *st = obj->inst->state;
    cephfsro_obj_t   *os = obj->state;
    uint64_t          objno = 0;
    off_t             objoff = 0;
    size_t            run;
    char              oid[64];
    ssize_t           n;

    if (off < 0) { errno = EINVAL; return -1; }
    if ((uint64_t) off >= os->size) { return 0; }          /* at/after EOF */

    run = cephfsro_map(&os->layout, off, &objno, &objoff);
    if (run == 0) { errno = EIO; return -1; }
    if (run > len) { run = len; }
    if ((uint64_t) off + run > os->size) {                 /* clamp to file size */
        run = (size_t) (os->size - (uint64_t) off);
    }

    snprintf(oid, sizeof(oid), "%llx.%08llx",
             (unsigned long long) os->ino, (unsigned long long) objno);
    {
        int attempt;
        for (attempt = 0; ; attempt++) {
            n = sd_ceph_oid_read(st->data, oid, buf, run, objoff);
            if (n >= 0) { break; }
            if (errno == ENOENT) {              /* sparse hole within EOF → zeros */
                memset(buf, 0, run);
                return (ssize_t) run;
            }
            if (cephfsro_is_transient(errno) && attempt < st->max_retry) {
                cephfsro_backoff(attempt);
                continue;
            }
            return -1;
        }
    }
    if (n == 0 && run > 0) {                     /* object shorter than expected */
        memset(buf, 0, run);
        return (ssize_t) run;
    }
    return n;
}

static ssize_t
cephfsro_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
                off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = cephfsro_pread(obj, iov[i].iov_base, iov[i].iov_len, off);
        if (n < 0) { return (total > 0) ? total : -1; }
        total += n;
        off   += n;
        if ((size_t) n < iov[i].iov_len) { break; }   /* short read → stop */
    }
    return total;
}

static ngx_int_t
cephfsro_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

/* ---- namespace ------------------------------------------------------------ */

static ngx_int_t
cephfsro_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    cephfsro_state_t *st = inst->state;
    cephfs_dentry_t   dn;
    int               rc = cephfsro_resolve_retry(st, path, &dn);

    if (rc != 0) { errno = (rc == 1) ? ENOENT : errno; return NGX_ERROR; }
    if (dn.kind != CEPHFS_DENTRY_PRIMARY) { errno = ENOTSUP; return NGX_ERROR; }
    cephfsro_stat_from_inode(&dn.inode, out);
    return NGX_OK;
}

/* ---- xattr (read-only) ---------------------------------------------------- */

/* Resolve a path's inode xattrs into a stack dentry; shared by get/list. */
static int
cephfsro_resolve_xattrs(brix_sd_instance_t *inst, const char *path,
                        cephfs_dentry_t *dn)
{
    cephfsro_state_t *st = inst->state;
    int               rc = cephfsro_resolve_retry(st, path, dn);

    if (rc != 0) { errno = (rc == 1) ? ENOENT : errno; return -1; }
    if (dn->kind != CEPHFS_DENTRY_PRIMARY) { errno = ENOTSUP; return -1; }
    return 0;
}

static ssize_t
cephfsro_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
                  void *buf, size_t cap)
{
    cephfs_dentry_t dn;
    uint32_t        i;

    if (cephfsro_resolve_xattrs(inst, path, &dn) != 0) { return -1; }
    for (i = 0; i < dn.nxattrs; i++) {
        if (dn.xattrs[i].name_len == strlen(name)
            && memcmp(dn.xattrs[i].name, name, dn.xattrs[i].name_len) == 0)
        {
            if (cap == 0) { return (ssize_t) dn.xattrs[i].val_len; }   /* size probe */
            if (dn.xattrs[i].val_len > cap) { errno = ERANGE; return -1; }
            memcpy(buf, dn.xattrs[i].val, dn.xattrs[i].val_len);
            return (ssize_t) dn.xattrs[i].val_len;
        }
    }
    errno = ENODATA;
    return -1;
}

static ssize_t
cephfsro_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
                   size_t cap)
{
    cephfs_dentry_t dn;
    uint32_t        i;
    size_t          need = 0;
    char           *out  = buf;

    if (cephfsro_resolve_xattrs(inst, path, &dn) != 0) { return -1; }
    for (i = 0; i < dn.nxattrs; i++) {
        need += dn.xattrs[i].name_len + 1;          /* name + NUL */
    }
    if (cap == 0) { return (ssize_t) need; }        /* size probe */
    if (need > cap) { errno = ERANGE; return -1; }
    for (i = 0; i < dn.nxattrs; i++) {
        memcpy(out, dn.xattrs[i].name, dn.xattrs[i].name_len);
        out += dn.xattrs[i].name_len;
        *out++ = '\0';
    }
    return (ssize_t) need;
}

/* ---- driver descriptor ---------------------------------------------------- */

const brix_sd_driver_t brix_sd_cephfs_ro_driver = {
    .name = "cephfsro",
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_MEMFILE,

    .init    = cephfsro_init,
    .cleanup = cephfsro_cleanup,

    .open  = cephfsro_open,
    .close = cephfsro_close,

    .pread  = cephfsro_pread,
    .preadv = cephfsro_preadv,
    .fstat  = cephfsro_fstat,

    .stat = cephfsro_stat,

    .opendir  = cephfsro_opendir,
    .readdir  = cephfsro_readdir,
    .closedir = cephfsro_closedir,

    .getxattr  = cephfsro_getxattr,
    .listxattr = cephfsro_listxattr,

    /* every mutating slot is intentionally absent (read-only driver) */
};

#endif /* BRIX_HAVE_CEPH */
