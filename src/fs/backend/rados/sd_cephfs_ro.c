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
 * The whole driver compiles only when the build found librados (BRIX_HAVE_CEPH);
 * otherwise this is an empty translation unit and the registry never references
 * the symbol.
 */
#include "sd_ceph.h"

#if BRIX_HAVE_CEPH

#include "cephfs_layout.h"

#include <rados/librados.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CEPHFS_ROOT_INO       1ull
#define CEPHFS_DENTRY_VAL_MAX (64u * 1024u)   /* a dentry omap value is ~0.5–4 KiB */
#define CEPHFS_READDIR_PAGE   256             /* omap keys fetched per round       */
#define CEPHFS_RO_MAX_RETRY   3               /* bounded retries on transient/race */
#define CEPHFS_RO_MAXDEPTH    128             /* path components tracked for revalid*/
#define CEPHFS_RO_BACKOFF_US  2000            /* base backoff (×2^attempt, capped)  */

/* ---- driver-private state ------------------------------------------------- */

/* per-export: connections to the metadata + data pools, plus the consistency
 * mode. `live` enables best-effort tracking of a still-mounted fs: optimistic
 * walk-version revalidation (detect an MDS write that landed mid-walk and retry)
 * and a bounded retry of a not-found whose path raced. `quiesced` mode trusts the
 * fs is frozen and only retries genuinely transient cluster errors. */
typedef struct {
    sd_ceph_conn_t *meta;
    sd_ceph_conn_t *data;
    int             live;
    int             max_retry;
} cephfsro_state_t;

/* One on-path directory object captured during a resolve, with the RADOS object
 * version at read time, so a later revalidation can tell if it changed under us. */
typedef struct {
    char     oid[64];
    uint64_t version;
} cephfsro_pathver_t;

/* Optional per-resolve walk record (live mode): the dir objects touched on the
 * path and their versions, for optimistic revalidation. */
typedef struct {
    cephfsro_pathver_t ent[CEPHFS_RO_MAXDEPTH];
    int                n;
} cephfsro_walk_t;

/* per-open object: the resolved inode identity + (for files) its layout/size. */
typedef struct {
    uint64_t        ino;
    uint64_t        size;
    cephfs_layout_t layout;
    int             is_dir;
} cephfsro_obj_t;

/* per-opendir: the directory inode + its leaf fragments, plus an omap-paging
 * cursor and one buffered page of entry names. */
typedef struct {
    uint64_t  ino;
    uint32_t  frags[CEPHFS_MAX_FRAGS];
    uint32_t  nfrags;
    uint32_t  fi;                                   /* current fragment index   */
    char      last_key[256];                        /* omap pagination cursor   */
    int       more_in_frag;                         /* current frag has more    */
    char      names[CEPHFS_READDIR_PAGE][256];      /* buffered page            */
    uint32_t  npage;
    uint32_t  pi;                                   /* next page slot to return */
} cephfsro_dir_t;

/* ---- retry policy --------------------------------------------------------- */

/* A transient cluster error is worth retrying regardless of consistency mode
 * (cluster blip, peering, blocklist churn); a permanent one (ENOENT/EACCES/…) is
 * fast-failed. EIO is treated as transient because librados surfaces several
 * recoverable conditions as EIO. */
static int
cephfsro_is_transient(int err)
{
    switch (err) {
    case EAGAIN: case ETIMEDOUT: case EBUSY: case EINTR: case EIO:
        return 1;
    default:
        return 0;
    }
}

/* Sleep an exponentially-growing, jittered, capped backoff before a retry. Held
 * only on the (rare) error/race path; the ceph data path is synchronous anyway. */
static void
cephfsro_backoff(int attempt)
{
    long            us = (long) CEPHFS_RO_BACKOFF_US << attempt;
    struct timespec ts;

    if (us > 50000) { us = 50000; }                 /* cap at 50 ms */
    us += (long) (us / 4) ? (long) (clock() % (us / 4 + 1)) : 0;   /* light jitter */
    ts.tv_sec  = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

/* ---- small helpers -------------------------------------------------------- */

/* Read a single omap value by key from `oid` into `buf`. On success returns the
 * value length (>=0) via *outlen and 0; returns -1/errno on a RADOS error and 1
 * when the key is simply absent (so callers distinguish "not found" from error).
 * When `version` is non-NULL it receives the RADOS object version at read time
 * (for optimistic revalidation). */
static int
cephfsro_omap_get1(rados_ioctx_t ioctx, const char *oid, const char *key,
                   void *buf, size_t cap, size_t *outlen, uint64_t *version)
{
    const char        *keys[1];
    rados_omap_iter_t  it = NULL;
    rados_read_op_t    op;
    int                prval = 0, rc, found = 0;
    char              *k = NULL, *v = NULL;
    size_t             vlen = 0;

    keys[0] = key;
    op = rados_create_read_op();
    rados_read_op_omap_get_vals_by_keys(op, keys, 1, &it, &prval);
    rc = rados_read_op_operate(op, ioctx, oid, 0);
    if (rc < 0) {
        rados_release_read_op(op);
        errno = -rc;
        return -1;
    }
    if (version != NULL) { *version = rados_get_last_version(ioctx); }
    if (it != NULL && rados_omap_get_next(it, &k, &v, &vlen) == 0
        && k != NULL && v != NULL)
    {
        size_t n = (vlen < cap) ? vlen : cap;
        memcpy(buf, v, n);
        *outlen = n;
        found = 1;
    }
    if (it != NULL) { rados_omap_get_end(it); }
    rados_release_read_op(op);
    return found ? 0 : 1;
}

/* Current RADOS version of `oid` (a cheap stat op). Returns 0 / -1 (errno). */
static int
cephfsro_obj_version(rados_ioctx_t ioctx, const char *oid, uint64_t *version)
{
    rados_read_op_t op = rados_create_read_op();
    uint64_t        psize = 0;
    struct timespec pmt;
    int             prval = 0, rc;

    rados_read_op_stat2(op, &psize, &pmt, &prval);
    rc = rados_read_op_operate(op, ioctx, oid, 0);
    rados_release_read_op(op);
    if (rc < 0) { errno = -rc; return -1; }
    *version = rados_get_last_version(ioctx);
    return 0;
}

/* Append a (oid, version) record to a walk, if capturing and not full. */
static void
cephfsro_walk_add(cephfsro_walk_t *w, const char *oid, uint64_t version)
{
    if (w == NULL || w->n >= CEPHFS_RO_MAXDEPTH) { return; }
    snprintf(w->ent[w->n].oid, sizeof(w->ent[w->n].oid), "%s", oid);
    w->ent[w->n].version = version;
    w->n++;
}

/* Look up `name` directly beneath directory inode `dirino` whose leaf fragments
 * are `frags[0..nfrags)`: scan each fragment object for "<name>_head" and decode
 * the first hit into *out. Scanning every leaf frag is correct for both unsplit
 * and fragmented dirs (a dentry lives in exactly one frag) and avoids needing the
 * dentry-hash→frag mapping. When `walk` is non-NULL the dir object the result
 * depended on (the frag that held the entry, or the first frag searched when
 * absent) is recorded with its version for later revalidation. Returns 0 (found),
 * 1 (absent), -1 (error). */
static int
cephfsro_lookup(cephfsro_state_t *st, uint64_t dirino, const uint32_t *frags,
                uint32_t nfrags, const char *name, cephfs_dentry_t *out,
                cephfsro_walk_t *walk)
{
    rados_ioctx_t meta = sd_ceph_conn_ioctx(st->meta);
    char          key[300];
    char          first_oid[64] = "";
    uint64_t      first_ver = 0;
    int           have_first = 0;
    uint32_t      i;

    if (snprintf(key, sizeof(key), "%s_head", name) >= (int) sizeof(key)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    for (i = 0; i < nfrags; i++) {
        char     oid[64];
        char     val[CEPHFS_DENTRY_VAL_MAX];
        size_t   vlen = 0;
        uint64_t ver = 0;
        int      rc;

        snprintf(oid, sizeof(oid), "%llx.%08llx",
                 (unsigned long long) dirino, (unsigned long long) frags[i]);
        rc = cephfsro_omap_get1(meta, oid, key, val, sizeof(val), &vlen, &ver);
        if (rc < 0) {
            /* an absent fragment object is not an error — try the next frag */
            if (errno == ENOENT) { continue; }
            return -1;
        }
        if (!have_first) {
            snprintf(first_oid, sizeof(first_oid), "%s", oid);
            first_ver = ver; have_first = 1;
        }
        if (rc == 0) {
            if (cephfs_decode_dentry(val, vlen, out) != 0) {
                errno = EIO;
                return -1;
            }
            cephfsro_walk_add(walk, oid, ver);     /* depended on this frag */
            return 0;
        }
    }
    /* absent: record the dir we searched so a concurrent change is detectable */
    if (have_first) { cephfsro_walk_add(walk, first_oid, first_ver); }
    return 1;   /* not found in any fragment */
}

/* Fill *out with a synthetic dentry for the CephFS root (inode 1). The root is
 * assumed unfragmented (the overwhelmingly common case); its single fragment
 * object is "1.00000000". */
static void
cephfsro_fill_root(cephfs_dentry_t *out)
{
    memset(out, 0, sizeof(*out));
    out->kind          = CEPHFS_DENTRY_PRIMARY;
    out->inode.ino     = CEPHFS_ROOT_INO;
    out->inode.mode    = CEPHFS_S_IFDIR | 0755;
    out->inode.nlink   = 2;
    out->nfrags        = 1;
    out->frag_enc[0]   = 0;
}

/* Resolve an absolute logical path to its dentry by walking from the root. The
 * leading '/' is optional; "" or "/" resolves to the root. When `walk` is
 * non-NULL, the dir objects each component depended on are recorded with their
 * versions for optimistic revalidation. Returns 0 on success, 1 when a component
 * is absent (ENOENT), -1 on error. */
static int
cephfsro_resolve(cephfsro_state_t *st, const char *path, cephfs_dentry_t *out,
                 cephfsro_walk_t *walk)
{
    uint64_t parent_ino = CEPHFS_ROOT_INO;
    uint32_t parent_frags[CEPHFS_MAX_FRAGS];
    uint32_t parent_nfrags = 1;
    const char *p = (path != NULL) ? path : "";

    parent_frags[0] = 0;
    cephfsro_fill_root(out);
    if (walk != NULL) { walk->n = 0; }

    while (*p != '\0') {
        char     comp[256];
        size_t   len = 0;
        int      rc;

        while (*p == '/') { p++; }
        if (*p == '\0') { break; }
        while (*p != '\0' && *p != '/') {
            if (len + 1 >= sizeof(comp)) { errno = ENAMETOOLONG; return -1; }
            comp[len++] = *p++;
        }
        comp[len] = '\0';

        rc = cephfsro_lookup(st, parent_ino, parent_frags, parent_nfrags, comp,
                             out, walk);
        if (rc != 0) { return rc; }            /* absent (1) or error (-1) */

        if (out->kind == CEPHFS_DENTRY_REMOTE) {
            /* a hardlink: terminal use is fine, but we cannot descend through it */
            while (*p == '/') { p++; }
            if (*p != '\0') { errno = ENOTDIR; return -1; }
            return 0;
        }

        parent_ino    = out->inode.ino;
        parent_nfrags = (out->nfrags < CEPHFS_MAX_FRAGS) ? out->nfrags
                                                         : CEPHFS_MAX_FRAGS;
        memcpy(parent_frags, out->frag_enc, parent_nfrags * sizeof(uint32_t));
    }
    return 0;
}

/* Re-check every dir object a resolve depended on: 1 if any changed version
 * since the walk (an MDS write landed mid-walk → the result may be inconsistent),
 * 0 if all stable, and 1 (conservatively "changed") if a probe errors. */
static int
cephfsro_walk_changed(cephfsro_state_t *st, const cephfsro_walk_t *w)
{
    rados_ioctx_t meta = sd_ceph_conn_ioctx(st->meta);
    int           i;

    for (i = 0; i < w->n; i++) {
        uint64_t now = 0;
        if (cephfsro_obj_version(meta, w->ent[i].oid, &now) != 0) {
            return 1;                          /* can't confirm stable → retry */
        }
        if (now != w->ent[i].version) { return 1; }
    }
    return 0;
}

/* Resolve with the consistency policy applied: bounded retries on a transient
 * cluster error always, and — in live mode — a retry when optimistic
 * revalidation shows a dir on the path changed during the walk (so an infrequent
 * MDS sync that lands mid-resolve is picked up rather than served torn/stale).
 * A genuine, stable not-found or permanent error fast-fails. Returns 0 / 1 / -1
 * like cephfsro_resolve, with errno set. */
static int
cephfsro_resolve_retry(cephfsro_state_t *st, const char *path,
                       cephfs_dentry_t *out)
{
    int attempt;

    for (attempt = 0; ; attempt++) {
        cephfsro_walk_t  walk;
        cephfsro_walk_t *wp = st->live ? &walk : NULL;
        int              rc;

        walk.n = 0;
        rc = cephfsro_resolve(st, path, out, wp);

        if (rc == 0) {                                     /* found */
            if (wp != NULL && cephfsro_walk_changed(st, wp)
                && attempt < st->max_retry)
            {
                cephfsro_backoff(attempt);                 /* raced — re-resolve */
                continue;
            }
            return 0;
        }
        if (rc < 0 && cephfsro_is_transient(errno)
            && attempt < st->max_retry)
        {
            cephfsro_backoff(attempt);                     /* transient — retry  */
            continue;
        }
        if (rc == 1 && wp != NULL && cephfsro_walk_changed(st, wp)
            && attempt < st->max_retry)
        {
            cephfsro_backoff(attempt);     /* not-found but path raced — retry   */
            continue;
        }
        return rc;                                         /* stable result      */
    }
}

/* Fill an SD stat from a decoded primary inode. */
static void
cephfsro_stat_from_inode(const cephfs_inode_t *in, brix_sd_stat_t *out)
{
    memset(out, 0, sizeof(*out));
    out->size   = (off_t) in->size;
    out->mtime  = (time_t) in->mtime_sec;
    out->ctime  = (time_t) in->ctime_sec;
    out->mode   = (mode_t) in->mode;
    out->ino    = (ino_t) in->ino;
    out->is_dir = cephfs_mode_is_dir(in->mode) ? 1 : 0;
    out->is_reg = cephfs_mode_is_reg(in->mode) ? 1 : 0;
}

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

/* ---- directory iteration -------------------------------------------------- */

static int cephfsro_dir_fetch_page(cephfsro_state_t *st, cephfsro_dir_t *ds);

static brix_sd_dir_t *
cephfsro_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    cephfsro_state_t *st = inst->state;
    cephfs_dentry_t   dn;
    brix_sd_dir_t  *d;
    cephfsro_dir_t   *ds;
    int               rc = cephfsro_resolve_retry(st, path, &dn);

    if (rc != 0) {
        if (err_out != NULL) { *err_out = (rc == 1) ? ENOENT : errno; }
        return NULL;
    }
    if (dn.kind != CEPHFS_DENTRY_PRIMARY || !cephfs_mode_is_dir(dn.inode.mode)) {
        if (err_out != NULL) { *err_out = ENOTDIR; }
        return NULL;
    }

    d  = ngx_pcalloc(inst->pool, sizeof(*d));
    ds = ngx_pcalloc(inst->pool, sizeof(*ds));
    if (d == NULL || ds == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ds->ino    = dn.inode.ino;
    ds->nfrags = (dn.nfrags < CEPHFS_MAX_FRAGS) ? dn.nfrags : CEPHFS_MAX_FRAGS;
    if (ds->nfrags == 0) { ds->nfrags = 1; ds->frags[0] = 0; }
    else { memcpy(ds->frags, dn.frag_enc, ds->nfrags * sizeof(uint32_t)); }

    /* prime the first fragment's page so readdir starts serving immediately */
    if (cephfsro_dir_fetch_page(st, ds) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    d->inst  = inst;
    d->state = ds;
    return d;
}

/* Strip the trailing "_<snapid>" (e.g. "_head") from a dir omap key to recover
 * the dentry name. Copies up to the last '_' into out. Returns 0, or -1 if the
 * key has no '_' (not a dentry key — caller should skip it). */
static int
cephfsro_key_to_name(const char *key, char *out, size_t cap)
{
    const char *us = strrchr(key, '_');
    size_t      n;

    if (us == NULL) { return -1; }
    n = (size_t) (us - key);
    if (n == 0 || n + 1 > cap) { return -1; }
    memcpy(out, key, n);
    out[n] = '\0';
    return 0;
}

/* Fetch the next page of dentry names for the directory's current fragment into
 * ds->names[], advancing the omap cursor. Returns 0 on success (npage set, may be
 * 0), -1/errno on a RADOS error. */
static int
cephfsro_dir_fetch_page(cephfsro_state_t *st, cephfsro_dir_t *ds)
{
    rados_ioctx_t      meta = sd_ceph_conn_ioctx(st->meta);
    char               oid[64];
    rados_omap_iter_t  it = NULL;
    rados_read_op_t    op;
    int                prval = 0, rc;
    unsigned char      pmore = 0;
    char              *k = NULL, *v = NULL;
    size_t             vlen = 0;

    ds->npage = 0;
    ds->pi    = 0;

    snprintf(oid, sizeof(oid), "%llx.%08llx",
             (unsigned long long) ds->ino,
             (unsigned long long) ds->frags[ds->fi]);

    {
        int attempt;
        for (attempt = 0; ; attempt++) {
            op = rados_create_read_op();
            rados_read_op_omap_get_vals2(op, ds->last_key[0] ? ds->last_key : "",
                                         "", CEPHFS_READDIR_PAGE, &it, &pmore,
                                         &prval);
            rc = rados_read_op_operate(op, meta, oid, 0);
            if (rc >= 0) { break; }
            rados_release_read_op(op);
            if (-rc == ENOENT) { ds->more_in_frag = 0; return 0; } /* no such frag */
            if (cephfsro_is_transient(-rc) && attempt < st->max_retry) {
                cephfsro_backoff(attempt);
                continue;
            }
            errno = -rc;
            return -1;
        }
    }
    while (it != NULL && rados_omap_get_next(it, &k, &v, &vlen) == 0 && k != NULL) {
        char name[256];
        (void) v; (void) vlen;
        if (ds->npage < CEPHFS_READDIR_PAGE
            && cephfsro_key_to_name(k, name, sizeof(name)) == 0)
        {
            ngx_memcpy(ds->names[ds->npage], name, strlen(name) + 1);
            ds->npage++;
        }
        ngx_memcpy(ds->last_key, k, strlen(k) + 1);   /* cursor = last key seen */
    }
    if (it != NULL) { rados_omap_get_end(it); }
    rados_release_read_op(op);
    ds->more_in_frag = (pmore != 0);
    return 0;
}

static ngx_int_t
cephfsro_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    cephfsro_state_t *st = d->inst->state;
    cephfsro_dir_t   *ds = d->state;

    for (;;) {
        if (ds->pi < ds->npage) {
            ngx_memcpy(out->name, ds->names[ds->pi], strlen(ds->names[ds->pi]) + 1);
            ds->pi++;
            return NGX_OK;
        }
        /* current page exhausted: more in this frag? */
        if (ds->more_in_frag) {
            if (cephfsro_dir_fetch_page(st, ds) != 0) { return NGX_ERROR; }
            continue;
        }
        /* advance to the next fragment */
        ds->fi++;
        if (ds->fi >= ds->nfrags) { return NGX_DONE; }   /* end of directory */
        ds->last_key[0] = '\0';
        ds->more_in_frag = 1;                            /* force a first fetch */
        if (cephfsro_dir_fetch_page(st, ds) != 0) { return NGX_ERROR; }
    }
}

static ngx_int_t
cephfsro_closedir(brix_sd_dir_t *d)
{
    (void) d;          /* dir + state are on the instance pool */
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
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_XATTR,

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
